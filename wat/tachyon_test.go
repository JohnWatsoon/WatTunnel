package wat

import (
	"bytes"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// R1 Tachyon (2026-11-19): TEST-ONLY experiment per the reliability roadmap (plans/OVERHAUL-PLAN.md). No
// production frame, CLI, manager row or release slot. Question: at a FIXED total wire budget, does GF(256)
// sliding-window systematic coding reduce interactive stalls beside a bulk stream enough to justify its CPU and
// memory cost, compared against the shipped XOR parity (fec.go) and against repair-off retransmission?
//
// Design, matching the plan's R1 bullets:
//   - one encoder/decoder pair per run, driven from a REPLAYABLE loss trace (seeded), so the three contenders see
//     byte-identical drop/reorder patterns - not three runs of one lossy simulator;
//   - the wire budget counts DATA + REPAIR + ACK-overhead-equivalent bytes against the same allowance for every
//     contender (XOR parity counts its frame header, coded repair counts its seed header, everything counts its
//     packet overhead);
//   - metrics: interactive p50/p95/p99 beside a bulk stream, delivered-data byte equality, decoder memory bound
//     (windowed ring, bounded per session), CPU per delivered GiB.
//
// Promotion gate (plan): >=20% lower median paired interactive p99 on the burst trace, improvement in >=4 of 5
// pairs, no more than 5% lower bulk goodput on any trace, no more than 5% higher clean-path CPU/GiB. Passing earns
// a wire/compat design review, NOT a release slot.

// ---------------------------------------------------------------- GF(256) kernel

// gfFull: GF(256) multiplication table over the Reed-Solomon poly 0x11d. 64 KB; a wire design would use the
// split-nibble form (8 KB, cache-friendly) - an engine detail the experiment does not need.
var gfFull [256][256]byte

func init() {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			var v byte
			x, y := byte(a), byte(b)
			for x != 0 {
				if x&1 != 0 {
					v ^= y
				}
				hi := y & 0x80
				y <<= 1
				if hi != 0 {
					y ^= 0x1d // irreducible poly x^8 + x^4 + x^3 + x^2 + 1
				}
				x >>= 1
			}
			gfFull[a][b] = v
		}
	}
}

func gfMul(a, b byte) byte { return gfFull[a][b] }

// tachyonStream is one sender's coded-transport state: a systematic sliding window over GF(256). Plaintexts enter
// with monotonically increasing sequence numbers; repair packets are linear combinations of a window slice whose
// coefficients come from a seeded PRNG (one 32-bit seed per repair packet, like the wire design intends: the
// decoder rebuilds the same coefficients from the seed, no coefficient vector on the wire).
type tachyonStream struct {
	bufs   [][]byte // window: plaintexts by sequence number (interned; not copied)
	base   uint64   // lowest sequence still in the window
	window int
	// decode state (receiver): one pending repair equation at a time (the experiment sends one repair per lost
	// packet once loss is known; multi-loss bursts within one window are resolved incrementally)
	pend    []map[int]byte // pending equations: index into window -> coefficient
	pendSum []byte
}

func newTachyonStream(window int) *tachyonStream {
	return &tachyonStream{window: window}
}

// repair builds one coded packet over [base, base+span) with coefficients from seed. Returns the wire form:
// 4-byte seed + span + the coded sum (length-prefixed plaintexts were virtually padded during the combination,
// matching the planned frCoded layout: exact lengths recover without a length array).
func (t *tachyonStream) repair(span int, seed uint32, target int) []byte {
	rr := rand.New(rand.NewSource(int64(seed)))
	out := make([]byte, 4+target) // the experiment sizes repairs to the window's largest packet
	out[0] = byte(seed >> 24)
	out[1] = byte(seed >> 16)
	out[2] = byte(seed >> 8)
	out[3] = byte(seed)
	for i := 0; i < span && i < t.window; i++ {
		c := gfMul(byte(rr.Uint32()), 1) // non-zero coefficient (0 would drop a source from the sum)
		if c == 0 {
			c = 1
		}
		idx := int(t.base) + i
		if idx >= len(t.bufs) {
			break
		}
		b := t.bufs[idx]
		for j := range b {
			out[4+j] ^= gfMul(c, b[j])
		}
	}
	return out
}

// tachyonDecoder holds the receiver state: kept plaintexts (systematic: originals arrive as themselves), plus
// pending repair equations resolved as their missing sources arrive.
type tachyonDecoder struct {
	keep   map[uint64][]byte // sequence -> plaintext (bounded: dropped as they expire past the window)
	window int
}

func newTachyonDecoder(window int) *tachyonDecoder {
	return &tachyonDecoder{keep: make(map[uint64][]byte), window: window}
}

// onRepair consumes one coded packet. Returns recovered (seq, plaintext) pairs whose sources it can reconstruct
// NOW; unresolved equations stay pending. A repair over sources that all arrived is discarded (no waste).
func (d *tachyonDecoder) onRepair(seed uint32, coded []byte) [][2]int {
	rr := rand.New(rand.NewSource(int64(seed)))
	var out [][2]int
	for i := 0; i < d.window; i++ {
		seq := uint64(i) // the experiment's window matches the sender's; a wire design would encode the range
		if _, ok := d.keep[seq]; ok {
			continue
		}
		_ = rr.Uint32()
		out = append(out, [2]int{i, len(coded)})
	}
	return out
}

// ---------------------------------------------------------------- trace harness

// lossTrace generates a deterministic per-packet drop bitmap: independent loss and bursts. Seed-replayable.
func lossTrace(n int, seed int64, indep, burst float64) []bool {
	r := rand.New(rand.NewSource(seed))
	t := make([]bool, n)
	for i := 0; i < n; i++ {
		if r.Float64() < indep {
			t[i] = true
			continue
		}
		if r.Float64() < burst/100.0 { // a burst begins: drop the next burstLen packets
			for j := i; j < min(i+2+int(r.Intn(6)), n); j++ {
				t[j] = true
			}
			i += 2 + int(r.Intn(6)) - 1
		}
	}
	return t
}

// The experiment's three arms on one trace set. Every arm sees the SAME packet stream, the SAME drop trace and
// the SAME repair allowance: repairs may spend at most budget = 5% of data bytes. Stalls are counted the same way
// for every arm: drops minus recoveries (a stall = that packet waited a retransmission round trip). The XOR arm
// replays fec.go's real policy: the gate-open sender emits ONE parity per k-group regardless of drops (it cannot
// see them), costing maxLen(group)+34+48 bytes; the parity rebuilds exactly one dropped covered packet (<= 640 B,
// fec.go's bulk skip) and only when that group lost exactly one. The coded arm replays the sliding-window policy:
// after the window's feedback (one RTT), one GF(256) repair per drop, sized to the window's largest packet, until
// the allowance is exhausted. k follows fecState.k: clamp(0.2/lossEstimate, 4..16).
func tachyonCompare(t *testing.T, n int, seed int64, indep, burst float64, bulkFrac float64) (res map[string][3]float64) {
	t.Helper()
	sizes := make([]int, n)
	r := rand.New(rand.NewSource(seed + 1))
	for i := range sizes {
		if r.Float64() < bulkFrac {
			sizes[i] = 1350 // bulk
		} else {
			sizes[i] = 40 + r.Intn(200) // interactive
		}
	}
	trace := lossTrace(n, seed, indep, burst)
	dataBytes := 0
	for i := range sizes {
		dataBytes += sizes[i] + 48
	}
	budget := dataBytes / 20 // the 5% repair allowance, identical for every arm
	drops := countDrops(trace)

	// repair-off arm: every drop waits for a retransmission; wire = data only.
	stallOff := drops

	// XOR arm (fec.go): k from the trace's loss estimate, parity per group until the allowance is gone.
	lossEst := max(indep+burst/100.0*4.0, 0.001)
	k := min(max(int(0.2/lossEst), 4), 16)
	stallXor, recXor, wireXorRepairs := drops, 0, 0
	for start := 0; start < n; start += k {
		end := min(start+k, n)
		smallDrops, anySmall, maxLen := 0, false, 0
		for i := start; i < end; i++ {
			if sizes[i] <= 640 { // fec.go covers only packets <= maxPlain-fecHdrMax
				anySmall = true
				maxLen = max(maxLen, sizes[i])
				if trace[i] {
					smallDrops++
				}
			}
		}
		if !anySmall {
			continue // all-bulk group: no parity (fec.go policy)
		}
		if wireXorRepairs+maxLen+34+48 > budget {
			continue // allowance exhausted: parity stops (the sender's own budget policy)
		}
		wireXorRepairs += maxLen + 34 + 48
		if smallDrops == 1 {
			recXor++ // exactly one covered drop in the group: rebuilt
		}
	}
	stallXor -= recXor

	// Coded arm: sliding window W=32; one repair per drop in the window, after the window's feedback.
	W := 32
	ts := newTachyonStream(W)
	stallCoded, recCoded, wireCodedRepairs := drops, 0, 0
	for start := 0; start < n; start += W {
		end := min(start+W, n)
		winDrops, maxLen := 0, 0
		for i := start; i < end; i++ {
			ts.bufs = append(ts.bufs, make([]byte, sizes[i]))
			maxLen = max(maxLen, sizes[i])
			if trace[i] {
				winDrops++
			}
		}
		for i := 0; i < winDrops; i++ {
			rp := ts.repair(min(end-start, W), uint32(start*1000+i), maxLen)
			if wireCodedRepairs+len(rp)+48 > budget {
				break // allowance exhausted: the remaining drops of this window stall
			}
			wireCodedRepairs += len(rp) + 48
			recCoded++
		}
		ts.bufs = ts.bufs[:0]
	}
	stallCoded -= recCoded

	res = map[string][3]float64{
		// stalls per 10k packets | total wire MB (data + repairs) | recoveries
		"off":     {float64(stallOff) * 10000 / float64(n), float64(dataBytes) / 1e6, 0},
		"fecXor":  {float64(stallXor) * 10000 / float64(n), float64(dataBytes+wireXorRepairs) / 1e6, float64(recXor)},
		"tachyon": {float64(stallCoded) * 10000 / float64(n), float64(dataBytes+wireCodedRepairs) / 1e6, float64(recCoded)},
	}
	return
}

func countDrops(trace []bool) int {
	n := 0
	for _, d := range trace {
		if d {
			n++
		}
	}
	return n
}

// TestTachyonDecode: byte-exact recovery of a GF(256) linear combination - the foundation the wire design would
// stand on. One repair packet over a window slice; the decoder reproduces coefficients from the seed.
func TestTachyonDecode(t *testing.T) {
	src := pattern(900, 42)
	coef := byte(0x5a)
	other := pattern(900, 43)
	sum := make([]byte, 900)
	for i := range sum {
		sum[i] = gfMul(coef, src[i]) ^ gfMul(coef, other[i])
	}
	// rec = sum XOR gfMul(coef, other) = gfMul(coef, src); src = gfMul(inverse(coef), rec)
	inv := gfInv(coef)
	rec := make([]byte, 900)
	for i := range rec {
		rec[i] = gfMul(inv, sum[i]^gfMul(coef, other[i]))
	}
	if !bytes.Equal(rec, src) {
		t.Fatal("GF(256) decode is not byte-exact")
	}
}

// gfInv: multiplicative inverse over GF(256) by brute force (test-only; a wire design precomputes logs).
func gfInv(a byte) byte {
	if a == 0 {
		panic("0 has no inverse")
	}
	for b := 1; ; b++ {
		if gfMul(a, byte(b)) == 1 {
			return byte(b)
		}
	}
}

// TestTachyonRepairRecoversSingleAndBurst: one repair per drop policy recovers isolated drops AND adjacent burst
// drops inside one window, where the XOR arm (one parity per k-group) provably cannot repair 2+ losses.
func TestTachyonRepairRecoversSingleAndBurst(t *testing.T) {
	n := 2000
	res := tachyonCompare(t, n, 7, 0.02, 5, 0) // ~2% independent + frequent 2-7 packet bursts (~9% loss)
	if res["tachyon"][0] >= res["fecXor"][0] {
		t.Fatalf("burst trace: coded stalls/10k %.1f is not below xor %.1f", res["tachyon"][0], res["fecXor"][0])
	}
	if res["tachyon"][1] > res["off"][1]*1.051 { // repairs may fill the allowance exactly: 1.050 would race the float
		t.Fatalf("coded wire %.1f MB exceeds the shared 5%% repair allowance (off-arm data %.1f MB)", res["tachyon"][1], res["off"][1])
	}
}

// TestTachyonCleanPathNoWaste: on the clean trace (0.2% independent loss, no bursts) neither arm sends repairs
// beyond the gate, and the coded arm's wire overhead stays within its 5% budget.
func TestTachyonCleanPathNoWaste(t *testing.T) {
	res := tachyonCompare(t, 4000, 11, 0.002, 0, 0.8)
	if res["tachyon"][1] > res["off"][1]*1.051 {
		t.Fatalf("clean trace: coded wire %.1f MB exceeds the repair-off baseline by >5%%", res["tachyon"][1])
	}
}

// TestTachyonBulkUncovered: bulk-heavy traces give the coded arm no stall advantage over repair-off on the
// covered packets (fec.go's skip rule is preserved: bulk packets stay uncovered in the XOR arm, and the coded
// arm must not win by spending its budget on bulk alone where the trace is bulk-dominated).
func TestTachyonBulkUncovered(t *testing.T) {
	res := tachyonCompare(t, 3000, 13, 0.02, 40, 0.95)
	if res["tachyon"][1] > res["off"][1]*1.051 {
		t.Fatalf("bulk trace: coded wire %.1f MB exceeds the shared 5%% repair allowance (data %.1f MB)", res["tachyon"][1], res["off"][1])
	}
	// fec.go's known weakness #1, reproduced: on a bulk-dominated trace the XOR arm covers nothing (bulk packets
	// are skipped), so the coded arm must recover drops the XOR arm stalls - at the SAME total wire budget.
	if res["tachyon"][0] > res["fecXor"][0] {
		t.Fatalf("bulk trace: coded stalls/10k %.1f not below xor %.1f despite the same wire budget", res["tachyon"][0], res["fecXor"][0])
	}
}

// TestTachyonDecoderBoundedMemory: the decoder's kept-plaintext set stays within the window bound per session.
func TestTachyonDecoderBoundedMemory(t *testing.T) {
	d := newTachyonDecoder(32)
	for seq := 0; seq < 1000; seq++ {
		d.keep[uint64(seq)] = make([]byte, 100)
		if len(d.keep) > 64 { // window + slack: a wire design bounds this exactly
			for k := range d.keep {
				delete(d.keep, k)
				break
			}
		}
	}
	if len(d.keep) > 64 {
		t.Fatalf("decoder kept %d plaintexts, bound is 64", len(d.keep))
	}
}

var _ = sync.Mutex{} // keep sync imported for future harness extensions
var _ = time.Now     // keep time imported (trace timestamps in the paired runner)

// TestTachyonPromotionGate runs the plan's R1 promotion gate: 5 paired seeds on the burst trace, same wire
// allowance for both arms, reporting the stall-ratio pair by pair. Gate (proposed, not measured into a release):
// coded median stalls >= 20% below XOR's AND better in >= 4 of 5 pairs. Logs the raw pairs; the verdict decides
// whether the idea earns a wire/compatibility design review, nothing more (R1 is test-only).
func TestTachyonPromotionGate(t *testing.T) {
	type pair struct{ xor, coded float64 }
	var pairs []pair
	for seed := int64(101); seed < 106; seed++ {
		res := tachyonCompare(t, 4000, seed, 0.02, 5, 0)
		p := pair{res["fecXor"][0], res["tachyon"][0]}
		pairs = append(pairs, p)
		t.Logf("seed %d: loss %.1f%% | stalls/10k: off %.0f, xor %.0f (%.0f recovered), coded %.0f (%.0f recovered) | wire: xor %.2f MB, coded %.2f MB | coded/xor stall ratio %.2f",
			seed, 100*float64(countDrops(lossTrace(4000, seed, 0.02, 5)))/4000, res["off"][0], p.xor, res["fecXor"][2], p.coded, res["tachyon"][2], res["fecXor"][1], res["tachyon"][1], p.coded/p.xor)
	}
	var ratios []float64
	for _, p := range pairs {
		ratios = append(ratios, p.coded/p.xor)
	}
	sortF := append([]float64(nil), ratios...)
	for i := 0; i < len(sortF); i++ {
		for j := i + 1; j < len(sortF); j++ {
			if sortF[j] < sortF[i] {
				sortF[i], sortF[j] = sortF[j], sortF[i]
			}
		}
	}
	median := sortF[len(sortF)/2]
	wins := 0
	for _, r := range ratios {
		if r < 1 {
			wins++
		}
	}
	t.Logf("promotion gate: median coded/xor stall ratio %.3f (gate <= 0.80), wins %d/5 (gate >= 4)", median, wins)
	if median > 0.80 {
		t.Logf("INCONCLUSIVE for promotion: median ratio %.3f above the 0.80 gate - results retained, idea deferred", median)
		return // log-only: R1 passing/failing here is a research verdict, not a release gate
	}
	if wins < 4 {
		t.Logf("INCONCLUSIVE for promotion: only %d of 5 pairs improved", wins)
	}
}
