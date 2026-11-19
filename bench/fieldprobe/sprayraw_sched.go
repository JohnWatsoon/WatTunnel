package main

// Shared, platform-independent pieces of the spray-raw probe: the 5-tuple rotation schedule and
// the new-tuple token bucket. No build tag so the scheduler tests run on any GOOS (this checkout
// is Windows; the sockets themselves live in sprayraw_linux.go).

import (
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// portRange is an inclusive UDP port range, "lo-hi" or a single "port".
type portRange struct{ lo, hi uint16 }

func parsePortRange(s string) (portRange, bool) {
	lo, hi, isRange := strings.Cut(s, "-")
	if !isRange {
		hi = lo
	}
	l, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return portRange{}, false
	}
	h, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err != nil || h < l || l == 0 {
		return portRange{}, false
	}
	return portRange{uint16(l), uint16(h)}, true
}

func (r portRange) span() int { return int(r.hi) - int(r.lo) + 1 }

// tupleSched hands out rotation plans for the spray-raw sender: a fresh (sport, dport) pair and
// how many packets to send on it. Burst is 12-20, jittered per tuple, so every 5-tuple stays well
// under the ~29-34-packet cut the 2026-11-14 field probe saw on per-5-tuple counters.
type tupleSched struct {
	sports, dports portRange
	rnd            *rand.Rand
}

func newTupleSched(sports, dports portRange, seed int64) *tupleSched {
	return &tupleSched{sports: sports, dports: dports, rnd: rand.New(rand.NewSource(seed))}
}

func (s *tupleSched) next() (sport, dport uint16, burst int) {
	sport = s.sports.lo + uint16(s.rnd.Intn(s.sports.span()))
	dport = s.dports.lo + uint16(s.rnd.Intn(s.dports.span()))
	burst = 12 + s.rnd.Intn(9)
	return sport, dport, burst
}

// tokenBucket caps the rate of a repeating event — new 5-tuple transitions — at rate per second
// (anti-scan discipline: measure what passes, don't hammer the middlebox with churn). Capacity
// equals one second of rate, so a stopped sender can never owe more than that.
type tokenBucket struct {
	rate, cap, tokens float64
	last              time.Time
}

func newTokenBucket(perSec float64) *tokenBucket {
	return &tokenBucket{rate: perSec, cap: perSec, tokens: perSec, last: time.Now()}
}

// delay returns how long the caller must wait before the next event is allowed (0 = go now).
func (b *tokenBucket) delay(now time.Time) time.Duration {
	if now.After(b.last) {
		b.tokens = min(b.cap, b.tokens+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return 0
	}
	return time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
}

// ---- the receiver's classic-BPF filter, platform-independent so its test runs on any GOOS ----

// bpfIns is one classic-BPF instruction (the linux sock_filter shape, here without x/sys so the
// program and its interpreter can be tested on Windows too).
type bpfIns struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// classic-BPF instruction-class constants (values from the kernel's uapi bpf_common.h; the same
// numbers x/sys/unix re-exports, which do not exist on every GOOS).
const (
	bpfLDk  uint16 = 0x00 // BPF_LD | BPF_W | BPF_ABS
	bpfLDb  uint16 = 0x30 // BPF_LD | BPF_B | BPF_ABS
	bpfLDh  uint16 = 0x28 // BPF_LD | BPF_H | BPF_ABS
	bpfALUk uint16 = 0x54 // BPF_ALU | BPF_AND | BPF_K
	bpfJEQk uint16 = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJGEk uint16 = 0x35 // BPF_JMP | BPF_JGE | BPF_K
	bpfJGTk uint16 = 0x25 // BPF_JMP | BPF_JGT | BPF_K
	bpfRETa uint16 = 0x06 // BPF_RET | BPF_A (accept)
	bpfRETk uint16 = 0x16 // BPF_RET | BPF_K
)

// bpfDportProgram keeps only IPv4 frames with IHL=5, protocol UDP and dport in [lo,hi]. Offsets are
// from the start of the IP header (an AF_INET raw socket sees the IP header, not an Ethernet one).
// The 2026-11-20 review (F7) found the first version inverted: it used JSET on the IHL nibble,
// which is nonzero for EVERY real IPv4 header, so a successful SO_ATTACH_FILTER dropped all
// packets and the probe would have measured nothing. Equality on the nibble (ALU AND + JEQ 5) is
// the expressible form of "IHL==5"; the version nibble needs no check (the kernel delivers only
// IPv4 to an AF_INET socket).
func bpfDportProgram(lo, hi uint16) []bpfIns {
	return []bpfIns{
		{Code: bpfLDb, K: 0},                  // A = byte 0 (version<<4 | IHL)
		{Code: bpfALUk, K: 0x0f},              // A = IHL nibble
		{Code: bpfJEQk, Jf: 6, K: 5},          // IHL != 5: drop (pc 2+6=9)
		{Code: bpfLDb, K: 9},                  // A = protocol
		{Code: bpfJEQk, Jf: 4, K: 17},         // not UDP: drop (pc 4+4=9; IPPROTO_UDP=17)
		{Code: bpfLDh, K: 22},                 // A = dport (IP 20 + UDP 2)
		{Code: bpfJGEk, Jf: 2, K: uint32(lo)}, // < lo: drop (pc 6+2=9)
		{Code: bpfJGTk, Jt: 1, K: uint32(hi)}, // > hi: drop (pc 7+1=9)
		{Code: bpfRETa, K: 0xffffffff},        // accept
		{Code: bpfRETk, K: 0},                 // drop
	}
}

// runBPF interprets the program over a packet the way the kernel would (A = accumulator, X
// unused by this program). Only the classes the program uses are implemented.
func runBPF(prog []bpfIns, pkt []byte) uint32 {
	var a uint32
	pc := 0
	for pc < len(prog) {
		ins := prog[pc]
		switch ins.Code {
		case bpfLDb:
			a = uint32(pkt[ins.K])
		case bpfLDh:
			a = uint32(pkt[ins.K])<<8 | uint32(pkt[ins.K+1])
		case bpfLDk:
			a = uint32(pkt[ins.K])<<24 | uint32(pkt[ins.K+1])<<16 | uint32(pkt[ins.K+2])<<8 | uint32(pkt[ins.K+3])
		case bpfALUk:
			a &= ins.K
		case bpfJEQk:
			if a == ins.K {
				pc += 1 + int(ins.Jt)
			} else {
				pc += 1 + int(ins.Jf)
			}
			continue
		case bpfJGEk:
			if a >= ins.K {
				pc += 1 + int(ins.Jt)
			} else {
				pc += 1 + int(ins.Jf)
			}
			continue
		case bpfJGTk:
			if a > ins.K {
				pc += 1 + int(ins.Jt)
			} else {
				pc += 1 + int(ins.Jf)
			}
			continue
		case bpfRETa:
			return ins.K
		case bpfRETk:
			return ins.K
		default:
			return 0 // unknown instruction: drop, like the kernel would reject the program
		}
		pc++
	}
	return 0
}
