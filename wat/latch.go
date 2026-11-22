// Scepter latch (3.5.0, phase A item 4): the keyed proof the in-band channel deliberately defers.
//
// The latch is the one Scepter surface a stranger can reach: when every unit of a paired group is inactive,
// Kharej listens on a wss pool carrier (cmd/wattun latch.go arms it) so the cockpit can revive it. The session
// AEAD already needs the PSK, but the latch PSK and the proof key are BOTH derived from the pairing key and the
// first line on the reserved stream must carry an HMAC over the current timestamp before ANY command is served
// (plan: "the latch contact must prove knowledge of the 32-byte pairing key"). A stranger that reaches the
// wss layer — a leaked PSK, a future carrier bug — still gets no command served, and a replayed proof line is
// bounded by the timestamp window (the same skew discipline as probeGuard, probeguard.go).

package wat

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// latchProofSkew is the tolerated clock error for the proof timestamp. Ten minutes, not seconds: the latch is a
// revival path of last resort, contacted by hand after an outage, and a false rejection costs an SSH trip.
const latchProofSkew = 10 * time.Minute

// latchProofDeadline caps how long the proof line may take to arrive (L1, 2026-11-22): a key-holder that
// opens the reserved stream and stalls the proof (half a line, silent after the first byte) would otherwise
// block the latch's one-session slot forever, and the latch can only re-arm when the contact's session dies.
// Deadline exceeded = denied+reset+close, exactly like a wrong proof. Var, not const: tests shrink it.
var latchProofDeadline = 10 * time.Second

// LatchKey derives the latch session PSK from the pairing key (domain-separated SHA-256, the hdrmask.go /
// ProbeGuardKey pattern). Distinct from the tunnel PSK so the latch port never accepts the tunnel's sessions
// and vice versa.
func LatchKey(p *PairingConfig) []byte {
	h := sha256.Sum256(append(append([]byte("wat-scepter-latch:"), p.UUID[:]...), p.Key[:]...))
	return h[:]
}

// LatchPath derives the latch URL path (plan D2 "key-derived path"): a prober that finds the port still gets
// the nginx pages unless it asks for exactly this path.
func LatchPath(p *PairingConfig) string {
	h := sha256.Sum256(append(append([]byte("wat-scepter-latch-path:"), p.UUID[:]...), p.Key[:]...))
	return "/l" + hex.EncodeToString(h[:8])
}

// LatchProof is the contact proof: HMAC-SHA256(latchKey, label|unix-seconds), hex. Fresh per contact.
func LatchProof(key []byte, ts int64) string {
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "wat-scepter-latch-proof:%d", ts)
	return hex.EncodeToString(m.Sum(nil))
}

func latchProofOK(key []byte, ts int64, proof string, now time.Time) bool {
	if ts == 0 || len(proof) != 2*sha256.Size {
		return false
	}
	if d := now.Sub(time.Unix(ts, 0)); d > latchProofSkew || d < -latchProofSkew {
		return false // outside the window: a replayed capture never validates again
	}
	return hmac.Equal([]byte(proof), []byte(LatchProof(key, ts)))
}

// ServeScepterLatch serves one latch session's reserved stream: the FIRST line must be the proof command
// {"id":"…","v":1,"cmd":"latch.proof","args":{"ts":…,"proof":"…"}} within latchProofDeadline; only then does
// the normal read-only command loop run. A wrong or stale proof — or a proof line that never completes within
// the deadline (L1, 2026-11-22: the stream has no read deadline of its own, so the wait races a timer) —
// answers one code=denied line when there is an answer to give, resets the stream and returns false — the
// caller (cmd/wattun) closes the whole session, so nothing else is ever served on it and the latch slot frees.
func ServeScepterLatch(st *Stream, ss *ScepterState, key []byte) bool {
	d := newScepterDecoder(st)
	type proofRes struct {
		req  ScepterRequest
		code int
	}
	ch := make(chan proofRes, 1) // buffered: a late decoder result must not leak its goroutine past the reset
	go func() {
		req, code := d.next()
		ch <- proofRes{req, code}
	}()
	var req ScepterRequest
	code := -1
	select {
	case r := <-ch:
		req, code = r.req, r.code
	case <-time.After(latchProofDeadline):
		// a proof line that never completes: denied+close, same as a wrong proof (the timer goroutine's
		// blocked ReadSlice dies with the reset below and its send lands in the buffered channel)
	}
	if code != CodeOK {
		st.Reset()
		return false
	}
	ts, okTS := argInt(req.Args, "ts")
	proof, okProof := argString(req.Args, "proof")
	if req.Cmd != "latch.proof" || !okTS || !okProof || !latchProofOK(key, int64(ts), proof, time.Now()) {
		var mu sync.Mutex // writeRespLine wants one; there is no concurrency yet on a fresh stream
		writeRespLine(st, &mu, ScepterResponse{ID: req.ID, Code: CodeDenied})
		st.Reset()
		return false
	}
	var mu sync.Mutex
	writeRespLine(st, &mu, ScepterResponse{ID: req.ID, Code: CodeOK})
	serveScepterLoop(st, d, ss)
	return true
}

// DialScepterLatch is DialScepter for a latch session: open the reserved stream, send the proof, then run the
// pairing hello. A denied proof fails the dial with the reason; the caller treats that as "wrong credential".
func DialScepterLatch(sess *Session, key []byte) (*ScepterClient, error) {
	if !sess.Paired() {
		return nil, ErrNoPairing
	}
	st, err := sess.OpenScepter()
	if err != nil {
		return nil, err
	}
	c := &ScepterClient{st: st, d: newScepterDecoder(st)}
	ts := time.Now().Unix()
	pf := ScepterRequest{ID: "latch.proof", V: scepterV, Cmd: "latch.proof",
		Args: map[string]any{"ts": ts, "proof": LatchProof(key, ts)}, TS: ts}
	b, err := json.Marshal(pf)
	if err != nil {
		st.Reset()
		return nil, err
	}
	if _, werr := st.Write(append(b, '\n')); werr != nil {
		st.Reset()
		return nil, werr
	}
	// The ack: one response line for the proof id. Anything else (garbage, a reset) fails the dial.
	_, code := c.waitResp("latch.proof", 30*time.Second)
	if code != CodeOK {
		st.Reset()
		return nil, fmt.Errorf("scepter latch: proof rejected (code %d)", code)
	}
	if err := c.helloExchange(sess); err != nil {
		return nil, err
	}
	return c, nil
}
