// Scepter phase A tests (3.5.0): the sim-pair RPC round-trip, the sid-0 reservation, event replay, journal
// idempotency, JSON parser robustness, capability denial, rate limiting, TTL expiry and mixed-version behavior.

package wat

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testPairing(caps uint32) *PairingConfig {
	p := &PairingConfig{Ver: 1, Caps: caps | (caps - 1)} // cumulative mask, like CapFromName issues
	for i := range p.UUID {
		p.UUID[i] = byte(i + 1)
	}
	for i := range p.Key {
		p.Key[i] = byte(255 - i)
	}
	return p
}

type fakeSource struct {
	mu         sync.Mutex
	statsCalls int
	logs       []string
}

func (f *fakeSource) Tunnels() []ScepterTunnelInfo {
	return []ScepterTunnelInfo{
		{Name: "t1", Carrier: "udp", State: "active", Health: "ok", Metrics: "127.0.0.1:19700"},
		{Name: "t2", Carrier: "icmp", State: "inactive", Health: "down"},
	}
}

func (f *fakeSource) TunnelStats(name string) (map[string]any, bool) {
	f.mu.Lock()
	f.statsCalls++
	f.mu.Unlock()
	if name != "t1" {
		return nil, false
	}
	return map[string]any{"name": name, "streams": 3, "rate_bps": 5e6}, true
}

func (f *fakeSource) TunnelLogs(name string, tail int) ([]string, bool) {
	if name != "t1" {
		return nil, false
	}
	if tail > len(f.logs) {
		tail = len(f.logs)
	}
	return f.logs[len(f.logs)-tail:], true
}

func (f *fakeSource) History(name string) ([]map[string]any, bool) {
	if name != "t1" {
		return nil, false
	}
	return []map[string]any{{"t": 1, "rate_bps": 1e6, "alive": true}}, true
}

// newScepterPair builds a paired sim pair with ServeScepter running on the server's accepted sid-0 stream,
// mirroring what cmd/wattun's serve() does. journalPath may be empty (no journal); ops, when given, arms the
// write side (phase B).
func newScepterPair(t *testing.T, caps uint32, journalPath string, src ScepterSource, ops ...ScepterOps) (*ScepterClient, *ScepterState) {
	t.Helper()
	pair := testPairing(caps)
	cfg := Config{Pairing: pair}
	cli, srv, _, _ := newPair(t, 0, 2*time.Millisecond, 20e6, cfg)
	state, err := NewScepterState(pair, src, journalPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range ops {
		state.SetOps(o)
	}
	t.Cleanup(func() { state.Stop(); state.journal.Close() }) // Windows: an open journal keeps TempDir from cleaning up
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			if st.ID() != 0 { // this test's server speaks scepter only; user streams are not expected
				st.Reset()
				continue
			}
			go ServeScepter(st, state)
		}
	}()
	c, err := DialScepter(cli)
	if err != nil {
		t.Fatal(err)
	}
	return c, state
}

// The Phase A round-trip: hello / state.get / tunnels.list / tunnel.stats over a real Session pair.
func TestScepterRoundTrip(t *testing.T) {
	c, _ := newScepterPair(t, CapFull, "", &fakeSource{})
	if c.Hello["ver"] != Version {
		t.Fatalf("hello ver = %v, want %s", c.Hello["ver"], Version)
	}
	if c.Hello["caps"] != "full" {
		t.Fatalf("hello caps = %v", c.Hello["caps"])
	}
	p, code := c.Call("state.get", nil)
	if code != CodeOK {
		t.Fatalf("state.get code %d", code)
	}
	if p["ver"] != Version || p["v"] != float64(scepterV) {
		t.Fatalf("state doc head: %v", p)
	}
	pair, _ := p["pair"].(map[string]any)
	if pair["caps"] != "full" || pair["uuid"] != testPairing(CapFull).UUIDString() {
		t.Fatalf("state doc pair: %v", pair)
	}
	if _, ok := p["uptime_s"]; !ok {
		t.Fatal("state doc has no uptime_s")
	}
	ts, ok := p["tunnels"].([]any)
	if !ok || len(ts) != 2 {
		t.Fatalf("state doc tunnels: %#v", p["tunnels"])
	}
	if t1, _ := ts[0].(map[string]any); t1 == nil || t1["name"] != "t1" || t1["state"] != "active" {
		t.Fatalf("state doc first tunnel: %#v", ts[0])
	}
	if p2, code := c.Call("tunnels.list", nil); code != CodeOK || len(p2["tunnels"].([]any)) != 2 {
		t.Fatalf("tunnels.list code %d", code)
	}
	st, code := c.Call("tunnel.stats", map[string]any{"name": "t1"})
	if code != CodeOK || st["name"] != "t1" || st["streams"] != float64(3) {
		t.Fatalf("tunnel.stats: %v code %d", st, code)
	}
	if _, code = c.Call("tunnel.stats", map[string]any{"name": "nope"}); code != CodeNotFound {
		t.Fatalf("tunnel.stats unknown name code %d, want %d", code, CodeNotFound)
	}
	if _, code = c.Call("scepter.ping", nil); code != CodeOK {
		t.Fatalf("ping code %d", code)
	}
}

// Sid 0 belongs to the manager: user streams never get it, nextSID starts at 1, OpenScepter is the only way to
// take id 0 (once, and only on a paired session).
func TestScepterSIDZeroReserved(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{})
	if cli.nextSID != 1 || srv.nextSID != 1 {
		t.Fatalf("nextSID = %d/%d, want 1/1 (sid 0 is reserved for the scepter stream)", cli.nextSID, srv.nextSID)
	}
	for i := 0; i < 50; i++ {
		st, err := cli.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		if st.ID() == 0 {
			t.Fatal("user stream got sid 0")
		}
		st.CloseWrite()
	}
	for i := 0; i < 10; i++ { // the server's own opens skip 0 too
		st, err := srv.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		if st.ID() == 0 {
			t.Fatal("server user stream got sid 0")
		}
		st.CloseWrite()
	}
	if _, err := cli.OpenScepter(); err != ErrNoPairing {
		t.Fatalf("unpaired OpenScepter err = %v, want ErrNoPairing", err)
	}
	pc, ps, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{Pairing: testPairing(CapTunnel)})
	st, err := pc.OpenScepter()
	if err != nil {
		t.Fatal(err)
	}
	if st.ID() != 0 {
		t.Fatalf("scepter stream id = %d, want 0", st.ID())
	}
	if _, err := pc.OpenScepter(); err == nil {
		t.Fatal("second OpenScepter on one session should fail")
	}
	if _, err := ps.OpenStream(); err != nil {
		t.Fatal(err)
	}
}

// events.since replays the ring; the ring keeps the last 512. Coalescing is disabled (evWindow 0) so the
// drill exercises the raw ring: the coalescing and backpressure behaviour have their own tests below.
func TestScepterEventReplay(t *testing.T) {
	c, state := newScepterPair(t, CapManage, "", &fakeSource{})
	state.evWindow = 0
	var seqs []uint64
	for i := 0; i < 5; i++ {
		seqs = append(seqs, state.AddEvent(EvTunnelUp, map[string]any{"name": "t1", "i": i}))
	}
	p, code := c.Call("events.since", map[string]any{"seq": seqs[1]})
	if code != CodeOK {
		t.Fatalf("events.since code %d", code)
	}
	evs := p["events"].([]any)
	if len(evs) != 3 {
		t.Fatalf("replay got %d events, want 3", len(evs))
	}
	first, _ := evs[0].(map[string]any)
	last, _ := evs[2].(map[string]any)
	if first["seq"] != float64(seqs[2]) || last["type"] != EvTunnelUp {
		t.Fatalf("replay: %#v", evs)
	}
	for i := 0; i < 700; i++ { // push past the 512 ring: only the newest 512 stay replayable
		state.AddEvent(EvHealAction, nil)
	}
	p, code = c.Call("events.since", map[string]any{"seq": 0})
	if code != CodeOK {
		t.Fatalf("events.since code %d", code)
	}
	if evs := p["events"].([]any); len(evs) != scepterEvents {
		t.Fatalf("ring kept %d events, want %d", len(evs), scepterEvents)
	}
	if cur := p["cursor"]; cur == float64(0) {
		t.Fatal("cursor is zero after events")
	}
}

// Event coalescing (plan E.1): a flapping tunnel must not flood the ring or the channel — max 1 event per
// window per (type, subject); coalesced repeats are dropped, never queued, and state_seq still advances so
// clients diffing by seq see that state moved. A fake clock drives the windows deterministically.
func TestScepterEventCoalescing(t *testing.T) {
	ss, err := NewScepterState(testPairing(CapManage), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Stop(); ss.journal.Close() })
	var secs atomic.Int64 // the fake clock: whole seconds from base
	base := time.Now()
	ss.nowf = func() time.Time { return base.Add(time.Duration(secs.Load()) * time.Second) }
	ring := func() []ScepterEvent {
		ss.mu.Lock()
		defer ss.mu.Unlock()
		return append([]ScepterEvent{}, ss.events...)
	}
	// a flapping tunnel: 10 up/down pairs inside one second — every change bumps state_seq (20), but only
	// the first up and the first down reach the ring; the other 18 are dropped, not queued
	for i := 0; i < 10; i++ {
		ss.AddEvent(EvTunnelUp, map[string]any{"name": "t1"})
		ss.AddEvent(EvTunnelDown, map[string]any{"name": "t1"})
	}
	if ss.StateSeq() != 20 {
		t.Fatalf("state_seq = %d after 20 changes, want 20 (coalescing advances seq even when it drops)", ss.StateSeq())
	}
	evs := ring()
	if len(evs) != 2 || evs[0].Type != EvTunnelUp || evs[1].Type != EvTunnelDown || evs[0].Seq != 1 || evs[1].Seq != 2 {
		t.Fatalf("flap kept %d ring events: %#v (want [up@1 down@2], one per type per window)", len(evs), evs)
	}
	// a different tunnel is a different subject: it fires inside the same window
	if s := ss.AddEvent(EvTunnelUp, map[string]any{"name": "t2"}); s != 21 {
		t.Fatalf("second subject coalesced against the first: seq %d", s)
	}
	// pair-scoped events (nil detail) coalesce too: reconnect churn keeps one scepter_up per window
	ss.AddEvent(EvScepterUp, nil)
	ss.AddEvent(EvScepterUp, nil)
	if n := len(ring()); n != 4 {
		t.Fatalf("ring has %d events, want 4 (up@1, down@2, up-t2@21, scepter_up@22)", n)
	}
	if ss.StateSeq() != 23 {
		t.Fatalf("state_seq = %d, want 23", ss.StateSeq())
	}
	// the window passes: the same key fires again, carrying the NEW state; different probes (ids) and
	// different update runs never coalesce against each other
	secs.Store(2)
	if s := ss.AddEvent(EvTunnelUp, map[string]any{"name": "t1"}); s != 24 {
		t.Fatalf("event after the window coalesced: seq %d", s)
	}
	evs = ring()
	if last := evs[len(evs)-1]; last.Seq != 24 || last.Type != EvTunnelUp {
		t.Fatalf("post-window event missing from the ring: %#v", last)
	}
}

// Backpressure (plan E.1): drop HISTORY first, never commands. A full ring evicts its oldest entries,
// events.since stays consistent at every cut (seq > since, ascending, cursor = newest), and the command
// queue path completes while the ring is full and a reader is hammering it — commands never block on the
// event ring.
func TestScepterEventRingBackpressure(t *testing.T) {
	ss, err := NewScepterState(testPairing(CapManage), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Stop(); ss.journal.Close() })
	ss.evWindow = 0 // fill fast: every event fires (coalescing off for this drill)
	const extra = 100
	for i := 0; i < scepterEvents+extra; i++ {
		ss.AddEvent(EvHealAction, map[string]any{"name": "t" + itoa(i)})
	}
	ss.mu.Lock()
	first, last := ss.events[0].Seq, ss.events[len(ss.events)-1].Seq
	ss.mu.Unlock()
	if first != extra+1 || last != scepterEvents+extra {
		t.Fatalf("ring holds seqs %d..%d, want %d..%d (oldest evicted)", first, last, extra+1, scepterEvents+extra)
	}
	// consistency at three cuts: exactly the events after `since`, ascending, none below the cut, cursor newest
	// (cmdEventsSince called directly returns the []ScepterEvent slice, pre-JSON)
	for _, cut := range []int{0, extra, int(last) - 50} {
		p, code := cmdEventsSince(ss, ScepterRequest{Args: map[string]any{"seq": float64(cut)}})
		if code != CodeOK {
			t.Fatalf("events.since(%d) code %d", cut, code)
		}
		raw := p["events"].([]ScepterEvent)
		wantN := int(last) - cut
		if wantN > scepterEvents {
			wantN = scepterEvents
		}
		if len(raw) != wantN {
			t.Fatalf("events.since(%d) returned %d, want %d", cut, len(raw), wantN)
		}
		prev := uint64(cut)
		for _, e := range raw {
			if e.Seq <= prev {
				t.Fatalf("events.since(%d) not ascending above the cut: %d after %d", cut, e.Seq, prev)
			}
			prev = e.Seq
		}
		if cur := p["cursor"].(uint64); cur != last {
			t.Fatalf("cursor %v, want %d", cur, last)
		}
	}
	// the surviving window is contiguous (eviction never tears a hole in the middle of the ring)
	p, _ := cmdEventsSince(ss, ScepterRequest{Args: map[string]any{"seq": 0}})
	raw := p["events"].([]ScepterEvent)
	for i, e := range raw {
		if e.Seq != first+uint64(i) {
			t.Fatalf("ring torn at offset %d: seq %d, want %d", i, e.Seq, first+uint64(i))
		}
	}
	// commands never block on the ring: with it full and a reader hammering events.since, a command
	// completes promptly and further churn keeps the ring bounded — history is what gets dropped
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				cmdEventsSince(ss, ScepterRequest{Args: map[string]any{"seq": 0}})
			}
		}
	}()
	start := time.Now()
	resp := ss.Handle(ScepterRequest{ID: "bp-1", V: scepterV, Cmd: "scepter.ping", TS: time.Now().Unix()}, testPairing(CapManage).Caps)
	if resp.Code != CodeOK {
		t.Fatalf("command over a full ring: code %d", resp.Code)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("command blocked on the event ring for %v", el)
	}
	for i := 0; i < 50; i++ {
		ss.AddEvent(EvHealAction, map[string]any{"name": "post" + itoa(i)})
	}
	close(stop)
	<-done
	ss.mu.Lock()
	n := len(ss.events)
	ss.mu.Unlock()
	if n != scepterEvents {
		t.Fatalf("ring grew past the cap under churn: %d", n)
	}
}

// Retries of the same command id return the recorded outcome and run the handler once (at-most-once) — for
// MUTATING commands only (H1/F4, 2026-11-22): a read is a re-executable pure function, so the same id on a
// read re-runs it (journaling reads once grew the replay set without bound and stale-replayed a hello across
// an engine update).
func TestScepterJournalIdempotency(t *testing.T) {
	src := &fakeSource{}
	ops := newFakeOps(t)
	ops.writeDirect("t1", t)
	c, _ := newScepterPair(t, CapManage, t.TempDir()+"/.journal", src, ops)
	args := map[string]any{"name": "t1", "set": map[string]any{"ping-every": "5"}}
	p1, code1 := c.call("tunnel.edit", args, "fixed-id-1", time.Now().Unix(), 10*time.Second)
	p2, code2 := c.call("tunnel.edit", args, "fixed-id-1", time.Now().Unix(), 10*time.Second)
	if code1 != CodeOK || code2 != CodeOK {
		t.Fatalf("codes %d/%d", code1, code2)
	}
	b1, _ := json.Marshal(p1)
	b2, _ := json.Marshal(p2)
	if string(b1) != string(b2) {
		t.Fatalf("retry outcome differs: %s vs %s", b1, b2)
	}
	restarts := 0
	for _, a := range ops.actions {
		if a == "t1:restart" {
			restarts++
		}
	}
	if restarts != 1 {
		t.Fatalf("mutation ran %d times, want 1", restarts)
	}
	// a read under the same rules: a fixed id does NOT replay it, it re-executes
	c.call("tunnel.stats", map[string]any{"name": "t1"}, "fixed-id-2", time.Now().Unix(), 10*time.Second)
	c.call("tunnel.stats", map[string]any{"name": "t1"}, "fixed-id-2", time.Now().Unix(), 10*time.Second)
	src.mu.Lock()
	calls := src.statsCalls
	src.mu.Unlock()
	if calls != 2 {
		t.Fatalf("read ran %d times, want 2 (reads are re-executable, never replayed)", calls)
	}
}

// The authenticated peer may still send garbage: every malformed line answers with a machine code, nothing
// crashes, and a valid command right after still works. Decode-level rejects are AUDITED too (L4, 2026-11-22):
// a garbage flood leaves cmd "?" rows in the shared audit file, with the id where it could be parsed.
func TestScepterJSONRobustness(t *testing.T) {
	pair := testPairing(CapFull)
	cfg := Config{Pairing: pair}
	cli, srv, _, _ := newPair(t, 0, time.Millisecond, 20e6, cfg)
	dir := t.TempDir()
	state, err := NewScepterState(pair, &fakeSource{}, filepath.Join(dir, ".pairing.journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Stop(); state.journal.Close() })
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			if st.ID() != 0 {
				st.Reset()
				continue
			}
			go ServeScepter(st, state)
		}
	}()
	st, err := cli.OpenScepter()
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{
		"not json at all",
		`{"id":"a","v":2,"cmd":"scepter.ping"}`,                 // wrong protocol version
		`{"id":"b","v":1}`,                                      // no command
		`{"id":"c","v":1,"cmd":"state.get","args":{"x":[1,,]}}`, // malformed args JSON
		strings.Repeat("x", scepterMaxLine+1024),                // oversized
	}
	go func() {
		w := bufio.NewWriter(st)
		for _, l := range lines {
			w.WriteString(l)
			w.WriteByte('\n')
		}
		w.Flush()
		b, _ := json.Marshal(ScepterRequest{ID: "ok1", V: scepterV, Cmd: "scepter.ping", TS: time.Now().Unix()})
		w.Write(append(b, '\n'))
		w.Flush()
	}()
	rd := bufio.NewReader(st)
	want := []int{CodeBadRequest, CodeBadRequest, CodeUnknownCmd, CodeBadRequest, CodeTooLarge, CodeOK}
	type res struct {
		resp ScepterResponse
		err  error
	}
	out := make(chan res, len(want))
	go func() { // line-based, exactly the protocol; a hang surfaces as the test timeout (no Stream deadlines)
		for range want {
			var r res
			line, err := rd.ReadBytes('\n')
			if err == nil {
				r.err = json.Unmarshal(trimEOL(line), &r.resp)
			} else {
				r.err = err
			}
			out <- r
		}
	}()
	for i, wantCode := range want {
		var r res
		select {
		case r = <-out:
		case <-time.After(30 * time.Second):
			t.Fatalf("line %d: timeout waiting for a response", i)
		}
		if r.err != nil {
			t.Fatalf("line %d: %v", i, r.err)
		}
		if r.resp.Code != wantCode {
			t.Fatalf("line %d (%q…): code %d, want %d", i, lines[i][:min(24, len(lines[i]))], r.resp.Code, wantCode)
		}
	}
	// the audit saw the flood: three decode-level rows with cmd "?" (lines 1/4/5 — wholly unparseable or
	// oversized), the wrong-v line audited with its PARSED cmd and id (round-2 fix 6, 2026-11-22: it used to
	// be a fourth "?"), line 3 (a v=1 line with no command) audited by Handle as the empty command, plus the
	// good ping
	ab, err := os.ReadFile(filepath.Join(dir, ScepterAuditFile))
	if err != nil {
		t.Fatal(err)
	}
	var pluses, wrongV, ping int
	for _, l := range strings.Split(strings.TrimRight(string(ab), "\n"), "\n") {
		switch {
		case strings.Contains(l, " cmd=? code=1"):
			pluses++
		case strings.Contains(l, " cmd=? code=8"):
			pluses++
		case strings.HasSuffix(l, "cmd=scepter.ping code=1 id=a"):
			wrongV++
		case strings.HasSuffix(l, "cmd=scepter.ping code=0 id=ok1"):
			ping++
		}
	}
	if pluses != 3 || wrongV != 1 || ping != 1 {
		t.Fatalf("audit rows for garbage: ?=%d (wrong-v %d), ping=%d, file %q", pluses, wrongV, ping, ab)
	}
}

// A tunnel-only credential reads the pairing's own state but not the telemetry commands (D4: manage = stats).
func TestScepterCapabilityDenied(t *testing.T) {
	c, _ := newScepterPair(t, CapTunnel, "", &fakeSource{})
	if _, code := c.Call("state.get", nil); code != CodeOK {
		t.Fatalf("state.get code %d, want OK for a tunnel credential", code)
	}
	if _, code := c.Call("tunnels.list", nil); code != CodeOK {
		t.Fatalf("tunnels.list code %d, want OK", code)
	}
	for _, cmd := range []string{"tunnel.stats", "tunnel.logs", "events.since", "history"} {
		if _, code := c.Call(cmd, map[string]any{"name": "t1", "seq": 0}); code != CodeDenied {
			t.Fatalf("%s code %d, want %d", cmd, code, CodeDenied)
		}
	}
}

// The per-pair token bucket: beyond the burst every command answers rate_limited.
func TestScepterRateLimit(t *testing.T) {
	state, err := NewScepterState(testPairing(CapFull), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	state.rate = scepterRate{rate: 0.0001, burst: 3} // effectively burst-only
	ok := 0
	for i := 0; i < 6; i++ {
		resp := state.Handle(ScepterRequest{ID: itoa(i), V: scepterV, Cmd: "scepter.ping", TS: time.Now().Unix()}, testPairing(CapFull).Caps)
		if resp.Code == CodeOK {
			ok++
		} else if resp.Code != CodeRateLimited {
			t.Fatalf("code %d, want rate_limited", resp.Code)
		}
	}
	if ok != 3 {
		t.Fatalf("%d commands passed, want the burst of 3", ok)
	}
}

// Expired intents are rejected stale; the default TTL is 600 s and the client can lower it.
func TestScepterTTLExpiry(t *testing.T) {
	state, err := NewScepterState(testPairing(CapFull), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if resp := state.Handle(ScepterRequest{ID: "fresh", V: scepterV, Cmd: "scepter.ping", TS: now}, testPairing(CapFull).Caps); resp.Code != CodeOK {
		t.Fatalf("fresh code %d", resp.Code)
	}
	old := now - scepterTTL - int64(scepterSkew.Seconds()) - 10
	if resp := state.Handle(ScepterRequest{ID: "old", V: scepterV, Cmd: "scepter.ping", TS: old}, testPairing(CapFull).Caps); resp.Code != CodeStale {
		t.Fatalf("expired code %d, want %d", resp.Code, CodeStale)
	}
	mid := now - 700 // inside the default 600+skew? no: 700 > 600, stale unless ttl set
	resp := state.Handle(ScepterRequest{ID: "mid", V: scepterV, Cmd: "scepter.ping", TS: mid, TTL: 900}, testPairing(CapFull).Caps)
	if resp.Code != CodeOK {
		t.Fatalf("raised-ttl code %d, want OK", resp.Code)
	}
}

// Mixed versions: an unpaired client never opens sid 0; a paired client toward an unpaired server fails the
// hello once and the tunnel keeps working — zero scepter traffic beyond that single attempt.
func TestScepterMixedVersion(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0, time.Millisecond, 20e6, Config{})
	if _, err := cli.OpenScepter(); err != ErrNoPairing {
		t.Fatalf("unpaired client: err %v, want ErrNoPairing", err)
	}
	// the plain tunnel still carries data
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(st, st); st.CloseWrite() }()
		}
	}()
	st, _ := cli.OpenStream()
	st.Write([]byte("hello"))
	st.CloseWrite()
	ch := make(chan string, 1)
	go func() { b, _ := io.ReadAll(st); ch <- string(b) }()
	select {
	case got := <-ch:
		if got != "hello" {
			t.Fatalf("tunnel data after failed pairing: %q", got)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timeout reading tunnel data")
	}

	// paired client, unpaired server (an old peer): hello fails, tunnel works
	pcfg := Config{Pairing: testPairing(CapFull)}
	pcli, psrv, _, _ := newPair(t, 0, time.Millisecond, 20e6, pcfg)
	_ = psrv
	go func() { // the unpaired server resets sid 0 like serve() does with scepter == nil
		for {
			st, err := psrv.Accept()
			if err != nil {
				return
			}
			if st.ID() == 0 {
				st.Reset()
				continue
			}
			go func() { io.Copy(st, st); st.CloseWrite() }()
		}
	}()
	if _, err := DialScepter(pcli); err == nil {
		t.Fatal("DialScepter toward an unpaired server should fail")
	}
	st2, _ := pcli.OpenStream()
	st2.Write([]byte("data"))
	st2.CloseWrite()
	ch2 := make(chan string, 1)
	go func() { b, _ := io.ReadAll(st2); ch2 <- string(b) }()
	select {
	case got := <-ch2:
		if got != "data" {
			t.Fatalf("tunnel data after failed hello: %q", got)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timeout reading tunnel data after failed hello")
	}
}

// Large log fetches arrive chunked and reassemble (1000 lines x ~55 B spans several 16 KiB chunks).
func TestScepterChunkedLogs(t *testing.T) {
	src := &fakeSource{}
	for i := 0; i < 1000; i++ {
		src.logs = append(src.logs, strings.Repeat("l", 50)+itoa(i))
	}
	c, _ := newScepterPair(t, CapManage, "", src)
	p, code := c.Call("tunnel.logs", map[string]any{"name": "t1", "tail": 1000})
	if code != CodeOK {
		t.Fatalf("tunnel.logs code %d", code)
	}
	logs, ok := p["logs"].([]string)
	if !ok || len(logs) != 1000 {
		t.Fatalf("reassembled %d logs, want 1000", len(logs))
	}
	if logs[0] != strings.Repeat("l", 50)+"0" || logs[999] != strings.Repeat("l", 50)+"999" {
		t.Fatal("chunk reassembly corrupted the payload")
	}
}

// Credential parsing: the watp1 line round-trips, bad lines fail loudly, and the classic-token field 10 is
// optional (old 6/7/9-field tokens parse to no pairing).
func TestParsePairing(t *testing.T) {
	p := testPairing(CapManage)
	got, err := ParsePairingLine(p.Line())
	if err != nil {
		t.Fatal(err)
	}
	if got.UUID != p.UUID || got.Key != p.Key || got.Caps != p.Caps || got.Ver != p.Ver {
		t.Fatalf("round-trip mismatch: %#v", got)
	}
	for _, bad := range []string{
		"", "wat1:xxx", "watp1:1|only-three|fields",
		"watp1:2|" + testPairing(0).UUIDString() + "|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|full",
		"watp1:1|not-a-uuid|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|full",
		"watp1:1|" + testPairing(0).UUIDString() + "|not-base64!|full",
		"watp1:1|" + testPairing(0).UUIDString() + "|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|superuser",
	} {
		if _, err := ParsePairingLine(bad); err == nil {
			t.Fatalf("bad line accepted: %q", bad)
		}
	}
	// token field 10
	if f, err := ParsePairingTokenField("", []byte("k")); f != nil || err != nil {
		t.Fatal("empty field 10 must parse to no pairing")
	}
	if f, err := ParsePairingTokenField("auto-plan", []byte("k")); f != nil || err != nil {
		t.Fatal("an old 9-field token's field 10 (auto plan) must parse to no pairing")
	}
	f, err := ParsePairingTokenField("pair", []byte("classic-token-key"))
	if err != nil || f == nil || f.Caps != CapTunnel { // tunnel is the lowest tier: mask == the single bit
		t.Fatalf("pair field: %v %#v", err, f)
	}
	f2, _ := ParsePairingTokenField("pair", []byte("classic-token-key"))
	if f2.UUID != f.UUID {
		t.Fatal("token-derived UUID must be stable per key")
	}
	if f, err := ParsePairingTokenField("pair=full", []byte("k")); err != nil || f.Caps != CapTunnel|CapCreate|CapManage|CapFull {
		t.Fatalf("pair=full: %v %#v", err, f)
	}
	if _, err := ParsePairingTokenField("pair=bogus", []byte("k")); err == nil {
		t.Fatal("pair=bogus accepted")
	}
	// lookalikes are NOT the pair field (L5-strict, 2026-11-22): only exact "pair" / "pair=<tier>" marks a
	// credential — a prefix match once silently promoted "pairxyz" to a tunnel-capability pairing
	for _, lookalike := range []string{"pairxyz", "pairing", "pairs"} {
		if f, err := ParsePairingTokenField(lookalike, []byte("k")); f != nil || err != nil {
			t.Fatalf("lookalike %q must parse to no pairing, got %v %v", lookalike, f, err)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ---- phase B: write intents ----

// fakeOps is the TEST implementation of ScepterOps (plan B.3): the same contract as the production
// fileScepterOps — name rules, name_taken, port collisions, real files in a temp CONF dir (atomic writes),
// backup before apply, rollback on a failed unit start — without systemd: unit actions are recorded and tests
// inject failures via failStart.
type fakeOps struct {
	dir       string
	failStart map[string]bool // unit starts "succeed" but the unit dies: the verify catches it
	binds     map[int]string  // canned port collisions: bind port -> user (what the production scan would find)
	actions   []string        // recorded "name:action" (unit ops)
	active    map[string]bool
	creates   int // Create calls that executed (journal idempotency counting)

	// phase C: probe lifecycle bookkeeping and the auto-test rows the fake serves
	probes      map[string]string // probe id -> carrier, while open
	probeSeq    int
	failLink    map[string]bool // carrier.change link check fails for these tunnels
	autoMu      sync.Mutex      // the run flag rides a goroutine (async like the production run)
	autoRunning bool
	autoRunID   string
	autoMode    string
	rows        []map[string]any // the canned ranked table (carrier, port, ok)

	inN, maxIn atomic.Int64 // concurrency probe: the queue test pins max concurrent edits to 1
	delay      time.Duration

	// phase D: canned update/doctor answers and backup-export parameters
	updMu       sync.Mutex
	updTo       string
	updRuns     int
	updStatus   map[string]any
	doctorExtra map[string]any
	backupPad   int // pad the tarball past scepterChunk so the chunked transfer is exercised
	backupCode  int
	auditN      []string
}

func newFakeOps(t *testing.T) *fakeOps {
	return &fakeOps{dir: t.TempDir(), failStart: map[string]bool{}, binds: map[int]string{}, active: map[string]bool{},
		probes: map[string]string{}, failLink: map[string]bool{}, backupCode: CodeOK,
		rows: []map[string]any{
			{"rank": 1, "carrier": "tcp", "port": 20501, "ok": true, "down_mbps": 9.5},
			{"rank": 2, "carrier": "udp", "port": 20502, "ok": false, "why": "no link"},
		}}
}

func (f *fakeOps) runUnit(name, action string) {
	f.actions = append(f.actions, name+":"+action)
	switch action {
	case "start", "restart":
		f.active[name] = !f.failStart[name]
	case "stop":
		f.active[name] = false
	}
}

func (f *fakeOps) yml(name string) string { return filepath.Join(f.dir, name+".yml") }

func (f *fakeOps) has(name string) bool {
	_, err := os.Stat(f.yml(name))
	return err == nil
}

func (f *fakeOps) begin() {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	n := f.inN.Add(1)
	for {
		m := f.maxIn.Load()
		if n <= m || f.maxIn.CompareAndSwap(m, n) {
			break
		}
	}
}

func (f *fakeOps) end() { f.inN.Add(-1) }

// setYMLKey / dropYMLKey: the fake's line surgery, the same top-level semantics as the production ops.
func setYMLKey(text, k, v string) string {
	var out []string
	done := false
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, k+":") && !strings.HasPrefix(l, " ") {
			continue
		}
		if !done && (strings.HasPrefix(l, "metrics:") || strings.HasPrefix(l, "ports:")) {
			out = append(out, k+": "+v)
			done = true
		}
		out = append(out, l)
	}
	if !done {
		out = append(out, k+": "+v)
	}
	return strings.Join(out, "\n")
}

func dropYMLKey(text, k string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, k+":") && !strings.HasPrefix(l, " ") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func writeAtomicTest(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (f *fakeOps) Create(spec ScepterTunnelSpec) (map[string]any, int) {
	f.creates++
	f.begin()
	defer f.end()
	name := spec.Name
	if name == "" {
		name = "tunnel"
	}
	if !ValidScepterName(name) {
		return map[string]any{"name": name}, CodeBadRequest
	}
	if f.has(name) {
		return map[string]any{"name": name}, CodeNameTaken
	}
	if spec.Carrier == "icmp" && runtime.GOOS != "linux" {
		// platform check first, like the production ops: a carrier that cannot run here never reaches the port scan
		return map[string]any{"carrier": "icmp", "ver": Version, "need": "linux+CAP_NET_RAW"}, CodeCarrierNeeds
	}
	port := 4443 // the fake's bind rule: the carrier default, or params' listen
	if v := spec.Params["listen"]; v != "" {
		if i := strings.LastIndex(v, ":"); i >= 0 {
			fmt.Sscanf(v[i+1:], "%d", &port)
		}
	}
	if user, busy := f.binds[port]; busy {
		return map[string]any{"port": port, "user": user}, CodePortBusy
	}
	body := "mode: server\nkey: " + spec.Key + "\ncarrier: " + spec.Carrier + "\nports:\n  - 20030\n"
	if err := writeAtomicTest(f.yml(name), body); err != nil {
		return map[string]any{"detail": err.Error()}, CodeInternal
	}
	if err := writeAtomicTest(filepath.Join(f.dir, name+".key"), spec.Key); err != nil {
		return map[string]any{"detail": err.Error()}, CodeInternal
	}
	f.runUnit(name, "start")
	if !f.active[name] { // the rollback drill: restore absence
		f.runUnit(name, "stop")
		os.Remove(f.yml(name))
		os.Remove(filepath.Join(f.dir, name+".key"))
		return map[string]any{"detail": "unit did not come up", "rolled_back": true}, CodeInternal
	}
	return map[string]any{"name": name, "carrier": spec.Carrier, "key": spec.Key, "token": "wat1:fake"}, CodeOK
}

func (f *fakeOps) Edit(name string, patch ScepterPatch) (map[string]any, int) {
	f.begin()
	defer f.end()
	b, err := os.ReadFile(f.yml(name))
	if err != nil {
		return map[string]any{"name": name}, CodeNotFound
	}
	text := string(b)
	for _, k := range patch.Drop {
		text = dropYMLKey(text, k)
	}
	for k, v := range patch.Set {
		text = setYMLKey(text, k, v)
	}
	writeAtomicTest(f.yml(name)+".bak", string(b))
	writeAtomicTest(f.yml(name), text)
	f.runUnit(name, "restart")
	if !f.active[name] {
		writeAtomicTest(f.yml(name), string(b))
		f.runUnit(name, "restart")
		return map[string]any{"detail": "rolled back", "rolled_back": true}, CodeInternal
	}
	p := map[string]any{"name": name}
	if c, is := patch.Set["carrier"]; is {
		p["carrier"] = c
	}
	return p, CodeOK
}

func (f *fakeOps) Delete(name string) (map[string]any, int) {
	f.begin()
	defer f.end()
	if !f.has(name) {
		return map[string]any{"name": name}, CodeNotFound
	}
	f.runUnit(name, "stop")
	os.Rename(f.yml(name), f.yml(name)+".bak")
	os.Remove(filepath.Join(f.dir, name+".key"))
	return map[string]any{"name": name, "stopped": true}, CodeOK
}

func (f *fakeOps) Unit(name, action string) (map[string]any, int) {
	f.begin()
	defer f.end()
	if !f.has(name) {
		return map[string]any{"name": name}, CodeNotFound
	}
	f.runUnit(name, action)
	want := action != "stop"
	if f.active[name] != want {
		return map[string]any{"detail": "state"}, CodeInternal
	}
	state := "inactive"
	if want {
		state = "active"
	}
	return map[string]any{"name": name, "state": state}, CodeOK
}

func (f *fakeOps) SetLimits(name string, items []string) (map[string]any, int) {
	b, err := os.ReadFile(f.yml(name))
	if err != nil {
		return map[string]any{"name": name}, CodeNotFound
	}
	writeAtomicTest(f.yml(name), setYMLKey(string(b), "limits", strings.Join(items, ", ")))
	return map[string]any{"name": name, "limits": len(items)}, CodeOK
}

// ---- phase C fakes: probes, carrier change, the auto-test table ----

func (f *fakeOps) TestOpen(carrier string, ttlS int) (map[string]any, int) {
	f.begin()
	defer f.end()
	if carrier == "" || strings.Contains(carrier, "+") || carrier == "icmp" {
		return map[string]any{"carrier": carrier}, CodeBadRequest
	}
	f.probeSeq++
	id := fmt.Sprintf("probe-%d", f.probeSeq)
	f.probes[id] = carrier
	return map[string]any{"id": id, "carrier": carrier, "port": 20900 + f.probeSeq,
		"key": "probekey123456789012345678901234", "path": "/wat", "ttl": ttlS}, CodeOK
}

func (f *fakeOps) TestClose(id string) (map[string]any, int) {
	f.begin()
	defer f.end()
	if _, open := f.probes[id]; !open {
		return map[string]any{"id": id}, CodeNotFound
	}
	delete(f.probes, id)
	return map[string]any{"id": id, "closed": true}, CodeOK
}

// CarrierChange runs the fake's edit path; a failed link check restores the pre-change yml and reports
// rolled_back — the same shape the production ops answers.
func (f *fakeOps) CarrierChange(name, carrier string, params map[string]string) (map[string]any, int) {
	f.begin()
	defer f.end()
	pre, err := os.ReadFile(f.yml(name))
	if err != nil {
		return map[string]any{"name": name}, CodeNotFound
	}
	set := map[string]string{"carrier": carrier}
	for k, v := range params {
		set[k] = v
	}
	p, code := f.Edit(name, ScepterPatch{Set: set})
	if code != CodeOK {
		return p, code
	}
	if f.failLink[name] {
		writeAtomicTest(f.yml(name), string(pre))
		f.runUnit(name, "restart")
		return map[string]any{"detail": "link check failed", "rolled_back": true}, CodeInternal
	}
	p["listen"] = ":" + fmt.Sprint(4400+f.probeSeq)
	return p, CodeOK
}

func (f *fakeOps) AutoTest(mode string, done func(ok, total int)) (map[string]any, int) {
	if mode != "" && mode != "plain" && mode != "tls" {
		return map[string]any{"modes": "plain,tls"}, CodeBadRequest
	}
	f.autoMu.Lock()
	if f.autoRunning {
		run := f.autoRunID
		f.autoMu.Unlock()
		return map[string]any{"run": run, "already_running": true}, CodeOK
	}
	f.autoRunning, f.autoRunID, f.autoMode = true, fmt.Sprintf("at-%d", time.Now().UnixNano()), mode
	run := f.autoRunID
	f.autoMu.Unlock()
	go func() { // async like the production run; the engine learns the finish through done
		time.Sleep(20 * time.Millisecond)
		ok := 0
		for _, r := range f.rows {
			if r["ok"] == true {
				ok++
			}
		}
		f.autoMu.Lock()
		f.autoRunning = false
		f.autoMu.Unlock()
		done(ok, len(f.rows))
		_ = run
	}()
	return map[string]any{"run": run, "mode": mode, "shapes": len(f.rows)}, CodeOK
}

func (f *fakeOps) AutoRows() (map[string]any, int) {
	f.autoMu.Lock()
	defer f.autoMu.Unlock()
	rows := make([]map[string]any, len(f.rows))
	copy(rows, f.rows)
	return map[string]any{"run": f.autoRunID, "mode": f.autoMode, "done": !f.autoRunning, "rows": rows}, CodeOK
}

func (f *fakeOps) ApplyRow(name string, row int) (map[string]any, int) {
	if row < 1 || row > len(f.rows) {
		return map[string]any{"row": row}, CodeNotFound
	}
	r := f.rows[row-1]
	carrier, _ := r["carrier"].(string)
	port, _ := r["port"].(int)
	p, code := f.CarrierChange(name, carrier, map[string]string{"listen": fmt.Sprintf(":%d", port)})
	if code == CodeOK {
		p["row"] = row
	}
	return p, code
}

// ---- phase D: update / doctor / backup / audit ----

func (f *fakeOps) UpdateStatus() (map[string]any, int) {
	if f.updStatus == nil {
		return map[string]any{"ver": Version, "prev": map[string]any{"present": false}}, CodeOK
	}
	return f.updStatus, CodeOK
}

func (f *fakeOps) UpdateRun(to string) (map[string]any, int) {
	f.updMu.Lock()
	defer f.updMu.Unlock()
	f.updTo = to
	f.updRuns++ // the channel-survival drill counts this: a journal replay must NOT re-run the op
	if to == "" {
		to = "latest" // the production ops echo the resolved target, not the empty argument
	}
	return map[string]any{"run": fmt.Sprintf("upd-%d", f.updRuns), "to": to, "phase": UpdatePhaseStarted}, CodeOK
}

func (f *fakeOps) Doctor() (map[string]any, int) {
	if f.doctorExtra == nil {
		return map[string]any{"latch": map[string]any{"enabled": false}}, CodeOK
	}
	return f.doctorExtra, CodeOK
}

// BackupExport builds a REAL tar in memory (one t1.yml entry, padded past the chunk size when pad is set)
// and returns it in the chunked-logs convention — the same shape the production ops answer with.
func (f *fakeOps) BackupExport() (map[string]any, int) {
	if f.backupCode != CodeOK {
		return map[string]any{"why": "too big"}, f.backupCode
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := "mode: server\n"
	if f.backupPad > 0 {
		content += strings.Repeat("x", f.backupPad)
	}
	tw.WriteHeader(&tar.Header{Name: "t1.yml", Mode: 0o600, Size: int64(len(content))})
	tw.Write([]byte(content))
	tw.Close()
	doc, _ := json.Marshal(map[string]any{"b64": base64.StdEncoding.EncodeToString(buf.Bytes()),
		"sha256": fmt.Sprintf("%x", sha256.Sum256(buf.Bytes())), "size": buf.Len(), "files": 1})
	return map[string]any{"logs": []string{string(doc)}}, CodeOK
}

func (f *fakeOps) AuditTail(n int) (map[string]any, int) {
	entries := f.auditN
	if n < len(entries) {
		entries = entries[len(entries)-n:] // the ops answer the TAIL, like the manager's pairing_audit_tail
	}
	da, _ := json.Marshal(map[string]any{"src": "audit", "entries": entries})
	dj, _ := json.Marshal(map[string]any{"src": "journal", "entries": []string{}})
	return map[string]any{"logs": []string{string(da), string(dj)}}, CodeOK
}

// dirSource is the ScepterSource reading the fake ops' CONF dir, so the state document reflects what the
// write intents did to the files (create/delete round-trips are visible in tunnels.list).
type dirSource struct{ dir string }

func (d dirSource) Tunnels() []ScepterTunnelInfo {
	out := []ScepterTunnelInfo{} // never nil: an empty list marshals as [], not null
	files, _ := filepath.Glob(filepath.Join(d.dir, "*.yml"))
	sort.Slice(files, func(i, j int) bool { return files[i] < files[j] })
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".yml")
		out = append(out, ScepterTunnelInfo{Name: name, Carrier: "udp", State: "active", Health: "ok"})
	}
	return out
}

func (d dirSource) TunnelStats(string) (map[string]any, bool) { return nil, false }
func (d dirSource) TunnelLogs(string, int) ([]string, bool)   { return nil, false }
func (d dirSource) History(string) ([]map[string]any, bool)   { return nil, false }

func testWriteArgs(extra map[string]any) map[string]any {
	a := map[string]any{"carrier": "udp", "ports": "20030"}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

// Create/edit/delete round-trips on a sim Kharej with real files in a temp CONF (plan B.4): the files appear,
// the state document follows, the delete moves everything aside.
func TestScepterWriteRoundTrip(t *testing.T) {
	ops := newFakeOps(t)
	src := dirSource{ops.dir}
	c, _ := newScepterPair(t, CapFull, "", src, ops)

	p, code := c.Call("tunnel.create", testWriteArgs(map[string]any{"name": "wt1", "base_seq": 7, "ttl_s": 300}))
	if code != CodeOK {
		t.Fatalf("create code %d params %v", code, p)
	}
	if p["name"] != "wt1" || p["key"] == "" || p["token"] != "wat1:fake" {
		t.Fatalf("create params: %v", p)
	}
	if _, err := os.Stat(filepath.Join(ops.dir, "wt1.key")); err != nil {
		t.Fatal("create wrote no key file")
	}
	// base_seq mismatch is not fatal, but the response carries the fresh state (the plan's state model)
	if _, ok := p["state"]; !ok {
		t.Fatalf("stale base_seq must carry the fresh state: %v", p)
	}
	if st, _ := p["state"].(map[string]any); st["state_seq"] == float64(7) {
		t.Fatal("carried state must be fresher than base_seq 7")
	}
	// the event and the state document followed
	p, code = c.Call("tunnels.list", nil)
	if code != CodeOK || len(p["tunnels"].([]any)) != 1 {
		t.Fatalf("tunnels.list after create: %v %v", code, p)
	}
	// edit: set a key, the file changes, the unit restarted
	p, code = c.Call("tunnel.edit", map[string]any{"name": "wt1", "set": map[string]any{"ping-every": "5"}})
	if code != CodeOK {
		t.Fatalf("edit code %d params %v", code, p)
	}
	b, _ := os.ReadFile(filepath.Join(ops.dir, "wt1.yml"))
	if !strings.Contains(string(b), "ping-every: 5") {
		t.Fatalf("edit did not land in the yml: %q", b)
	}
	if _, err := os.Stat(filepath.Join(ops.dir, "wt1.yml.bak")); err != nil {
		t.Fatal("edit left no .bak")
	}
	// limits and presets go through the same file
	if p, code = c.Call("limits.set", map[string]any{"name": "wt1", "limits": []any{"20030 rate=5MB quota=100GB"}}); code != CodeOK {
		t.Fatalf("limits.set code %d params %v", code, p)
	}
	if p, code = c.Call("preset.apply", map[string]any{"name": "wt1", "preset": "plain"}); code != CodeOK {
		t.Fatalf("preset.apply code %d params %v", code, p)
	}
	// unit ops
	if p, code = c.Call("tunnel.stop", map[string]any{"name": "wt1"}); code != CodeOK || p["state"] != "inactive" {
		t.Fatalf("stop: %v %v", code, p)
	}
	if p, code = c.Call("tunnel.start", map[string]any{"name": "wt1"}); code != CodeOK || p["state"] != "active" {
		t.Fatalf("start: %v %v", code, p)
	}
	// delete: confirm mismatch is refused, the right one moves the files aside
	if _, code = c.Call("tunnel.delete", map[string]any{"name": "wt1", "confirm": "nope"}); code != CodeBadRequest {
		t.Fatalf("wrong confirm code %d", code)
	}
	if _, code = c.Call("tunnel.delete", map[string]any{"name": "wt1", "confirm": "wt1"}); code != CodeOK {
		t.Fatalf("delete code %d", code)
	}
	if ops.has("wt1") {
		t.Fatal("deleted tunnel's yml still live")
	}
	if _, err := os.Stat(filepath.Join(ops.dir, "wt1.yml.bak")); err != nil {
		t.Fatal("delete kept no .bak (not reversible by construction)")
	}
	p, _ = c.Call("tunnels.list", nil)
	if n := len(p["tunnels"].([]any)); n != 0 {
		t.Fatalf("tunnels.list after delete: %d entries", n)
	}
}

// Every structured rejection code of plan B.2, exercised over the wire.
func TestScepterWriteRejections(t *testing.T) {
	ops := newFakeOps(t)
	ops.binds[4443] = "t-old"
	c, _ := newScepterPair(t, CapFull, "", &fakeSource{}, ops)
	// name_taken
	ops.writeDirect("dup", t)
	if _, code := c.Call("tunnel.create", testWriteArgs(map[string]any{"name": "dup"})); code != CodeNameTaken {
		t.Fatalf("name_taken code %d", code)
	}
	// port_busy {port}
	p, code := c.Call("tunnel.create", testWriteArgs(nil))
	if code != CodePortBusy || p["port"] != float64(4443) || p["user"] != "t-old" {
		t.Fatalf("port_busy: %v %v", code, p)
	}
	// carrier_needs {ver}: the raw carriers need Linux (this checkout is Windows; CI's Linux run creates it fine)
	if runtime.GOOS != "linux" {
		if p, code = c.Call("tunnel.create", testWriteArgs(map[string]any{"name": "raw1", "carrier": "icmp"})); code != CodeCarrierNeeds || p["ver"] != Version {
			t.Fatalf("carrier_needs: %v %v", code, p)
		}
	}
	// bad name syntax
	if _, code = c.Call("tunnel.create", testWriteArgs(map[string]any{"name": "../evil"})); code != CodeBadRequest {
		t.Fatalf("bad name code %d", code)
	}
	// stale: an expired intent (checked while the command bucket is still fresh — the TTL answer precedes any op)
	old := time.Now().Unix() - 4000
	if _, code = c.call("tunnel.create", testWriteArgs(map[string]any{"name": "stale1", "carrier": "nope-carrier"}), "stale-id", old, 30*time.Second); code != CodeStale {
		t.Fatalf("stale code %d", code)
	}
	// ttl_s in args raises the window (clamped to the 3600 s ceiling, F6/L6): a 700 s-old intent proceeds
	// at ttl_s 900 (and a wrong type is bad_request). The free listen keeps the create away from the canned
	// 4443 collision this test plants.
	younger := time.Now().Unix() - 700
	if _, code = c.call("tunnel.create", testWriteArgs(map[string]any{"name": "ttls", "carrier": "nope-carrier",
		"ttl_s": 900, "params": map[string]any{"listen": ":20041"}}), "ttls-id", younger, 30*time.Second); code != CodeOK {
		t.Fatalf("ttl_s must apply to the intent window too, code %d", code)
	}
	if _, code = c.call("tunnel.create", map[string]any{"carrier": "udp", "ports": "1", "ttl_s": "x"}, "ttlx-id", time.Now().Unix(), 30*time.Second); code != CodeBadRequest {
		t.Fatalf("wrong ttl_s type code %d", code)
	}
	// rate_limited: the create bucket (burst 5) is spent by the attempts above
	for i := 0; i < 6; i++ {
		c.Call("tunnel.create", testWriteArgs(map[string]any{"name": "rl" + itoa(i), "carrier": "nope-carrier"}))
	}
	if _, code = c.Call("tunnel.create", testWriteArgs(map[string]any{"name": "rl-final", "carrier": "nope-carrier"})); code != CodeRateLimited {
		t.Fatalf("rate_limited code %d", code)
	}
	_ = ops // rl0..rl5 etc created files in the temp dir; only the codes matter here
	// denied: a tunnel-only credential has no create bit (server-side check, plan security requirement)
	c2, _ := newScepterPair(t, CapTunnel, "", &fakeSource{}, newFakeOps(t))
	if _, code = c2.Call("tunnel.create", testWriteArgs(map[string]any{"name": "d1"})); code != CodeDenied {
		t.Fatalf("denied code %d", code)
	}
	if _, code = c2.Call("tunnel.edit", map[string]any{"name": "t1"}); code != CodeDenied {
		t.Fatalf("edit denied code %d", code)
	}
	// unknown: write commands toward a phase-A server (no ops armed) do not exist
	c3, _ := newScepterPair(t, CapFull, "", &fakeSource{})
	if _, code = c3.Call("tunnel.create", testWriteArgs(nil)); code != CodeUnknownCmd {
		t.Fatalf("no-ops create code %d, want unknown_cmd", code)
	}
}

// writeDirect seeds the fake CONF dir like a pre-existing tunnel (bypassing the ops: it is "already there").
func (f *fakeOps) writeDirect(name string, t *testing.T) {
	t.Helper()
	if err := os.WriteFile(f.yml(name), []byte("mode: server\ncarrier: udp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The rollback drill (plan B.4): the unit refuses to come up → CodeInternal with rolled_back, the files are
// gone, the state document is unchanged (no event, no state_seq bump), and a retry with a fresh id works.
func TestScepterCreateRollback(t *testing.T) {
	ops := newFakeOps(t)
	c, state := newScepterPair(t, CapFull, "", dirSource{ops.dir}, ops)
	ops.failStart["rb1"] = true
	seqBefore := state.StateSeq()
	args := testWriteArgs(map[string]any{"name": "rb1"})
	p, code := c.call("tunnel.create", args, "rb-retry", time.Now().Unix(), 30*time.Second) // fixed id: the retry below must replay it
	if code != CodeInternal || p["rolled_back"] != true {
		t.Fatalf("rollback: %v %v", code, p)
	}
	if ops.has("rb1") {
		t.Fatal("rolled-back create left its yml behind")
	}
	if _, err := os.Stat(filepath.Join(ops.dir, "rb1.key")); !os.IsNotExist(err) {
		t.Fatal("rolled-back create left its key behind")
	}
	if state.StateSeq() != seqBefore {
		t.Fatal("a rolled-back intent must not bump state_seq (no change, no event)")
	}
	// a failed outcome is NOT journaled (round-2 fix 2, 2026-11-22): the same-id retry re-runs the op and
	// rolls back again — re-executable rejections, and a re-run is the recovery when a panic skipped the
	// rollback. The replay-from-journal contract covers APPLIED outcomes only (TestScepterWriteJournalReplay).
	before := ops.creates
	p2, code2 := c.call("tunnel.create", args, "rb-retry", time.Now().Unix(), 30*time.Second)
	if code2 != CodeInternal || p2["rolled_back"] != true {
		t.Fatalf("re-executed failure: %v %v", code2, p2)
	}
	if ops.creates != before+1 {
		t.Fatal("the failed create was journaled: the retry replayed instead of re-running the op")
	}
	// edit rollback: the unit refuses the new config, the .bak content is restored
	ops.writeDirect("rb2", t)
	ops.failStart["rb2"] = true
	if _, code = c.Call("tunnel.edit", map[string]any{"name": "rb2", "set": map[string]any{"ping-every": "9"}}); code != CodeInternal {
		t.Fatalf("edit rollback code %d", code)
	}
	b, _ := os.ReadFile(filepath.Join(ops.dir, "rb2.yml"))
	if strings.Contains(string(b), "ping-every: 9") {
		t.Fatalf("edit rollback left the patch in place: %q", b)
	}
	ops.failStart["rb2"] = false
	if p, code = c.Call("tunnel.edit", map[string]any{"name": "rb2", "set": map[string]any{"ping-every": "9"}}); code != CodeOK {
		t.Fatalf("edit after rollback fix: %v %v", code, p)
	}
}

// Journal replay idempotency for write intents (plan B.4): a retried create runs once, and the journal
// carries the outcome across a state rebuild (Kharej restart).
func TestScepterWriteJournalReplay(t *testing.T) {
	ops := newFakeOps(t)
	jp := filepath.Join(t.TempDir(), ".journal")
	c, _ := newScepterPair(t, CapFull, jp, dirSource{ops.dir}, ops)
	args := testWriteArgs(map[string]any{"name": "jr1"})
	p1, code1 := c.call("tunnel.create", args, "jr-fixed", time.Now().Unix(), 30*time.Second)
	p2, code2 := c.call("tunnel.create", args, "jr-fixed", time.Now().Unix(), 30*time.Second)
	if code1 != CodeOK || code2 != CodeOK {
		t.Fatalf("codes %d/%d", code1, code2)
	}
	b1, _ := json.Marshal(p1)
	b2, _ := json.Marshal(p2)
	if string(b1) != string(b2) {
		t.Fatalf("retry outcome differs: %s vs %s", b1, b2)
	}
	if ops.creates != 1 {
		t.Fatalf("op ran %d times, want 1", ops.creates)
	}
	// across a "restart": a fresh state over the same journal answers from the records
	ops2 := newFakeOps(t)
	ops2.dir = ops.dir // same CONF, fresh ops (the new binary's reality)
	c.Close()
	state2, err := NewScepterState(testPairing(CapFull), dirSource{ops.dir}, jp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { state2.Stop(); state2.journal.Close() }()
	state2.SetOps(ops2)
	resp := state2.Handle(ScepterRequest{ID: "jr-fixed", V: scepterV, Cmd: "tunnel.create",
		Args: args, TS: time.Now().Unix()}, testPairing(CapFull).Caps)
	if resp.Code != CodeOK {
		t.Fatalf("replayed code %d", resp.Code)
	}
	if ops2.creates != 0 {
		t.Fatal("the replayed create ran the op again after the restart")
	}
}

// base_seq: absent skips the check; a matching seq applies silently.
func TestScepterWriteBaseSeqOptional(t *testing.T) {
	ops := newFakeOps(t)
	c, state := newScepterPair(t, CapFull, "", dirSource{ops.dir}, ops)
	seq := state.StateSeq()
	p, code := c.Call("tunnel.create", testWriteArgs(map[string]any{"name": "bs1", "base_seq": float64(seq)}))
	if code != CodeOK {
		t.Fatal(code)
	}
	if _, ok := p["state"]; ok {
		t.Fatalf("matching base_seq must not carry the state: %v", p)
	}
}

// Concurrent commands from two clients serialize on the one queue (plan B.4/E.2): write intents never
// interleave — the fake's concurrency probe pins max-concurrent-edits to 1, and a reader issuing its Handle
// while a slow edit is in flight only observes the state AFTER it. The calls go through Handle exactly as two
// serveScepterLoop goroutines (two clients, two streams) would; the wire itself is pinned by the round-trip
// tests (one ScepterClient's reader is not safe for concurrent waits, by design one stream = one caller).
func TestScepterQueueSerializes(t *testing.T) {
	ops := newFakeOps(t)
	ops.delay = 30 * time.Millisecond
	state, err := NewScepterState(testPairing(CapFull), dirSource{ops.dir}, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Stop(); state.journal.Close() })
	state.SetOps(ops)
	ops.writeDirect("q1", t)
	caps := testPairing(CapFull).Caps
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ { // two clients issuing writes at once
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				req := ScepterRequest{ID: fmt.Sprintf("q%d-%d", i, j), V: scepterV, Cmd: "tunnel.edit", TS: time.Now().Unix(),
					Args: map[string]any{"name": "q1", "set": map[string]any{"ping-every": itoa(i*10 + j)}}}
				if resp := state.Handle(req, caps); resp.Code != CodeOK {
					t.Errorf("concurrent edit code %d", resp.Code)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if m := ops.maxIn.Load(); m != 1 {
		t.Fatalf("write intents overlapped: max concurrent = %d, want 1 (one command queue)", m)
	}
	// a reader during a slow write waits behind it (one queue for reads and writes alike)
	done := make(chan uint64, 1)
	go func() {
		state.Handle(ScepterRequest{ID: "q-slow", V: scepterV, Cmd: "tunnel.edit", TS: time.Now().Unix(),
			Args: map[string]any{"name": "q1", "set": map[string]any{"ping-every": "1"}}}, caps)
		done <- state.StateSeq()
	}()
	time.Sleep(5 * time.Millisecond) // the edit (30 ms) is now in flight
	pre := state.StateSeq()
	post := <-done
	if post != pre+1 {
		t.Fatalf("state moved by %d across the in-flight edit (pre %d, post %d): the write did not run as one unit", post-pre, pre, post)
	}
}

// Presets: the engine-owned catalog, applied through the edit path; unknown presets answer bad_request with
// the catalog.
func TestScepterPresetApply(t *testing.T) {
	ops := newFakeOps(t)
	c, _ := newScepterPair(t, CapManage, "", dirSource{ops.dir}, ops)
	ops.writeDirect("pr1", t)
	if _, code := c.Call("preset.apply", map[string]any{"name": "pr1", "preset": "stealth"}); code != CodeOK {
		t.Fatal(code)
	}
	b, _ := os.ReadFile(filepath.Join(ops.dir, "pr1.yml"))
	if !strings.Contains(string(b), "noise: med") || !strings.Contains(string(b), "shape-data: 8") {
		t.Fatalf("stealth preset did not land: %q", b)
	}
	p, code := c.Call("preset.apply", map[string]any{"name": "pr1", "preset": "nope"})
	if code != CodeBadRequest || p["presets"] != "plain,stealth" {
		t.Fatalf("unknown preset: %v %v", code, p)
	}
}

// CallRaw streams every raw response line for its id — the -scepter-call contract the Go manager parses.
func TestScepterCallRaw(t *testing.T) {
	c, _ := newScepterPair(t, CapManage, "", &fakeSource{})
	var sb strings.Builder
	code, err := c.CallRaw("tunnel.stats", map[string]any{"name": "t1"}, "raw1", &sb)
	if err != nil || code != CodeOK {
		t.Fatalf("CallRaw: code %d err %v", code, err)
	}
	var resp ScepterResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(sb.String())), &resp); err != nil {
		t.Fatalf("raw line: %v (%q)", err, sb.String())
	}
	if resp.ID != "raw1" || resp.Seq == 0 {
		t.Fatalf("raw response: %+v", resp)
	}
	// chunked payloads arrive as several raw lines in order
	src := &fakeSource{}
	for i := 0; i < 400; i++ {
		src.logs = append(src.logs, strings.Repeat("r", 80)+itoa(i))
	}
	c2, _ := newScepterPair(t, CapManage, "", src)
	sb.Reset()
	if code, err = c2.CallRaw("tunnel.logs", map[string]any{"name": "t1", "tail": 400}, "raw2", &sb); err != nil || code != CodeOK {
		t.Fatalf("chunked CallRaw: %d %v", code, err)
	}
	lines := strings.Split(strings.TrimSpace(sb.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected several chunk lines, got %d", len(lines))
	}
	first, last := lines[0], lines[len(lines)-1]
	var fr, lr ScepterResponse
	json.Unmarshal([]byte(first), &fr)
	json.Unmarshal([]byte(last), &lr)
	if fr.Chunk == nil || lr.Chunk == nil || lr.Chunk.I != lr.Chunk.N-1 {
		t.Fatalf("chunk lines: first %v last %v", fr.Chunk, lr.Chunk)
	}
}

// ---- phase C: remote carrier work ----

// The probe lifecycle drill (plan C.3) over the RPC: open reports the dial parameters, the ttl is clamped and
// echoed, the event ring logs open and close, and a second close of the same probe is not_found.
func TestScepterTestOpenLifecycle(t *testing.T) {
	ops := newFakeOps(t)
	c, _ := newScepterPair(t, CapManage, "", dirSource{ops.dir}, ops)
	// strictly-typed args first (they must not burn probe tokens)
	if p, code := c.Call("test.open", map[string]any{}); code != CodeBadRequest {
		t.Fatalf("open without carrier: %v %v", code, p)
	}
	if p, code := c.Call("test.open", map[string]any{"carrier": "udp", "ttl": "soon"}); code != CodeBadRequest {
		t.Fatalf("open with a string ttl: %v %v", code, p)
	}
	p, code := c.Call("test.open", map[string]any{"carrier": "udp", "ttl": 5})
	if code != CodeOK {
		t.Fatalf("open: %v %v", code, p)
	}
	if p["ttl"] != float64(probeTTLMin) || p["carrier"] != "udp" || p["port"] == 0 || p["key"] == "" || p["id"] == "" {
		t.Fatalf("open params: %v", p)
	}
	id1 := p["id"].(string)
	if p, code = c.Call("test.open", map[string]any{"carrier": "tcp", "ttl": 99999}); code != CodeOK || p["ttl"] != float64(probeTTLMax) {
		t.Fatalf("open clamped ttl: %v %v", code, p)
	}
	if p, code = c.Call("test.open", map[string]any{"carrier": "ws"}); code != CodeOK || p["path"] != "/wat" {
		t.Fatalf("http-family probe must report the shared path: %v %v", code, p)
	}
	if p, code = c.Call("test.open", map[string]any{"carrier": "h2c"}); code != CodeRateLimited || p["resource"] != "probe" {
		t.Fatalf("the fourth probe must hit the per-pair bucket: %v %v", code, p)
	}
	if _, code = c.Call("test.close", map[string]any{"probe": id1}); code != CodeOK {
		t.Fatal("close")
	}
	if p, code = c.Call("test.close", map[string]any{"probe": id1}); code != CodeNotFound {
		t.Fatalf("double close: %v %v", code, p)
	}
	if p, code = c.Call("test.close", map[string]any{}); code != CodeBadRequest {
		t.Fatalf("close without probe: %v %v", code, p)
	}
	// the event ring saw the lifecycle
	p, code = c.Call("events.since", map[string]any{"seq": 0})
	if code != CodeOK {
		t.Fatal(code)
	}
	evs := p["events"].([]any)
	var opened, closed int
	for _, e := range evs {
		switch m := e.(map[string]any); m["type"] {
		case EvTestOpened:
			opened++
		case EvTestClosed:
			closed++
		}
	}
	if opened != 3 || closed != 1 {
		t.Fatalf("events: opened %d closed %d (want 3/1)", opened, closed)
	}
}

// carrier.change over the RPC: the happy switch reports carrier+listen and fires carrier_switched; a failed
// link check rolls back, is journaled (a same-id retry replays it), and the base_seq tail carries fresh state.
func TestScepterCarrierChangeRPC(t *testing.T) {
	ops := newFakeOps(t)
	ops.writeDirect("w1", t)
	c, _ := newScepterPair(t, CapManage, "", dirSource{ops.dir}, ops)
	p, code := c.Call("carrier.change", map[string]any{"name": "w1", "carrier": "tcp", "base_seq": 999})
	if code != CodeOK || p["carrier"] != "tcp" || p["listen"] == nil {
		t.Fatalf("carrier.change: %v %v", code, p)
	}
	if _, moved := p["state"]; !moved { // built on a stale base_seq: the fresh document rides along
		t.Fatalf("stale base_seq must carry the state tail: %v", p)
	}
	b, _ := os.ReadFile(filepath.Join(ops.dir, "w1.yml"))
	if !strings.Contains(string(b), "carrier: tcp") {
		t.Fatalf("change did not land: %q", b)
	}
	if _, err := os.Stat(filepath.Join(ops.dir, "w1.yml.bak")); err != nil {
		t.Fatal("no .bak after the change")
	}
	p, code = c.Call("carrier.change", map[string]any{"name": "w1", "carrier": "tcp", "params": map[string]any{"carrier": "udp"}})
	if code != CodeBadRequest {
		t.Fatalf("duplicate carrier in params: %v %v", code, p)
	}
	if _, code = c.Call("carrier.change", map[string]any{"name": "w1", "carrier": ""}); code != CodeBadRequest {
		t.Fatal("empty carrier accepted")
	}
	// the structural bucket shared with tunnel.create: five ops pass, the sixth is rate_limited
	for i := 0; i < 4; i++ {
		car := "tcp"
		if i%2 == 0 {
			car = "udp"
		}
		if _, code = c.Call("carrier.change", map[string]any{"name": "w1", "carrier": car}); code != CodeOK {
			t.Fatalf("structural op %d: %v", i, code)
		}
	}
	if p, code = c.Call("carrier.change", map[string]any{"name": "w1", "carrier": "tcp"}); code != CodeRateLimited || p["resource"] != "carrier.change" {
		t.Fatalf("sixth structural op must be rate limited: %v %v", code, p)
	}
}

// The carrier-change rollback drill: the link check fails → rolled_back, the pre-change config is restored
// and up again, and a retry re-runs the op and fails the same way — failed outcomes are not journaled
// (round-2 fix 2, 2026-11-22), so the observable result is identical while the rollback keeps guarding.
func TestScepterCarrierChangeRollback(t *testing.T) {
	ops := newFakeOps(t)
	ops.failLink["w2"] = true
	ops.writeDirect("w2", t)
	jp := filepath.Join(t.TempDir(), "journal.jsonl")
	c, _ := newScepterPair(t, CapManage, jp, dirSource{ops.dir}, ops)
	p, code := c.Call("carrier.change", map[string]any{"name": "w2", "carrier": "ws", "id": "cc-7"})
	if code != CodeInternal || p["rolled_back"] != true {
		t.Fatalf("link-check failure: %v %v", code, p)
	}
	b, _ := os.ReadFile(filepath.Join(ops.dir, "w2.yml"))
	if !strings.Contains(string(b), "carrier: udp") {
		t.Fatalf("rollback did not restore the pre-change carrier: %q", b)
	}
	// the retry re-executes (a failed outcome is not journaled): the link check fails again, the rollback
	// restores the same pre-change config
	p, code = c.Call("carrier.change", map[string]any{"name": "w2", "carrier": "ws", "id": "cc-7"})
	if code != CodeInternal || p["rolled_back"] != true {
		t.Fatalf("retry: %v %v", code, p)
	}
	if b2, _ := os.ReadFile(filepath.Join(ops.dir, "w2.yml")); string(b2) != string(b) {
		t.Fatal("the replay mutated the tunnel")
	}
}

// The fleet auto-test round-trip on a sim Kharej (plan C.3): trigger, wait for EvAutoTested, read the ranked
// table, apply row 1 through the carrier.change path.
func TestScepterAutoTestRPC(t *testing.T) {
	ops := newFakeOps(t)
	ops.writeDirect("at1", t)
	c, _ := newScepterPair(t, CapManage, "", dirSource{ops.dir}, ops)
	if p, code := c.Call("auto.test", map[string]any{"mode": "nope"}); code != CodeBadRequest || p["modes"] != "plain,tls" {
		t.Fatalf("unknown mode: %v %v", code, p)
	}
	p, code := c.Call("auto.test", nil)
	if code != CodeOK || p["mode"] != "plain" || p["shapes"] != float64(2) || p["run"] == "" {
		t.Fatalf("auto.test: %v %v", code, p)
	}
	// wait for the run to finish (the trigger answers before it does)
	var rows []any
	deadline := time.Now().Add(3 * time.Second)
	for {
		pr, pc := c.Call("auto.rows", nil)
		if pc != CodeOK {
			t.Fatalf("auto.rows: %v", pc)
		}
		if done, _ := pr["done"].(bool); done {
			rows = pr["rows"].([]any)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("auto.test run never finished")
		}
		time.Sleep(20 * time.Millisecond)
	}
	r1 := rows[0].(map[string]any)
	if r1["rank"] != float64(1) || r1["carrier"] != "tcp" || r1["ok"] != true {
		t.Fatalf("rank 1 must be the servable shape: %v", r1)
	}
	r2 := rows[1].(map[string]any)
	if r2["ok"] != false || r2["why"] == "" {
		t.Fatalf("rank 2 is the failed shape: %v", r2)
	}
	// EvAutoTested announced the finish
	p, _ = c.Call("events.since", map[string]any{"seq": 0})
	var tested bool
	for _, e := range p["events"].([]any) {
		if m := e.(map[string]any); m["type"] == EvAutoTested {
			if d := m["detail"].(map[string]any); d["ok"] == float64(1) && d["total"] == float64(2) {
				tested = true
			}
		}
	}
	if !tested {
		t.Fatalf("no auto_test event with (ok 1, total 2): %v", p["events"])
	}
	// apply row 1 through the carrier.change path
	p, code = c.Call("auto.apply", map[string]any{"name": "at1", "row": 1})
	if code != CodeOK || p["carrier"] != "tcp" || p["row"] != float64(1) {
		t.Fatalf("auto.apply: %v %v", code, p)
	}
	b, _ := os.ReadFile(filepath.Join(ops.dir, "at1.yml"))
	if !strings.Contains(string(b), "carrier: tcp") || !strings.Contains(string(b), "listen: :20501") {
		t.Fatalf("auto.apply did not land: %q", b)
	}
	if _, code = c.Call("auto.apply", map[string]any{"name": "at1", "row": 0}); code != CodeBadRequest {
		t.Fatal("row 0 accepted")
	}
	if p, code = c.Call("auto.apply", map[string]any{"name": "at1", "row": 9}); code != CodeNotFound {
		t.Fatalf("out-of-range row: %v %v", code, p)
	}
	if _, code = c.Call("auto.apply", map[string]any{"name": "at1"}); code != CodeBadRequest {
		t.Fatal("missing row accepted")
	}
}

// ---- phase D: operations ----

// update.status passes through, update.run is the one CapFull command: denied at manage (recomputed on a
// retry — pure rejections are not journaled), accepted at full, and the version argument is validated before
// the ops ever see it (below the first Scepter release the cockpit's own channel would not come back; the
// running version is a nothing-to-do).
func TestScepterUpdateRPC(t *testing.T) {
	ops := newFakeOps(t)
	c, _ := newScepterPair(t, CapManage, "", &fakeSource{}, ops)
	p, code := c.Call("update.status", nil)
	if code != CodeOK || p["ver"] != Version {
		t.Fatalf("update.status: %v %v", code, p)
	}
	if _, code = c.Call("update.run", nil); code != CodeDenied {
		t.Fatalf("update.run at manage: code %d, want %d (denied)", code, CodeDenied)
	}
	// a full-capability credential gets through; the version gates are checked before the bucket, so every
	// rejection shape is visible without waiting out the 5 min refill
	ops2 := newFakeOps(t)
	c2, _ := newScepterPair(t, CapFull, "", &fakeSource{}, ops2)
	for _, bad := range []any{"three.six", "v3.6", "3.6.0.1", Version, "3.4.9", 6} {
		if _, code = c2.Call("update.run", map[string]any{"to": bad}); code != CodeBadRequest {
			t.Fatalf("to %v accepted (code %d)", bad, code)
		}
	}
	if _, code = c2.Call("update.run", map[string]any{"ttl_s": "soon"}); code != CodeBadRequest {
		t.Fatal("bad ttl_s type accepted")
	}
	p, code = c2.Call("update.run", map[string]any{"to": "v3.6.0"})
	if code != CodeOK || p["phase"] != UpdatePhaseStarted || p["to"] != "v3.6.0" || p["run"] == nil {
		t.Fatalf("update.run at full: %v %v", code, p)
	}
	if ops2.updRuns != 1 || ops2.updTo != "v3.6.0" {
		t.Fatalf("ops saw %d run(s), to %q", ops2.updRuns, ops2.updTo)
	}
	// the started event fired in-life (the watcher owns the terminal events, this handler owns started)
	p, _ = c2.Call("events.since", map[string]any{"seq": 0})
	fired := false
	for _, e := range p["events"].([]any) {
		if m := e.(map[string]any); m["type"] == EvUpdateStarted {
			fired = true
		}
	}
	if !fired {
		t.Fatal("no update_started event in-life")
	}
	// the per-pair update bucket: one at once, one per 5 min — a retry loop can never machine-gun restarts
	if p, code = c2.Call("update.run", nil); code != CodeRateLimited || p["resource"] != "update" {
		t.Fatalf("second update.run in the same window: %v %v", code, p)
	}
	// no args = the latest release (a fresh state: its own bucket)
	ops3 := newFakeOps(t)
	c3, _ := newScepterPair(t, CapFull, "", &fakeSource{}, ops3)
	if p, code = c3.Call("update.run", nil); code != CodeOK || p["to"] != "latest" || ops3.updTo != "" {
		t.Fatalf("update.run latest: %v %v (ops to %q)", code, p, ops3.updTo)
	}
	if _, code = c2.Call("update.run", map[string]any{"ttl_s": "soon"}); code != CodeBadRequest {
		t.Fatal("bad ttl_s type accepted")
	}
}

// doctor.fetch: the state document plus the doctor's last-commands trace, enriched by the ops fragment
// (latch status et al) — the same data the loopback /scepter endpoint serves, packaged for the cockpit.
func TestScepterDoctorFetchRPC(t *testing.T) {
	ops := newFakeOps(t)
	ops.doctorExtra = map[string]any{"latch": map[string]any{"enabled": true, "port": 8443},
		"unit": map[string]any{"name": "server", "active": true}}
	c, _ := newScepterPair(t, CapManage, "", &fakeSource{}, ops)
	if _, code := c.Call("scepter.ping", nil); code != CodeOK {
		t.Fatal("ping")
	}
	p, code := c.Call("doctor.fetch", nil)
	if code != CodeOK {
		t.Fatalf("doctor.fetch code %d", code)
	}
	if p["ver"] != Version {
		t.Fatalf("doctor core ver: %v", p["ver"])
	}
	if _, ok := p["tunnels"]; !ok {
		t.Fatal("doctor has no tunnels")
	}
	latch, _ := p["latch"].(map[string]any)
	if latch == nil || latch["enabled"] != true || latch["port"] != float64(8443) {
		t.Fatalf("doctor latch fragment: %v", p["latch"])
	}
	recent, _ := p["recent"].([]any)
	if len(recent) != 2 { // ping + this doctor.fetch
		t.Fatalf("recent trace: %v", p["recent"])
	}
}

// backup.export rides the chunked-logs convention: a tarball over scepterChunk arrives as chunk pieces, the
// client reassembles them into the one newline-free doc, and the doc decodes back to the exact tar (b64 and
// sha256 pinned). A monster export is refused, not exploded.
func TestScepterBackupExportChunked(t *testing.T) {
	ops := newFakeOps(t)
	ops.backupPad = scepterChunk * 2 // forces 3+ chunks through the real writeResp
	c, _ := newScepterPair(t, CapManage, "", &fakeSource{}, ops)
	p, code := c.Call("backup.export", nil)
	if code != CodeOK {
		t.Fatalf("backup.export code %d", code)
	}
	logs, ok := p["logs"].([]string) // waitResp reassembles chunks into a []string logs list
	if !ok || len(logs) != 1 {
		t.Fatalf("reassembled logs: %#v", p["logs"])
	}
	var doc struct {
		B64    string `json:"b64"`
		Sha256 string `json:"sha256"`
		Size   int    `json:"size"`
		Files  int    `json:"files"`
	}
	if err := json.Unmarshal([]byte(logs[0]), &doc); err != nil {
		t.Fatalf("backup doc: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(doc.B64)
	if err != nil {
		t.Fatalf("b64: %v", err)
	}
	if len(raw) != doc.Size || fmt.Sprintf("%x", sha256.Sum256(raw)) != doc.Sha256 || doc.Files != 1 {
		t.Fatalf("backup doc integrity: size %d/%d sha %q files %d", len(raw), doc.Size, doc.Sha256, doc.Files)
	}
	tr := tar.NewReader(bytes.NewReader(raw))
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "t1.yml" {
		t.Fatalf("tar entry: %v %v", hdr, err)
	}
	b, _ := io.ReadAll(tr)
	if !strings.HasPrefix(string(b), "mode: server\n") {
		t.Fatalf("tar content: %q", b)
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatal("tar has extra entries")
	}
	ops.backupCode = CodeTooLarge
	if _, code = c.Call("backup.export", nil); code != CodeTooLarge {
		t.Fatalf("too-large export: code %d", code)
	}
}

// audit.tail: the last n entries of each source come back as two newline-free JSON docs in the logs list
// (audit first, journal second), parse-free raw lines, with the count/type gates holding. The response is
// small enough to pass unchunked, so the params are the wire-roundtripped []any — the logsAs helper reads
// both that and the chunked-reassembly []string shape.
func TestScepterAuditTailRPC(t *testing.T) {
	ops := newFakeOps(t)
	ops.auditN = []string{"2026-11-22T10:00:00Z pair_created u1", "2026-11-22T11:00:00Z pair_rotated u1",
		"2026-11-22T12:00:00Z pair_revoked u1"}
	c, _ := newScepterPair(t, CapManage, "", &fakeSource{}, ops)
	p, code := c.Call("audit.tail", nil)
	if code != CodeOK {
		t.Fatalf("audit.tail code %d", code)
	}
	logs := logsAs(p)
	if len(logs) != 2 {
		t.Fatalf("audit.tail logs: %#v", p["logs"])
	}
	var a struct {
		Src     string   `json:"src"`
		Entries []string `json:"entries"`
	}
	if json.Unmarshal([]byte(logs[0]), &a) != nil || a.Src != "audit" || len(a.Entries) != 3 {
		t.Fatalf("audit doc: %s", logs[0])
	}
	var j struct {
		Src string `json:"src"`
	}
	if json.Unmarshal([]byte(logs[1]), &j) != nil || j.Src != "journal" {
		t.Fatalf("journal doc: %s", logs[1])
	}
	if p, code = c.Call("audit.tail", map[string]any{"n": 2}); code != CodeOK {
		t.Fatal("audit.tail n=2")
	}
	logs = logsAs(p)
	json.Unmarshal([]byte(logs[0]), &a)
	if len(a.Entries) != 2 || a.Entries[1] != ops.auditN[2] {
		t.Fatalf("n=2 tail: %v", a.Entries)
	}
	if _, code = c.Call("audit.tail", map[string]any{"n": "many"}); code != CodeBadRequest {
		t.Fatal("bad n type accepted")
	}
	if _, code = c.Call("audit.tail", map[string]any{"n": -1}); code != CodeBadRequest {
		t.Fatal("negative n accepted")
	}
}

// Audit completeness (plan E.3): EVERY handled command lands in the shared audit file with the credential
// UUID — ok, denied, stale, rate_limited and unknown_cmd alike (the journal stays outcomes-only for replay)
// — in THE SAME file and line shape wattun-manager's console writes ("<RFC3339> <event> <detail>"), so
// audit.tail reads one credential+command trail. A newline in a peer-supplied id cannot forge audit lines.
func TestScepterAuditPerCommand(t *testing.T) {
	dir := t.TempDir()
	jp := filepath.Join(dir, ".pairing.journal")
	ops := newFakeOps(t)
	ops.writeDirect("t1", t)
	ss, err := NewScepterState(testPairing(CapFull), nil, jp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Stop(); ss.journal.Close() })
	ss.SetOps(ops)
	pair := testPairing(CapFull)
	ap := filepath.Join(dir, ScepterAuditFile)

	// the manager's console wrote here first: the shared file keeps both writers' lines
	mgr := "2026-11-22T09:00:00Z pair_created " + pair.UUIDString() + " caps=full\n"
	if err := os.WriteFile(ap, []byte(mgr), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	edit := map[string]any{"name": "t1", "set": map[string]any{"ping-every": "5"}}
	if r := ss.Handle(ScepterRequest{ID: "ok-1", V: scepterV, Cmd: "tunnel.edit", Args: edit, TS: now}, pair.Caps); r.Code != CodeOK {
		t.Fatalf("ok command: code %d", r.Code)
	}
	if r := ss.Handle(ScepterRequest{ID: "den-1", V: scepterV, Cmd: "tunnel.stats", Args: map[string]any{"name": "t1"}, TS: now}, CapTunnel); r.Code != CodeDenied {
		t.Fatalf("denied command: code %d", r.Code)
	}
	if r := ss.Handle(ScepterRequest{ID: "old-1", V: scepterV, Cmd: "scepter.ping", TS: now - scepterTTL - 120}, pair.Caps); r.Code != CodeStale {
		t.Fatalf("stale command: code %d", r.Code)
	}
	if r := ss.Handle(ScepterRequest{ID: "unk-1", V: scepterV, Cmd: "nope.cmd", TS: now}, pair.Caps); r.Code != CodeUnknownCmd {
		t.Fatalf("unknown command: code %d", r.Code)
	}
	ss.rate = scepterRate{rate: 0.0001, burst: 0} // burst-only bucket drained: the next attempt is rate_limited
	if r := ss.Handle(ScepterRequest{ID: "rl-1", V: scepterV, Cmd: "scepter.ping", TS: now}, pair.Caps); r.Code != CodeRateLimited {
		t.Fatalf("rate limited: code %d", r.Code)
	}
	ss.rate = scepterRate{rate: 20, burst: 40}
	// a journaled retry replays the recorded outcome and is audited as the attempt it was
	if r := ss.Handle(ScepterRequest{ID: "ok-1", V: scepterV, Cmd: "tunnel.edit", Args: edit, TS: now}, pair.Caps); r.Code != CodeOK {
		t.Fatalf("replayed retry: code %d", r.Code)
	}
	// a newline in the id collapses: one command, one line, no forged entries
	if r := ss.Handle(ScepterRequest{ID: "evil\nid", V: scepterV, Cmd: "tunnel.edit", Args: edit, TS: now}, pair.Caps); r.Code != CodeOK {
		t.Fatalf("sanitized command: code %d", r.Code)
	}

	b, err := os.ReadFile(ap)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	want := []struct {
		cmd, id string
		code    int
	}{
		{"tunnel.edit", "ok-1", CodeOK},
		{"tunnel.stats", "den-1", CodeDenied},
		{"scepter.ping", "old-1", CodeStale},
		{"nope.cmd", "unk-1", CodeUnknownCmd},
		{"scepter.ping", "rl-1", CodeRateLimited},
		{"tunnel.edit", "ok-1", CodeOK}, // the replay, audited again
		{"tunnel.edit", "evil_id", CodeOK},
	}
	if len(lines) != len(want)+1 || lines[0] != strings.TrimRight(mgr, "\n") {
		t.Fatalf("audit lines (%d): %q", len(lines), lines)
	}
	for i, w := range want {
		l := lines[i+1]
		pre := " scepter_cmd uuid=" + pair.UUIDString() + " cmd=" + w.cmd + " code=" + itoa(w.code) + " id=" + w.id
		if !strings.HasSuffix(l, pre) {
			t.Fatalf("audit line %d = %q, want suffix %q", i+1, l, pre)
		}
		if !isRFC3339Stamp(l) { // "<RFC3339> <event> <detail>" — the manager's line shape, seconds resolution
			t.Fatalf("audit line %d does not start with an RFC3339 UTC stamp: %q", i+1, l)
		}
	}
	// the journal stayed outcomes-only, MUTATIONS only (H1/F4): the applied edits are there, none of the
	// rejections and none of the pings (reads re-execute, they are never replayed)
	jb, err := os.ReadFile(jp)
	if err != nil {
		t.Fatal(err)
	}
	jl := strings.Split(strings.TrimRight(string(jb), "\n"), "\n")
	if len(jl) != 2 { // ok-1 (the retry replays, never re-records) and the sanitized edit — both code 0
		t.Fatalf("journal holds %d records, want the 2 applied edits only", len(jl))
	}
	for _, l := range jl {
		if strings.Contains(l, "den-1") || strings.Contains(l, "old-1") || strings.Contains(l, "unk-1") || strings.Contains(l, "rl-1") {
			t.Fatalf("a pure rejection was journaled: %q", l)
		}
		if !strings.Contains(l, `"code":0`) || !strings.Contains(l, `"cmd":"tunnel.edit"`) {
			t.Fatalf("journal line is not a mutation outcome record: %q", l)
		}
	}
}

// isRFC3339Stamp reports whether s starts with a "YYYY-MM-DDTHH:MM:SSZ" UTC stamp (the shared audit line
// shape; kept tiny and dependency-free on purpose).
func isRFC3339Stamp(s string) bool {
	if len(s) < 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != 'Z' {
		return false
	}
	for _, i := range []int{0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18} {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Audit rotation (plan E.3): past the 1 MiB journal threshold the live file is renamed to
// ScepterAuditFile+".1" — a fresh live file, the old generation preserved wholesale (never rewritten away).
func TestScepterAuditRotation(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenScepterAudit(filepath.Join(dir, ScepterAuditFile))
	if err != nil {
		t.Fatal(err)
	}
	live, old := filepath.Join(dir, ScepterAuditFile), filepath.Join(dir, ScepterAuditFile+".1")
	now := time.Now()
	for i := 0; ; i++ { // write past the threshold; ~75 B/line so this is a few thousand quick records
		a.record(now, "uu", "scepter.ping", itoa(i), CodeOK)
		if _, err := os.Stat(old); err == nil {
			break
		}
		if i > 200000 {
			t.Fatal("audit never rotated past the threshold")
		}
	}
	st, err := os.Stat(old)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() < scepterJournalRotate {
		t.Fatalf("rotated at %d bytes, below the %d threshold", st.Size(), scepterJournalRotate)
	}
	oldLines := strings.Count(mustRead(t, old), "\n")
	if oldLines < 2 {
		t.Fatalf("old generation holds %d lines, want the whole pre-rotation content", oldLines)
	}
	// the live file starts fresh; the old generation is untouched by later records
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatalf("live audit after rotation: %v (want gone until the next record)", err)
	}
	a.record(now, "uu", "scepter.ping", "post", CodeOK)
	b := mustRead(t, live)
	if n := strings.Count(b, "\n"); n != 1 || !strings.HasSuffix(strings.TrimSpace(b), "id=post") {
		t.Fatalf("fresh live audit holds %d line(s): %q", n, b)
	}
	if st2, err := os.Stat(old); err != nil || st2.Size() != st.Size() {
		t.Fatalf("old generation changed after rotation: %v vs %d bytes", st2, st.Size())
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The channel-survival semantics (plan D.1/D.3), end to end over real sessions and a real journal file:
// the update.run response is flushed BEFORE the "restart" (the client received it), the intent lives in the
// journal across the engine's death, the revived engine answers a retry of the SAME id from the journal
// (at-most-once: the ops never re-run), and the revived state's watcher turns the update mailbox into the
// update_applied event — in production the latch's job is exactly this re-dial during the dead window.
func TestScepterUpdateChannelSurvival(t *testing.T) {
	dir := t.TempDir()
	jp := filepath.Join(dir, ".pairing.journal")
	ops1 := newFakeOps(t)
	c1, _ := newScepterPair(t, CapFull, jp, &fakeSource{}, ops1)
	id := "survive-1"
	p, code := c1.call("update.run", map[string]any{"to": "v3.6.0"}, id, time.Now().Unix(), 30*time.Second)
	if code != CodeOK || p["phase"] != UpdatePhaseStarted {
		t.Fatalf("update.run: %v %v", code, p)
	}
	if ops1.updRuns != 1 {
		t.Fatalf("ops ran %d time(s)", ops1.updRuns)
	}
	startedPhase := fmt.Sprint(p["phase"])
	c1.Close() // the engine "restarts": the in-band channel dies right after the flushed response

	// the update job finished while the engine was down: the mailbox records the outcome
	writeAtomicTest(filepath.Join(dir, ScepterUpdateStatusFile),
		`{"phase":"applied","run":"survive-1","from":"`+Version+`","to":"v3.6.0","ts":`+
			strconv.FormatInt(time.Now().Unix(), 10)+`}`)

	ops2 := newFakeOps(t)
	c2, _ := newScepterPair(t, CapFull, jp, &fakeSource{}, ops2) // revival: in-band again, or via the latch
	p, code = c2.call("update.run", map[string]any{"to": "v3.6.0"}, id, time.Now().Unix(), 30*time.Second)
	if code != CodeOK {
		t.Fatalf("retry code %d", code)
	}
	if fmt.Sprint(p["phase"]) != startedPhase {
		t.Fatalf("replayed response changed: %v (started phase %q)", p, startedPhase)
	}
	if ops2.updRuns != 0 {
		t.Fatal("the journal replay re-ran the update op (at-most-once broken)")
	}
	deadline := time.Now().Add(8 * time.Second) // the revived watcher polls the mailbox every 2 s
	for {
		p, _ = c2.Call("events.since", map[string]any{"seq": 0})
		found := false
		for _, e := range p["events"].([]any) {
			if m := e.(map[string]any); m["type"] == EvUpdateApplied {
				if d := m["detail"].(map[string]any); d["run"] == "survive-1" && d["to"] == "v3.6.0" {
					found = true
				}
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no update_applied event after revival: %v", p["events"])
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// The watcher unit drill: applied and rolled_back records fire while fresh, a started record silent past the
// stale threshold fires interrupted, and stale history never re-fires on a later poll. The threshold pins
// ABOVE the job's 15 min download cap (round-2 fix 10, 2026-11-22): a healthy slow update still in flight
// must not be declared interrupted.
func TestScepterUpdateWatcher(t *testing.T) {
	if scepterUpdateStale <= 15*time.Minute {
		t.Fatalf("scepterUpdateStale = %v, want above the job's 15 min download cap", scepterUpdateStale)
	}
	dir := t.TempDir()
	jp := filepath.Join(dir, ".pairing.journal")
	ss, err := NewScepterState(testPairing(CapManage), nil, jp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Stop(); ss.journal.Close() })
	ss.SetOps(newFakeOps(t)) // arms the watcher (the status path exists next to the journal)
	mail := filepath.Join(dir, ScepterUpdateStatusFile)
	now := time.Now().Unix()
	writeAtomicTest(mail, `{"phase":"applied","run":"w1","from":"`+Version+`","to":"v3.6.0","ts":`+
		strconv.FormatInt(now, 10)+`}`)
	waitScepterEvent(t, ss, EvUpdateApplied, "")
	writeAtomicTest(mail, `{"phase":"rolled_back","run":"w2","ts":`+strconv.FormatInt(now+3, 10)+`}`)
	waitScepterEvent(t, ss, EvUpdateFailed, UpdatePhaseRolledBack)
	writeAtomicTest(mail, `{"phase":"started","run":"w3","ts":`+
		strconv.FormatInt(now-2*int64(scepterUpdateStale/time.Second), 10)+`}`) // silent past the threshold
	waitScepterEvent(t, ss, EvUpdateFailed, "interrupted")
	seq := ss.StateSeq()
	writeAtomicTest(mail, `{"phase":"failed","run":"w4","ts":`+
		strconv.FormatInt(now-2*int64(time.Hour/time.Second), 10)+`}`) // stale history: not news
	time.Sleep(3 * scepterUpdatePoll)
	if ss.StateSeq() != seq {
		t.Fatal("a stale status record fired an event")
	}
}

// logsAs reads the logs list in either wire shape: a small (unchunked) response roundtrips as []any, a
// chunked response is reassembled by waitResp into []string.
func logsAs(p map[string]any) []string {
	switch v := p["logs"].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, len(v))
		for i, e := range v {
			out[i], _ = e.(string)
		}
		return out
	}
	return nil
}

// waitScepterEvent polls the state's event ring for kind (and detail.phase when want is non-empty).
func waitScepterEvent(t *testing.T, ss *ScepterState, kind, want string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		ss.mu.Lock()
		found := false
		for _, ev := range ss.events {
			if ev.Type != kind {
				continue
			}
			if want == "" || ev.Detail["phase"] == want {
				found = true
			}
		}
		ss.mu.Unlock()
		if found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s event (phase %q) within the deadline", kind, want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ---- wave-2 hardening pins (2026-11-22): journal bounds, cmd mismatch, TTL clamp, panic recovery,
// tunnel liveness watcher, hello floor, name rule, reload/disarm, session CloseScepter ----

// The journal bound (H1/F4): a read flood through Handle journals NOTHING; a mutation flood keeps the
// replay set at scepterJournalKeep (oldest pruned); the reload after rotation sees at most the pruned set,
// with the recorded command intact (Lookup matches on cmd).
func TestScepterJournalBounded(t *testing.T) {
	jp := filepath.Join(t.TempDir(), ".pairing.journal")
	ss, err := NewScepterState(testPairing(CapFull), nil, jp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Stop(); ss.journal.Close() })
	// reads: never journaled, no matter how many (Handle is the enforcement point; rate-limited reads are
	// pure rejections and equally unrecorded)
	now := time.Now().Unix()
	for i := 0; i < 2000; i++ {
		ss.Handle(ScepterRequest{ID: "read-" + itoa(i), V: scepterV, Cmd: "scepter.ping", TS: now}, testPairing(CapFull).Caps)
	}
	if len(ss.journal.keep) != 0 {
		t.Fatalf("read flood journaled %d records, want 0", len(ss.journal.keep))
	}
	if st, serr := os.Stat(jp); serr == nil && st.Size() > 0 {
		t.Fatalf("read flood wrote %d bytes to the journal", st.Size())
	}
	// mutations: the replay set stays at the bound, the oldest ids pruned in insertion order (Record is the
	// journal's own low-level API — Handle filters by scepterMutations before it)
	j := ss.journal
	resp := ScepterResponse{ID: "x", Code: CodeOK}
	for i := 0; i < 20000; i++ { // ~1.6 MB of ~80 B records: rotation fires mid-flood
		j.Record("tunnel.edit", "mut-"+itoa(i), time.Now().Unix(), resp)
	}
	if len(j.keep) != scepterJournalKeep || len(j.order) != scepterJournalKeep {
		t.Fatalf("keep = %d/%d, want the %d bound", len(j.keep), len(j.order), scepterJournalKeep)
	}
	if _, ok := j.keep["mut-0"]; ok {
		t.Fatal("the oldest id survived the prune")
	}
	if _, ok := j.keep["mut-19999"]; !ok {
		t.Fatal("the newest id was pruned")
	}
	if _, ok := j.Lookup("mut-0", "tunnel.edit"); ok {
		t.Fatal("a pruned id replayed")
	}
	j.Close()
	// a reload after the rotation: at most the pruned set, with cmd intact (a rotated record replays for
	// its own command and misses for any other)
	j2, err := OpenScepterJournal(jp)
	if err != nil {
		t.Fatal(err)
	}
	defer j2.Close()
	if len(j2.keep) > scepterJournalKeep {
		t.Fatalf("reload holds %d records, want at most %d", len(j2.keep), scepterJournalKeep)
	}
	if _, ok := j2.Lookup("mut-19999", "tunnel.edit"); !ok {
		t.Fatal("the newest id did not survive the reload")
	}
	if _, ok := j2.Lookup("mut-19999", "tunnel.stop"); ok {
		t.Fatal("a reloaded record replayed for a different command")
	}
}

// A pruned (or unknown) id re-executes fresh through the full Handle path: the op runs again and the answer
// is a new CodeOK, not a replay.
func TestScepterPrunedIDReexecutes(t *testing.T) {
	ops := newFakeOps(t)
	ops.writeDirect("t1", t)
	dir := t.TempDir()
	ss, err := NewScepterState(testPairing(CapFull), nil, filepath.Join(dir, ".pairing.journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Stop(); ss.journal.Close() })
	ss.SetOps(ops)
	args := map[string]any{"name": "t1", "set": map[string]any{"ping-every": "1"}}
	req := ScepterRequest{ID: "prune-1", V: scepterV, Cmd: "tunnel.edit", Args: args, TS: time.Now().Unix()}
	if r := ss.Handle(req, testPairing(CapFull).Caps); r.Code != CodeOK {
		t.Fatalf("first run: %d", r.Code)
	}
	for i := 0; i < scepterJournalKeep+10; i++ { // flood the journal past the bound: prune-1 ages out
		ss.journal.Record("tunnel.edit", "flood-"+itoa(i), time.Now().Unix(), ScepterResponse{ID: "flood", Code: CodeOK})
	}
	restarts := 0
	for _, a := range ops.actions {
		if a == "t1:restart" {
			restarts++
		}
	}
	if r := ss.Handle(req, testPairing(CapFull).Caps); r.Code != CodeOK {
		t.Fatalf("re-executed run: %d", r.Code)
	}
	n := 0
	for _, a := range ops.actions {
		if a == "t1:restart" {
			n++
		}
	}
	if n != restarts+1 {
		t.Fatalf("the pruned id replayed (op ran %d -> %d)", restarts, n)
	}
}

// A reused id with a DIFFERENT command is refused (F4/M2 + round-2 fix 1, 2026-11-22): answering it would
// re-record over the id and erase the FIRST command's outcome — its legit retry would then miss and
// re-execute a mutation (double-apply). The reuse answers bad_request without recording; the original
// command's retry still replays from the intact record.
func TestScepterJournalCmdMismatch(t *testing.T) {
	ops := newFakeOps(t)
	ops.writeDirect("t1", t)
	jp := filepath.Join(t.TempDir(), ".pairing.journal")
	c, _ := newScepterPair(t, CapManage, jp, dirSource{ops.dir}, ops)
	now := time.Now().Unix()
	editArgs := map[string]any{"name": "t1", "set": map[string]any{"ping-every": "3"}}
	p, code := c.call("tunnel.edit", editArgs, "dup-id", now, 10*time.Second)
	if code != CodeOK {
		t.Fatalf("edit: %d %v", code, p)
	}
	// the reuse: bad_request with the why, and the stop NEVER ran
	p2, code := c.call("tunnel.stop", map[string]any{"name": "t1"}, "dup-id", now, 10*time.Second)
	if code != CodeBadRequest || p2["why"] != "command id reused with a different command" {
		t.Fatalf("same id, different cmd: %v %v (want bad_request with the why)", code, p2)
	}
	for _, a := range ops.actions {
		if a == "t1:stop" {
			t.Fatal("the mismatched command executed instead of being refused")
		}
	}
	// the original command's retry with the same id still replays the recorded outcome (no re-run)
	restarts := 0
	for _, a := range ops.actions {
		if a == "t1:restart" {
			restarts++
		}
	}
	p3, code := c.call("tunnel.edit", editArgs, "dup-id", now, 10*time.Second)
	if code != CodeOK {
		t.Fatalf("the original command's retry: %d %v (want the recorded replay)", code, p3)
	}
	n := 0
	for _, a := range ops.actions {
		if a == "t1:restart" {
			n++
		}
	}
	if n != restarts {
		t.Fatalf("the retry re-ran the op (restarts %d -> %d) instead of replaying", restarts, n)
	}
}

// The intent TTL is the server's, not the client's (F6/L6): a huge ttl is clamped to the 3600 s ceiling (a
// 4000 s-old intent can NEVER be fresh), a tiny one to the 60 s floor, and a future-minted intent is judged
// from the moment the server saw it, so it expires normally instead of living forever.
func TestScepterTTLClampAndFutureTS(t *testing.T) {
	ss, err := NewScepterState(testPairing(CapFull), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Stop(); ss.journal.Close() })
	now := time.Now().Unix()
	pair := testPairing(CapFull).Caps
	// ceiling: 4000 s old + clamped 3600 + 60 skew is still expired
	if r := ss.Handle(ScepterRequest{ID: "huge", V: scepterV, Cmd: "scepter.ping", TS: now - 4000, TTL: 999999}, pair); r.Code != CodeStale {
		t.Fatalf("huge ttl code %d, want stale (clamped to the ceiling)", r.Code)
	}
	// floor: 100 s old + clamped 60 + skew is fresh (the request's ttl 10 would have expired it)
	if r := ss.Handle(ScepterRequest{ID: "tiny", V: scepterV, Cmd: "scepter.ping", TS: now - 100, TTL: 10}, pair); r.Code != CodeOK {
		t.Fatalf("tiny ttl code %d, want OK (clamped to the floor)", r.Code)
	}
	// future ts: expires normally — a finite horizon, never immortal. At arrival the clamp judges it from
	// NOW; once the server clock passes the claimed ts + clamped ttl + skew it is stale (a controllable
	// clock proves it; the horizon here is 1000 + 3600 + 60).
	var secs atomic.Int64
	base := time.Now()
	ss.nowf = func() time.Time { return base.Add(time.Duration(secs.Load()) * time.Second) }
	if r := ss.Handle(ScepterRequest{ID: "future", V: scepterV, Cmd: "scepter.ping", TS: base.Unix() + 1000, TTL: 3600}, pair); r.Code != CodeOK {
		t.Fatalf("future-minted intent code %d, want OK (ts judged from now)", r.Code)
	}
	secs.Store(1000 + int64(intentTTLMax) + int64(scepterSkew/time.Second) + 1)
	if r := ss.Handle(ScepterRequest{ID: "future2", V: scepterV, Cmd: "scepter.ping", TS: base.Unix() + 1000, TTL: 3600}, pair); r.Code != CodeStale {
		t.Fatalf("the future-minted intent outlived its horizon: code %d, want stale", r.Code)
	}
}

// A panicking handler (an ops bug — the ops run inside the recovered invocation) answers CodeInternal, is
// audited, and the engine keeps serving (L3, 2026-11-22). The panic rides the ops, not a registry override,
// so the shared command map is never mutated by a test.
func TestScepterPanicRecovered(t *testing.T) {
	dir := t.TempDir()
	ss, err := NewScepterState(testPairing(CapFull), nil, filepath.Join(dir, ".pairing.journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Stop(); ss.journal.Close() })
	ops := &panickyOps{fakeOps: newFakeOps(t)}
	ops.writeDirect("t1", t)
	ss.SetOps(ops)
	now := time.Now().Unix()
	r := ss.Handle(ScepterRequest{ID: "p-1", V: scepterV, Cmd: "tunnel.edit",
		Args: map[string]any{"name": "t1", "set": map[string]any{"ping-every": "1"}}, TS: now}, testPairing(CapFull).Caps)
	if r.Code != CodeInternal || r.Params["detail"] == nil {
		t.Fatalf("panic code %d params %v, want internal with a detail", r.Code, r.Params)
	}
	if r := ss.Handle(ScepterRequest{ID: "p-2", V: scepterV, Cmd: "scepter.ping", TS: now}, testPairing(CapFull).Caps); r.Code != CodeOK {
		t.Fatalf("the engine died with the panic: code %d", r.Code)
	}
	ab, err := os.ReadFile(filepath.Join(dir, ScepterAuditFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ab), "cmd=tunnel.edit code=7 id=p-1") {
		t.Fatalf("the panic left no audit row: %q", ab)
	}
	// the panic outcome is NOT journaled (round-2 fix 2, 2026-11-22): the panic unwound past the ops'
	// rollback, so a journaled failure would replay forever and pin the half-applied state — the fresh
	// attempt (even the same id) re-executes instead.
	if len(ss.journal.keep) != 0 {
		t.Fatalf("the panic outcome was journaled (%d records), want an empty journal", len(ss.journal.keep))
	}
	if r := ss.Handle(ScepterRequest{ID: "p-1", V: scepterV, Cmd: "tunnel.edit",
		Args: map[string]any{"name": "t1", "set": map[string]any{"ping-every": "1"}}, TS: now}, testPairing(CapFull).Caps); r.Code != CodeInternal {
		t.Fatalf("same-id retry code %d, want internal (re-executed, never a replayed failure)", r.Code)
	}
	if ops.edits != 2 {
		t.Fatalf("Edit ran %d times, want 2 (the retry replayed the failure instead of re-running)", ops.edits)
	}
	if len(ss.journal.keep) != 0 {
		t.Fatal("the retried panic was journaled")
	}
}

// panickyOps is a fakeOps whose Edit blows up mid-op: the L3 recovery must catch it like any op failure,
// and the round-2 pin counts invocations to prove a not-journaled failure re-executes.
type panickyOps struct {
	*fakeOps
	edits int // Handle holds the command queue, so a plain counter is race-free
}

func (p *panickyOps) Edit(string, ScepterPatch) (map[string]any, int) {
	p.edits++
	panic("boom")
}

// The tunnel liveness watcher (F8-state): a tunnel dying OUTSIDE scepter (systemd stop, a crash) still
// reaches seq-diffing clients — the watcher fires tunnel_down (and up again) with via:"watch" and the
// state_seq advances. First sightings record their baseline silently (the create path owns that event).
func TestScepterTunnelWatcher(t *testing.T) {
	old := scepterWatchPoll
	scepterWatchPoll = 100 * time.Millisecond
	t.Cleanup(func() { scepterWatchPoll = old }) // runs LAST: the watcher is stopped before the var is restored
	ws := &watchSrc{up: true}
	ss, err := NewScepterState(testPairing(CapManage), ws, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Stop) // runs FIRST
	// the baseline: the watcher's first poll records the tunnel silently (a first sighting is not news —
	// the create path owns that event). Wait for it before flipping, or the flip lands on the baseline.
	deadline := time.Now().Add(5 * time.Second)
	for {
		ss.mu.Lock()
		n := len(ss.watchSnap)
		ss.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the watcher never took its baseline snapshot")
		}
		time.Sleep(10 * time.Millisecond)
	}
	seq := ss.StateSeq()
	ws.mu.Lock()
	ws.up = false
	ws.mu.Unlock()
	waitScepterEvent(t, ss, EvTunnelDown, "")
	if ss.StateSeq() == seq {
		t.Fatal("tunnel_down did not advance state_seq")
	}
	var down map[string]any
	ss.mu.Lock()
	for _, ev := range ss.events {
		if ev.Type == EvTunnelDown {
			down = ev.Detail
		}
	}
	ss.mu.Unlock()
	if down["via"] != "watch" || down["name"] != "w1" {
		t.Fatalf("tunnel_down detail: %v (want via watch, name w1)", down)
	}
	seq = ss.StateSeq()
	ws.mu.Lock()
	ws.up = true
	ws.mu.Unlock()
	waitScepterEvent(t, ss, EvTunnelUp, "")
	if ss.StateSeq() == seq {
		t.Fatal("tunnel_up did not advance state_seq")
	}
}

// watchSrc is a one-tunnel ScepterSource the watcher test can flip between active/ok and inactive/down.
type watchSrc struct {
	mu sync.Mutex
	up bool
}

func (w *watchSrc) Tunnels() []ScepterTunnelInfo {
	w.mu.Lock()
	defer w.mu.Unlock()
	st, h := "inactive", "down"
	if w.up {
		st, h = "active", "ok"
	}
	return []ScepterTunnelInfo{{Name: "w1", Carrier: "udp", State: st, Health: h}}
}

func (w *watchSrc) TunnelStats(string) (map[string]any, bool) { return nil, false }
func (w *watchSrc) TunnelLogs(string, int) ([]string, bool)   { return nil, false }
func (w *watchSrc) History(string) ([]map[string]any, bool)   { return nil, false }

// The hello gate is the SCEPTER FLOOR, not the client's own version (M3): a server reporting exactly
// scepterMinScepterVer pairs with a newer client — a 3.5.1 cockpit must not kill a 3.5.0 server's channel.
// The gate function is pinned below; the canned-server drill runs the real helloExchange against both sides
// of the floor (in-process both ends report Version, so only a canned answer exercises the skew).
func TestScepterHelloFloor(t *testing.T) {
	if !scepterPeerVerOK(scepterMinScepterVer) || !scepterPeerVerOK("3.6.0") {
		t.Fatal("the floor and anything above it must pair")
	}
	if scepterPeerVerOK("3.4.9") || scepterPeerVerOK("") {
		t.Fatal("below the floor (or unparseable) must fail closed")
	}
	for _, srvVer := range []string{scepterMinScepterVer, "3.4.9"} {
		pair := testPairing(CapFull)
		cfg := Config{Pairing: pair}
		cli, srv, _, _ := newPair(t, 0, time.Millisecond, 20e6, cfg)
		go func() { // a canned sid-0 server: answers the hello itself with srvVer, never a real command
			st, err := srv.Accept()
			if err != nil {
				return
			}
			if st.ID() != 0 {
				st.Reset()
				return
			}
			b, _ := json.Marshal(ScepterResponse{ID: "hello", Code: CodeOK, Params: map[string]any{
				"ver": srvVer, "v": scepterV, "caps": "full", "uuid": pair.UUIDString(), "state_seq": 0}})
			st.Write(append(b, '\n'))
			st.CloseWrite()
		}()
		wantErr := srvVer != scepterMinScepterVer
		c, err := DialScepter(cli)
		if (err != nil) != wantErr {
			t.Fatalf("server %s: dial err %v, wantErr %v", srvVer, err, wantErr)
		}
		if err == nil {
			if c.Hello["ver"] != srvVer {
				t.Fatalf("hello ver = %v, want %s", c.Hello["ver"], srvVer)
			}
			c.Close()
		}
	}
}

// The name rule (F12-name): the manager's own shape, plus the ban on the auto reverse companion shape —
// "x-r" is hidden by the manager's listings whenever x is an auto Kharej tunnel (companion_of), so the
// cockpit never mints one. Ordinary dashes stay legal (v_name allows them).
func TestScepterNameRule(t *testing.T) {
	for _, ok := range []string{"t1", "a-b_c9", "R", "myr", "r-x", "x-rr", strings.Repeat("n", 32)} {
		if !ValidScepterName(ok) {
			t.Fatalf("%q must be valid (dashes are ordinary)", ok)
		}
	}
	for _, bad := range []string{"", "x-r", "a-r", "1-2-3-r", "-r", strings.Repeat("n", 33), "sp ace", "dot.dot"} {
		if ValidScepterName(bad) {
			t.Fatalf("%q must be invalid (companion shape, size, or charset)", bad)
		}
	}
}

// ReloadPairing with a new credential: the NEXT command's capability check uses the NEW caps, over the wire,
// on the SAME live stream (rotation overlaps; only revocation kills the channel).
func TestScepterReloadPairingRotate(t *testing.T) {
	pair := testPairing(CapFull)
	cfg := Config{Pairing: pair}
	cli, srv, _, _ := newPair(t, 0, time.Millisecond, 20e6, cfg)
	state, err := NewScepterState(pair, &fakeSource{}, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Stop(); state.journal.Close(); cli.Close(); srv.Close() })
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			if st.ID() != 0 {
				st.Reset()
				continue
			}
			go ServeScepter(st, state)
		}
	}()
	c, err := DialScepter(cli)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, code := c.Call("tunnel.stats", map[string]any{"name": "t1"}); code != CodeOK {
		t.Fatalf("pre-rotation stats code %d", code)
	}
	tunnelOnly := testPairing(CapTunnel)
	state.ReloadPairing(tunnelOnly)
	if _, code := c.Call("tunnel.stats", map[string]any{"name": "t1"}); code != CodeDenied {
		t.Fatalf("post-rotation stats code %d, want denied (new caps, same stream)", code)
	}
	if _, code := c.Call("state.get", nil); code != CodeOK {
		t.Fatalf("post-rotation state.get code %d (still a tunnel-capability command)", code)
	}
	u, caps := state.PairingInfo()
	if u != tunnelOnly.UUIDString() || caps != tunnelOnly.Caps {
		t.Fatalf("pairing info after rotate: %s %d", u, caps)
	}
	waitScepterEvent(t, state, EvPairRotated, "")
}

// ReloadPairing(nil) disarms: the live scepter stream dies mid-call (the in-flight call errors), and new
// sid-0 service is refused — while the tunnel itself (user streams on the same session) keeps working.
func TestScepterReloadPairingDisarm(t *testing.T) {
	pair := testPairing(CapFull)
	cfg := Config{Pairing: pair}
	cli, srv, _, _ := newPair(t, 0, time.Millisecond, 20e6, cfg)
	blk := &blockStatsSource{gate: make(chan struct{})}
	state, err := NewScepterState(pair, blk, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Stop(); state.journal.Close(); cli.Close(); srv.Close() })
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			if st.ID() != 0 {
				// the tunnel lives on: user streams echo (revocation must kill only the management plane)
				go func(s *Stream) { io.Copy(s, s); s.CloseWrite() }(st)
				continue
			}
			go ServeScepter(st, state)
		}
	}()
	c, err := DialScepter(cli)
	if err != nil {
		t.Fatal(err)
	}
	// the in-flight call: the server is parked inside the source until we open the gate
	callDone := make(chan int, 1)
	go func() { _, code := c.Call("tunnel.stats", map[string]any{"name": "t1"}); callDone <- code }()
	deadline := time.Now().Add(2 * time.Second)
	for blk.entered.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	state.ReloadPairing(nil) // instant revocation: the stream dies under the parked call
	close(blk.gate)          // let the (already doomed) handler finish
	select {
	case code := <-callDone:
		if code != CodeInternal {
			t.Fatalf("in-flight call during disarm: code %d, want internal (stream error)", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the in-flight call never noticed the disarm")
	}
	// new sid-0 service is refused: NO command answer ever comes back on a fresh scepter stream. The disarm
	// reset tombstoned sid 0 on the server (the stream-id reuse discipline, ~2 min), so within the tomb
	// window the attempt is simply never answered (onStream drops it), and after it the serve-loop guard
	// resets; either way nothing is served — that is the property pinned here.
	st, err := cli.OpenScepter()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ScepterRequest{ID: "after", V: scepterV, Cmd: "scepter.ping", TS: time.Now().Unix()})
	if _, werr := st.Write(append(b, '\n')); werr != nil {
		t.Fatal(werr)
	}
	got := make(chan []byte, 1)
	go func() {
		line, _ := bufio.NewReader(st).ReadBytes('\n') // a reset also lands here, as an empty (errored) read
		got <- line
	}()
	select {
	case line := <-got:
		if len(line) > 0 {
			t.Fatalf("a disarmed state served an answer: %q", line)
		}
	case <-time.After(1500 * time.Millisecond):
		// the wanted outcome: silence
	}
	// the tunnel lives on: a user stream round-trips on the same session after the revocation
	us, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	us.Write([]byte("alive"))
	us.CloseWrite()
	got2 := make(chan []byte, 1)
	go func() { b2, _ := io.ReadAll(us); got2 <- b2 }()
	select {
	case b2 := <-got2:
		if string(b2) != "alive" {
			t.Fatalf("user stream data: %q", b2)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("user stream dead after disarm (revocation must kill only the management plane)")
	}
	waitScepterEvent(t, state, EvPairRevoked, "")
	if u, caps := state.PairingInfo(); u != "" || caps != 0 {
		t.Fatalf("disarmed pairing info: %s %d", u, caps)
	}
}

// blockStatsSource parks every TunnelStats caller on a channel: the disarm drill needs the server parked
// mid-command so the stream reset lands under a genuinely in-flight call.
type blockStatsSource struct {
	gate    chan struct{}
	entered atomic.Int64
}

func (b *blockStatsSource) Tunnels() []ScepterTunnelInfo {
	return []ScepterTunnelInfo{{Name: "t1", Carrier: "udp", State: "active", Health: "ok"}}
}

func (b *blockStatsSource) TunnelStats(string) (map[string]any, bool) {
	b.entered.Store(1)
	<-b.gate
	return map[string]any{"name": "t1"}, true
}

func (b *blockStatsSource) TunnelLogs(string, int) ([]string, bool) { return nil, false }
func (b *blockStatsSource) History(string) ([]map[string]any, bool) { return nil, false }

// Session.CloseScepter kills the sid-0 stream and nothing else (F8-revoke): the peer's scepter stream dies
// with the frRst, user streams on the same session keep working, and a session without an open sid-0
// stream is a no-op.
func TestSessionCloseScepter(t *testing.T) {
	pcfg := Config{Pairing: testPairing(CapTunnel)}
	cli, srv, _, _ := newPair(t, 0, time.Millisecond, 10e6, pcfg)
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() { // the server echoes user streams; the scepter stream is popped untouched (CloseScepter's subject)
		for {
			s, err := srv.Accept()
			if err != nil {
				return
			}
			if s.ID() == 0 {
				continue
			}
			go func(s *Stream) { io.Copy(s, s); s.CloseWrite() }(s)
		}
	}()
	srv.CloseScepter() // no sid-0 open: must be a no-op, not a crash
	st, err := cli.OpenScepter()
	if err != nil {
		t.Fatal(err)
	}
	// materialize sid 0 on the server: a stream comes into being THERE only with its first data frame
	if _, werr := st.Write([]byte(`{"id":"x"`)); werr != nil {
		t.Fatal(werr)
	}
	// the kill must reach the client's read as a reset
	errc := make(chan error, 1)
	go func() { _, rerr := st.Read(make([]byte, 16)); errc <- rerr }()
	time.Sleep(50 * time.Millisecond) // let the data frame cross and the server create the stream
	srv.CloseScepter()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("the client's scepter stream survived CloseScepter")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the frRst never reached the client")
	}
	// a user stream round-trips on the same session: only the management plane died
	us, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	us.Write([]byte("fine"))
	us.CloseWrite()
	got := make(chan string, 1)
	go func() { b, _ := io.ReadAll(us); got <- string(b) }()
	select {
	case s := <-got:
		if s != "fine" {
			t.Fatalf("user stream data: %q", s)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("user stream dead after CloseScepter")
	}
}

// ---- round-2 debug pins (2026-11-22): capability before replay, id/cmd conflict, ttl_s typing, line-cap
// content bytes, decode-reject audit, audit rotation, watcher double-fire, two-miss rule ----

// The capability check precedes the journal replay (round-2 fix 3): a rotated lower-cap credential must not
// replay an outcome recorded under higher caps — every command's capability is judged fresh, retries
// included. A capable retry still replays the recorded outcome.
func TestScepterCapCheckBeforeReplay(t *testing.T) {
	dir := t.TempDir()
	ss, err := NewScepterState(testPairing(CapFull), nil, filepath.Join(dir, ".pairing.journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Stop(); ss.journal.Close() })
	ops := newFakeOps(t)
	ops.writeDirect("t1", t)
	ss.SetOps(ops)
	now := time.Now().Unix()
	req := ScepterRequest{ID: "cap-1", V: scepterV, Cmd: "tunnel.edit",
		Args: map[string]any{"name": "t1", "set": map[string]any{"ping-every": "1"}}, TS: now}
	if r := ss.Handle(req, testPairing(CapFull).Caps); r.Code != CodeOK {
		t.Fatalf("record under full caps: %d", r.Code)
	}
	tunnelOnly := testPairing(CapTunnel)
	ss.ReloadPairing(tunnelOnly)
	_, caps := ss.PairingInfo()
	if caps != tunnelOnly.Caps {
		t.Fatalf("reload caps %d, want %d", caps, tunnelOnly.Caps)
	}
	if r := ss.Handle(req, caps); r.Code != CodeDenied {
		t.Fatalf("replay under lower caps: code %d, want denied (never the recorded OK)", r.Code)
	}
	ss.ReloadPairing(testPairing(CapFull))
	_, caps = ss.PairingInfo()
	if r := ss.Handle(req, caps); r.Code != CodeOK {
		t.Fatalf("capable retry: code %d, want the recorded OK replay", r.Code)
	}
}

// The ttl_s args alias is strictly typed on EVERY command carrying it, wire ttl set or not (round-2 fix 4):
// {"ttl":600,"ttl_s":"x"} used to slip through because the type check only ran when the wire ttl was unset.
func TestScepterTTLSAlwaysTypeChecked(t *testing.T) {
	ss, err := NewScepterState(testPairing(CapFull), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Stop(); ss.journal.Close() })
	now := time.Now().Unix()
	caps := testPairing(CapFull).Caps
	if r := ss.Handle(ScepterRequest{ID: "tts-bad", V: scepterV, Cmd: "scepter.ping", TS: now, TTL: 600,
		Args: map[string]any{"ttl_s": "x"}}, caps); r.Code != CodeBadRequest {
		t.Fatalf("wrong-typed ttl_s with the wire ttl set: code %d, want bad_request", r.Code)
	}
	if r := ss.Handle(ScepterRequest{ID: "tts-ok", V: scepterV, Cmd: "scepter.ping", TS: now,
		Args: map[string]any{"ttl_s": float64(300)}}, caps); r.Code != CodeOK {
		t.Fatalf("numeric ttl_s alias: code %d, want OK", r.Code)
	}
}

// The 64 KiB command cap counts CONTENT bytes, the line terminator excluded (round-2 fix 5): exactly
// scepterMaxLine content bytes + \n is a legal command (it used to be rejected, an off-by-one); one byte
// more is too_large. Writes go out through a bufio.Writer in stream-sized pieces — the suite's proven
// large-write path (a single 64 KiB Stream.Write stalls the sim link) — and the answers are read raw with a
// select timeout: waitResp would block in Stream.Read past its own deadline on any transport stall.
func TestScepterLineCapContentBytes(t *testing.T) {
	c, _ := newScepterPair(t, CapFull, "", &fakeSource{})
	build := func(id string, content int) []byte {
		head := fmt.Sprintf(`{"id":%q,"v":1,"cmd":"scepter.ping","args":{"pad":"`, id)
		tail := `"}}`
		pad := content - len(head) - len(tail)
		if pad < 0 {
			t.Fatalf("content %d below the envelope size", content)
		}
		return []byte(head + strings.Repeat("p", pad) + tail)
	}
	type res struct {
		resp ScepterResponse
		err  error
	}
	out := make(chan res, 2)
	go func() { // raw responses via the client's own decoder buffer, in order
		for i := 0; i < 2; i++ {
			var r res
			line, err := c.d.br.ReadSlice('\n')
			if err == bufio.ErrBufferFull {
				for {
					if _, e := c.d.br.ReadSlice('\n'); e != bufio.ErrBufferFull {
						break
					}
				}
				err = errors.New("oversized response line")
			} else if err == nil {
				err = json.Unmarshal(trimEOL(line), &r.resp)
			}
			out <- r
		}
	}()
	send := func(line []byte) {
		w := bufio.NewWriter(c.st)
		w.Write(line)
		w.WriteByte('\n')
		w.Flush()
	}
	line := build("cap-ok", scepterMaxLine)
	if len(line) != scepterMaxLine {
		t.Fatalf("built line = %d bytes, want exactly %d content bytes", len(line), scepterMaxLine)
	}
	send(line)
	select {
	case r := <-out:
		if r.err != nil {
			t.Fatalf("cap-ok: %v", r.err)
		}
		if r.resp.Code != CodeOK {
			t.Fatalf("exactly %d content bytes: code %d, want OK", scepterMaxLine, r.resp.Code)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for the max-content answer")
	}
	send(build("cap-big", scepterMaxLine+1))
	select {
	case r := <-out:
		if r.err != nil {
			t.Fatalf("cap-big: %v", r.err)
		}
		if r.resp.Code != CodeTooLarge {
			t.Fatalf("%d content bytes: code %d, want too_large", scepterMaxLine+1, r.resp.Code)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for the over-cap answer")
	}
}

// A decode-level rejection audits the PARTIAL request's cmd when the line parsed that far (round-2 fix 6):
// a wrong-v line with a valid cmd used to audit cmd "?", blinding the trail to what was attempted. Wholly
// unparseable lines still audit "?".
func TestScepterDecodeRejectAuditCmd(t *testing.T) {
	dir := t.TempDir()
	c, _ := newScepterPair(t, CapManage, filepath.Join(dir, ".pairing.journal"), &fakeSource{})
	if _, err := c.st.Write([]byte(`{"id":"wv-9","v":99,"cmd":"tunnel.stats","args":{"name":"t1"}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if _, code := c.waitResp("wv-9", 10*time.Second); code != CodeBadRequest {
		t.Fatalf("wrong-v line: code %d, want bad_request", code)
	}
	ab, err := os.ReadFile(filepath.Join(dir, ScepterAuditFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ab), "cmd=tunnel.stats code=1 id=wv-9") {
		t.Fatalf("the wrong-v attempt lost its parsed cmd in the audit: %q", ab)
	}
	if _, err := c.st.Write([]byte("not json\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		ab, err := os.ReadFile(filepath.Join(dir, ScepterAuditFile))
		if err == nil && strings.Contains(string(ab), "cmd=? code=1") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the unparseable line left no cmd=? audit row: %q", ab)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Audit rotation renames the full live file to ".1"; the SECOND rotation must REPLACE that generation — a
// plain rename onto an existing file fails on Windows and the error was once ignored, so a dev checkout's
// audit grew without bound (round-2 fix 7): on failure the stale generation is removed and the rename
// retried once.
func TestScepterAuditRotationReplacesGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ScepterAuditFile)
	if err := os.WriteFile(path, []byte(strings.Repeat("x", scepterJournalRotate)), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := OpenScepterAudit(path) // a.size = the filler: the next record crosses the threshold
	if err != nil {
		t.Fatal(err)
	}
	a.record(time.Now(), "u", "scepter.ping", "r1", CodeOK)
	if st, err := os.Stat(path + ".1"); err != nil || st.Size() < int64(scepterJournalRotate) {
		t.Fatalf("first rotation: .1 = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the rotated live file is still there: %v", err)
	}
	// the second rotation must replace the .1 generation (the Windows rename-over case)
	if err := os.WriteFile(path, []byte(strings.Repeat("y", scepterJournalRotate)), 0o600); err != nil {
		t.Fatal(err)
	}
	a.record(time.Now(), "u", "scepter.ping", "r2", CodeOK)
	st, err := os.Stat(path + ".1")
	if err != nil || st.Size() < int64(scepterJournalRotate) {
		t.Fatalf("second rotation did not replace .1: %v", err)
	}
	b, _ := os.ReadFile(path + ".1")
	if !strings.Contains(string(b), "id=r2") {
		t.Fatalf("the second generation kept the OLD audit (rename-over failed): tail %q", b[len(b)-100:])
	}
}

// liveSrc is a one-tunnel ScepterSource driven by test callbacks: presence and liveness exactly as a listing
// would report them (the watcher pins flip them mid-test).
type liveSrc struct {
	present func() bool
	up      func() bool
}

func (l liveSrc) Tunnels() []ScepterTunnelInfo {
	if l.present != nil && !l.present() {
		return []ScepterTunnelInfo{}
	}
	st, h := "inactive", "down"
	if l.up() {
		st, h = "active", "ok"
	}
	return []ScepterTunnelInfo{{Name: "w1", Carrier: "udp", State: st, Health: h}}
}

func (liveSrc) TunnelStats(string) (map[string]any, bool) { return nil, false }
func (liveSrc) TunnelLogs(string, int) ([]string, bool)   { return nil, false }
func (liveSrc) History(string) ([]map[string]any, bool)   { return nil, false }

// The scepter path's own start/stop fires tunnel_up/tunnel_down (via:"scepter"); the liveness watcher's next
// poll used to fire the same flip again via:"watch" — one state change, two events (round-2 fix 8). The
// watcher skips a flip the scepter path announced within the window; real flips still fire.
func TestScepterWatcherNoDoubleFire(t *testing.T) {
	old := scepterWatchPoll
	scepterWatchPoll = 100 * time.Millisecond
	t.Cleanup(func() { scepterWatchPoll = old }) // runs LAST: the watcher is stopped before the var is restored
	ops := newFakeOps(t)
	ops.writeDirect("w1", t)
	ops.runUnit("w1", "start") // the tunnel is up before the watcher baselines
	ws := liveSrc{present: func() bool { return true }, up: func() bool { return ops.active["w1"] }}
	ss, err := NewScepterState(testPairing(CapManage), ws, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Stop) // runs FIRST
	ss.SetOps(ops)
	ss.evWindow = 0 // coalescing must not mask a double fire
	// the baseline: the first poll records the tunnel silently
	deadline := time.Now().Add(5 * time.Second)
	for {
		ss.mu.Lock()
		e, ok := ss.watchSnap["w1"]
		ss.mu.Unlock()
		if ok && e.up {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the watcher never baselined the up tunnel")
		}
		time.Sleep(10 * time.Millisecond)
	}
	seq := ss.StateSeq()
	if r := ss.Handle(ScepterRequest{ID: "df-1", V: scepterV, Cmd: "tunnel.stop",
		Args: map[string]any{"name": "w1"}, TS: time.Now().Unix()}, testPairing(CapManage).Caps); r.Code != CodeOK {
		t.Fatalf("tunnel.stop: %d", r.Code)
	}
	time.Sleep(4 * scepterWatchPoll) // several polls over the flip: no via:watch repeat may appear
	ss.mu.Lock()
	downs, viaScepter := 0, false
	for _, ev := range ss.events {
		if ev.Type != EvTunnelDown || ev.Detail["name"] != "w1" {
			continue
		}
		downs++
		if ev.Detail["via"] == "scepter" {
			viaScepter = true
		}
	}
	endSeq := ss.seq
	ss.mu.Unlock()
	if downs != 1 || !viaScepter {
		t.Fatalf("tunnel_down fired %d times (want exactly 1, via scepter)", downs)
	}
	if endSeq != seq+1 {
		t.Fatalf("state_seq moved %d -> %d: a via:watch event fired for the scepter flip", seq, endSeq)
	}
	// a real flip with no scepter involvement still fires
	ops.active["w1"] = true
	waitScepterEvent(t, ss, EvTunnelUp, "")
}

// A one-poll listing omission must not re-baseline a tunnel (round-2 fix 9): it is treated as gone only on
// the SECOND consecutive miss — a reappearance after one miss keeps its history (a later flip still fires),
// and two consecutive omissions of a last-known-up tunnel fire tunnel_down why:"gone" (a unit that vanished
// outside scepter is news).
func TestScepterWatcherTwoMissRule(t *testing.T) {
	old := scepterWatchPoll
	scepterWatchPoll = 100 * time.Millisecond
	t.Cleanup(func() { scepterWatchPoll = old })
	var present, up atomic.Bool
	present.Store(true)
	up.Store(true)
	ws := liveSrc{present: func() bool { return present.Load() }, up: func() bool { return up.Load() }}
	ss, err := NewScepterState(testPairing(CapManage), ws, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Stop)
	ss.evWindow = 0
	waitEntry := func(want func(scepterWatchEnt) bool, what string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			ss.mu.Lock()
			e, ok := ss.watchSnap["w1"]
			ss.mu.Unlock()
			if ok && want(e) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the watch entry never %s (last %+v)", what, e)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitEntry(func(e scepterWatchEnt) bool { return e.up && e.miss == 0 }, "baselined up")
	seq := ss.StateSeq()
	// one miss: the entry is kept, nothing fires
	present.Store(false)
	waitEntry(func(e scepterWatchEnt) bool { return e.miss == 1 }, "counted one miss")
	if ss.StateSeq() != seq {
		t.Fatal("a one-poll omission fired an event")
	}
	// reappearance: history kept — the miss resets and a later flip still fires
	present.Store(true)
	waitEntry(func(e scepterWatchEnt) bool { return e.up && e.miss == 0 }, "rebaselined after one miss")
	if ss.StateSeq() != seq {
		t.Fatal("a reappearance after one miss fired an event")
	}
	up.Store(false)
	waitScepterEvent(t, ss, EvTunnelDown, "") // the flip across the hiccup is not swallowed
	up.Store(true)
	waitEntry(func(e scepterWatchEnt) bool { return e.up && e.miss == 0 }, "back up")
	// two consecutive omissions: gone
	present.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for {
		ss.mu.Lock()
		found := false
		for _, ev := range ss.events {
			if ev.Type == EvTunnelDown && ev.Detail["why"] == "gone" && ev.Detail["via"] == "watch" {
				found = true
			}
		}
		ss.mu.Unlock()
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no tunnel_down why:gone after two consecutive omissions")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
