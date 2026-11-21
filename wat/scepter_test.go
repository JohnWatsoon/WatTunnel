// Scepter phase A tests (3.5.0): the sim-pair RPC round-trip, the sid-0 reservation, event replay, journal
// idempotency, JSON parser robustness, capability denial, rate limiting, TTL expiry and mixed-version behavior.

package wat

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"sync"
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
// mirroring what cmd/wattun's serve() does. journalPath may be empty (no journal).
func newScepterPair(t *testing.T, caps uint32, journalPath string, src ScepterSource) (*ScepterClient, *ScepterState) {
	t.Helper()
	pair := testPairing(caps)
	cfg := Config{Pairing: pair}
	cli, srv, _, _ := newPair(t, 0, 2*time.Millisecond, 20e6, cfg)
	state, err := NewScepterState(pair, src, journalPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.journal.Close() }) // Windows: an open journal keeps TempDir from cleaning up
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

// events.since replays the ring; the ring keeps the last 512.
func TestScepterEventReplay(t *testing.T) {
	c, state := newScepterPair(t, CapManage, "", &fakeSource{})
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

// Retries of the same command id return the recorded outcome and run the handler once (at-most-once).
func TestScepterJournalIdempotency(t *testing.T) {
	src := &fakeSource{}
	c, _ := newScepterPair(t, CapManage, t.TempDir()+"/.journal", src)
	args := map[string]any{"name": "t1"}
	p1, code1 := c.call("tunnel.stats", args, "fixed-id-1", time.Now().Unix(), 10*time.Second)
	p2, code2 := c.call("tunnel.stats", args, "fixed-id-1", time.Now().Unix(), 10*time.Second)
	if code1 != CodeOK || code2 != CodeOK {
		t.Fatalf("codes %d/%d", code1, code2)
	}
	b1, _ := json.Marshal(p1)
	b2, _ := json.Marshal(p2)
	if string(b1) != string(b2) {
		t.Fatalf("retry outcome differs: %s vs %s", b1, b2)
	}
	src.mu.Lock()
	calls := src.statsCalls
	src.mu.Unlock()
	if calls != 1 {
		t.Fatalf("handler ran %d times, want 1", calls)
	}
}

// The authenticated peer may still send garbage: every malformed line answers with a machine code, nothing
// crashes, and a valid command right after still works.
func TestScepterJSONRobustness(t *testing.T) {
	pair := testPairing(CapFull)
	cfg := Config{Pairing: pair}
	cli, srv, _, _ := newPair(t, 0, time.Millisecond, 20e6, cfg)
	state, err := NewScepterState(pair, &fakeSource{}, "")
	if err != nil {
		t.Fatal(err)
	}
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
