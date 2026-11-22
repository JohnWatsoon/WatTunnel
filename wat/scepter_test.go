// Scepter phase A tests (3.5.0): the sim-pair RPC round-trip, the sid-0 reservation, event replay, journal
// idempotency, JSON parser robustness, capability denial, rate limiting, TTL expiry and mixed-version behavior.

package wat

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

	inN, maxIn atomic.Int64 // concurrency probe: the queue test pins max concurrent edits to 1
	delay      time.Duration
}

func newFakeOps(t *testing.T) *fakeOps {
	return &fakeOps{dir: t.TempDir(), failStart: map[string]bool{}, binds: map[int]string{}, active: map[string]bool{}}
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
	// ttl_s in args raises the window: the same intent age now proceeds (and a wrong type is bad_request).
	// The free listen keeps the create away from the canned 4443 collision this test plants.
	if _, code = c.call("tunnel.create", testWriteArgs(map[string]any{"name": "ttls", "carrier": "nope-carrier",
		"ttl_s": 90000, "params": map[string]any{"listen": ":20041"}}), "ttls-id", old, 30*time.Second); code != CodeOK {
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
	// the failure is journaled: the same id replays the recorded outcome without re-running the op
	before := ops.creates
	p2, code2 := c.call("tunnel.create", args, "rb-retry", time.Now().Unix(), 30*time.Second)
	if code2 != CodeInternal || p2["rolled_back"] != true {
		t.Fatalf("replayed failure: %v %v", code2, p2)
	}
	if ops.creates != before {
		t.Fatal("a journaled failure re-ran the op")
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
	defer state2.journal.Close()
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
	t.Cleanup(func() { state.journal.Close() })
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
