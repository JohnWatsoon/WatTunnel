package mgr

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// TestMain doubles as the fake engine of the -pair-to contract tests (the
// exec-helper pattern): with WAT_MGR_FAKE_ENGINE set, this binary IS the child
// `wattun` and behaves like the engine's standalone -pair-to action (b24af32,
// 2026-11-22) — validate the watp1: line, write `pairing: true` into the tunnel
// yml, exit 0; a refused attach exits 1 with its reason on stderr. No hang: the
// parent's shell-out always gets an exit code. WAT_MGR_FAKE_ENGINE=hang is the
// wedged pre-b24af32 child for the deadline test: it sleeps past any sane
// deadline, and the parent's exec context must kill it first.
func TestMain(m *testing.M) {
	switch os.Getenv("WAT_MGR_FAKE_ENGINE") {
	case "hang":
		time.Sleep(30 * time.Second) // the wedged child; the parent's deadline must kill it first
		os.Exit(0)
	case "":
		// the test binary proper
	default:
		os.Exit(fakePairToEngine())
	}
	os.Exit(m.Run())
}

// fakePairToEngine validates with the ENGINE's own parser (wat.ParsePairingLine
// — test-only import; production mgr does not import wat), so a line the mgr
// accepts and the engine would reject fails here instead of shipping: exactly
// the drift class the F10-parser bug was. The re-attach rule mirrors the
// engine's attachPairing (round-2 finding, 2026-11-22): a re-attach overwrites
// the credential and is NOT a refusal; the yml's pairing key, already present,
// is left alone (setPairingKey's rule).
func fakePairToEngine() int {
	fail := func(msg string) int {
		fmt.Fprintln(os.Stderr, msg)
		return 1
	}
	fs := flag.NewFlagSet("fake-wattun", flag.ContinueOnError)
	cfg := fs.String("config", "", "")
	line := fs.String("pair-to", "", "")
	if fs.Parse(os.Args[1:]) != nil {
		return fail("fake wattun: bad flags")
	}
	if _, err := wat.ParsePairingLine(*line); err != nil {
		return fail(err.Error())
	}
	body, err := os.ReadFile(*cfg)
	if err != nil {
		return fail(err.Error())
	}
	if strings.Contains(string(body), "pairing:") {
		return 0 // already marked: setPairingKey leaves the owner's key alone
	}
	f, err := os.OpenFile(*cfg, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fail(err.Error())
	}
	defer f.Close()
	if _, err := f.WriteString("pairing: true\n"); err != nil {
		return fail(err.Error())
	}
	return 0
}

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestPairingLineRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		uuid string
		caps ScepterCaps
		toks string
	}{
		{"tunnel tier", "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", CapTunnel, "tunnel"},
		{"create tier", "1B0E6A52-9F3D-4C2A-8E77-2F0A51D3C9E4", CapTunnel | CapCreate, "create"},
		{"manage tier", "00000000-0000-0000-0000-000000000001", CapTunnel | CapCreate | CapManage, "manage"},
		{"full tier", "ffffffff-ffff-ffff-ffff-ffffffffffff", CapTunnel | CapCreate | CapManage | CapFull, "full"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := MakePairingLine(ScepterVersion, c.uuid, testKey(), c.caps)
			if !strings.HasPrefix(line, "watp1:") {
				t.Fatalf("line %q lacks the watp1: prefix", line)
			}
			// the render is ONE tier word (what the engine's CapName writes and
			// ParsePairingLine accepts), never a comma list
			if !strings.HasSuffix(line, "|"+c.toks) {
				t.Errorf("MakePairingLine rendered %q, want the single %q tier word", line, c.toks)
			}
			p, err := ReadPairingLine(line)
			if err != nil {
				t.Fatalf("ReadPairingLine: %v", err)
			}
			if p.UUID != strings.ToLower(c.uuid) {
				t.Errorf("UUID = %q, want lowercased %q", p.UUID, c.uuid)
			}
			if len(p.Key) != 32 || p.Key[0] != 1 || p.Key[31] != 32 {
				t.Errorf("key damaged: %d bytes", len(p.Key))
			}
			if p.Caps != c.caps {
				t.Errorf("caps = %d, want %d", p.Caps, c.caps)
			}
			// an unpadded key field (hand-trimmed '=' like an unpadded wat1:) is
			// refused: the engine's ParsePairingLine (StdEncoding only) refuses
			// it too, and the pasted line travels to -pair-to verbatim — the
			// manager must never accept more than the engine (round-2 finding)
			fs := strings.Split(strings.TrimPrefix(line, "watp1:"), "|")
			unpadded := strings.TrimSuffix(fs[2], "=")
			if _, err := ReadPairingLine("watp1:" + strings.Join([]string{fs[0], fs[1], unpadded, fs[3]}, "|")); err == nil {
				t.Error("an unpadded key must be refused (the engine refuses it)")
			}
		})
	}
}

func TestReadPairingLineRejects(t *testing.T) {
	good := MakePairingLine(ScepterVersion, "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", testKey(), CapCreate)
	fields := func(repl ...string) string {
		fs := strings.Split(strings.TrimPrefix(good, "watp1:"), "|")
		for i, v := range repl {
			if v != "\x00" { // \x00 = leave the field as-is
				fs[i] = v
			}
		}
		return "watp1:" + strings.Join(fs, "|")
	}
	bad := []struct {
		name, line, wantErr string
	}{
		{"not a pairing line", "wat1:zzz", "not a watp1: pairing line"},
		{"three fields", "watp1:1|1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4|QUJD", "4 fields"},
		{"future version", fields("2", "\x00", "\x00"), "newer than this manager"},
		{"nonnumeric version", fields("x", "\x00", "\x00"), "bad pairing line version"},
		{"uuid shape", fields("\x00", "not-a-uuid", "\x00"), "not a pairing UUID"},
		{"uuid hex", fields("\x00", "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9gg", "\x00"), "not a pairing UUID"},
		{"key base64", fields("\x00", "\x00", "!!!"), "not valid base64"},
		{"key short", fields("\x00", "\x00", "QUJD", "\x00"), "want exactly 32"},
		// round-2 finding: an unpadded key the engine refuses must be refused HERE
		// (the pasted line travels to -pair-to verbatim; the old RawStdEncoding
		// fallback accepted more than the engine)
		{"unpadded key", func() string {
			fs := strings.Split(strings.TrimPrefix(good, "watp1:"), "|")
			fs[2] = strings.TrimSuffix(fs[2], "=")
			return "watp1:" + strings.Join(fs, "|")
		}(), "not valid base64"},
		// F10-parser: the engine takes exactly one tier word (CapFromName), so a
		// comma list must be refused HERE — the pasted line reaches -pair-to
		// verbatim and the engine would refuse it only at attach
		{"comma list", fields("\x00", "\x00", "\x00", "tunnel,create"), "one tier word"},
		{"dup cap", fields("\x00", "\x00", "\x00", "tunnel,tunnel"), "one tier word"},
		{"unknown cap", fields("\x00", "\x00", "\x00", "root"), "one tier word"},
		{"uppercase cap", fields("\x00", "\x00", "\x00", "FULL"), "one tier word"},
		{"empty caps", fields("\x00", "\x00", "\x00", ""), "one tier word"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := ReadPairingLine(c.line)
			if err == nil {
				t.Fatalf("no error for %q", c.line)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %q, want it to contain %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestCaps(t *testing.T) {
	// D4 tiers are cumulative: the line names ONE tier word (all the engine's
	// ParsePairingLine accepts), the mask carries the tower
	key := base64.StdEncoding.EncodeToString(testKey())
	for tok, want := range map[string]struct {
		caps   ScepterCaps
		labels string
	}{
		"tunnel": {CapTunnel, "tunnel"},
		"create": {CapTunnel | CapCreate, "tunnel,create"},
		"manage": {CapTunnel | CapCreate | CapManage, "tunnel,create,manage"},
		"full":   {CapTunnel | CapCreate | CapManage | CapFull, "tunnel,create,manage,full"},
	} {
		p, err := ReadPairingLine("watp1:1|1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4|" + key + "|" + tok)
		if err != nil {
			t.Fatalf("ReadPairingLine tier %q: %v", tok, err)
		}
		if p.Caps != want.caps {
			t.Errorf("tier %q -> mask %d, want %d", tok, p.Caps, want.caps)
		}
		if got := want.caps.Labels(); got != want.labels {
			t.Errorf("Labels(%q) = %q, want %q", tok, got, want.labels)
		}
	}
	if s := ScepterCaps(0).Labels(); s != "" {
		t.Errorf("empty mask labels = %q, want \"\"", s)
	}
	tower := CapTunnel | CapCreate | CapManage | CapFull
	if !(CapTunnel | CapCreate | CapManage).Has(CapManage) || !tower.Has(CapFull) {
		t.Error("Has is broken")
	}
	if !tower.Has(CapTunnel | CapCreate | CapManage | CapFull) {
		t.Error("full must have every bit")
	}
}

func TestVScepterPair(t *testing.T) {
	InitColor(false, 8)
	errN0 := ErrN()
	if !vScepterPair(MakePairingLine(ScepterVersion, "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", testKey(), CapManage)) {
		t.Error("valid line rejected")
	}
	if vScepterPair("watp1:1|x|y|z") {
		t.Error("garbage line accepted")
	}
	if ErrN() != errN0+1 {
		t.Errorf("validator must print exactly one error, got %d", ErrN()-errN0)
	}
}

func TestPairedBadge(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	ir := "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n"
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte(ir), 0o600)
	os.WriteFile(filepath.Join(dir, "irp.yml"), []byte(ir+"pairing: true\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "kh.yml"), []byte("mode: server\ncarrier: udp\npairing: true\n"), 0o600)
	if got := PairedBadge("ir"); got != "" {
		t.Errorf("unpaired Iran badge = %q, want empty", got)
	}
	if got := PairedBadge("irp"); got != " [paired]" {
		t.Errorf("paired Iran badge = %q, want \" [paired]\"", got)
	}
	// pairing on a Kharej config is not the Iran badge (the Kharej side stores
	// the credential in .pairing, not in a tunnel yml — Phase A.2)
	if got := PairedBadge("kh"); got != "" {
		t.Errorf("Kharej badge = %q, want empty", got)
	}
	if !IsPaired("irp") || IsPaired("ir") || IsPaired("kh") {
		t.Error("IsPaired disagrees with PairedBadge")
	}
}

func TestScepterScreenStubTransport(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	// an unpaired tunnel refuses at the dial — the honest answer, no rows
	out := capture(t, func() { scepterRead("ir", "state.get", "the state document") })
	if !strings.Contains(out, "state.get") || !strings.Contains(out, "not paired") {
		t.Errorf("dial refusal missing command/reason:\n%s", out)
	}
	// a fake client proves the success path prints params, code errors print codes
	oldDial := scepterDial
	scepterDial = func(string) (ScepterClient, error) {
		return stubClient{ScepterResult{Code: 0, Params: map[string]any{"state_seq": 7}}}, nil
	}
	defer func() { scepterDial = oldDial }()
	out = capture(t, func() { scepterRead("ir", "state.get", "the state document") })
	if !strings.Contains(out, "state_seq") || !strings.Contains(out, "7") {
		t.Errorf("params not printed:\n%s", out)
	}
}

type stubClient struct{ r ScepterResult }

func (s stubClient) Call(string, map[string]any) (ScepterResult, error) { return s.r, nil }

func TestScepterParseCall(t *testing.T) {
	// one plain answer line: code and params ride through
	res, err := scepterParseCall([]byte(`{"id":"x","code":0,"params":{"a":1},"seq":5}` + "\n"))
	if err != nil || res.Code != 0 || res.Params["a"] != float64(1) {
		t.Errorf("plain line: res=%+v err=%v", res, err)
	}
	// an answered rejection: exit 0, the code rides the JSON
	res, err = scepterParseCall([]byte(`{"id":"x","code":10,"params":{"name":"tunnel"}}` + "\n"))
	if err != nil || res.Code != 10 || res.Params["name"] != "tunnel" {
		t.Errorf("rejection line: res=%+v err=%v", res, err)
	}
	// chunked, arriving in order: pieces join and reassemble into logs
	chunked := `{"id":"x","code":0,"chunk":{"chunk":0,"of":2,"data":"line1\nli"}}` + "\n" +
		`{"id":"x","code":0,"chunk":{"chunk":1,"of":2,"data":"ne2\nline3"}}` + "\n"
	res, err = scepterParseCall([]byte(chunked))
	if err != nil || res.Code != 0 {
		t.Fatalf("chunked: res=%+v err=%v", res, err)
	}
	logs, _ := res.Params["logs"].([]string)
	if len(logs) != 3 || logs[0] != "line1" || logs[1] != "line2" || logs[2] != "line3" {
		t.Errorf("chunked logs = %v", logs)
	}
	// chunked, arriving out of order: the pieces still join by index
	swapped := `{"id":"x","code":0,"chunk":{"chunk":1,"of":2,"data":"ne2"}}` + "\n" +
		`{"id":"x","code":0,"chunk":{"chunk":0,"of":2,"data":"li"}}` + "\n"
	res, err = scepterParseCall([]byte(swapped))
	if err != nil {
		t.Fatalf("swapped chunks: %v", err)
	}
	if logs, _ := res.Params["logs"].([]string); len(logs) != 1 || logs[0] != "line2" {
		t.Errorf("swapped chunks joined = %v", logs)
	}
	// a chunk piece with data spanning a real line break survives the split
	empty := `{"id":"x","code":0,"chunk":{"chunk":0,"of":1,"data":""}}` + "\n"
	res, err = scepterParseCall([]byte(empty))
	if err != nil {
		t.Fatalf("single empty chunk: %v", err)
	}
	if logs, _ := res.Params["logs"].([]string); len(logs) != 1 || logs[0] != "" {
		t.Errorf("single empty chunk logs = %v", logs)
	}
	// transport-shaped failures: garbage, empty, incomplete chunking, duplicates
	for _, c := range []struct {
		name, out string
	}{
		{"garbage", "not json at all\n"},
		{"empty", ""},
		{"only whitespace", "  \n \n"},
		{"incomplete chunks", `{"id":"x","code":0,"chunk":{"chunk":0,"of":3,"data":"a"}}` + "\n"},
		{"count changed", `{"id":"x","code":0,"chunk":{"chunk":0,"of":2,"data":"a"}}` + "\n" +
			`{"id":"x","code":0,"chunk":{"chunk":1,"of":5,"data":"b"}}` + "\n"},
		{"duplicate piece", `{"id":"x","code":0,"chunk":{"chunk":0,"of":2,"data":"a"}}` + "\n" +
			`{"id":"x","code":0,"chunk":{"chunk":0,"of":2,"data":"a"}}` + "\n"},
		{"index out of range", `{"id":"x","code":0,"chunk":{"chunk":9,"of":2,"data":"a"}}` + "\n"},
		{"zero of", `{"id":"x","code":0,"chunk":{"chunk":0,"of":0,"data":""}}` + "\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := scepterParseCall([]byte(c.out)); err == nil {
				t.Errorf("no error for %q", c.name)
			}
		})
	}
}

func TestScepterExecTransportFailure(t *testing.T) {
	old := P.Bin
	defer func() { P.Bin = old }()
	// a binary that does not exist: the exec failure surfaces, no data invented
	P.Bin = filepath.Join(t.TempDir(), "no-such-wattun")
	if _, err := scepterExec("ir", "state.get", nil); err == nil {
		t.Error("no error for a missing binary")
	}
	// a binary that fails with stderr: the engine's own words surface untouched
	// (the test binary rejects the flags; the point is that its stderr arrives)
	P.Bin = os.Args[0]
	_, err := scepterExec("ir", "state.get", nil)
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Errorf("stderr of the failing child not surfaced: %v", err)
	}
}

func TestScepterCodeHints(t *testing.T) {
	cases := []struct {
		code int
		p    map[string]any
		want string
	}{
		{scepterCodeOK, nil, ""},
		{scepterCodeBad, map[string]any{"key": "max-mbps", "why": "unknown config key"}, "max-mbps"},
		{scepterCodeBad, map[string]any{"ports": "bad port item"}, "refused the ports"},
		{scepterCodeBad, nil, "bad arguments"},
		{scepterCodeDenied, map[string]any{"need": "manage"}, "'manage'"},
		{scepterCodeStale, nil, "outdated state"},
		{scepterCodeRate, nil, "wait a moment"},
		{scepterCodeUnknownCmd, nil, "3.5.0"},
		{scepterCodeNotFound, nil, "no such tunnel"},
		{scepterCodeInternal, map[string]any{"rolled_back": true, "detail": "unit did not come up"}, "rolled back"},
		{scepterCodeInternal, nil, "Kharej-side failure"},
		{scepterCodeUnpaired, nil, "pairing is not active"},
		{scepterCodeNameTaken, map[string]any{"name": "t1"}, "'t1' is already used"},
		{scepterCodePortBusy, map[string]any{"port": float64(443), "user": "t2"}, "port 443 is already bound by t2"},
		{scepterCodeCarrierNeeds, map[string]any{"carrier": "icmp", "need": "linux+CAP_NET_RAW"}, "icmp' needs linux+CAP_NET_RAW"},
		{99, nil, ""},
	}
	for _, c := range cases {
		if got := scepterCodeHint(c.code, c.p); !strings.Contains(got, c.want) {
			t.Errorf("hint(%d, %v) = %q, want it to contain %q", c.code, c.p, got, c.want)
		}
	}
}

func TestScepterCreateArgs(t *testing.T) {
	// the full intent: id, name, carrier, ports, params, base_seq, ttl_s
	args := scepterCreateArgs("t1", "udp", "443", map[string]string{"listen": ":8443"}, 41, "mgr1")
	for k, want := range map[string]any{
		"id": "mgr1", "name": "t1", "carrier": "udp", "ports": "443",
		"base_seq": uint64(41), "ttl_s": scepterTTLDefault,
	} {
		if got := args[k]; got != want {
			t.Errorf("args[%q] = %v, want %v", k, got, want)
		}
	}
	if p, ok := args["params"].(map[string]string); !ok || p["listen"] != ":8443" {
		t.Errorf("params = %v", args["params"])
	}
	// an empty name stays absent (Kharej suggests one) and so do empty params
	args = scepterCreateArgs("", "udp", "443", nil, 0, "mgr2")
	if _, present := args["name"]; present {
		t.Error("empty name must stay absent")
	}
	if _, present := args["params"]; present {
		t.Error("empty params must stay absent")
	}
	if args["base_seq"] != uint64(0) || args["ttl_s"] != 600 {
		t.Errorf("base_seq/ttl defaults = %v/%v", args["base_seq"], args["ttl_s"])
	}
}

func TestScepterRemoteNameSuggest(t *testing.T) {
	rows := []scepterTunRow{{Name: "tunnel"}, {Name: "tunnel-2"}, {Name: "other"}}
	if got := scepterRemoteNameSuggest(rows); got != "tunnel-3" {
		t.Errorf("suggest over taken names = %q, want tunnel-3", got)
	}
	if got := scepterRemoteNameSuggest(nil); got != "tunnel" {
		t.Errorf("suggest over an empty list = %q, want tunnel", got)
	}
}

func TestScepterRunStaleRetry(t *testing.T) {
	InitColor(false, 8)
	// the stale retry's "rebuild on the fresh state?" goes through Confirm;
	// NonInteractive answers yes and keeps the loop deterministic.
	old := NonInteractive
	NonInteractive = true
	defer func() { NonInteractive = old }()
	// scripted channel: the first create answers stale, state.get answers the
	// fresh document (seq 41), the resend is recorded and answers OK.
	stale := ScepterResult{Code: scepterCodeStale}
	fresh := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "state_seq": float64(41), "tunnels": []any{}, "pair": map[string]any{},
	}}
	done := ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "t1"}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"tunnel.create": {{r: stale}, {r: done}},
		"state.get":     {{r: fresh}},
	}}
	var firstID string
	var seqs []uint64
	_, ok := scepterRun(cl, "tunnel.create", func(seq uint64, id string) map[string]any {
		if firstID == "" {
			firstID = id
		}
		seqs = append(seqs, seq)
		return scepterCreateArgs("t1", "udp", "443", nil, seq, id)
	}, 7)
	if !ok {
		t.Fatal("no final answer")
	}
	if len(seqs) != 2 || seqs[0] != 7 || seqs[1] != 41 {
		t.Errorf("base_seq per send = %v, want [7 41]", seqs)
	}
	sent := cl.cmds["tunnel.create"]
	if len(sent) != 2 {
		t.Fatalf("sent %d creates, want 2", len(sent))
	}
	if sent[0]["id"] == sent[1]["id"] {
		t.Error("a stale retry must mint a fresh command id (the old intent never applied)")
	}
	if sent[0]["id"] != firstID || sent[1]["base_seq"] != uint64(41) {
		t.Errorf("ids/base_seq = %v/%v", sent[0]["id"], sent[1]["base_seq"])
	}
}

func TestScepterRunTransportRetryKeepsID(t *testing.T) {
	InitColor(false, 8)
	// first send fails at the transport (outcome unknown), the resend of the
	// SAME id is what makes the journal replay instead of double-applying.
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"tunnel.create": {{e: fmt.Errorf("channel dead")}, {r: ScepterResult{Code: scepterCodeOK}}},
	}}
	// the retry question goes through Confirm; NonInteractive answers yes
	old := NonInteractive
	NonInteractive = true
	defer func() { NonInteractive = old }()
	_, ok := scepterRun(cl, "tunnel.create", func(seq uint64, id string) map[string]any {
		return scepterCreateArgs("t1", "udp", "443", nil, seq, id)
	}, 7)
	if !ok {
		t.Fatal("retry did not land")
	}
	sent := cl.cmds["tunnel.create"]
	if len(sent) != 2 || sent[0]["id"] != sent[1]["id"] {
		t.Errorf("transport retry must reuse the command id: %v vs %v", sent[0]["id"], sent[1]["id"])
	}
	if sent[0]["base_seq"] != uint64(7) || sent[1]["base_seq"] != uint64(7) {
		t.Error("a transport retry keeps the intent (and its base_seq) untouched")
	}
}

// scriptClient answers each command from a per-command script of answers and
// records the args of every send — the seam's stub for the intent-loop tests.
type scriptClient struct {
	byCmd map[string][]scriptAns
	cmds  map[string][]map[string]any
}

type scriptAns struct {
	r ScepterResult
	e error
}

func (s *scriptClient) Call(cmd string, args map[string]any) (ScepterResult, error) {
	if s.cmds == nil {
		s.cmds = map[string][]map[string]any{}
	}
	s.cmds[cmd] = append(s.cmds[cmd], args)
	q := s.byCmd[cmd]
	if len(q) == 0 {
		return ScepterResult{}, fmt.Errorf("script exhausted for %s", cmd)
	}
	a := q[0]
	s.byCmd[cmd] = q[1:]
	return a.r, a.e
}

func TestScepterParseDoc(t *testing.T) {
	// a recorded state.get answer: the full document shape
	doc, err := scepterParseDoc(map[string]any{
		"v": float64(1), "ver": "3.5.0", "state_seq": float64(12), "uptime_s": float64(3600),
		"event_cursor": float64(9),
		"pair":         map[string]any{"uuid": "1b0e6a52-0000", "caps": "manage"},
		"tunnels": []any{
			map[string]any{"name": "t1", "carrier": "udp", "state": "active", "health": "ok",
				"ports": "443", "metrics": "127.0.0.1:19700"},
			map[string]any{"name": "t2", "carrier": "icmp", "state": "inactive", "health": "down"},
		},
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.Ver != "3.5.0" || doc.StateSeq != 12 || doc.UptimeS != 3600 || doc.Cursor != 9 {
		t.Errorf("doc head = %+v", doc)
	}
	if doc.PairCaps != "manage" || len(doc.Tunnels) != 2 || doc.Tunnels[0].Name != "t1" || doc.Tunnels[1].Ports != "" {
		t.Errorf("doc body = %+v", doc)
	}
	// garbage and empty answers are errors, never an empty-looking success
	if _, err := scepterParseDoc(nil); err == nil {
		t.Error("nil params accepted")
	}
	if _, err := scepterParseDoc(map[string]any{"unrelated": 1}); err == nil {
		t.Error("params without a document accepted")
	}
}

func TestScepterCapsOf(t *testing.T) {
	for tier, want := range map[string]ScepterCaps{
		"tunnel": CapTunnel,
		"create": CapTunnel | CapCreate,
		"manage": CapTunnel | CapCreate | CapManage,
		"full":   CapTunnel | CapCreate | CapManage | CapFull,
	} {
		if got := scepterCapsOf(map[string]any{"caps": tier}); got != want {
			t.Errorf("capsOf(%q) = %d, want %d", tier, got, want)
		}
	}
	// an unknown or missing tier is no capability at all (write items hide)
	if scepterCapsOf(map[string]any{"caps": "root"}) != 0 || scepterCapsOf(nil) != 0 {
		t.Error("unknown tier must map to 0")
	}
}

func TestScepterValidators(t *testing.T) {
	InitColor(false, 8)
	// remote names: the engine's name rule without the local file check
	if !vScepterName("T-1_x") || vScepterName("") || vScepterName("-way-too-long-0123456789abcdef0123") ||
		vScepterName("bad name") || vScepterName("dot.dot") {
		t.Error("vScepterName disagrees with the name rule")
	}
	// ports: the engine's parsePortItem grammar
	for _, s := range []string{"443", "443,53/udp", "8443:443/udp", "2000-2010", "2000-2010:3000-3010/tcp", "80/tcp"} {
		if !vScepterPorts(s) {
			t.Errorf("ports %q rejected", s)
		}
	}
	for _, s := range []string{"", "  ", "0", "443, ", "1-2:3", "a", "443/", "-5", "70000", "443:444:555"} {
		if vScepterPorts(s) {
			t.Errorf("ports %q accepted", s)
		}
	}
	// limits: the engine's parseLimitItem grammar, comma-separated; empty clears;
	// a bare port is parsed (and ignored) by the engine too, period needs a quota
	for _, s := range []string{"", "443", "443 rate=10MB", "443 rate=10MB,53 quota=1GB period=week"} {
		if !vScepterLimits(s) {
			t.Errorf("limits %q rejected", s)
		}
	}
	for _, s := range []string{"443 speed=10MB", "443 rate=", "443 period=month", "x rate=1MB"} {
		if vScepterLimits(s) {
			t.Errorf("limits %q accepted", s)
		}
	}
}

func TestScepterFleetScreen(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "a.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "b.yml"), []byte("mode: client\ncarrier: tcp\npairing: true\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "c.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	// a answers with a real document; b's channel is down — the row says so
	doc := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "state_seq": float64(4), "uptime_s": float64(90), "event_cursor": float64(2),
		"tunnels": []any{map[string]any{"name": "web", "carrier": "udp", "state": "active", "health": "ok"}},
	}}
	oldDial := scepterDial
	defer func() { scepterDial = oldDial }()
	scepterDial = func(tunnel string) (ScepterClient, error) {
		if tunnel == "a" {
			return stubClient{doc}, nil
		}
		return nil, fmt.Errorf("channel dead")
	}
	defer feed("0")() // open nothing, then leave
	out := capture(t, scepterFleet)
	// the fleet shows the pair summary (version, seq, tunnel COUNT), not the
	// remote tunnel names — those open through the pair screen
	for _, want := range []string{"a", "3.5.0", "1 tunnel(s)", "b", "unreachable"} {
		if !strings.Contains(out, want) {
			t.Errorf("fleet output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "c\n") || strings.Contains(out, " c ") {
		t.Errorf("the unpaired tunnel must not be a fleet row:\n%s", out)
	}
}

func TestScepterFleetScreenEmpty(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	defer feed("0")()
	out := capture(t, scepterFleet)
	if !strings.Contains(out, "no pairs") || !strings.Contains(out, "watp1:") {
		t.Errorf("empty fleet hint missing:\n%s", out)
	}
}

func TestScepterPairScreenSmoke(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	// hello says manage, state.get lists one remote tunnel; the screen renders
	// both and leaves on esc without calling anything else.
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"scepter.hello": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{
			"ver": "3.5.0", "caps": "manage", "uuid": "u1", "state_seq": float64(6)}}}},
		"state.get": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{
			"ver": "3.5.0", "state_seq": float64(6), "uptime_s": float64(60), "event_cursor": float64(3),
			"pair":    map[string]any{"uuid": "u1", "caps": "manage"},
			"tunnels": []any{map[string]any{"name": "web", "carrier": "udp", "state": "active", "health": "ok"}},
		}}}},
	}}
	oldDial := scepterDial
	scepterDial = func(string) (ScepterClient, error) { return cl, nil }
	defer func() { scepterDial = oldDial }()
	defer feed("0")()
	out := capture(t, func() { scepterScreen("ir") })
	for _, want := range []string{"web", "3.5.0", "create", "State document"} {
		if !strings.Contains(out, want) {
			t.Errorf("pair screen missing %q:\n%s", want, out)
		}
	}
	if len(cl.cmds["scepter.hello"]) != 1 || len(cl.cmds["state.get"]) < 1 {
		t.Errorf("unexpected call pattern: %v", cl.cmds)
	}
}

func TestScepterTunnelPageSmoke(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	stats := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"name": "web", "alive": true, "streams": float64(3), "rate_bps": float64(1500000), "loss_pct": float64(0.4),
	}}
	doc := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "state_seq": float64(6), "event_cursor": float64(3),
		"tunnels": []any{map[string]any{"name": "web", "carrier": "udp", "state": "active", "health": "ok"}},
	}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"state.get":    {{r: doc}, {r: doc}}, // page entry + refresh after the stats action
		"tunnel.stats": {{r: stats}},
	}}
	oldDial := scepterDial
	scepterDial = func(string) (ScepterClient, error) { return cl, nil }
	defer func() { scepterDial = oldDial }()
	defer feed("s0")() // open stats, then back out of the page
	out := capture(t, func() { scepterTunnelPage("ir", cl, CapTunnel|CapCreate|CapManage, "web") })
	for _, want := range []string{"Stats", "Streams", "Rate", "MB/s", "Loss"} {
		if !strings.Contains(out, want) {
			t.Errorf("tunnel page missing %q:\n%s", want, out)
		}
	}
	if len(cl.cmds["tunnel.stats"]) != 1 {
		t.Errorf("stats called %d times, want 1", len(cl.cmds["tunnel.stats"]))
	}
}

// TestScepterPairToEngineContract pins scepterPairTo against the engine's
// standalone -pair-to action (b24af32): exit 0 after writing `pairing: true`
// into the tunnel yml (IsPaired flips), and a refusal (exit 1 + stderr)
// surfaces as the engine's own words — both with a real exec, no hang.
func TestScepterPairToEngineContract(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	oldConf, oldBin := P.Conf, P.Bin
	defer func() { P.Conf, P.Bin = oldConf, oldBin }()
	P.Conf = dir
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n"), 0o600)
	os.Setenv("WAT_MGR_FAKE_ENGINE", "1")
	defer os.Unsetenv("WAT_MGR_FAKE_ENGINE")
	P.Bin = os.Args[0] // the test binary, running as the fake engine (TestMain)
	line := MakePairingLine(ScepterVersion, "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", testKey(), CapManage)
	if err := scepterPairTo("ir", line); err != nil {
		t.Fatalf("exit-0 attach refused: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "ir.yml"))
	if !strings.Contains(string(body), "pairing: true") {
		t.Errorf("yml lacks `pairing: true` after the exit-0 attach:\n%s", body)
	}
	if !IsPaired("ir") {
		t.Error("the attached tunnel is not IsPaired")
	}
	// a re-attach is allowed by the engine (attachPairing overwrites the store;
	// setPairingKey leaves the yml key alone) — the fake mirrors that, and the
	// manager must not turn an engine-allowed re-attach into a failure
	// (round-2 finding: the fake was once stricter than the engine)
	if err := scepterPairTo("ir", line); err != nil {
		t.Errorf("a re-attach must succeed: %v", err)
	}
	body, _ = os.ReadFile(filepath.Join(dir, "ir.yml"))
	if n := strings.Count(string(body), "pairing: true"); n != 1 {
		t.Errorf("the yml marker must not duplicate on a re-attach: %d in:\n%s", n, body)
	}
}

// TestScepterPairToDeadline pins the round-2 finding: the bare exec.Command in
// scepterPairTo hung forever against a pre-b24af32 engine (the old -pair-to
// ran the tunnel forever after storing the credential). The shell-out now
// rides the 65 s context like scepterExec; a wedged child dies on it — proven
// with a hanging fake and the shortened deadline var.
func TestScepterPairToDeadline(t *testing.T) {
	dir := t.TempDir()
	oldConf, oldBin := P.Conf, P.Bin
	defer func() { P.Conf, P.Bin = oldConf, oldBin }()
	P.Conf = dir
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	os.Setenv("WAT_MGR_FAKE_ENGINE", "hang")
	defer os.Unsetenv("WAT_MGR_FAKE_ENGINE")
	P.Bin = os.Args[0] // the test binary, hanging as the fake engine (TestMain)
	old := scepterPairToTimeout
	scepterPairToTimeout = 250 * time.Millisecond
	defer func() { scepterPairToTimeout = old }()
	err := scepterPairTo("ir", MakePairingLine(ScepterVersion, "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", testKey(), CapManage))
	if err == nil || !strings.Contains(err.Error(), "no answer within") {
		t.Fatalf("a wedged -pair-to must die on the deadline: %v", err)
	}
}

// TestScepterAttachScreenFlow drives scepterAttach end to end against the fake
// engine: paste (the local validator accepts what the engine will), confirm,
// and the shell-out lands the exit-0 write; a refused attach prints the
// engine's stderr on the screen.
func TestScepterAttachScreenFlow(t *testing.T) {
	InitColor(false, 8)
	ni := NonInteractive
	NonInteractive = false
	defer func() { NonInteractive = ni }()
	dir := t.TempDir()
	oldConf, oldBin := P.Conf, P.Bin
	defer func() { P.Conf, P.Bin = oldConf, oldBin }()
	P.Conf = dir
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	os.Setenv("WAT_MGR_FAKE_ENGINE", "1")
	defer os.Unsetenv("WAT_MGR_FAKE_ENGINE")
	P.Bin = os.Args[0]
	line := MakePairingLine(ScepterVersion, "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", testKey(), CapFull)
	restore := feed(line + "\ny") // the AskOK paste, then the Confirm y
	out := capture(t, func() { scepterAttach("ir") })
	restore()
	body, _ := os.ReadFile(filepath.Join(dir, "ir.yml"))
	if !strings.Contains(string(body), "pairing: true") {
		t.Errorf("yml lacks `pairing: true` after the screen attach:\n%s", body)
	}
	if !IsPaired("ir") {
		t.Error("the attached tunnel is not IsPaired")
	}
	// a re-attach is allowed by the engine (attachPairing overwrites; the fake
	// mirrors it — round-2 finding): the screen reports success, the yml keeps
	// exactly one marker
	restore = feed(line + "\ny")
	out = capture(t, func() { scepterAttach("ir") })
	restore()
	if !strings.Contains(out, "Pairing attached") {
		t.Errorf("a re-attach must succeed on the screen:\n%s", out)
	}
	body, _ = os.ReadFile(filepath.Join(dir, "ir.yml"))
	if n := strings.Count(string(body), "pairing: true"); n != 1 {
		t.Errorf("the yml marker must not duplicate on a re-attach: %d in:\n%s", n, body)
	}
}

// TestScepterWizardPortBusyReasksListen pins the round-2 finding: port_busy is
// always a BIND port (the intent's listen or the carrier default), so the
// wizard re-asks the LISTEN prompt once and resends with the new listen; the
// forwarded ports stay. The old re-ask of the ports string resent the same
// listen and looped forever.
func TestScepterWizardPortBusyReasksListen(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	busy := ScepterResult{Code: scepterCodePortBusy, Params: map[string]any{"port": float64(4444), "user": "web"}}
	done := ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "tunnel", "carrier": "udp"}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"tunnel.create": {{r: busy}, {r: done}},
	}}
	// name default, udp (quick pick 2), listen default (empty), ports 443, send,
	// then the re-asked listen 18443
	defer feed("\n2\n443\ny18443\n")()
	out := capture(t, func() { scepterWizardCreate("ir", cl, scepterDoc{StateSeq: 7}) })
	sent := cl.cmds["tunnel.create"]
	if len(sent) != 2 {
		t.Fatalf("sends = %d, want 2:\n%s", len(sent), out)
	}
	if n := strings.Count(out, "Listen port on Kharej"); n != 2 {
		t.Errorf("listen prompts = %d, want 2 (initial + exactly one re-ask):\n%s", n, out)
	}
	if n := strings.Count(out, "Forwarded ports"); n != 1 {
		t.Errorf("ports prompts = %d, want 1 (the forwarded ports stay):\n%s", n, out)
	}
	if p, ok := sent[1]["params"].(map[string]string); !ok || p["listen"] != ":18443" || len(p) != 1 {
		t.Errorf("the rebuilt intent must carry the new listen: %v", sent[1]["params"])
	}
	if sent[1]["ports"] != "443" {
		t.Errorf("the forwarded ports changed: %v", sent[1]["ports"])
	}
}

// TestScepterWizardCarrierNeedsRebuilds pins the round-2 finding: a re-pick
// after carrier_needs rebuilds the params for the NEW carrier — the old
// shape's sni must not ride into a carrier that reads none, and the listen
// bind stays only because the pre-filled prompt is confirmed with Enter.
func TestScepterWizardCarrierNeedsRebuilds(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	needs := ScepterResult{Code: scepterCodeCarrierNeeds, Params: map[string]any{
		"carrier": "tls", "need": "a cert store on Kharej"}}
	done := ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "tunnel", "carrier": "tcp"}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"tunnel.create": {{r: needs}, {r: done}},
	}}
	// name default, tls (quick pick 4), listen 8443, sni old-sni.ir, ports 443,
	// send, then re-pick tcp (quick pick 3) and Enter keeps the pre-filled 8443
	defer feed("\n48443\nold-sni.ir\n443\ny3\n")()
	out := capture(t, func() { scepterWizardCreate("ir", cl, scepterDoc{StateSeq: 7}) })
	sent := cl.cmds["tunnel.create"]
	if len(sent) != 2 {
		t.Fatalf("sends = %d, want 2:\n%s", len(sent), out)
	}
	if p, _ := sent[0]["params"].(map[string]string); p["sni"] != "old-sni.ir" || p["listen"] != ":8443" {
		t.Errorf("the first intent should carry the old shape's params: %v", sent[0]["params"])
	}
	if sent[1]["carrier"] != "tcp" {
		t.Errorf("the re-picked carrier = %v", sent[1]["carrier"])
	}
	p, present := sent[1]["params"].(map[string]string)
	if !present || len(p) != 1 || p["listen"] != ":8443" {
		t.Errorf("the rebuilt params must keep only the confirmed listen: %v (present %v)", sent[1]["params"], present)
	}
	if n := strings.Count(out, "Listen port on Kharej"); n != 2 {
		t.Errorf("listen prompts = %d, want 2 (the new carrier's bind is re-confirmed):\n%s", n, out)
	}
}

// TestScepterFleetSelectionAndDials pins the fleet loop's two round-2 fixes:
// the selection survives a move (F4: sel was re-declared inside the redraw
// loop and the highlight snapped back to row 0), and a move does not re-dial
// every pair (F5: one state.get shell-out per pair per second while idle —
// rows are fetched on entry and on r only).
func TestScepterFleetSelectionAndDials(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "a.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "b.yml"), []byte("mode: client\ncarrier: tcp\npairing: true\n"), 0o600)
	doc := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "state_seq": float64(4), "uptime_s": float64(90),
		"tunnels": []any{map[string]any{"name": "web", "carrier": "udp", "state": "active", "health": "ok"}},
	}}
	calls := 0
	oldDial := scepterDial
	scepterDial = func(string) (ScepterClient, error) { calls++; return stubClient{doc}, nil }
	defer func() { scepterDial = oldDial }()
	defer feed("j0")() // one down-move, then leave: the move must not re-dial
	out := capture(t, scepterFleet)
	if calls != 2 {
		t.Errorf("state.get dials = %d, want 2 (one per pair, fetched once on entry):\n%s", calls, out)
	}
	// the redraw after the move highlights row b — the selection survived the loop
	if n := strings.Count(out, "❯ 2  b"); n != 1 {
		t.Errorf("the moved-to row must stay highlighted (%d hits):\n%s", n, out)
	}
}

// TestScepterTunnelPageBaseSeq pins the round-2 finding: tunnel.edit and
// preset.apply are built on the state's state_seq, never the event cursor
// (the cursor moves on every event, so a cursor-built intent answered stale).
func TestScepterTunnelPageBaseSeq(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	doc := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "state_seq": float64(6), "event_cursor": float64(3),
		"tunnels": []any{map[string]any{"name": "web", "carrier": "udp", "state": "active", "health": "ok", "ports": "443"}},
	}}
	okRes := ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "web"}}
	for _, c := range []struct {
		name, keys, cmd string
		docs            int // state.get answers: page entry + menu refetch + refresh
	}{
		{"ports", "p443\nx0", "tunnel.edit", 2},
		{"config key set", "km5\n0", "tunnel.edit", 3},
		{"config key drop", "ku-\n0", "tunnel.edit", 3},
		{"preset fallback", "zsx0", "preset.apply", 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			docs := make([]scriptAns, c.docs)
			for i := range docs {
				docs[i] = scriptAns{r: doc}
			}
			cl := &scriptClient{byCmd: map[string][]scriptAns{
				"state.get": docs, // page entry + (the key menu's seq refetch) + the post-action refresh
				c.cmd:       {{r: okRes}},
			}}
			defer feed(c.keys)() // page key, the action's prompts, a pause key, then leave
			out := capture(t, func() { scepterTunnelPage("ir", cl, CapTunnel|CapCreate|CapManage, "web") })
			sent := cl.cmds[c.cmd]
			if len(sent) != 1 {
				t.Fatalf("%s sends = %d, want 1:\n%s", c.cmd, len(sent), out)
			}
			if sent[0]["base_seq"] != uint64(6) {
				t.Errorf("base_seq = %v, want the state seq 6 (not the event cursor 3)", sent[0]["base_seq"])
			}
		})
	}
	// the key menu's set and drop shapes, and the post-edit seq refetch that
	// keeps the NEXT edit off the stale path
	t.Run("config key shapes", func(t *testing.T) {
		docs := []scriptAns{{r: doc}, {r: doc}, {r: doc}, {r: doc}}
		cl := &scriptClient{byCmd: map[string][]scriptAns{
			"state.get":   docs,
			"tunnel.edit": {{r: okRes}, {r: okRes}},
		}}
		defer feed("km5\nku-\n00")() // set max-mbps 5, then drop mtu, then leave twice
		out := capture(t, func() { scepterTunnelPage("ir", cl, CapTunnel|CapCreate|CapManage, "web") })
		sent := cl.cmds["tunnel.edit"]
		if len(sent) != 2 {
			t.Fatalf("edits = %d, want 2:\n%s", len(sent), out)
		}
		set, _ := sent[0]["set"].(map[string]string)
		if set["max-mbps"] != "5" {
			t.Errorf("first edit set = %v, want max-mbps 5", sent[0]["set"])
		}
		drop, _ := sent[1]["drop"].([]string)
		if len(drop) != 1 || drop[0] != "mtu" {
			t.Errorf("second edit drop = %v, want [mtu]", sent[1]["drop"])
		}
	})
}

// Token-bootstrap pairing (owner directive 2026-11-22): field 10 of the tunnel's
// token pairs it without any yml key; `pairing: false` is the explicit off
// switch; a lookalike or unknown tier field is not a credential (the engine's
// L5-strict ParsePairingTokenField gate, mirrored here).
func TestIsPairedTokenField(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	ir := "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n"
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte(ir), 0o600)
	os.WriteFile(filepath.Join(dir, "iroff.yml"), []byte(ir+"pairing: false\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "irtrue.yml"), []byte(ir+"pairing: true\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "kh.yml"), []byte("mode: server\ncarrier: udp\n"), 0o600)
	mint := func(f10 string) {
		os.WriteFile(filepath.Join(dir, "ir.token"),
			[]byte(MakeToken("udp", "198.51.100.7:4443", "k", "", "", "", "", "", "", f10)), 0o600)
	}
	mint("pair=full")
	if !IsPaired("ir") {
		t.Error("a token-bootstrap pair (field 10 pair=full) is not IsPaired")
	}
	if got := PairedBadge("ir"); got != " [paired]" {
		t.Errorf("token-pair badge = %q, want \" [paired]\"", got)
	}
	if IsPaired("iroff") {
		t.Error("pairing: false must beat the token's pair field")
	}
	if !IsPaired("irtrue") {
		t.Error("pairing: true with no token is not IsPaired")
	}
	for f10, want := range map[string]bool{
		"pair":        true,  // bare pair = tunnel-tier credential
		"pair=manage": true,  // any valid tier pairs
		"pairxyz":     false, // a lookalike is not the pair field (L5-strict)
		"pairing":     false,
		"pair=root":   false, // the engine refuses an unknown tier
		"":            false,
	} {
		mint(f10)
		if got := IsPaired("ir"); got != want {
			t.Errorf("IsPaired(field 10 %q) = %v, want %v", f10, got, want)
		}
	}
	os.Remove(filepath.Join(dir, "ir.token"))
	if IsPaired("ir") {
		t.Error("no token and no pairing key must not be IsPaired")
	}
	if IsPaired("kh") {
		t.Error("a Kharej config is never an Iran pair")
	}
}

// The pair screen's local mask: Kharej's hello answer first; with no hello a
// token-bootstrap pair falls back to its own field-10 tier (owner directive
// 2026-11-22 — the mask never needs the yml pairing key).
func TestScepterPairCapsFallback(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ir.token"),
		[]byte(MakeToken("udp", "198.51.100.7:4443", "k", "", "", "", "", "", "", "pair=manage")), 0o600)
	if got := scepterPairCaps("ir", map[string]any{"caps": "tunnel"}, ""); got != CapTunnel {
		t.Errorf("hello caps = %v, want tunnel", got)
	}
	if got := scepterPairCaps("ir", nil, "channel error"); got != CapTunnel|CapCreate|CapManage {
		t.Errorf("fallback caps = %v, want the manage tower", got)
	}
	if got := scepterPairCaps("ir", map[string]any{}, ""); got != 0 {
		t.Errorf("an answered hello without caps = %v, want none (Kharej's word stands)", got)
	}
}

// The automatic fast-preset anti-censor verdict (owner directive 2026-11-22):
// after a successful follow it runs the existing fast machinery on the changed
// carrier and prints the ranked table plus a verdict; the shared at_* state
// comes back out the way it went in.
func TestScepterACVerdict(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	oldP, oldVer, oldSpawn, oldFetch, oldSpeed, oldDesync, oldBusy, savedPreset, savedQuiet := P, engineVer,
		envSpawnClient, p1FetchStats, p1Speedtest, scepterCanDesync, scepterVerdictBusy.Load(), atPreset, atQuiet
	P.Conf, P.Run = dir, dir
	engineVer = func() string { return "9.9.9" }
	scepterCanDesync = func() bool { return true }
	scepterVerdictBusy.Store(false)
	t.Cleanup(func() {
		P, engineVer, envSpawnClient, p1FetchStats, p1Speedtest = oldP, oldVer, oldSpawn, oldFetch, oldSpeed
		scepterCanDesync, atPreset, atQuiet = oldDesync, savedPreset, savedQuiet
		scepterVerdictBusy.Store(oldBusy)
	})
	yml := "mode: client\ncarrier: tcp\npeer: 203.0.113.10:26443\nkey-file: " + dir + "/ir.key\nmetrics: 127.0.0.1:19999\nports:\n  - 443\n"
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte(yml), 0o600)
	os.WriteFile(filepath.Join(dir, "ir.key"), []byte("kk\n"), 0o600)
	probes := 0
	envSpawnClient = func(args []string, logFile string) (clientProc, error) {
		probes++
		for i, a := range args {
			if a == "-carrier" && i+1 < len(args) && args[i+1] == "tcp" {
				return fakeProc{}, nil
			}
		}
		return nil, os.ErrPermission //nolint:staticcheck // the icmp row reports its own failure
	}
	p1FetchStats = func(addr string) string { return `{"alive":true,"rtt_ms":21.5}` }
	p1Speedtest = func(int, string) (bool, float64) { return true, 25 }
	timeSleep = func(int) {}
	atPreset = "normal"
	var out string
	out = capture(t, func() { scepterACVerdict("ir") })
	if !strings.Contains(out, "Anti-censor verdict") || !strings.Contains(out, "the plain shape passes") {
		t.Errorf("verdict missing:\n%s", out)
	}
	if !strings.Contains(out, "tcp rst mci.ir") { // the fast grid's rows, ranked table included
		t.Errorf("fast rows missing from the table:\n%s", out)
	}
	if probes < 7 { // plain + rst/synrst x 3 SNIs (icmp fails fast)
		t.Errorf("probe count = %d, want the fast grid", probes)
	}
	if atPreset != "normal" { // the run restores the shared at_* state
		t.Errorf("atPreset = %q after the verdict, want %q restored", atPreset, savedPreset)
	}
	// gates: no desync host, non-dialing end, reverse, udp, bond — none of them probe
	for _, tc := range []struct {
		name, yml string
		desync    bool
	}{{"no desync host", yml, false}, {"udp has no SNI rows", "mode: client\ncarrier: udp\npeer: 203.0.113.10:4443\nkey-file: " + dir + "/ir.key\n", true},
		{"reverse", yml + "reverse: true\n", true}, {"bond", "mode: client\ncarrier: tcp+udp\npeer: 203.0.113.10:4443\nkey-file: " + dir + "/ir.key\n", true}} {
		os.WriteFile(filepath.Join(dir, "ir.yml"), []byte(tc.yml), 0o600)
		scepterCanDesync = func() bool { return tc.desync }
		before := probes
		out = capture(t, func() { scepterACVerdict("ir") })
		if probes != before {
			t.Errorf("%s: %d probes ran, want none\n%s", tc.name, probes-before, out)
		}
	}
}

// ---- wave-2 cockpit coverage (preset catalog, per-key menu, keyrotate,
// mute, quota reset, the local page's pair status and Kharej view) ----

func TestScepterParsePresets(t *testing.T) {
	rows := scepterParsePresets(map[string]any{"presets": []any{
		map[string]any{"name": "stealth", "desc": "pad and filler"},
		map[string]any{"name": "plain"},   // desc optional
		map[string]any{"desc": "no name"}, // skipped
		"junk",                            // skipped
	}})
	if len(rows) != 2 || rows[0].Name != "stealth" || rows[0].Desc != "pad and filler" || rows[1].Desc != "" {
		t.Errorf("rows = %+v", rows)
	}
	// an answer without a presets list is not trusted (the caller falls back)
	if scepterParsePresets(nil) != nil || scepterParsePresets(map[string]any{"presets": "stealth,plain"}) != nil {
		t.Error("a non-list presets field must parse as nil")
	}
}

func TestScepterRemotePresetCatalog(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"preset.list": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{
			"presets": []any{
				map[string]any{"name": "stealth", "desc": "pad and filler"},
				map[string]any{"name": "plain", "desc": "remove both"},
				map[string]any{"name": "fortress", "desc": "the blackout bond"},
			}}}}},
		"preset.apply": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "web"}}}},
	}}
	defer feed("\ry")() // enter picks the first catalog row, y confirms
	out := capture(t, func() { scepterRemotePreset(cl, "web", 6) })
	for _, want := range []string{"stealth", "plain", "fortress", "the blackout bond"} {
		if !strings.Contains(out, want) {
			t.Errorf("catalog row %q missing:\n%s", want, out)
		}
	}
	sent := cl.cmds["preset.apply"]
	if len(sent) != 1 {
		t.Fatalf("preset.apply sends = %d, want 1:\n%s", len(sent), out)
	}
	if sent[0]["preset"] != "stealth" || sent[0]["name"] != "web" || sent[0]["base_seq"] != uint64(6) {
		t.Errorf("args = %v", sent[0])
	}
}

// an old peer answers unknown_cmd for preset.list: the built-in stealth/plain
// menu takes over (and its preset still rides the same intent shape).
func TestScepterRemotePresetFallbackUnknownCmd(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"preset.list":  {{r: ScepterResult{Code: scepterCodeUnknownCmd}}},
		"preset.apply": {{r: ScepterResult{Code: scepterCodeOK}}},
	}}
	defer feed("p")() // the plain row of the built-in pair
	out := capture(t, func() { scepterRemotePreset(cl, "web", 6) })
	if !strings.Contains(out, "preset.list") {
		t.Errorf("the old-peer hint is missing:\n%s", out)
	}
	sent := cl.cmds["preset.apply"]
	if len(sent) != 1 || sent[0]["preset"] != "plain" {
		t.Errorf("fallback args = %v", sent)
	}
}

// TestScepterRemoteKeyrotateTwin pins the twin rewrite: the rotated token's
// key lands in the local twin's .key (what it dials with) and .token, and the
// old field-10 pair capability survives (F7) even though the rotated token
// itself carries none.
func TestScepterRemoteKeyrotateTwin(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ir.key"), []byte("old-key\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ir.token"),
		[]byte(MakeToken("udp", "198.51.100.7:4443", "old-key", "", "", "", "", "", "", "pair=manage")+"\n"), 0o600)
	newTok := MakeToken("udp", "198.51.100.7:4443", "brand-new-key-42", "", "", "", "", "", "")
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"tunnel.keyrotate": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "ir", "token": newTok}}}},
	}}
	defer feed("yn")() // y rotates, n skips the twin restart
	out := capture(t, func() { scepterRemoteKeyrotate("ir", cl, "ir", 6) })
	sent := cl.cmds["tunnel.keyrotate"]
	if len(sent) != 1 || sent[0]["name"] != "ir" {
		t.Fatalf("keyrotate args = %v:\n%s", sent, out)
	}
	if key := mustRead(filepath.Join(dir, "ir.key")); !strings.Contains(key, "brand-new-key-42") {
		t.Errorf("the twin's key file was not rewritten: %q", key)
	}
	// the token file carries the rotated token, reminted with the old pair
	// capability (the token itself is opaque base64 — compare whole)
	want := MakeToken("udp", "198.51.100.7:4443", "brand-new-key-42", "", "", "", "", "", "", "pair=manage") + "\n"
	if tok := mustRead(filepath.Join(dir, "ir.token")); tok != want {
		t.Errorf("the twin's token file = %q, want %q", tok, want)
	}
	if scepterRotSuffix("ir") == "" {
		t.Error("the rotation marker is missing from the pair status")
	}
	if !strings.Contains(out, "now to dial with the new key") {
		t.Errorf("the restart offer is missing:\n%s", out)
	}
	// the carry claim is honest: the old token DID carry pair=manage and the
	// rewrite merged it in, so and only so the line says "carried over"
	// (round-3 finding)
	if !strings.Contains(out, "pair capability carried over") {
		t.Errorf("the carried-over claim is missing:\n%s", out)
	}
}

// The twin rewrite without an old token: the success line must NOT claim the
// pair capability was carried over (there was none to carry — round-3
// finding), and the new key still lands.
func TestScepterRemoteKeyrotateTwinNoOldToken(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ir.key"), []byte("old-key\n"), 0o600)
	newTok := MakeToken("udp", "198.51.100.7:4443", "brand-new-key-42", "", "", "", "", "", "")
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"tunnel.keyrotate": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "ir", "token": newTok}}}},
	}}
	defer feed("yn")() // y rotates, n skips the twin restart
	out := capture(t, func() { scepterRemoteKeyrotate("ir", cl, "ir", 6) })
	if key := mustRead(filepath.Join(dir, "ir.key")); !strings.Contains(key, "brand-new-key-42") {
		t.Errorf("the twin's key file was not rewritten: %q", key)
	}
	if strings.Contains(out, "carried over") {
		t.Errorf("no old token existed — the line must not claim a carry:\n%s", out)
	}
	if !strings.Contains(out, "rewritten: new key and token") {
		t.Errorf("the honest success line is missing:\n%s", out)
	}
}

// The peerless-pair twin (round-3 finding): the remote name matches the local
// tunnel, but the pair's config has no resolvable host — a same-named local
// tunnel proves nothing, so nothing is rewritten and the token goes out by
// hand. A bare save-file name lands in the conf dir, not the CWD (the old
// dead `filepath.Dir(s) == ""` check never ran and the CWD got the file).
func TestScepterRemoteKeyrotateSavePath(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	// peerless pair: the local "ir" IS the same-named twin shape the old code
	// rewrote on sight (host == "" passed the old twin check)
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\nreverse: true\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ir.key"), []byte("old-key\n"), 0o600)
	newTok := MakeToken("udp", "198.51.100.7:4443", "brand-new-key-42", "", "", "", "", "", "")
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"tunnel.keyrotate": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "ir", "token": newTok}}}},
	}}
	defer feed("y0tok.txt\n0")() // y rotates, 0 past the empty pick screen, bare save name, pause
	out := capture(t, func() { scepterRemoteKeyrotate("ir", cl, "ir", 6) })
	if len(cl.cmds["tunnel.keyrotate"]) != 1 {
		t.Fatalf("keyrotate not sent:\n%s", out)
	}
	if key := mustRead(filepath.Join(dir, "ir.key")); key != "old-key\n" {
		t.Errorf("the peerless twin's key was rewritten: %q", key)
	}
	if _, err := os.Stat(filepath.Join(dir, "ir.token")); err == nil {
		t.Error("the peerless twin's token must not be written")
	}
	if !strings.Contains(out, "New token for this tunnel's Iran side") {
		t.Errorf("the token is not shown:\n%s", out)
	}
	// the bare name resolved into the conf dir next to the tunnel's files
	if got := mustRead(filepath.Join(dir, "tok.txt")); got != newTok+"\n" {
		t.Errorf("the saved token = %q, want the rotated token in the conf dir", got)
	}
	if !strings.Contains(out, "Token saved") {
		t.Errorf("the save is not reported:\n%s", out)
	}
}

// The wrong-peer twin (round-3 finding): a local tunnel with the remote's name
// but dialing another host is never silently rewritten — the pick screen lists
// only tunnels dialing the pair's host, and a declined pick hands the token
// out instead of rewriting anything.
func TestScepterRemoteKeyrotateWrongPeerTwin(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	// pk is the pair (dials 198.51.100.7); ir shares the remote's name but
	// dials a DIFFERENT Kharej (198.51.100.9); pk2 also dials the pair's host
	// so the pick screen has two candidates to decline
	os.WriteFile(filepath.Join(dir, "pk.yml"), []byte("mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\npeer: 198.51.100.9:4443\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "pk2.yml"), []byte("mode: client\ncarrier: tcp\npeer: 198.51.100.7:5543\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ir.key"), []byte("wrong-peer-key\n"), 0o600)
	newTok := MakeToken("udp", "198.51.100.7:4443", "brand-new-key-42", "", "", "", "", "", "")
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"tunnel.keyrotate": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "ir", "token": newTok}}}},
	}}
	defer feed("yq\n0")() // y rotates, q declines the pick screen, no save line, pause
	out := capture(t, func() { scepterRemoteKeyrotate("pk", cl, "ir", 6) })
	if key := mustRead(filepath.Join(dir, "ir.key")); key != "wrong-peer-key\n" {
		t.Errorf("the wrong-peer twin's key was rewritten: %q", key)
	}
	if _, err := os.Stat(filepath.Join(dir, "pk.key")); err == nil {
		t.Error("a declined pick must not rewrite any key file")
	}
	if !strings.Contains(out, "Which local tunnel is 'ir's Iran side?") {
		t.Errorf("the pick screen did not open:\n%s", out)
	}
	if !strings.Contains(out, "New token for this tunnel's Iran side") {
		t.Errorf("the declined pick must hand the token out:\n%s", out)
	}
}

func TestScepterRemoteMute(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	// the gate: a lone carrier has no leg to mute, nothing is sent
	cl := &scriptClient{}
	out := capture(t, func() { scepterRemoteMute(cl, "web", scepterTunRow{Carrier: "udp"}) })
	if len(cl.cmds["carrier.mute"]) != 0 {
		t.Errorf("a lone carrier must not send carrier.mute:\n%s", out)
	}
	// a bond: pick the first leg, mute it — {name, carrier, mute} on the wire
	cl = &scriptClient{byCmd: map[string][]scriptAns{
		"carrier.mute": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{
			"name": "web", "carrier": "udp", "muted": true}}}},
	}}
	defer feed("\rm")() // enter picks leg 1, m mutes
	out = capture(t, func() { scepterRemoteMute(cl, "web", scepterTunRow{Carrier: "udp+tcp"}) })
	sent := cl.cmds["carrier.mute"]
	if len(sent) != 1 {
		t.Fatalf("carrier.mute sends = %d, want 1:\n%s", len(sent), out)
	}
	if sent[0]["name"] != "web" || sent[0]["carrier"] != "udp" || sent[0]["mute"] != true {
		t.Errorf("args = %v", sent[0])
	}
	if !strings.Contains(out, "muted on Kharej") {
		t.Errorf("outcome missing:\n%s", out)
	}
}

func TestScepterRemoteLimitsReset(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	cl := &scriptClient{}
	defer feed("n")() // the confirm defaults to no: n cancels, nothing sent
	capture(t, func() { scepterRemoteLimitsReset(cl, "web") })
	if len(cl.cmds["limits.reset"]) != 0 {
		t.Error("a declined reset must not send")
	}
	cl = &scriptClient{byCmd: map[string][]scriptAns{
		"limits.reset": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{"name": "web"}}}},
	}}
	defer feed("y")()
	out := capture(t, func() { scepterRemoteLimitsReset(cl, "web") })
	sent := cl.cmds["limits.reset"]
	if len(sent) != 1 || sent[0]["name"] != "web" {
		t.Errorf("args = %v:\n%s", sent, out)
	}
	if !strings.Contains(out, "Quota counters reset") {
		t.Errorf("outcome missing:\n%s", out)
	}
}

// The local tunnel page's pair status: hello-derived, cached (one fetch per
// TTL, never per redraw), empty for an unpaired tunnel.
func TestScepterPairStatusCache(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	calls := 0
	oldFetch, oldTTL, oldBy := scepterStatusFetch, scepterStatusTTL, scepterStatusBy
	scepterStatusFetch = func(string) string { calls++; return "Kharej 3.5.0 · manage · seq 4" }
	scepterStatusTTL = time.Hour
	scepterStatusBy = map[string]scepterStatusEntry{}
	defer func() { scepterStatusFetch, scepterStatusTTL, scepterStatusBy = oldFetch, oldTTL, oldBy }()
	if s := ScepterPairStatus("nope"); s != "" {
		t.Errorf("unpaired status = %q, want empty", s)
	}
	s1 := ScepterPairStatus("ir")
	if calls != 1 || !strings.Contains(s1, "3.5.0") || !strings.Contains(s1, "seq 4") {
		t.Errorf("first status = %q (calls %d)", s1, calls)
	}
	ScepterPairStatus("ir")
	if calls != 1 {
		t.Errorf("the cached status refetched (calls %d)", calls)
	}
	scepterStatusTTL = 0 // expired: the next call fetches again
	ScepterPairStatus("ir")
	if calls != 2 {
		t.Errorf("an expired cache must refetch (calls %d)", calls)
	}
}

// The Kharej view jump: the same-named remote tunnel opens its remote page;
// without one, the pair screen (the honest "which one?" list) opens.
func TestScepterKharejView(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\npairing: true\n"), 0o600)
	hello := ScepterResult{Code: scepterCodeOK, Params: map[string]any{"ver": "3.5.0", "caps": "manage", "uuid": "u1"}}
	doc := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "state_seq": float64(6), "uptime_s": float64(60),
		"pair":    map[string]any{"uuid": "u1", "caps": "manage"},
		"tunnels": []any{map[string]any{"name": "ir", "carrier": "udp", "state": "active", "health": "ok"}},
	}}
	oldDial := scepterDial
	defer func() { scepterDial = oldDial }()
	scepterDial = func(string) (ScepterClient, error) {
		return &scriptClient{byCmd: map[string][]scriptAns{
			"scepter.hello": {{r: hello}},
			"state.get":     {{r: doc}, {r: doc}},
		}}, nil
	}
	defer feed("0")()
	ok := false
	out := capture(t, func() { ok = ScepterKharejView("ir") })
	if !ok || !strings.Contains(out, "on Kharej ir") {
		t.Errorf("the twin's remote page did not open (ok %v):\n%s", ok, out)
	}
	// no same-named remote tunnel: the pair screen lists instead
	doc.Params["tunnels"] = []any{map[string]any{"name": "web", "carrier": "udp", "state": "active", "health": "ok"}}
	scepterDial = func(string) (ScepterClient, error) {
		return &scriptClient{byCmd: map[string][]scriptAns{
			"scepter.hello": {{r: hello}, {r: hello}},
			"state.get":     {{r: doc}, {r: doc}},
		}}, nil
	}
	defer feed("0")()
	ok = false
	out = capture(t, func() { ok = ScepterKharejView("ir") })
	if !ok || !strings.Contains(out, "Iran cockpit") {
		t.Errorf("the pair screen did not open (ok %v):\n%s", ok, out)
	}
}

// The home lane wires the fleet through the registry under scepter_fleet.
func TestScepterFleetEntryRegistered(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	defer feed("0")() // the empty fleet's pause
	if !registered("scepter_fleet") {
		t.Fatal("scepter_fleet is not registered")
	}
	if rc := dispatch("scepter_fleet"); rc != 0 {
		t.Errorf("dispatch rc = %d, want 0", rc)
	}
}

// ---- round-3 fix pins (fix-cluster FX-A) ----

// An answered rejection must never reach a success line: scepterRun prints
// the code error and returns the answer, so every "… applied on Kharej" /
// "created" line is gated on the answer's Code == scepterCodeOK (round-3
// finding: the old code printed Ok for ANY answered code).
func TestScepterAppliedGateOnCode(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	denied := ScepterResult{Code: scepterCodeDenied, Params: map[string]any{"need": "manage"}}
	internal := ScepterResult{Code: scepterCodeInternal, Params: map[string]any{"rolled_back": true}}
	for _, c := range []struct {
		name   string
		run    func(cl ScepterClient)
		script map[string][]scriptAns
		feed   string
		noLine string // the success phrase that must stay absent
	}{
		{
			"ports", func(cl ScepterClient) { scepterRemotePorts(cl, "web", "443", 6) },
			map[string][]scriptAns{"tunnel.edit": {{r: denied}}},
			"443\n0", "applied on Kharej",
		},
		{
			"preset catalog", func(cl ScepterClient) { scepterRemotePreset(cl, "web", 6) },
			map[string][]scriptAns{
				"preset.list": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{
					"presets": []any{map[string]any{"name": "stealth", "desc": "pad"}}}}}},
				"preset.apply": {{r: denied}},
			},
			"\ry0", "applied on Kharej",
		},
		{
			"preset plain", func(cl ScepterClient) { scepterRemotePreset(cl, "web", 6) },
			map[string][]scriptAns{
				"preset.list":  {{r: ScepterResult{Code: scepterCodeUnknownCmd}}},
				"preset.apply": {{r: denied}},
			},
			"s0", "applied on Kharej",
		},
		{
			"keyrotate", func(cl ScepterClient) { scepterRemoteKeyrotate("ir", cl, "web", 6) },
			map[string][]scriptAns{"tunnel.keyrotate": {{r: denied}}},
			"y0\n0", "rewritten",
		},
		{
			"wizard create", func(cl ScepterClient) { scepterWizardCreate("ir", cl, scepterDoc{StateSeq: 7}) },
			map[string][]scriptAns{"tunnel.create": {{r: internal}}},
			"\n2\n\n443\ny", "created on Kharej",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := &scriptClient{byCmd: c.script}
			defer feed(c.feed)()
			out := capture(t, func() { c.run(cl) })
			if !strings.Contains(out, "answered code") {
				t.Errorf("the rejection was not printed:\n%s", out)
			}
			if strings.Contains(out, c.noLine) {
				t.Errorf("a rejected intent must not print %q:\n%s", c.noLine, out)
			}
		})
	}
}

// The remote state-save row treats "0" as the real value it is (save on
// shutdown only), not an unset word — the local Advanced page excludes it the
// same way (advanced.go's state-save row; round-3 finding: the old
// scepterKeyAskSet path dropped the key instead of setting 0).
func TestScepterStateSaveZero(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	rows := scepterKeyRows("udp", false)
	var row *scepterKeyRow
	for i := range rows {
		if rows[i].key == "state-save" {
			row = &rows[i]
		}
	}
	if row == nil {
		t.Fatal("no state-save row")
	}
	rest := feed("0\n")
	patch, ok := row.ask("udp")
	rest()
	if !ok || len(patch.drop) != 0 || patch.set["state-save"] != "0" {
		t.Errorf("state-save 0 = %+v (ok %v), want set {state-save: 0}, no drop", patch, ok)
	}
	rest = feed("-\n")
	patch, ok = row.ask("udp")
	rest()
	if !ok || len(patch.set) != 0 || len(patch.drop) != 1 || patch.drop[0] != "state-save" {
		t.Errorf("state-save - = %+v (ok %v), want a drop", patch, ok)
	}
}

// The remote rows know the tunnel's direction (from the local twin): sessions
// > 1 is refused on a reverse tunnel with the engine's reason, and the
// fake-mode picker omits sum/seqsum there (the engine refuses both — offering
// them only bought an apply-rollback; round-3 finding).
func TestScepterKeyRowsReverse(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	rowOf := func(key string, rev bool) *scepterKeyRow {
		rows := scepterKeyRows("udp", rev)
		for i := range rows {
			if rows[i].key == key {
				return &rows[i]
			}
		}
		return nil
	}
	// sessions with rev=true: 8 is refused (the validator re-asks), "-" unsets
	s := rowOf("sessions", true)
	if s == nil {
		t.Fatal("no sessions row")
	}
	rest := feed("8\n-\n")
	patch, ok := s.ask("udp")
	rest()
	if !ok || len(patch.set) != 0 || len(patch.drop) != 1 || patch.drop[0] != "sessions" {
		t.Errorf("reverse sessions ask = %+v (ok %v), want 8 refused then a drop", patch, ok)
	}
	// with rev=false the same answer sets the key (the flag reached the validator)
	s = rowOf("sessions", false)
	rest = feed("8\n")
	patch, ok = s.ask("udp")
	rest()
	if !ok || patch.set["sessions"] != "8" {
		t.Errorf("direct sessions ask = %+v (ok %v), want sessions 8 set", patch, ok)
	}
	// the fake-mode list: sum/seqsum only off-reverse
	opts := scepterFakeModes(true)
	for _, o := range opts {
		if o.v == "sum" || o.v == "seqsum" {
			t.Errorf("reverse fake-mode picker offers %q (the engine refuses it)", o.v)
		}
	}
	have := map[string]bool{}
	for _, o := range opts {
		have[o.v] = true
	}
	if !have["rst"] || !have["seq"] || !have["ttl"] {
		t.Error("the reverse fake-mode picker lost its usable modes")
	}
	opts = scepterFakeModes(false)
	have = map[string]bool{}
	for _, o := range opts {
		have[o.v] = true
	}
	if !have["sum"] || !have["seqsum"] {
		t.Error("the direct fake-mode picker must still offer sum/seqsum")
	}
}

// The port-offset row is a plain flag like the "Other key" row always
// admitted: the standard prompt sets it, the row no longer claims it needs a
// future engine command (round-3 finding).
func TestScepterPortOffsetRow(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	rows := scepterKeyRows("udp", false)
	var row *scepterKeyRow
	for i := range rows {
		if rows[i].key == "port-offset" {
			row = &rows[i]
		}
	}
	if row == nil {
		t.Fatal("no port-offset row")
	}
	if row.ask == nil {
		t.Fatal("port-offset must be settable (the grey row lied)")
	}
	rest := feed("99999\n500\n")
	patch, ok := row.ask("udp")
	rest()
	if !ok || patch.set["port-offset"] != "500" {
		t.Errorf("port-offset ask = %+v (ok %v), want 99999 refused then 500 set", patch, ok)
	}
	rest = feed("0\n")
	patch, ok = row.ask("udp")
	rest()
	if !ok || len(patch.drop) != 1 || patch.drop[0] != "port-offset" {
		t.Errorf("port-offset 0 = %+v (ok %v), want a drop (0 is the engine default)", patch, ok)
	}
}

// The command id carries the process id (seamed): two manager processes
// minting on the same coarse Windows clock tick would collide and the
// engine's journal would replay the wrong outcome into the other process
// (round-3 finding).
func TestScepterNewIDPidSeam(t *testing.T) {
	old := scepterPID
	defer func() { scepterPID = old }()
	scepterPID = 111
	a := scepterNewID()
	scepterPID = 222
	b := scepterNewID()
	if a == b {
		t.Errorf("ids from different pid seams collided: %q", a)
	}
	if !strings.HasPrefix(a, "mgr111-") || !strings.HasPrefix(b, "mgr222-") {
		t.Errorf("id shape = %q / %q, want mgr<pid>-<nano>-<seq>", a, b)
	}
}

// The in-memory caches (pair statuses, rotation markers) drop entries older
// than 24 h: a renamed or deleted tunnel's entry must not live forever in a
// long-running manager (round-3 finding).
func TestScepterCachePruned(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\npairing: true\n"), 0o600)
	oldFetch, oldBy := scepterStatusFetch, scepterStatusBy
	fetches := 0
	scepterStatusFetch = func(string) string { fetches++; return "Kharej 3.5.0" }
	scepterStatusBy = map[string]scepterStatusEntry{
		"gone": {txt: "stale", at: time.Now().Add(-25 * time.Hour)},
	}
	defer func() { scepterStatusFetch, scepterStatusBy = oldFetch, oldBy }()
	ScepterPairStatus("ir")
	scepterStatusMu.Lock()
	_, live := scepterStatusBy["gone"]
	n := len(scepterStatusBy)
	scepterStatusMu.Unlock()
	if live {
		t.Error("the stale status entry survived the prune")
	}
	if n != 1 || fetches != 1 {
		t.Errorf("status cache = %d entries after %d fetch(es), want only the fresh one", n, fetches)
	}
	// the rotation markers prune the same way
	oldRot := scepterRotBy
	scepterRotBy = map[string]time.Time{"gone": time.Now().Add(-25 * time.Hour)}
	defer func() { scepterRotBy = oldRot }()
	scepterRotMark("ir")
	scepterRotMu.Lock()
	_, live = scepterRotBy["gone"]
	scepterRotMu.Unlock()
	if live {
		t.Error("the stale rotation marker survived the prune")
	}
	if scepterRotSuffix("ir") == "" {
		t.Error("the fresh rotation marker is missing")
	}
	if scepterRotSuffix("gone") != "" {
		t.Error("a pruned marker must not render")
	}
}

// The delete screen carries the band like every other screen (round-3
// cosmetic), and the delete still works end to end.
func TestScepterRemoteDeleteBand(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"tunnel.delete": {{r: ScepterResult{Code: scepterCodeOK, Params: map[string]any{"backup": "web.yml.bak"}}}},
	}}
	defer feed("web\n0")() // type the name, pause
	out := capture(t, func() { scepterRemoteDelete(cl, "web") })
	if len(cl.cmds["tunnel.delete"]) != 1 || cl.cmds["tunnel.delete"][0]["confirm"] != "web" {
		t.Errorf("delete args = %v", cl.cmds["tunnel.delete"])
	}
	if !strings.Contains(out, "Deleted. Backup on Kharej") {
		t.Errorf("the outcome is missing:\n%s", out)
	}
	if !strings.Contains(out, strings.Repeat("─", uiW())) {
		t.Errorf("the delete screen lacks the GradBand rule:\n%s", out)
	}
}
