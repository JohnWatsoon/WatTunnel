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
	}{
		{"ports", "p443\nx0", "tunnel.edit"},
		{"config key", "ksmax-mbps\n5\nx0", "tunnel.edit"},
		{"preset", "zsx0", "preset.apply"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := &scriptClient{byCmd: map[string][]scriptAns{
				"state.get": {{r: doc}, {r: doc}}, // page entry + the post-action refresh
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
}
