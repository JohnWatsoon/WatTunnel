package mgr

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The phase D ops surfaces (plan D; docs/TECHNICAL.md "Phase D commands:
// operations"): arg shapes, the parsers, the capability gates, the screen
// flows — all against the stubbed ScepterClient seam, like the phase A-C
// scepter tests. Nothing here dials a real channel.

func TestScepterUpdateRunArgs(t *testing.T) {
	// a target rides as `to`; empty means latest and stays absent
	args := scepterUpdateRunArgs("v3.6.0", "mgr1")
	if args["id"] != "mgr1" || args["to"] != "v3.6.0" {
		t.Errorf("args = %v", args)
	}
	args = scepterUpdateRunArgs("", "mgr2")
	if _, present := args["to"]; present {
		t.Errorf("empty target must stay absent: %v", args)
	}
	if args["id"] != "mgr2" {
		t.Errorf("id = %v", args["id"])
	}
}

func TestScepterUpdateRunIdempotentRetry(t *testing.T) {
	InitColor(false, 8)
	// update.run is the scariest intent: a transport failure after an unclear
	// outcome must resend the SAME command id, so the Kharej journal replays
	// the recorded started answer instead of starting a second update.
	old := NonInteractive
	NonInteractive = true
	defer func() { NonInteractive = old }()
	started := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"run": "upd-1", "to": "v3.6.0", "phase": "started", "grace_s": float64(3)}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"update.run": {{e: fmt.Errorf("channel dead mid-update")}, {r: started}},
	}}
	res, ok := scepterRun(cl, "update.run", func(_ uint64, id string) map[string]any {
		return scepterUpdateRunArgs("v3.6.0", id)
	}, 0)
	if !ok || res.Code != scepterCodeOK {
		t.Fatalf("retry did not land: %+v %v", res, ok)
	}
	sent := cl.cmds["update.run"]
	if len(sent) != 2 || sent[0]["id"] == "" || sent[0]["id"] != sent[1]["id"] {
		t.Errorf("update.run retry must reuse the command id: %v vs %v", sent[0]["id"], sent[1]["id"])
	}
}

func TestScepterTagValidator(t *testing.T) {
	InitColor(false, 8)
	for _, s := range []string{"", "  ", "3.6.0", "v3.6.0", "3.5.1", "10.20.30"} {
		if !vScepterTag(s) {
			t.Errorf("tag %q rejected", s)
		}
	}
	for _, s := range []string{"3.6", "3", "v", "3.6.0.1", "3.6.x", "3.-6.0", "12345.1.2", "3.6.0-beta"} {
		if vScepterTag(s) {
			t.Errorf("tag %q accepted", s)
		}
	}
}

func TestScepterAuditTailArgs(t *testing.T) {
	// empty = the engine's default 100; the 1000 cap is mirrored client-side
	for n, want := range map[int]int{0: 100, -3: 100, 42: 42, 1000: 1000, 5000: 1000} {
		args := scepterAuditTailArgs(n)
		if got := args["n"].(int); got != want {
			t.Errorf("scepterAuditTailArgs(%d).n = %d, want %d", n, got, want)
		}
	}
}

func TestScepterLogsOf(t *testing.T) {
	// chunked reassembly: []string (the transport parser's shape)
	if got := scepterLogsOf(map[string]any{"logs": []string{"a", "b"}}); len(got) != 2 || got[1] != "b" {
		t.Errorf("[]string form = %v", got)
	}
	// small answer: the JSON-roundtripped []any form
	if got := scepterLogsOf(map[string]any{"logs": []any{"a", "b"}}); len(got) != 2 || got[1] != "b" {
		t.Errorf("[]any form = %v", got)
	}
	// non-strings and missing logs never become fake documents
	if got := scepterLogsOf(map[string]any{"logs": []any{1, "a"}}); len(got) != 1 {
		t.Errorf("mixed list = %v", got)
	}
	if scepterLogsOf(map[string]any{}) != nil || scepterLogsOf(nil) != nil {
		t.Error("missing logs must be nil")
	}
}

func TestScepterParseBackupDoc(t *testing.T) {
	// a real tarball, the engine's BackupExport payload shape
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range []struct{ name, body string }{{"web.yml", "mode: server\n"}, {"web.key", "k\n"}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o600, Size: int64(len(f.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	sum := sha256.Sum256(buf.Bytes())
	doc, _ := json.Marshal(map[string]any{"b64": base64.StdEncoding.EncodeToString(buf.Bytes()),
		"sha256": hex.EncodeToString(sum[:]), "size": buf.Len(), "files": 2})
	d, raw, err := scepterParseBackupDoc(string(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.Files != 2 || !bytes.Equal(raw, buf.Bytes()) {
		t.Errorf("doc = %+v, raw %d bytes", d, len(raw))
	}
	// a corrupted reassembly is caught by the document's own sha256/size
	bad := map[string]any{}
	json.Unmarshal(doc, &bad)
	bad["sha256"] = strings.Repeat("0", 64)
	b, _ := json.Marshal(bad)
	if _, _, err := scepterParseBackupDoc(string(b)); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("tampered sha accepted: %v", err)
	}
	json.Unmarshal(doc, &bad)
	bad["size"] = float64(buf.Len() - 1)
	b, _ = json.Marshal(bad)
	if _, _, err := scepterParseBackupDoc(string(b)); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Errorf("size mismatch accepted: %v", err)
	}
	if _, _, err := scepterParseBackupDoc("not json"); err == nil {
		t.Error("garbage document accepted")
	}
	if _, _, err := scepterParseBackupDoc(`{"sha256":"ab"}`); err == nil {
		t.Error("incomplete document accepted")
	}
}

func TestScepterParseUpdStatus(t *testing.T) {
	// the engine's update.status answer: evidence, units, mailbox, staging
	p := map[string]any{
		"ver": "3.5.0", "goos": "linux", "arch": "amd64", "systemd": true,
		"bin": "/usr/local/bin/wattun", "conf": "/etc/wattun",
		"prev": map[string]any{"present": true, "path": "/usr/local/bin/wattun.prev",
			"bytes": float64(15 << 20), "mtime": float64(1763999999), "ver": "3.4.9"},
		"units": []any{
			map[string]any{"name": "web", "active": true},
			map[string]any{"name": "kh", "active": false},
		},
		"update": map[string]any{"phase": "applied", "run": "upd-1", "from": "3.4.9", "to": "v3.5.0",
			"ts": float64(1763999999)},
		"staged": map[string]any{"bytes": float64(4096)},
	}
	s, err := scepterParseUpdStatus(p)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Ver != "3.5.0" || !s.Systemd || !s.PrevPresent || s.PrevVer != "3.4.9" || s.PrevMtime != 1763999999 {
		t.Errorf("head/prev = %+v", s)
	}
	if len(s.Units) != 2 || !s.Units[0].Active || s.Units[1].Active {
		t.Errorf("units = %+v", s.Units)
	}
	if s.Mail == nil || s.Mail.Phase != "applied" || s.Mail.To != "v3.5.0" {
		t.Errorf("mailbox = %+v", s.Mail)
	}
	if s.StagedBytes != 4096 {
		t.Errorf("staged = %d", s.StagedBytes)
	}
	// no update ever run: prev present=false, no mailbox record — parsed, not invented
	s, err = scepterParseUpdStatus(map[string]any{"ver": "3.5.0", "prev": map[string]any{"present": false}})
	if err != nil || s.PrevPresent || s.Mail != nil {
		t.Errorf("bare answer: %+v err=%v", s, err)
	}
	if _, err := scepterParseUpdStatus(nil); err == nil {
		t.Error("nil params accepted")
	}
}

func TestScepterRenderRows(t *testing.T) {
	// doctor.fetch's nested document flattens to sorted dotted-path rows
	rows := scepterRenderRows(map[string]any{
		"ver":     "3.5.0",
		"latch":   map[string]any{"armed": false, "port": float64(0)},
		"recent":  []any{map[string]any{"cmd": "state.get", "code": float64(0)}},
		"tunnels": []string{"web"},
	})
	want := []string{"latch.armed: false", "latch.port: 0", "recent[0].cmd: state.get",
		"recent[0].code: 0", "tunnels[0]: web", "ver: 3.5.0"}
	if len(rows) != len(want) {
		t.Fatalf("rows = %v, want %v", rows, want)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("rows[%d] = %q, want %q", i, rows[i], want[i])
		}
	}
}

func TestScepterOpsCapGating(t *testing.T) {
	InitColor(false, 8)
	manage := CapTunnel | CapCreate | CapManage
	full := manage | CapFull
	// the ops menu hides what the pairing does not cover: manage-only has no
	// update.run item (client-side UX; Kharej's CapFull check is the real gate)
	items := scepterOpsItems(manage)
	if len(items) != 4 {
		t.Fatalf("manage-only ops items = %d, want 4", len(items))
	}
	for _, it := range items {
		if it.Key == "u" {
			t.Error("update.run must be hidden without the full capability")
		}
	}
	items = scepterOpsItems(full)
	if len(items) != 5 || items[len(items)-1].Key != "u" {
		t.Errorf("full ops items = %+v", items)
	}
	// a direct call refuses too, before any RPC (the action repeats its gate)
	cl := &scriptClient{}
	old := NonInteractive
	NonInteractive = true
	defer func() { NonInteractive = old }()
	out := capture(t, func() { scepterUpdateRun("ir", cl, manage) })
	if !strings.Contains(out, "'full' capability") {
		t.Errorf("manage-only update.run refused without the reason:\n%s", out)
	}
	if len(cl.cmds) != 0 {
		t.Errorf("a gated update.run must not reach the channel: %v", cl.cmds)
	}
	// and the pair screen hides the whole ops item without manage
	pairItems, _ := scepterPairItems(scepterDoc{}, "", CapTunnel|CapCreate)
	for _, it := range pairItems {
		if it.Key == "o" {
			t.Error("the ops item must be hidden without the manage capability")
		}
	}
	pairItems, _ = scepterPairItems(scepterDoc{}, "", manage)
	found := false
	for _, it := range pairItems {
		if it.Key == "o" {
			found = true
		}
	}
	if !found {
		t.Error("the ops item must be there with manage")
	}
}

func TestScepterOpsMenuSmoke(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	defer feed("0")()
	cl := &scriptClient{}
	out := capture(t, func() { scepterOpsScreen("ir", cl, CapTunnel|CapCreate|CapManage) })
	for _, want := range []string{"Update status", "Doctor", "Export backup", "Audit trail"} {
		if !strings.Contains(out, want) {
			t.Errorf("ops menu missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Run update") {
		t.Error("manage-only ops menu must not offer update.run")
	}
}

func TestScepterUpdateStatusView(t *testing.T) {
	InitColor(false, 8)
	st := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "goos": "linux", "arch": "amd64", "systemd": true,
		"bin": "/usr/local/bin/wattun",
		"prev": map[string]any{"present": true, "path": "/usr/local/bin/wattun.prev",
			"bytes": float64(15 << 20), "mtime": float64(1763999999), "ver": "3.4.9"},
		"units": []any{map[string]any{"name": "web", "active": true}},
		"update": map[string]any{"phase": "started", "run": "upd-1", "from": "3.4.9", "to": "latest",
			"ts": float64(1763999999)},
	}}
	cl := stubClient{st}
	out := capture(t, func() { scepterUpdateStatusView(cl) })
	for _, want := range []string{"3.5.0", "linux/amd64", "systemd yes", "wattun.prev", "3.4.9",
		"web", "●", "started · run upd-1", "3.4.9 → latest"} {
		if !strings.Contains(out, want) {
			t.Errorf("update status view missing %q:\n%s", want, out)
		}
	}
	// a started mailbox record carries the survival semantics: the journal
	// replays for the same command id, the revived engine reports the outcome
	if !strings.Contains(out, "journal replays") || !strings.Contains(out, "interrupted") {
		t.Errorf("started record must explain the journal-replay semantics:\n%s", out)
	}
	// no prev evidence: the watchdog gate says so, honestly
	cl2 := stubClient{ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "prev": map[string]any{"present": false}}}}
	out = capture(t, func() { scepterUpdateStatusView(cl2) })
	if !strings.Contains(out, "No wattun.prev evidence") || !strings.Contains(out, "backup path") {
		t.Errorf("absent prev evidence not surfaced:\n%s", out)
	}
}

func TestScepterUpdateRunConfirmFlow(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	oldP := P.Conf
	P.Conf = dir
	defer func() { P.Conf = oldP }()
	// the full flow through the ops menu: pick Run update, type the target,
	// answer the HARD confirm (default no) with y, pause, leave.
	started := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"run": "upd-1", "to": "v3.6.0", "phase": "started", "grace_s": float64(3)}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"update.run": {{r: started}},
	}}
	defer feed("uv3.6.0\nyx0")()
	out := capture(t, func() { scepterOpsScreen("ir", cl, CapTunnel|CapCreate|CapManage|CapFull) })
	// the drop warning and the survival contract are on the screen BEFORE the confirm
	for _, want := range []string{"channel WILL drop", "latch", "journal", "Update status",
		"Update accepted", "upd-1", "Nothing moves for 3 s"} {
		if !strings.Contains(out, want) {
			t.Errorf("update.run flow missing %q:\n%s", want, out)
		}
	}
	sent := cl.cmds["update.run"]
	if len(sent) != 1 || sent[0]["to"] != "v3.6.0" || sent[0]["id"] == "" {
		t.Errorf("update.run args = %v", sent)
	}
	// an empty target means latest: the args carry no `to` at all
	cl1 := &scriptClient{byCmd: map[string][]scriptAns{"update.run": {{r: started}}}}
	defer feed("u\nyx0")()
	capture(t, func() { scepterOpsScreen("ir", cl1, CapTunnel|CapCreate|CapManage|CapFull) })
	if sent1 := cl1.cmds["update.run"]; len(sent1) != 1 {
		t.Fatalf("empty-target flow sent %v", sent1)
	} else if _, present := sent1[0]["to"]; present {
		t.Errorf("an empty target must send no `to`: %v", sent1[0])
	}
	// the hard confirm defaults to no: `n` cancels and sends nothing
	cl2 := &scriptClient{}
	defer feed("u\nnx0")()
	out = capture(t, func() { scepterOpsScreen("ir", cl2, CapTunnel|CapCreate|CapManage|CapFull) })
	if !strings.Contains(out, "Cancelled") || len(cl2.cmds) != 0 {
		t.Errorf("default answer must cancel update.run:\n%s / %v", out, cl2.cmds)
	}
}

func TestScepterDoctorView(t *testing.T) {
	dir := scepterCarrierTestConf(t)
	writeTestYml(t, dir, "ir", "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n")
	res := ScepterResult{Code: scepterCodeOK, Params: map[string]any{
		"ver": "3.5.0", "state_seq": float64(9),
		"latch":  map[string]any{"armed": false, "enabled": true, "port": float64(20443)},
		"recent": []any{map[string]any{"cmd": "update.status", "code": float64(0)}},
		"update": map[string]any{"phase": "applied", "run": "upd-1"},
	}}
	out := capture(t, func() { scepterDoctorView("ir", stubClient{res}) })
	if Cfg("ir", "latch-port") != "20443" {
		t.Errorf("doctor answer must self-heal the client latch-port, got %q", Cfg("ir", "latch-port"))
	}
	for _, want := range []string{"latch.armed: false", "recent[0].cmd: update.status",
		"update.phase: applied", "ver: 3.5.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor view missing %q:\n%s", want, out)
		}
	}
}

func TestScepterAuditView(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	// the engine answers two source documents (audit + journal), raw lines;
	// the viewer prints them verbatim and r refreshes the same tail
	da, _ := json.Marshal(map[string]any{"src": "audit", "entries": []string{
		"2026-11-22T08:00:00Z pair 1b0e6a52 full",
		"2026-11-22T08:05:00Z revoke 1b0e6a52",
	}})
	dj, _ := json.Marshal(map[string]any{"src": "journal", "entries": []string{
		`{"id":"c1","cmd":"state.get","code":0}`,
	}})
	res := ScepterResult{Code: scepterCodeOK, Params: map[string]any{"logs": []any{string(da), string(dj)}}}
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"audit.tail": {{r: res}, {r: res}, {r: res}}, // fetch, the r refresh, the final redraw
	}}
	defer feed("a\nrx0")()
	out := capture(t, func() { scepterOpsScreen("ir", cl, CapTunnel|CapCreate|CapManage) })
	for _, want := range []string{".pairing.audit", ".pairing.journal", "(2 line(s))", "(1 line(s))",
		"revoke 1b0e6a52", `"cmd":"state.get"`} {
		if !strings.Contains(out, want) {
			t.Errorf("audit view missing %q:\n%s", want, out)
		}
	}
	// the ask went out with the mirrored default n=100 (empty input)
	sent := cl.cmds["audit.tail"]
	if len(sent) == 0 || sent[0]["n"] != 100 {
		t.Errorf("audit.tail n = %v, want 100", sent[0]["n"])
	}
}

func TestScepterBackupExportView(t *testing.T) {
	InitColor(false, 8)
	NonInteractive = false
	dir := t.TempDir()
	oldP := P.Conf
	P.Conf = dir
	defer func() { P.Conf = oldP }()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range []struct{ name, body string }{{"a.yml", "mode: server\n"}, {"a.key", "k\n"}} {
		tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o600, Size: int64(len(f.body))})
		tw.Write([]byte(f.body))
	}
	tw.Close()
	sum := sha256.Sum256(buf.Bytes())
	doc, _ := json.Marshal(map[string]any{"b64": base64.StdEncoding.EncodeToString(buf.Bytes()),
		"sha256": hex.EncodeToString(sum[:]), "size": buf.Len(), "files": 2})
	cl := &scriptClient{byCmd: map[string][]scriptAns{
		"backup.export": {{r: ScepterResult{Code: scepterCodeOK,
			Params: map[string]any{"logs": []any{string(doc)}}}}},
	}}
	defer feed("b\nx0")() // pick Export backup, keep the default save path, leave
	out := capture(t, func() { scepterOpsScreen("ir", cl, CapTunnel|CapCreate|CapManage) })
	if !strings.Contains(out, "Backup saved") || !strings.Contains(out, "2 file(s)") ||
		!strings.Contains(out, "sha256 verified") {
		t.Errorf("backup export outcome missing:\n%s", out)
	}
	m, _ := filepath.Glob(filepath.Join(dir, "ir-backup-*.tar"))
	if len(m) != 1 {
		t.Fatalf("backup file not written under the conf dir: %v", m)
	}
	got, _ := os.ReadFile(m[0])
	if !bytes.Equal(got, buf.Bytes()) {
		t.Error("the saved tarball differs from the verified payload")
	}
	// a checksum mismatch writes nothing — the failure is honest, no file
	bad, _ := json.Marshal(map[string]any{"b64": base64.StdEncoding.EncodeToString(buf.Bytes()),
		"sha256": strings.Repeat("0", 64), "size": buf.Len(), "files": 2})
	cl2 := &scriptClient{byCmd: map[string][]scriptAns{
		"backup.export": {{r: ScepterResult{Code: scepterCodeOK,
			Params: map[string]any{"logs": []any{string(bad)}}}}},
	}}
	defer feed("b\nx0")()
	out = capture(t, func() { scepterOpsScreen("ir", cl2, CapTunnel|CapCreate|CapManage) })
	if !strings.Contains(out, "checksum mismatch") {
		t.Errorf("checksum mismatch not surfaced:\n%s", out)
	}
	m, _ = filepath.Glob(filepath.Join(dir, "ir-backup-*.tar"))
	if len(m) != 1 { // still only the first export
		t.Errorf("a failed export must not write a file: %v", m)
	}
	// Kharej's own cap refusal rides through as code 8 with its hint
	cl3 := &scriptClient{byCmd: map[string][]scriptAns{
		"backup.export": {{r: ScepterResult{Code: scepterCodeTooLarge,
			Params: map[string]any{"why": "config dir larger than the 5 MB export cap"}}}},
	}}
	defer feed("bx0")()
	out = capture(t, func() { scepterOpsScreen("ir", cl3, CapTunnel|CapCreate|CapManage) })
	if !strings.Contains(out, "answered code 8") || !strings.Contains(out, "5 MB export cap") {
		t.Errorf("too_large not surfaced honestly:\n%s", out)
	}
}

func TestScepterHiddenFilter(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	// one paired Iran tunnel, the scepter artifacts around it: a Kharej-side
	// probe yml (test.open's throw-away listener, mode server), an auto helper
	// that carries a pairing key (it must still never be a pair), and the
	// dotfile state (pairing store/audit/journal/mailbox — never *.yml at all)
	ir := "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n"
	os.WriteFile(filepath.Join(dir, "irp.yml"), []byte(ir+"pairing: true\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "probe-1763999999.yml"), []byte("mode: server\ncarrier: udp\nlisten: :20500\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "h-e-x.yml"), []byte(ir+"pairing: true\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "h-e-x.autoext"), []byte(""), 0o600)
	os.WriteFile(filepath.Join(dir, ".pairing"), []byte("store"), 0o600)
	os.WriteFile(filepath.Join(dir, ".pairing.audit"), []byte("audit"), 0o600)
	os.WriteFile(filepath.Join(dir, ".update.status"), []byte("{}"), 0o600)
	// the dotfiles and the helper never reach the visible tunnel list at all
	names := Tunnels()
	for _, n := range names {
		if strings.HasPrefix(n, ".") || n == "h-e-x" {
			t.Errorf("hidden state leaked into Tunnels(): %v", names)
		}
	}
	if !slicesContain(names, "irp") {
		t.Errorf("the paired tunnel is not listed: %v", names)
	}
	// the fleet is pairs only: the probe yml is a Kharej config, the helper is
	// auto-hidden — neither can become a row, pairing key or not
	pairs := pairedTunnels()
	if len(pairs) != 1 || pairs[0] != "irp" {
		t.Errorf("pairedTunnels() = %v, want [irp]", pairs)
	}
}

func slicesContain(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestScepterOpsReachableFromPairScreen pins the E.4 completeness rule: the
// ops item rides the pair screen's action list with manage, and every phase
// A-C view still has its key on that screen.
func TestScepterOpsReachableFromPairScreen(t *testing.T) {
	InitColor(false, 8)
	doc := scepterDoc{Tunnels: []scepterTunRow{{Name: "web", Carrier: "udp"}}}
	items, rows := scepterPairItems(doc, "", CapTunnel|CapCreate|CapManage|CapFull)
	keys := map[string]bool{}
	for _, it := range items {
		if it.Key != "" {
			keys[it.Key] = true
		}
	}
	for _, k := range []string{"n", "t", "a", "o", "s", "e", "h"} { // B: create, C: probe+auto+rows, A: state/events/hello, D: ops
		if !keys[k] {
			t.Errorf("pair screen lost the %q item: %+v", k, items)
		}
	}
	if len(rows) != 1 || rows[0].Name != "web" {
		t.Errorf("remote tunnel rows = %+v", rows)
	}
	// the ops menu itself stays complete with full: five items, update last
	ops := scepterOpsItems(CapTunnel | CapCreate | CapManage | CapFull)
	if len(ops) != 5 || ops[0].Key != "s" || ops[len(ops)-1].Key != "u" {
		t.Errorf("ops items = %+v", ops)
	}
	// the tunnel page keeps every phase B/C action: stats, logs, carrier,
	// ports, key, preset, limits, restart, up/down, delete
	page := scepterTunnelItems(scepterTunRow{Name: "web", State: "active"}, CapTunnel|CapCreate|CapManage|CapFull)
	pkeys := map[string]bool{}
	for _, it := range page {
		pkeys[it.Key] = true
	}
	for _, k := range []string{"s", "l", "c", "p", "k", "z", "q", "r", "u", "d"} {
		if !pkeys[k] {
			t.Errorf("tunnel page lost the %q action: %+v", k, page)
		}
	}
}

// TestScepterTunnelPageCapHint pins the E.4 fix: a tunnel-only credential gets
// an empty action list and the head explains why instead of stranding the reader.
func TestScepterTunnelPageCapHint(t *testing.T) {
	InitColor(false, 8)
	var buf bytes.Buffer
	scepterTunnelHead(&buf, "ir", scepterTunRow{Name: "web", Carrier: "udp", State: "active", Health: "ok"}, 3, CapTunnel)
	if !strings.Contains(buf.String(), "'manage' capability") {
		t.Errorf("tunnel-only head must explain the empty action list:\n%s", buf.String())
	}
	buf.Reset()
	scepterTunnelHead(&buf, "ir", scepterTunRow{Name: "web", Carrier: "udp", State: "active", Health: "ok"}, 3,
		CapTunnel|CapCreate|CapManage)
	if strings.Contains(buf.String(), "'manage' capability") {
		t.Errorf("manage tier must not carry the gating hint:\n%s", buf.String())
	}
}
