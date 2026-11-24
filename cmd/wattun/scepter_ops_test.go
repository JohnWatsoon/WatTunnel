// Scepter write-side cmd tests (3.5.0, phase B): the REAL fileScepterOps against a temp CONF dir with real
// files — the full validate → backup → apply → verify → rollback flow without systemd (a fake unit runner
// records actions and can kill starts at will), plus the -scepter-call argument contract the Go manager uses.
// The handler/protocol layer is pinned in wat/scepter_test.go against the fake ops.

package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// fakeUnits is the systemd stand-in: every action recorded, liveness tracked, and a unit can be marked dead
// so a start "succeeds" while the verify sees nothing up — exactly how a bad config fails on a real host.
type fakeUnits struct {
	mu      sync.Mutex
	actions []string
	active  map[string]bool
	dead    map[string]bool
}

func newFakeUnits() *fakeUnits {
	return &fakeUnits{active: map[string]bool{}, dead: map[string]bool{}}
}

func (fu *fakeUnits) unit(name, action string) error {
	fu.mu.Lock()
	defer fu.mu.Unlock()
	fu.actions = append(fu.actions, name+":"+action)
	switch action {
	case "start", "restart":
		fu.active[name] = !fu.dead[name]
	case "stop":
		fu.active[name] = false
	}
	return nil
}

func (fu *fakeUnits) isActive(name string) bool {
	fu.mu.Lock()
	defer fu.mu.Unlock()
	return fu.active[name]
}

func (fu *fakeUnits) did(action string) bool {
	fu.mu.Lock()
	defer fu.mu.Unlock()
	for _, a := range fu.actions {
		if a == action {
			return true
		}
	}
	return false
}

func (fu *fakeUnits) count(action string) int {
	fu.mu.Lock()
	defer fu.mu.Unlock()
	n := 0
	for _, a := range fu.actions {
		if a == action {
			n++
		}
	}
	return n
}

func testOps2(t *testing.T) (*fileScepterOps, *fakeUnits, string) {
	t.Helper()
	fu := newFakeUnits()
	// known stands in for main's flag.Lookup closure (the real flags register in main(), which tests never run)
	knownKeys := map[string]bool{"peer": true, "ping-every": true, "listen": true, "reverse": true,
		"sni": true, "path": true, "host": true, "icmp-type": true, "metrics": true, "carrier": true}
	o := &fileScepterOps{conf: t.TempDir(), self: "self", maxTunnels: scepterMaxTunnels,
		unit: fu.unit, active: fu.isActive,
		known: func(k string) bool { return knownKeys[k] }, logf: func(string, ...any) {}}
	return o, fu, o.conf
}

func TestFileScepterOpsCreateRoundTrip(t *testing.T) {
	o, fu, _ := testOps2(t)
	spec := wat.ScepterTunnelSpec{Name: "t1", Carrier: "udp", Ports: "20030,8443:443/udp",
		Params: map[string]string{"peer": "198.51.100.7", "ping-every": "5"}, Key: "k1234567890123456789012345678901234567890"}
	p, code := o.Create(spec)
	if code != wat.CodeOK {
		t.Fatalf("create: %d %v", code, p)
	}
	if p["name"] != "t1" || p["key"] != spec.Key {
		t.Fatalf("create params: %v", p)
	}
	metrics, _ := p["metrics"].(string)
	if !strings.HasPrefix(metrics, "127.0.0.1:") {
		t.Fatalf("create assigned no loopback metrics port: %v", p)
	}
	tok, _ := p["token"].(string)
	if tok == "" || !strings.HasPrefix(tok, "wat1:") {
		t.Fatalf("client-facing create must return a token: %v", p)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(tok, "wat1:"))
	if err != nil {
		t.Fatalf("token base64: %v", err)
	}
	f := strings.Split(string(raw), "|")
	if len(f) != 7 || f[0] != "udp" || f[1] != "198.51.100.7" || f[2] != spec.Key || f[6] != "20030,443" {
		// trailing empty fields dropped (reverse unset): exactly the manager's make_token shape
		t.Fatalf("token fields: %#v", f)
	}
	y := mustReadExisting(t, filepath.Join(o.conf, "t1.yml"))
	for _, want := range []string{"mode: server", "key: " + spec.Key, "carrier: udp", "metrics: " + metrics,
		"peer: 198.51.100.7", "ping-every: 5", "ports:", "  - 20030", "  - 8443:443/udp", "# created by scepter"} {
		if !strings.Contains(y, want) {
			t.Fatalf("yml missing %q:\n%s", want, y)
		}
	}
	if b, err := os.ReadFile(filepath.Join(o.conf, "t1.key")); err != nil || strings.TrimSpace(string(b)) != spec.Key {
		t.Fatalf("key file: %v %q", err, b)
	}
	if _, err := os.Stat(filepath.Join(o.conf, "t1.token")); err != nil {
		t.Fatal("no token file")
	}
	if !fu.did("t1:start") {
		t.Fatal("unit was not started")
	}
	// a nameless create picks tunnel, tunnel-2 … (each binds its own listen port: t1 holds the udp default)
	if p, code = o.Create(wat.ScepterTunnelSpec{Carrier: "udp", Ports: "20031", Key: spec.Key,
		Params: map[string]string{"listen": ":20031"}}); code != wat.CodeOK || p["name"] != "tunnel" {
		t.Fatalf("suggested name: %d %v", code, p)
	}
	// Handoff 4 R4: the answer carries what the cockpit needs to build the token itself
	if p["listen_port"] != 20031 || p["allow"] != "20031" {
		t.Fatalf("listen_port/allow for the cockpit: %v", p)
	}
	if p, _ := o.Create(wat.ScepterTunnelSpec{Carrier: "udp", Ports: "20032", Key: spec.Key,
		Params: map[string]string{"listen": ":20032"}}); p["name"] != "tunnel-2" {
		t.Fatalf("second suggested name: %v", p)
	}
	// no leftover tmp files: every write was atomic
	if m, _ := filepath.Glob(filepath.Join(o.conf, "*.tmp")); len(m) != 0 {
		t.Fatalf("leftover tmp files: %v", m)
	}
}

func TestFileScepterOpsCreateRejections(t *testing.T) {
	o, _, _ := testOps2(t)
	if err := os.WriteFile(filepath.Join(o.conf, "x.yml"), []byte("mode: server\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := wat.ScepterTunnelSpec{Name: "x", Carrier: "udp", Ports: "20030", Key: "kk"}
	if p, code := o.Create(spec); code != wat.CodeNameTaken || p["name"] != "x" {
		t.Fatalf("name_taken: %d %v", code, p)
	}
	if p, code := o.Create(wat.ScepterTunnelSpec{Name: "../evil", Carrier: "udp", Ports: "1", Key: "kk"}); code != wat.CodeBadRequest {
		t.Fatalf("bad name: %d %v", code, p)
	}
	if p, code := o.Create(wat.ScepterTunnelSpec{Carrier: "udp", Ports: "20030,bad-port", Key: "kk"}); code != wat.CodeBadRequest {
		t.Fatalf("bad ports: %d %v", code, p)
	}
	if p, code := o.Create(wat.ScepterTunnelSpec{Name: "y", Carrier: "nope-carrier", Ports: "1", Key: "kk"}); code != wat.CodeBadRequest {
		t.Fatalf("unknown carrier: %d %v", code, p)
	}
	// the raw carriers need Linux + CAP_NET_RAW: on this Windows checkout carrier_needs, on Linux CI it creates
	if p, code := o.Create(wat.ScepterTunnelSpec{Name: "raw1", Carrier: "icmp", Ports: "1", Key: "kk"}); runtime.GOOS != "linux" && (code != wat.CodeCarrierNeeds || p["need"] != "linux+CAP_NET_RAW") {
		t.Fatalf("carrier_needs: %d %v", code, p)
	}
	// params: owned keys and unknown keys are rejected before any file is touched
	for _, bad := range []string{"mode", "key", "ports", "carrier", "config", "pair", "state-dir", "no-such-flag"} {
		p, code := o.Create(wat.ScepterTunnelSpec{Carrier: "udp", Ports: "1", Key: "kk",
			Params: map[string]string{bad: "1"}})
		if code != wat.CodeBadRequest {
			t.Fatalf("param %q accepted: %d %v", bad, code, p)
		}
	}
	// round-2 F4 (2026-11-22): metrics and key-file are keys the ops write themselves — a param metrics
	// would double the key, a param key-file would shadow the ops-written key. known accepts everything
	// here on purpose: only the deny list stops them.
	o.known = func(string) bool { return true }
	for _, bad := range []string{"metrics", "key-file"} {
		p, code := o.Create(wat.ScepterTunnelSpec{Carrier: "udp", Ports: "1", Key: "kk",
			Params: map[string]string{bad: "1"}})
		if code != wat.CodeBadRequest || p["why"] != "owned by tunnel.create itself" {
			t.Fatalf("param %q must hit the deny list: %d %v", bad, code, p)
		}
	}
	o.known = func(k string) bool {
		return map[string]bool{"peer": true, "ping-every": true, "listen": true, "reverse": true,
			"sni": true, "path": true, "host": true, "icmp-type": true, "metrics": true, "carrier": true}[k]
	}
	// port_busy {port, user}: another tunnel already binds the udp default :4443
	if err := os.WriteFile(filepath.Join(o.conf, "t-old.yml"),
		[]byte("mode: server\ncarrier: udp\nmetrics: 127.0.0.1:19700\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, code := o.Create(wat.ScepterTunnelSpec{Name: "t2", Carrier: "udp", Ports: "1", Key: "kk"})
	if code != wat.CodePortBusy || p["port"] != 4443 || p["user"] != "t-old" {
		t.Fatalf("port_busy: %d %v", code, p)
	}
	// an explicit -listen overrides the default and collides by value
	p, code = o.Create(wat.ScepterTunnelSpec{Name: "t3", Carrier: "tcp", Ports: "1", Key: "kk",
		Params: map[string]string{"listen": ":19700"}})
	if code != wat.CodePortBusy || p["port"] != 19700 || !strings.Contains(p["user"].(string), "metrics") {
		t.Fatalf("metrics collision: %d %v", code, p)
	}
	// a reverse tunnel binds nothing here
	if _, code = o.Create(wat.ScepterTunnelSpec{Name: "t4", Carrier: "udp", Ports: "1", Key: "kk",
		Params: map[string]string{"reverse": "true"}}); code != wat.CodeOK {
		t.Fatalf("reverse create code %d", code)
	}
	o.removeFiles("t4")
	// the tunnel cap (the connlimit pattern): fill the host to the cap, the next create is refused. Every
	// filler binds its own listen port so the only limit reached is the cap.
	for i := len(mustGlobExisting(t, o.conf)); i < o.maxTunnels; i++ {
		fill := wat.ScepterTunnelSpec{Name: "cap" + strconv.Itoa(i), Carrier: "udp", Ports: "1", Key: "kk",
			Params: map[string]string{"listen": fmt.Sprintf(":%d", 30000+i)}}
		if _, code := o.Create(fill); code != wat.CodeOK {
			t.Fatalf("filler create %d failed: %d", i, code)
		}
	}
	if p, code := o.Create(wat.ScepterTunnelSpec{Name: "over", Carrier: "udp", Ports: "1", Key: "kk",
		Params: map[string]string{"listen": ":40000"}}); code != wat.CodeRateLimited || p["cap"] != scepterMaxTunnels {
		t.Fatalf("tunnel cap: %d %v", code, p)
	}
}

// The rollback drill on the real ops: the unit refuses to come up → files removed, code=internal, rolled_back.
func TestFileScepterOpsCreateRollback(t *testing.T) {
	o, fu, _ := testOps2(t)
	fu.dead["rb1"] = true
	p, code := o.Create(wat.ScepterTunnelSpec{Name: "rb1", Carrier: "udp", Ports: "20030", Key: "kk"})
	if code != wat.CodeInternal || p["rolled_back"] != true {
		t.Fatalf("rollback: %d %v", code, p)
	}
	for _, ext := range []string{"yml", "key", "token"} {
		if _, err := os.Stat(filepath.Join(o.conf, "rb1."+ext)); !os.IsNotExist(err) {
			t.Fatalf("rolled-back create left its %s", ext)
		}
	}
	if !fu.did("rb1:stop") {
		t.Fatal("the dead unit was not stopped before cleanup")
	}
	// F10 (2026-11-22): start is enable --now, so the rollback must also DISABLE — a stopped-but-enabled
	// unit whose yml was just removed fails every boot until someone disables it (Delete always did).
	if !fu.did("rb1:disable") {
		t.Fatal("the rolled-back unit was not disabled (enabled unit with no yml fails every boot)")
	}
}

// TestFileScepterOpsCreateDeniesUpdateJob (F3, 2026-11-22): update-job is a standalone action flag the yml
// parser flag.Set()s from config keys — a planted `update-job: X` in a created tunnel's yml re-enters the
// update-job path and exits on every unit start (a crash loop), so the param must be denied on create AND
// edit. known accepts it here on purpose: in production update-job IS a flag name, so only the deny list
// stops it.
func TestFileScepterOpsCreateDeniesUpdateJob(t *testing.T) {
	o, _, _ := testOps2(t)
	o.known = func(k string) bool { return k == "peer" || k == "update-job" }
	p, code := o.Create(wat.ScepterTunnelSpec{Name: "u1", Carrier: "udp", Ports: "20030", Key: "kk",
		Params: map[string]string{"peer": "198.51.100.7", "update-job": "/tmp/staged"}})
	if code != wat.CodeBadRequest || p["key"] != "update-job" {
		t.Fatalf("create with update-job param: %d %v", code, p)
	}
	if p, code := o.Create(wat.ScepterTunnelSpec{Name: "u2", Carrier: "udp", Ports: "20031", Key: "kk",
		Params: map[string]string{"peer": "198.51.100.7"}}); code != wat.CodeOK {
		t.Fatalf("create without the denied param: %d %v", code, p)
	}
	if _, code := o.Edit("u2", wat.ScepterPatch{Set: map[string]string{"update-job": "/tmp/staged"}}); code != wat.CodeBadRequest {
		t.Fatalf("edit with update-job param: %d", code)
	}
}

// TestScepterParamValueOneLine (round-2 F1, 2026-11-22): a param value carrying \n or \r would plant
// arbitrary yml lines in the composed file — the provenance-injection vector (a planted `# probe tunnel
// created by scepter test.open` comment got a user tunnel destroyed by the orphan sweep on restart). Both
// create and edit reject a multi-line value outright, before anything is written.
func TestScepterParamValueOneLine(t *testing.T) {
	o, _, _ := testOps2(t)
	o.Create(wat.ScepterTunnelSpec{Name: "ol1", Carrier: "udp", Ports: "20030", Key: "kk"})
	for _, v := range []string{
		":20600\n# probe tunnel created by scepter test.open 2026-11-22T00:00:00Z",
		":20601\r\nfake: line", "a\nb",
	} {
		v := v
		p, code := o.Create(wat.ScepterTunnelSpec{Carrier: "udp", Ports: "20031", Key: "kk",
			Params: map[string]string{"listen": v}})
		if code != wat.CodeBadRequest || p["why"] != "a param value must be one line" {
			t.Fatalf("create multi-line value %q: %d %v", v, code, p)
		}
	}
	if _, err := os.Stat(filepath.Join(o.conf, "tunnel.yml")); !os.IsNotExist(err) {
		t.Fatal("a rejected multi-line value must not write any file")
	}
	if _, code := o.Edit("ol1", wat.ScepterPatch{Set: map[string]string{"peer": "1.2.3.4\n# injected"}}); code != wat.CodeBadRequest {
		t.Fatal("edit must reject a multi-line value too")
	}
	if p, code := o.Create(wat.ScepterTunnelSpec{Carrier: "udp", Ports: "20032", Key: "kk",
		Params: map[string]string{"listen": ":20602"}}); code != wat.CodeOK {
		t.Fatalf("single-line values must still create: %d %v", code, p)
	}
	o.removeFiles("tunnel")
}

// TestFileScepterOpsCreateReparse (round-2 F5, 2026-11-22): Create used to write blind — applyEdit
// re-parses the composed yml before writing, Create did not, so a value containing ` #` was silently
// truncated by stripComment and the unit ran with a different value than the cockpit asked for. The
// composed text is now re-parsed (and round-trip checked) BEFORE any file moves.
func TestFileScepterOpsCreateReparse(t *testing.T) {
	o, _, _ := testOps2(t)
	// `a"b'c" #d` carries BOTH quote kinds balanced before the ` #`, so scepterYMLValue gives up and writes
	// it raw, stripComment cuts ` #d` off, and the unit would run with `a"b'c"` instead of what the cockpit
	// asked for. (One quote kind alone survives via that kind's wrapping; an unbalanced quote keeps the
	// `#` inside the quote — those round-trip, which is exactly why the re-parse check is needed.)
	p, code := o.Create(wat.ScepterTunnelSpec{Name: "rp1", Carrier: "udp", Ports: "20030", Key: "kk",
		Params: map[string]string{"peer": `a"b'c" #d`}})
	if code != wat.CodeBadRequest {
		t.Fatalf("a value that truncates on re-parse must be refused: %d %v", code, p)
	}
	for _, ext := range []string{"yml", "key", "token"} {
		if _, err := os.Stat(filepath.Join(o.conf, "rp1."+ext)); !os.IsNotExist(err) {
			t.Fatalf("the refused create left rp1.%s behind", ext)
		}
	}
	// values that survive the round trip still create: the check is exact, not over-broad
	if p, code = o.Create(wat.ScepterTunnelSpec{Name: "rp2", Carrier: "udp", Ports: "20030", Key: "kk",
		Params: map[string]string{"peer": `a"b'c`}}); code != wat.CodeOK {
		t.Fatalf("a both-quote value must still create: %d %v", code, p)
	}
	o.removeFiles("rp2")
	if p, code = o.Create(wat.ScepterTunnelSpec{Name: "rp3", Carrier: "udp", Ports: "20030", Key: "kk",
		Params: map[string]string{"peer": `a" #b`}}); code != wat.CodeOK {
		t.Fatalf("a single-quote-wrappable value must still create: %d %v", code, p)
	}
	o.removeFiles("rp3")
}

// TestFileScepterOpsProbeCap (F7, 2026-11-22): probe units count toward scepterMaxTunnels — openProbe checks
// the cap like create does (their ymls live in the conf dir, so tunnelCount already counts them; the check
// just never ran here), and a sustained test.open is rate-limited instead of holding units past the cap.
func TestFileScepterOpsProbeCap(t *testing.T) {
	o, _, _ := testOps2(t)
	o.maxTunnels = 1 // one unit total, probes included
	link, _ := linkStub()
	o.linkCheck = link
	p, code := o.TestOpen("udp", 0)
	if code != wat.CodeOK {
		t.Fatalf("first probe under the cap: %v %v", code, p)
	}
	if _, code = o.TestOpen("tcp", 0); code != wat.CodeRateLimited {
		t.Fatalf("second probe must hit the cap: %d", code)
	}
	if p, code = o.TestOpen("udp", 0); code != wat.CodeRateLimited || p["resource"] != "probes" || p["cap"] != 1 {
		t.Fatalf("rate_limited must name the resource: %d %v", code, p)
	}
}

func TestFileScepterOpsEdit(t *testing.T) {
	o, fu, _ := testOps2(t)
	o.Create(wat.ScepterTunnelSpec{Name: "e1", Carrier: "udp", Ports: "20030", Key: "kk"})
	// happy path: set a key, backup exists, unit restarted
	p, code := o.Edit("e1", wat.ScepterPatch{Set: map[string]string{"ping-every": "7"}})
	if code != wat.CodeOK || p["name"] != "e1" {
		t.Fatalf("edit: %d %v", code, p)
	}
	if !fu.did("e1:restart") {
		t.Fatal("edit did not restart the unit")
	}
	y := mustReadExisting(t, filepath.Join(o.conf, "e1.yml"))
	if !strings.Contains(y, "ping-every: 7") || !strings.Contains(y, "carrier: udp") {
		t.Fatalf("edited yml:\n%s", y)
	}
	if old := mustReadExisting(t, filepath.Join(o.conf, "e1.yml.bak")); strings.Contains(old, "ping-every: 7") {
		t.Fatalf("backup is not the pre-edit file:\n%s", old)
	}
	// ports replacement with range normalization, and drop
	if p, code = o.Edit("e1", wat.ScepterPatch{Ports: "20030-20031", Drop: []string{"ping-every"}}); code != wat.CodeOK {
		t.Fatalf("edit ports: %d %v", code, p)
	}
	y = mustReadExisting(t, filepath.Join(o.conf, "e1.yml"))
	if strings.Contains(y, "ping-every") || !strings.Contains(y, "  - 20030") || !strings.Contains(y, "  - 20031") {
		t.Fatalf("ports replacement:\n%s", y)
	}
	// a carrier switch reports the new carrier (the handler turns it into carrier_switched)
	if p, code = o.Edit("e1", wat.ScepterPatch{Set: map[string]string{"carrier": "tcp"}}); code != wat.CodeOK || p["carrier"] != "tcp" {
		t.Fatalf("carrier edit: %d %v", code, p)
	}
	// reject: unknown target, empty patch, owned keys, a patch that would not parse
	if _, code = o.Edit("nope", wat.ScepterPatch{Set: map[string]string{"a": "b"}}); code != wat.CodeNotFound {
		t.Fatalf("missing edit: %d", code)
	}
	if _, code = o.Edit("e1", wat.ScepterPatch{}); code != wat.CodeBadRequest {
		t.Fatalf("empty patch: %d", code)
	}
	if _, code = o.Edit("e1", wat.ScepterPatch{Set: map[string]string{"mode": "client"}}); code != wat.CodeBadRequest {
		t.Fatalf("owned key edit: %d", code)
	}
	if _, code = o.Edit("e1", wat.ScepterPatch{Set: map[string]string{"no-such-flag": "1"}}); code != wat.CodeBadRequest {
		t.Fatalf("unknown key edit: %d", code)
	}
	// self is refused: the cockpit channel rides this unit
	if p, code = o.Edit("self", wat.ScepterPatch{Set: map[string]string{"ping-every": "9"}}); code != wat.CodeBadRequest || p["self"] != "self" {
		t.Fatalf("self edit: %d %v", code, p)
	}
	// rollback drill: the unit refuses the new config, the old file is restored and brought back up
	fu.dead["e1"] = true
	before := mustReadExisting(t, filepath.Join(o.conf, "e1.yml"))
	restarts := fu.count("e1:restart")
	if p, code = o.Edit("e1", wat.ScepterPatch{Set: map[string]string{"ping-every": "9"}}); code != wat.CodeInternal || p["rolled_back"] != true {
		t.Fatalf("edit rollback: %d %v", code, p)
	}
	if now := mustReadExisting(t, filepath.Join(o.conf, "e1.yml")); now != before {
		t.Fatalf("rollback did not restore the pre-edit file:\n%s", now)
	}
	if fu.count("e1:restart") <= restarts {
		t.Fatal("rollback did not restart the unit with the restored config")
	}
}

func TestFileScepterOpsDeleteAndUnit(t *testing.T) {
	o, fu, _ := testOps2(t)
	o.Create(wat.ScepterTunnelSpec{Name: "d1", Carrier: "udp", Ports: "20030", Key: "kk"})
	if _, code := o.Unit("d1", "frobnicate"); code != wat.CodeBadRequest {
		t.Fatalf("bad action: %d", code)
	}
	if p, code := o.Unit("d1", "stop"); code != wat.CodeOK || p["state"] != "inactive" {
		t.Fatalf("stop: %d %v", code, p)
	}
	if p, code := o.Unit("d1", "start"); code != wat.CodeOK || p["state"] != "active" {
		t.Fatalf("start: %d %v", code, p)
	}
	if _, code := o.Unit("nope", "start"); code != wat.CodeNotFound {
		t.Fatalf("unit of missing tunnel: %d", code)
	}
	if _, code := o.Unit("self", "restart"); code != wat.CodeBadRequest {
		t.Fatalf("self restart: %d", code)
	}
	if _, code := o.Delete("self"); code != wat.CodeBadRequest {
		t.Fatalf("self delete: %d", code)
	}
	// delete: stop first, then everything aside to .bak (reversible by construction)
	if p, code := o.Delete("d1"); code != wat.CodeOK || p["stopped"] != true {
		t.Fatalf("delete: %d %v", code, p)
	}
	for _, ext := range []string{"yml", "key"} {
		if _, err := os.Stat(filepath.Join(o.conf, "d1."+ext)); !os.IsNotExist(err) {
			t.Fatalf("deleted %s still live", ext)
		}
		if _, err := os.Stat(filepath.Join(o.conf, "d1."+ext+".bak")); err != nil {
			t.Fatalf("deleted %s kept no .bak", ext)
		}
	}
	if !fu.did("d1:stop") {
		t.Fatal("delete did not stop the unit")
	}
	if !fu.did("d1:disable") { // round-2 F6 (2026-11-22): the disable goes through the o.unit seam like
		// every other unit action — Delete was the one direct runSystemctl caller left
		t.Fatal("delete did not disable the unit")
	}
	if _, code := o.Delete("d1"); code != wat.CodeNotFound {
		t.Fatalf("second delete: %d", code)
	}
	// a unit that will not stop deletes nothing: stop "succeeds" but liveness stays active
	wedgedActive := true
	wedged := &fileScepterOps{conf: o.conf, self: "self", maxTunnels: scepterMaxTunnels,
		unit: func(name, action string) error { // the stop command "works", the unit ignores it
			if name == "d2" && action == "stop" {
				return nil
			}
			return fu.unit(name, action)
		},
		active: func(name string) bool { return name == "d2" && wedgedActive || fu.isActive(name) },
		logf:   func(string, ...any) {}}
	wedged.Create(wat.ScepterTunnelSpec{Name: "d2", Carrier: "udp", Ports: "20031", Key: "kk"})
	if _, code := wedged.Delete("d2"); code != wat.CodeInternal {
		t.Fatalf("undeletable unit: %d", code)
	}
	if _, err := os.Stat(filepath.Join(o.conf, "d2.yml")); err != nil {
		t.Fatal("the yml of a tunnel that would not stop was moved anyway")
	}
}

func TestFileScepterOpsLimits(t *testing.T) {
	o, fu, _ := testOps2(t)
	o.Create(wat.ScepterTunnelSpec{Name: "l1", Carrier: "udp", Ports: "20030", Key: "kk"})
	if p, code := o.SetLimits("l1", []string{"20030 rate=5MB quota=100GB period=month", "8443 quota=1GB"}); code != wat.CodeOK || p["limits"] != 2 {
		t.Fatalf("limits: %d %v", code, p)
	}
	y := mustReadExisting(t, filepath.Join(o.conf, "l1.yml"))
	if !strings.Contains(y, "limits:") || !strings.Contains(y, "  - 20030 rate=5MB quota=100GB period=month") {
		t.Fatalf("limits block:\n%s", y)
	}
	// the parseLimitItem round-trip: what the watcher will hot-reload parses
	cfg, err := parseConfig(y, nil)
	if err != nil || len(cfg.Limits) != 2 || cfg.Limits[0].Port != 20030 || cfg.Limits[1].Quota != 1e9 {
		t.Fatalf("limits re-parse: %v %+v", err, cfg.Limits)
	}
	if _, code := o.SetLimits("l1", nil); code != wat.CodeOK {
		t.Fatalf("clear limits: %d", code)
	}
	if cfg2, _ := parseConfig(mustReadExisting(t, filepath.Join(o.conf, "l1.yml")), nil); len(cfg2.Limits) != 0 {
		t.Fatalf("limits not cleared: %+v", cfg2.Limits)
	}
	if fu.did("l1:restart") || fu.did("l1:stop") {
		t.Fatal("limits.set must be hot-reload only, no unit op")
	}
	if _, code := o.SetLimits("l1", []string{"20030 rate=bogus"}); code != wat.CodeBadRequest {
		t.Fatalf("bad limit item: %d", code)
	}
	if _, code := o.SetLimits("l1", []string{"20030 rate=1MB", "20030 quota=1GB"}); code != wat.CodeBadRequest {
		t.Fatalf("duplicate limit port: %d", code)
	}
	if _, code := o.SetLimits("nope", nil); code != wat.CodeNotFound {
		t.Fatalf("limits of missing tunnel: %d", code)
	}
}

func TestParseScepterCallArgs(t *testing.T) {
	a, id, err := parseScepterCallArgs("")
	if err != nil || id != "" || len(a) != 0 {
		t.Fatalf("empty args: %v %q %v", a, id, err)
	}
	a, id, err = parseScepterCallArgs(`{"name":"t1","carrier":"udp","ports":"20030","id":"retry-7","n":3}`)
	if err != nil {
		t.Fatal(err)
	}
	if id != "retry-7" {
		t.Fatalf("id not lifted: %q", id)
	}
	if _, ok := a["id"]; ok {
		t.Fatal("id left in the args")
	}
	if a["name"] != "t1" || a["n"] != float64(3) {
		t.Fatalf("args: %v", a)
	}
	if _, _, err = parseScepterCallArgs("{bad json"); err == nil {
		t.Fatal("bad JSON accepted")
	}
	// test.close regression (2026-11-22): the probe rides "probe", NOT "id" — a top-level "id" is
	// lifted as the command id and deleted, so a probe sent as "id" never reached the engine and
	// every cockpit test.close came back code=1 (bad_request). Pin both halves of the split.
	a, id, err = parseScepterCallArgs(`{"probe":"p-42","id":"retry-9"}`)
	if err != nil {
		t.Fatal(err)
	}
	if id != "retry-9" || a["probe"] != "p-42" {
		t.Fatalf("probe/id split broken: id=%q args=%v", id, a)
	}
	if _, ok := a["id"]; ok {
		t.Fatal("lifted id left in the args")
	}
}

// The token builder is the manager's make_token twin: same 7 base fields, field 8 only when reverse.
func TestScepterTokenShape(t *testing.T) {
	ports, err := parseScepterPortItems("20030,8443:443/udp,9000-9002")
	if err != nil {
		t.Fatal(err)
	}
	spec := wat.ScepterTunnelSpec{Carrier: "udp", Key: "kk", Params: map[string]string{"peer": "203.0.113.9"}}
	tok := scepterToken(spec, ports)
	if tok == "" {
		t.Fatal("peer known, token expected")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(tok, "wat1:"))
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Split(string(raw), "|")
	if len(f) != 7 || f[6] != "20030,443,9000,9001,9002" {
		t.Fatalf("token fields: %#v", f)
	}
	spec.Params["reverse"] = "true"
	raw2, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(scepterToken(spec, ports), "wat1:"))
	if err != nil {
		t.Fatal(err)
	}
	f = strings.Split(string(raw2), "|")
	if len(f) != 8 || f[7] != "1" {
		t.Fatalf("reverse token: %#v", f)
	}
	spec.Params["peer"] = ""
	if scepterToken(spec, ports) != "" {
		t.Fatal("no peer: no token (the cockpit fills the peer itself)")
	}
}

func mustReadExisting(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustGlobExisting(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// ---- phase C: probe listeners, carrier change, the auto-test core ----

// linkStub is the link-check seam every probe/change test needs: the fake units bind no real sockets, so the
// production dialer would (correctly) report nothing listening. The stub records what it was asked to check.
func linkStub() (func(carrier string, binds map[int]string) error, *[]string) {
	var calls []string
	return func(carrier string, binds map[int]string) error {
		ps := make([]int, 0, len(binds))
		for p := range binds {
			ps = append(ps, p)
		}
		sort.Ints(ps)
		calls = append(calls, fmt.Sprintf("%s:%v", carrier, ps))
		return nil
	}, &calls
}

func TestFileScepterOpsTestOpenLifecycle(t *testing.T) {
	o, fu, _ := testOps2(t)
	o.probeMinS = 1 // the ttl-expiry drill must not wait the documented 10 s floor
	link, calls := linkStub()
	o.linkCheck = link
	// rejections before anything is written or started
	if p, code := o.TestOpen("tcp+udp", 0); code != wat.CodeBadRequest {
		t.Fatalf("bond probe: %v %v", code, p)
	}
	if p, code := o.TestOpen("icmp", 0); runtime.GOOS != "linux" && code != wat.CodeCarrierNeeds {
		t.Fatalf("raw-carrier probe on %s: %v %v", runtime.GOOS, code, p)
	} else if runtime.GOOS == "linux" && (code != wat.CodeBadRequest || p["why"] == "") {
		t.Fatalf("raw-carrier probe on linux: %v %v", code, p)
	}
	if p, code := o.TestOpen("nope-carrier", 0); code != wat.CodeBadRequest {
		t.Fatalf("unknown carrier: %v %v", code, p)
	}
	if len(*calls) != 0 || fu.count("start") != 0 {
		t.Fatal("a rejected probe must not touch units or the link check")
	}
	// open: the dial parameters come back, the speed-test-only yml is on disk, the unit is up
	p, code := o.TestOpen("udp", 0)
	if code != wat.CodeOK {
		t.Fatalf("open: %v %v", code, p)
	}
	id := p["id"].(string)
	port := p["port"].(int)
	if port < 20500 || port >= 21000 || p["key"] == "" || p["ttl"] != 300 {
		t.Fatalf("open params: %v", p)
	}
	if !fu.did(id + ":start") {
		t.Fatal("probe unit was not started")
	}
	y := mustReadExisting(t, filepath.Join(o.conf, id+".yml"))
	cfg, err := parseConfig(y, nil)
	if err != nil || !cfg.PortsSet || len(cfg.Ports) != 0 {
		t.Fatalf("probe yml must be a speed-test-only unit (empty ports list): %v\n%s", err, y)
	}
	if !strings.Contains(y, "carrier: udp") || !strings.Contains(y, fmt.Sprintf("listen: :%d", port)) || !strings.Contains(y, probeProvenance) {
		t.Fatalf("probe yml shape:\n%s", y)
	}
	// a second open lands on another name and port
	p2, code := o.TestOpen("tcp", 0)
	if code != wat.CodeOK || p2["port"] == port || p2["id"] == id {
		t.Fatalf("second open: %v %v", code, p2)
	}
	// explicit close: files gone, unit stopped, the id is no longer known
	if _, code = o.TestClose(id); code != wat.CodeOK {
		t.Fatal("close")
	}
	if _, err := os.Stat(filepath.Join(o.conf, id+".yml")); !os.IsNotExist(err) {
		t.Fatal("closed probe left its yml")
	}
	if !fu.did(id + ":stop") {
		t.Fatal("closed probe did not stop its unit")
	}
	// round-2 F2 (2026-11-22): start is enable --now, so every probe teardown must disable too — a
	// stopped-but-enabled unit with no yml fails every boot (the F10 rollback rule).
	if !fu.did(id + ":disable") {
		t.Fatal("closed probe did not disable its unit")
	}
	if _, code = o.TestClose(id); code != wat.CodeNotFound {
		t.Fatalf("double close: %v", code)
	}
	// ttl expiry: the shortest ttl the ops accept, then the timer must have done the same thing
	p3, code := o.TestOpen("udp", 1)
	if code != wat.CodeOK || p3["ttl"] != 1 {
		t.Fatalf("short-ttl open: %v %v", code, p3)
	}
	id3 := p3["id"].(string)
	deadline := time.Now().Add(4 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(o.conf, id3+".yml")); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the probe was not removed at ttl expiry")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !fu.did(id3 + ":stop") {
		t.Fatal("expired probe did not stop its unit")
	}
	if !fu.did(id3 + ":disable") { // round-2 F2: the ttl teardown disables like test.close does
		t.Fatal("expired probe did not disable its unit")
	}
	o.TestClose(p2["id"].(string))
	// the restart-orphan sweep (what newFileScepterOps runs at startup) takes exactly the ymls carrying the
	// probe provenance line: an engine restart forgets its timers, so the previous life's probes must not
	// linger, while a user tunnel merely named probe-something stays.
	p4, code := o.TestOpen("ws", 300)
	if code != wat.CodeOK {
		t.Fatalf("ws open: %v %v", code, p4)
	}
	time.Sleep(1100 * time.Millisecond) // probe names are second-granular: let the next open get its own name
	p5, _ := o.TestOpen("h2c", 300)
	o.TestClose(p5["id"].(string))
	userYML := filepath.Join(o.conf, "probe-user.yml")
	if err := os.WriteFile(userYML, []byte("mode: server\ncarrier: udp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// simulate the previous life: p4's files exist on disk but the live map forgot it
	orphan := p4["id"].(string)
	o.TestClose(orphan)
	os.WriteFile(o.path(orphan, "yml"), []byte("# "+probeProvenance+"\nmode: server\n"), 0o600)
	o.orphanSweep = false
	o.sweepOrphanProbes()
	if _, err := os.Stat(o.path(orphan, "yml")); !os.IsNotExist(err) {
		t.Fatal("orphan sweep left a provenance-marked probe yml")
	}
	if !fu.did(orphan + ":stop") {
		t.Fatal("orphan sweep did not stop the orphaned probe unit")
	}
	if !fu.did(orphan + ":disable") { // round-2 F2: the sweep disables like the probe teardowns do
		t.Fatal("orphan sweep did not disable the orphaned probe unit")
	}
	if _, err := os.Stat(userYML); err != nil {
		t.Fatal("sweep removed a user tunnel named probe-*")
	}
	os.Remove(userYML)
	// round-2 F1 (2026-11-22): the sweep matches the provenance only as the FIRST line of the yml — the
	// injection was a param value with an embedded newline planting the provenance comment mid-file, which
	// strings.Contains happily matched and got a user tunnel destroyed on restart. (New creates reject
	// multi-line values; ymls written before that rule are what this pin guards.)
	inj := filepath.Join(o.conf, "probe-injected.yml")
	if err := os.WriteFile(inj, []byte("mode: server\ncarrier: udp\nlisten: :20610\nnote: \"a\n# "+probeProvenance+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o.orphanSweep = false
	o.sweepOrphanProbes()
	if _, err := os.Stat(inj); err != nil {
		t.Fatal("the sweep destroyed a user tunnel whose mid-file value planted the provenance comment")
	}
	os.Remove(inj)
}

func TestFileScepterOpsCarrierChangeRollback(t *testing.T) {
	o, fu, _ := testOps2(t)
	link, calls := linkStub()
	o.linkCheck = link
	o.Create(wat.ScepterTunnelSpec{Name: "c1", Carrier: "udp", Ports: "20030", Key: "kk",
		Params: map[string]string{"listen": ":20100"}})
	// happy change: carrier key swapped, unit restarted, the link check saw the new bind, listen reported
	p, code := o.CarrierChange("c1", "tcp", nil)
	if code != wat.CodeOK || p["carrier"] != "tcp" || p["listen"] != 20100 {
		t.Fatalf("carrier change: %v %v", code, p)
	}
	y := mustReadExisting(t, filepath.Join(o.conf, "c1.yml"))
	if !strings.Contains(y, "carrier: tcp") || !strings.Contains(y, "listen: :20100") {
		t.Fatalf("change did not land:\n%s", y)
	}
	if fu.count("c1:restart") != 1 {
		t.Fatalf("change restarted the unit %d time(s)", fu.count("c1:restart"))
	}
	if len(*calls) != 1 {
		t.Fatalf("link check ran %d time(s)", len(*calls))
	}
	// params ride along (the cockpit moves the listen port with the shape)
	if p, code = o.CarrierChange("c1", "udp", map[string]string{"listen": ":20101"}); code != wat.CodeOK || p["listen"] != 20101 {
		t.Fatalf("change with params: %v %v", code, p)
	}
	// rejections: unknown shape, missing tunnel, self
	if _, code = o.CarrierChange("c1", "nope-carrier", nil); code != wat.CodeBadRequest {
		t.Fatal("unknown carrier accepted")
	}
	if _, code = o.CarrierChange("missing", "tcp", nil); code != wat.CodeNotFound {
		t.Fatal("missing tunnel accepted")
	}
	if _, code = o.CarrierChange("self", "tcp", nil); code != wat.CodeBadRequest {
		t.Fatal("self change accepted")
	}
	before := mustReadExisting(t, filepath.Join(o.conf, "c1.yml"))
	// rollback drill A: the unit refuses the new config — .bak restored, restarted again, rolled_back
	fu.dead["c1"] = true
	restarts := fu.count("c1:restart")
	if p, code = o.CarrierChange("c1", "tcp", nil); code != wat.CodeInternal || p["rolled_back"] != true {
		t.Fatalf("dead-unit change: %v %v", code, p)
	}
	if now := mustReadExisting(t, filepath.Join(o.conf, "c1.yml")); now != before {
		t.Fatalf("rollback did not restore:\n%s", now)
	}
	if fu.count("c1:restart") <= restarts {
		t.Fatal("rollback did not restart with the restored config")
	}
	// rollback drill B: the unit comes up but the link check fails — same contract
	fu.dead["c1"] = false
	o.linkCheck = func(string, map[int]string) error { return fmt.Errorf("link check: nothing accepting") }
	before = mustReadExisting(t, filepath.Join(o.conf, "c1.yml"))
	if p, code = o.CarrierChange("c1", "tcp", nil); code != wat.CodeInternal || p["rolled_back"] != true ||
		!strings.Contains(p["detail"].(string), "link check") {
		t.Fatalf("link-failure change: %v %v", code, p)
	}
	if now := mustReadExisting(t, filepath.Join(o.conf, "c1.yml")); now != before {
		t.Fatal("link-failure rollback did not restore the config")
	}
	if fu.count("c1:restart") <= restarts {
		t.Fatal("link-failure rollback did not restart the restored unit")
	}
}

// Multi-tunnel port bookkeeping (plan C.3): two remote creates take distinct metrics ports and listens, a
// live probe blocks its own port against a third create, and probes count toward the tunnel cap.
func TestFileScepterOpsMultiTunnelPorts(t *testing.T) {
	o, _, _ := testOps2(t)
	o.maxTunnels = 3 // small cap: two tunnels + one probe fill it
	link, _ := linkStub()
	o.linkCheck = link
	p1, code := o.Create(wat.ScepterTunnelSpec{Name: "m1", Carrier: "udp", Ports: "20030", Key: "kk",
		Params: map[string]string{"listen": ":20110"}})
	if code != wat.CodeOK {
		t.Fatalf("m1: %v %v", code, p1)
	}
	p2, code := o.Create(wat.ScepterTunnelSpec{Name: "m2", Carrier: "tcp", Ports: "20031", Key: "kk",
		Params: map[string]string{"listen": ":20111"}})
	if code != wat.CodeOK {
		t.Fatalf("m2: %v %v", code, p2)
	}
	m1, m2 := p1["metrics"].(string), p2["metrics"].(string)
	if m1 == "" || m2 == "" || m1 == m2 {
		t.Fatalf("metrics ports collided or missing: %q %q", m1, m2)
	}
	// a live probe is bookkept like any unit: its port is busy, and it fills the cap
	pr, code := o.TestOpen("udp", 300)
	if code != wat.CodeOK {
		t.Fatalf("probe open: %v %v", code, pr)
	}
	pp := pr["port"].(int)
	p3, code := o.Create(wat.ScepterTunnelSpec{Name: "m3", Carrier: "udp", Ports: "20032", Key: "kk",
		Params: map[string]string{"listen": fmt.Sprintf(":%d", pp)}})
	if code != wat.CodePortBusy || p3["user"] != pr["id"] || p3["port"] != pp {
		t.Fatalf("create on the probe's port: %v %v (probe id %v)", code, p3, pr["id"])
	}
	if p, code := o.Create(wat.ScepterTunnelSpec{Name: "m4", Carrier: "udp", Ports: "20033", Key: "kk",
		Params: map[string]string{"listen": ":20112"}}); code != wat.CodeRateLimited || p["cap"] != 3 {
		t.Fatalf("cap with a live probe: %v %v", code, p)
	}
	o.TestClose(pr["id"].(string))
	// the probe's port is free again; the cap slot is free again
	if _, code = o.Create(wat.ScepterTunnelSpec{Name: "m5", Carrier: "udp", Ports: "20034", Key: "kk",
		Params: map[string]string{"listen": fmt.Sprintf(":%d", pp)}}); code != wat.CodeOK {
		t.Fatalf("create on the closed probe's port: %v", code)
	}
}

// The auto-test core: the trigger answers before the run, a second trigger sees already_running, the table
// ranks servable shapes by rate, and row 1 applies through the carrier-change path.
func TestFileScepterOpsAutoTest(t *testing.T) {
	o, _, _ := testOps2(t)
	link, _ := linkStub()
	o.linkCheck = link
	o.Create(wat.ScepterTunnelSpec{Name: "t1", Carrier: "udp", Ports: "20030", Key: "kk",
		Params: map[string]string{"listen": ":20120"}})
	hold := make(chan struct{})
	o.runProbe = func(pr *scepterProbe) (float64, bool, string) {
		<-hold
		switch pr.carrier {
		case "udp":
			return 0, false, "no link"
		case "ws":
			return 7.0, true, ""
		case "h2c":
			return 3.0, true, ""
		default:
			return 9.5, true, ""
		}
	}
	if p, code := o.AutoTest("nope", nil); code != wat.CodeBadRequest || p["modes"] != "plain,tls" {
		t.Fatalf("unknown mode: %v %v", code, p)
	}
	p, code := o.AutoTest("", nil)
	if code != wat.CodeOK || p["mode"] != "plain" || p["shapes"] != 4 || p["run"] == "" {
		t.Fatalf("auto.test: %v %v", code, p)
	}
	run := p["run"].(string)
	// while the run holds on shape 1, a second trigger reports already_running and a row apply refuses
	p2, code := o.AutoTest("plain", nil)
	if code != wat.CodeOK || p2["already_running"] != true || p2["run"] != run {
		t.Fatalf("second trigger: %v %v", code, p2)
	}
	if p, code = o.ApplyRow("t1", 1); code != wat.CodeNotFound || !strings.Contains(p["why"].(string), "still going") {
		t.Fatalf("apply while running: %v %v", code, p)
	}
	close(hold)
	deadline := time.Now().Add(8 * time.Second)
	for {
		p, _ = o.AutoRows()
		if done, _ := p["done"].(bool); done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("auto-test run never finished")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if p["run"] != run || p["ok"] != 3 {
		t.Fatalf("rows head: %v", p)
	}
	rows := p["rows"].([]autoRow)
	if len(rows) != 4 || rows[0].Carrier != "tcp" || rows[0].DownMbps != 9.5 || rows[0].Rank != 1 ||
		rows[1].Carrier != "ws" || rows[2].Carrier != "h2c" || rows[3].Carrier != "udp" || rows[3].OK {
		t.Fatalf("ranking: %+v", rows)
	}
	// row 1 applies via the carrier-change path; out-of-range rows are not_found
	if p, code = o.ApplyRow("t1", 1); code != wat.CodeOK || p["carrier"] != "tcp" || p["row"] != 1 {
		t.Fatalf("apply row 1: %v %v", code, p)
	}
	if y := mustReadExisting(t, filepath.Join(o.conf, "t1.yml")); !strings.Contains(y, "carrier: tcp") {
		t.Fatalf("apply did not land:\n%s", y)
	}
	if p, code = o.ApplyRow("t1", 9); code != wat.CodeNotFound || p["why"] == nil {
		t.Fatalf("out-of-range row: %v %v", code, p)
	}
	// round-2 F3 (2026-11-22): a failed row (Port 0, nothing to check) must not apply — CarrierChange over
	// an empty bind map made the link check trivially pass and would switch the carrier to a shape this
	// host measurably cannot serve. Row 4 is the failed udp row (ranked last).
	if p, code = o.ApplyRow("t1", 4); code != wat.CodeBadRequest || !strings.Contains(p["why"].(string), "row 4 is a failed measurement") {
		t.Fatalf("apply failed row: %v %v", code, p)
	}
	if y := mustReadExisting(t, filepath.Join(o.conf, "t1.yml")); !strings.Contains(y, "carrier: tcp") {
		t.Fatalf("the refused row must not touch the config:\n%s", y)
	}
	// the run's probes are closed: nothing lingers
	if m, _ := filepath.Glob(filepath.Join(o.conf, "probe-*.yml")); len(m) != 0 {
		t.Fatalf("auto-test left probe units: %v", m)
	}
}

// The link check against REAL loopback sockets: TCP must connect, UDP must accept-and-drop the junk byte, and
// both must fail against a closed port.
func TestDialBindPort(t *testing.T) {
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			c.Close() // a probe listener accepts and waits; the check only needs the accept
		}
	}()
	tcpPort := tl.Addr().(*net.TCPAddr).Port
	if err := dialBindPort(tcpPort, false, time.Second); err != nil {
		t.Fatalf("tcp bind check: %v", err)
	}
	ul, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	udpPort := ul.LocalAddr().(*net.UDPAddr).Port
	if err := dialBindPort(udpPort, true, time.Second); err != nil {
		t.Fatalf("udp bind check: %v", err)
	}
	// closed ports: grab one, release it, then check
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := dead.Addr().(*net.TCPAddr).Port
	dead.Close()
	if err := dialBindPort(deadPort, false, 300*time.Millisecond); err == nil {
		t.Fatal("tcp check accepted a closed port")
	}
	if err := dialBindPort(deadPort, true, 300*time.Millisecond); err == nil {
		t.Fatal("udp check accepted a closed port")
	}
}

// The throw-away client command line the auto-test core spawns (pure; the production spawn uses it verbatim).
func TestProbeClientArgs(t *testing.T) {
	pr := &scepterProbe{id: "probe-1", carrier: "wss", port: 20505, key: "kk"}
	args := probeClientArgs(pr, "127.0.0.1:19750", 20506)
	want := []string{"-mode", "client", "-carrier", "wss", "-key", "kk", "-peer", "127.0.0.1:20505",
		"-metrics", "127.0.0.1:19750", "-map", "20506:1@127.0.0.1"}
	if len(args) != len(want) {
		t.Fatalf("args: %v", args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q (full: %v)", i, args[i], want[i], args)
		}
	}
}

// ---- phase D: update orchestration, doctor, backup.export, audit.tail ----

// update.status: local evidence only — version, wattun.prev (with its -version), unit states, the mailbox
// and the staging state. Never a network fetch.
func TestFileScepterOpsUpdateStatus(t *testing.T) {
	o, fu, conf := testOps2(t)
	if err := os.WriteFile(filepath.Join(conf, "t1.yml"), []byte("mode: server\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fu.active["t1"] = true
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "wattun")
	if err := os.WriteFile(bin, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin+".prev", []byte("PREV"), 0o755); err != nil {
		t.Fatal(err)
	}
	o.updPrevVer = func(string) string { return "3.4.9" }
	o.exePath = func() (string, error) { return bin, nil } // the test binary is not a wattun; point at the sandbox
	writeUpdateStatus(conf, wat.ScepterUpdateStatus{Phase: wat.UpdatePhaseApplied, Run: "u1",
		From: "3.4.9", To: wat.Version, Ts: time.Now().Unix()})
	p, code := o.UpdateStatus()
	if code != wat.CodeOK || p["ver"] != wat.Version {
		t.Fatalf("update.status: %v %v", code, p)
	}
	if p["systemd"] != systemdAvailable() { // the field reports the host: false on Windows, true on a systemd CI runner
		t.Fatalf("systemd on %s: %v", runtime.GOOS, p["systemd"])
	}
	prev := p["prev"].(map[string]any)
	if prev["present"] != true || prev["ver"] != "3.4.9" {
		t.Fatalf("prev evidence: %v", prev)
	}
	units := p["units"].([]map[string]any)
	if len(units) != 1 || units[0]["name"] != "t1" || units[0]["active"] != true {
		t.Fatalf("units: %v", units)
	}
	up := p["update"].(*wat.ScepterUpdateStatus)
	if up.Phase != wat.UpdatePhaseApplied || up.Run != "u1" {
		t.Fatalf("mailbox: %+v", up)
	}
	if _, ok := p["staged"]; ok {
		t.Fatal("no staging expected yet")
	}
	if err := os.MkdirAll(filepath.Join(conf, scepterUpdateDirF), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(conf, scepterUpdateDirF, "wattun.new"), []byte("NEW"), 0o700)
	p, _ = o.UpdateStatus()
	if st, ok := p["staged"].(map[string]any); !ok || st["bytes"] != int64(3) {
		t.Fatalf("staged evidence: %v", p["staged"])
	}
}

// The response-flush ordering, pinned structurally at the ops level: UpdateRun returns phase=started BEFORE
// the worker's first action (the grace sleep precedes everything), so the journaled response is long gone
// from the process by the time the job restarts the session's own unit. The gates are portable: on this
// checkout (Windows / no systemd) UpdateRun refuses before anything else.
func TestFileScepterOpsUpdateRunGates(t *testing.T) {
	o, _, _ := testOps2(t)
	if runtime.GOOS != "linux" || !systemdAvailable() {
		p, code := o.UpdateRun("")
		if code != wat.CodeBadRequest || p["why"] == nil {
			t.Fatalf("update.run on a host without systemd: %v %v", code, p)
		}
	} else {
		t.Skip("host runs systemd: the refusal gate cannot be tested here")
	}
	// the tag normalization the ops apply (the handler already validated the shape; the ops re-validate)
	for s, want := range map[string]struct {
		tag string
		ok  bool
	}{"3.6.0": {"v3.6.0", true}, "v3.6.0": {"v3.6.0", true}, "3.6": {"", false},
		"3.6.0.1": {"", false}, "": {"", false}, "three.six": {"", false}} {
		tag, ok := scepterNormTag(s)
		if ok != want.ok || tag != want.tag {
			t.Fatalf("scepterNormTag(%q) = %q,%v want %q,%v", s, tag, ok, want.tag, want.ok)
		}
	}
	// the mailbox-fresh in-flight guard: a started record inside the job window blocks a second job,
	// a stale started record (dead job) and terminal phases do not
	conf := o.conf
	writeUpdateStatus(conf, wat.ScepterUpdateStatus{Phase: wat.UpdatePhaseStarted, Run: "live", Ts: time.Now().Unix()})
	if run, busy := updateJobInFlight(conf); !busy || run != "live" {
		t.Fatalf("fresh started record not in flight: %q %v", run, busy)
	}
	writeUpdateStatus(conf, wat.ScepterUpdateStatus{Phase: wat.UpdatePhaseStarted, Run: "dead",
		Ts: time.Now().Unix() - int64((scepterUpdateWatch+2*scepterUpdateStable)/time.Second) - 10})
	if _, busy := updateJobInFlight(conf); busy {
		t.Fatal("a stale started record still counts as in flight")
	}
	writeUpdateStatus(conf, wat.ScepterUpdateStatus{Phase: wat.UpdatePhaseApplied, Ts: time.Now().Unix()})
	if _, busy := updateJobInFlight(conf); busy {
		t.Fatal("a terminal record counts as in flight")
	}
	// round-2 F7 (2026-11-22): staged — the worker rewrites the mailbox phase=staged with a fresh Ts at
	// LAUNCH, so the revived engine's gate counts from the swap, not from an accept time a long download
	// left behind. Same window semantics as started.
	writeUpdateStatus(conf, wat.ScepterUpdateStatus{Phase: updatePhaseStaged, Run: "swap", Ts: time.Now().Unix()})
	if run, busy := updateJobInFlight(conf); !busy || run != "swap" {
		t.Fatalf("fresh staged record not in flight: %q %v", run, busy)
	}
	writeUpdateStatus(conf, wat.ScepterUpdateStatus{Phase: updatePhaseStaged, Run: "old-swap",
		Ts: time.Now().Unix() - int64((scepterUpdateWatch+2*scepterUpdateStable)/time.Second) - 10})
	if _, busy := updateJobInFlight(conf); busy {
		t.Fatal("a stale staged record still counts as in flight")
	}
}

// The update drill in a sandbox (plan D.3, the manager tests' pattern): the REAL worker and the REAL job
// logic run over fake units and fake binary files — applied when the new engine stays up, rolled_back (with
// wattun.prev restored byte-for-byte) when it refuses to run, failed-untouched when the backup path is gone
// or the staged binary will not execute.
func TestFileScepterOpsUpdateDrill(t *testing.T) {
	newDrill := func(t *testing.T) (*fileScepterOps, *fakeUnits, string, string, string) {
		t.Helper()
		o, fu, conf := testOps2(t)
		if err := os.WriteFile(filepath.Join(conf, "t1.yml"), []byte("mode: server\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		fu.active["t1"] = true // the one pre-active unit (self is inactive in the fake)
		binDir := t.TempDir()
		bin := filepath.Join(binDir, "wattun")
		if err := os.WriteFile(bin, []byte("OLDBIN-3.5.0"), 0o755); err != nil {
			t.Fatal(err)
		}
		o.updGrace = time.Millisecond
		o.updProbe = func(string) (string, error) { return "99.0.0", nil }
		o.updFetch = func(dir, to string) error {
			if to != "latest" {
				t.Errorf("fetch got to %q, want latest", to)
			}
			return os.WriteFile(filepath.Join(dir, "wattun.new"), []byte("NEWBIN-99.0.0"), 0o700)
		}
		return o, fu, conf, bin, filepath.Join(binDir, "wattun.prev")
	}
	// launchViaJob is the sandbox's systemd-run: read the staged job.json, shrink the watch windows, run the
	// REAL job logic over the fake units. deadOnRestart makes the "new engine" refuse to run.
	launchViaJob := func(t *testing.T, fu *fakeUnits, prev string, deadOnRestart bool) func(stage, bin string) error {
		return func(stage, bin string) error {
			jb, err := os.ReadFile(filepath.Join(stage, scepterJobFile))
			if err != nil {
				return err
			}
			var job scepterUpdateJob
			if err := json.Unmarshal(jb, &job); err != nil {
				return err
			}
			job.WatchS, job.StableS = 1, 0 // the sandbox shrinks the windows (40 s / 10 s in production)
			first := true
			runUpdateJob(scepterUpdateEnv{Job: job, Prev: prev,
				restart: func(u string) error {
					if deadOnRestart && first {
						first = false
						fu.mu.Lock()
						fu.dead[u] = true // the new binary refuses: liveness never comes back
						fu.mu.Unlock()
					}
					return fu.unit(u, "restart")
				},
				isActive: fu.isActive, logf: func(_ string, _ ...any) {}, nowf: time.Now})
			return nil // the launch succeeded; the job's outcome lives in the mailbox (what the drills assert)
		}
	}

	t.Run("applied", func(t *testing.T) {
		o, fu, conf, bin, prev := newDrill(t)
		o.updLaunch = launchViaJob(t, fu, prev, false)
		o.updateWorker("upd-1", bin, "latest")
		st, err := readUpdateStatus(conf)
		if err != nil || st.Phase != wat.UpdatePhaseApplied {
			t.Fatalf("phase: %v %v", err, st)
		}
		if got := mustReadExisting(t, bin); got != "NEWBIN-99.0.0" {
			t.Fatalf("bin after install: %q", got)
		}
		if got := mustReadExisting(t, prev); got != "OLDBIN-3.5.0" {
			t.Fatalf("wattun.prev backup: %q", got)
		}
		if !fu.did("t1:restart") || fu.count("t1:restart") != 1 {
			t.Fatalf("unit restarts: %v", fu.actions)
		}
	})
	t.Run("rolled_back", func(t *testing.T) {
		o, fu, conf, bin, prev := newDrill(t)
		o.updLaunch = launchViaJob(t, fu, prev, true) // the new engine refuses to run
		o.updateWorker("upd-2", bin, "latest")
		st, err := readUpdateStatus(conf)
		if err != nil || st.Phase != wat.UpdatePhaseRolledBack || st.Detail == "" {
			t.Fatalf("phase: %v %v", err, st)
		}
		if got := mustReadExisting(t, bin); got != "OLDBIN-3.5.0" {
			t.Fatalf("rollback did not restore wattun.prev: %q", got)
		}
		if got := mustReadExisting(t, prev); got != "OLDBIN-3.5.0" {
			t.Fatalf("wattun.prev changed: %q", got)
		}
		if fu.count("t1:restart") != 2 { // install restart + rollback restart
			t.Fatalf("unit restarts: %v", fu.actions)
		}
	})
	t.Run("no_backup_path", func(t *testing.T) {
		o, fu, conf, bin, prev := newDrill(t)
		o.updLaunch = func(stage, bin string) error { // the sandbox: backup cannot even read the source
			os.Remove(bin)
			return launchViaJob(t, fu, prev, false)(stage, bin)
		}
		o.updateWorker("upd-3", bin, "latest")
		st, err := readUpdateStatus(conf)
		if err != nil || st.Phase != wat.UpdatePhaseFailed || !strings.Contains(st.Detail, "backup") {
			t.Fatalf("phase: %v %v", err, st)
		}
		if _, err := os.Stat(bin); !os.IsNotExist(err) {
			t.Fatal("the running binary was touched despite the failed backup gate")
		}
	})
	t.Run("staged_binary_refuses", func(t *testing.T) {
		o, _, conf, bin, _ := newDrill(t)
		o.updProbe = func(string) (string, error) { return "", fmt.Errorf("exec format error") }
		o.updateWorker("upd-4", bin, "latest")
		st, err := readUpdateStatus(conf)
		if err != nil || st.Phase != wat.UpdatePhaseFailed || !strings.Contains(st.Detail, "does not run") {
			t.Fatalf("phase: %v %v", err, st)
		}
		if _, err := os.Stat(filepath.Join(conf, scepterUpdateDirF)); !os.IsNotExist(err) {
			t.Fatal("a failed staging left the .update dir behind")
		}
	})
	t.Run("re-armed_at_launch", func(t *testing.T) {
		// round-2 F7 (2026-11-22): the worker re-arms the mailbox at LAUNCH — the moment the swap becomes
		// imminent — with a FRESH Ts, so the gate (and the revived engine after the swap) counts from there
		// instead of from an accept time a long download left behind. The phase stays started (the wat
		// watcher treats every fresh non-started phase as a failure event; updatePhaseStaged is reserved for
		// the wat-side follow-up). Captured by wrapping the launch seam.
		o, fu, conf, bin, prev := newDrill(t)
		var atLaunch *wat.ScepterUpdateStatus
		var gateRun string
		var gateBusy bool
		o.updLaunch = func(stage, bin string) error {
			st, err := readUpdateStatus(conf)
			if err != nil {
				return err
			}
			atLaunch = st
			gateRun, gateBusy = updateJobInFlight(conf) // the gate as the revived engine would see it
			return launchViaJob(t, fu, prev, false)(stage, bin)
		}
		o.updateWorker("upd-5", bin, "latest")
		if atLaunch == nil || atLaunch.Phase != wat.UpdatePhaseStarted || atLaunch.Run != "upd-5" || atLaunch.To != "99.0.0" {
			t.Fatalf("mailbox at launch must be the re-armed started record: %+v", atLaunch)
		}
		if time.Since(time.Unix(atLaunch.Ts, 0)) > 5*time.Second {
			t.Fatalf("the launch re-arm Ts is not fresh: %d", atLaunch.Ts)
		}
		// the fresh Ts keeps the in-flight gate closed across the restart (what the fix is for)
		if !gateBusy || gateRun != "upd-5" {
			t.Fatalf("the launch re-arm must keep the gate closed: %q %v", gateRun, gateBusy)
		}
	})
}

// backup.export: the tarball holds the restore set (ymls, keys, tokens, .bak edits, the pairing store, the
// audit) and holds back the machine state (the journal, the staging dir, tmp files); b64/sha256/files are
// consistent, and an oversized member is refused rather than silently skipped.
func TestFileScepterOpsBackupExport(t *testing.T) {
	o, _, conf := testOps2(t)
	files := map[string]string{
		"t1.yml": "mode: server\ncarrier: udp\n", "t1.key": "kk\n", "t1.token": "wat1:abc\n",
		"t1.yml.bak": "mode: server\n", ".pairing.audit": "2026-11-22T10:00:00Z pair_created u\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(conf, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(conf, ".pairing.journal"), []byte(`{"id":"x"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// F3b (owner decision 2026-11-22): the pairing credential itself is NOT restore data for this command —
	// backup.export serves any manage-tier credential, and shipping .pairing (the pairing KEY) would let a
	// manage holder re-mint the pairing elsewhere (manage→full escalation). The audit stays: evidence, not a
	// secret.
	if err := os.WriteFile(filepath.Join(conf, ".pairing"), []byte("watp1:1|u|k|manage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conf, "junk.tmp"), []byte("tmp"), 0o600); err != nil {
		t.Fatal(err)
	}
	// F9 (2026-11-22): the manager's crashed rewrites leave ".tmp.XXXXXX"-prefixed partials — a partial
	// .pairing rewrite must never travel in the tarball.
	if err := os.WriteFile(filepath.Join(conf, ".tmp.abc123"), []byte("partial .pairing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(conf, scepterUpdateDirF), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(conf, scepterUpdateDirF, "wattun.new"), []byte("NEW"), 0o700)
	p, code := o.BackupExport()
	if code != wat.CodeOK {
		t.Fatalf("backup.export: %v %v", code, p)
	}
	var doc struct {
		B64    string `json:"b64"`
		Sha256 string `json:"sha256"`
		Size   int    `json:"size"`
		Files  int    `json:"files"`
	}
	if err := json.Unmarshal([]byte(p["logs"].([]string)[0]), &doc); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(doc.B64)
	if err != nil || len(raw) != doc.Size || fmt.Sprintf("%x", sha256.Sum256(raw)) != doc.Sha256 {
		t.Fatalf("doc integrity: %v size %d/%d", err, len(raw), doc.Size)
	}
	got := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		got[hdr.Name] = string(b)
	}
	for name, content := range files {
		if got[name] != content {
			t.Fatalf("tar %q = %q, want %q", name, got[name], content)
		}
	}
	for _, absent := range []string{".pairing.journal", ".pairing", "junk.tmp", ".tmp.abc123", "wattun.new"} {
		if _, ok := got[absent]; ok {
			t.Fatalf("machine state %q must not be in the backup", absent)
		}
	}
	if doc.Files != len(files) {
		t.Fatalf("files count %d, want %d", doc.Files, len(files))
	}
	// an oversized member is refused (code=too_large), not silently skipped
	big := filepath.Join(conf, "big.yml")
	os.WriteFile(big, make([]byte, 5<<20), 0o600)
	if p, code = o.BackupExport(); code != wat.CodeTooLarge || p["file"] != "big.yml" {
		t.Fatalf("oversized member: %v %v", code, p)
	}
	os.Remove(big)
}

// audit.tail: the last n lines of each source, raw and parse-free; missing files are empty entries, not errors.
func TestFileScepterOpsAuditTail(t *testing.T) {
	o, _, conf := testOps2(t)
	audit := ""
	for i := 1; i <= 5; i++ {
		audit += fmt.Sprintf("2026-11-22T10:0%d:00Z pair_event u (%d)\n", i, i)
	}
	os.WriteFile(filepath.Join(conf, ".pairing.audit"), []byte(audit), 0o600)
	// journalRec lines as the journal writes them ({"id","cmd","ts","resp"}); built inline because the type
	// lives unexported in wat and the reader is deliberately parse-free
	journal := ""
	for i := 1; i <= 3; i++ {
		journal += fmt.Sprintf(`{"id":"id%d","cmd":"tunnel.edit","ts":%d,"resp":{"id":"id%d","code":0}}`+"\n", i, 100+i, i)
	}
	os.WriteFile(filepath.Join(conf, ".pairing.journal"), []byte(journal), 0o600)
	p, code := o.AuditTail(2)
	if code != wat.CodeOK {
		t.Fatalf("audit.tail: %v", code)
	}
	logs := p["logs"].([]string)
	var a, j struct {
		Src     string   `json:"src"`
		Entries []string `json:"entries"`
	}
	if json.Unmarshal([]byte(logs[0]), &a) != nil || a.Src != "audit" || len(a.Entries) != 2 ||
		a.Entries[0] != "2026-11-22T10:04:00Z pair_event u (4)" {
		t.Fatalf("audit tail: %+v", a)
	}
	if json.Unmarshal([]byte(logs[1]), &j) != nil || j.Src != "journal" || len(j.Entries) != 2 ||
		!strings.Contains(j.Entries[1], `"id3"`) {
		t.Fatalf("journal tail: %+v", j)
	}
	// missing files: empty entries, code ok
	o2, _, _ := testOps2(t)
	if p, code = o2.AuditTail(5); code != wat.CodeOK {
		t.Fatalf("audit.tail on an empty dir: %v", code)
	}
	logs = p["logs"].([]string)
	json.Unmarshal([]byte(logs[0]), &a)
	if len(a.Entries) != 0 {
		t.Fatalf("entries from a missing audit: %v", a.Entries)
	}
}

// doctor.fetch's ops fragment: the latch status (the same data the loopback /scepter endpoint serves), this
// unit's state, the update mailbox and the journal size — merged into the state document by the handler.
func TestFileScepterOpsDoctor(t *testing.T) {
	o, fu, conf := testOps2(t)
	fu.active["self"] = true
	oldLatch := latchNow.Load()
	t.Cleanup(func() { latchNow.Store(oldLatch) })
	latchNow.Store(&latchMonitor{port: 8443})
	writeUpdateStatus(conf, wat.ScepterUpdateStatus{Phase: wat.UpdatePhaseApplied, Run: "u1", Ts: time.Now().Unix()})
	p, code := o.Doctor()
	if code != wat.CodeOK {
		t.Fatalf("doctor: %v", code)
	}
	latch := p["latch"].(map[string]any)
	if latch["enabled"] != true || latch["port"] != 8443 || latch["armed"] != false {
		t.Fatalf("latch fragment: %v", latch)
	}
	unit := p["unit"].(map[string]any)
	if unit["name"] != "self" || unit["active"] != true {
		t.Fatalf("unit fragment: %v", unit)
	}
	if up := p["update"].(*wat.ScepterUpdateStatus); up.Run != "u1" {
		t.Fatalf("update fragment: %+v", up)
	}
	if _, ok := p["journal"]; ok {
		t.Fatal("no journal expected in a bare test dir")
	}
}

// The engine's pinned release-signing key must stay byte-identical to the installer's SIG_PUB (three copies
// exist: install.sh, wattun-manager, this engine; the test pins the engine copy to install.sh so they cannot
// drift). Skipped in checkouts without install.sh next to the module root.
func TestScepterUpdateSigPubMatchesInstallSh(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		t.Skipf("no install.sh at the module root: %v", err)
	}
	s := string(b)
	start := strings.Index(s, "SIG_PUB=$(cat <<'PEM'")
	if start < 0 {
		t.Fatal("install.sh has no SIG_PUB heredoc")
	}
	s = s[start:]
	end := strings.Index(s, "\nPEM\n")
	if end < 0 {
		t.Fatal("install.sh SIG_PUB heredoc unterminated")
	}
	body := s[strings.Index(s, "\n")+1 : end+1] // the PEM block incl. the trailing newline
	if body != scepterSigPub {
		t.Fatalf("scepterSigPub drifted from install.sh SIG_PUB:\n--- engine ---\n%s\n--- install.sh ---\n%s",
			scepterSigPub, body)
	}
}

// ---- U0 audit coverage (2026-11-23): keyrotate, pair.rotate, mute, limits.reset ----

// tokenFields decodes a wat1: token into its pipe fields (the manager's read_token layout).
func tokenFields(t *testing.T, tok string) []string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(tok, "wat1:"))
	if err != nil {
		t.Fatalf("token base64: %v", err)
	}
	return strings.Split(string(raw), "|")
}

// KeyRotate drill (U0 audit): the new key lands in yml + key file, the rebuilt token carries the NEW key
// and every existing field (both the .token-file path and the yml-composition fallback), the .bak set keeps
// the old state, the unit restarts, and self/missing tunnels are refused.
func TestFileScepterOpsKeyRotate(t *testing.T) {
	o, fu, _ := testOps2(t)
	spec := wat.ScepterTunnelSpec{Name: "kr", Carrier: "udp", Ports: "20030,8443:443/udp",
		Params: map[string]string{"peer": "198.51.100.7", "ping-every": "5"},
		Key:    "k1234567890123456789012345678901234567890"}
	if p, code := o.Create(spec); code != wat.CodeOK {
		t.Fatalf("create: %d %v", code, p)
	}
	oldTok := strings.TrimSpace(mustReadExisting(t, filepath.Join(o.conf, "kr.token")))
	p, code := o.KeyRotate("kr")
	if code != wat.CodeOK {
		t.Fatalf("keyrotate: %d %v", code, p)
	}
	newKey, _ := p["key"].(string)
	if newKey == "" || newKey == spec.Key {
		t.Fatalf("rotated key: %v", p)
	}
	// files carry the new key
	y := mustReadExisting(t, filepath.Join(o.conf, "kr.yml"))
	if !strings.Contains(y, "key: "+newKey) || strings.Contains(y, spec.Key) {
		t.Fatalf("yml not rotated:\n%s", y)
	}
	if kf := strings.TrimSpace(mustReadExisting(t, filepath.Join(o.conf, "kr.key"))); kf != newKey {
		t.Fatalf("key file: %q", kf)
	}
	// the rebuilt token: same fields, new key
	tok, _ := p["token"].(string)
	got := tokenFields(t, tok)
	want := tokenFields(t, oldTok)
	if len(got) != len(want) {
		t.Fatalf("token shape changed: %v vs %v", got, want)
	}
	for i := range want {
		w := want[i]
		if i == 2 {
			w = newKey
		}
		if got[i] != w {
			t.Fatalf("token field %d: got %q, want %q", i, got[i], w)
		}
	}
	if tf := strings.TrimSpace(mustReadExisting(t, filepath.Join(o.conf, "kr.token"))); tf != tok {
		t.Fatalf("token file not rewritten: %q", tf)
	}
	// the .bak set holds the pre-rotation state
	if bak := mustReadExisting(t, filepath.Join(o.conf, "kr.yml.bak")); !strings.Contains(bak, spec.Key) {
		t.Fatalf("yml .bak is not the old config:\n%s", bak)
	}
	if bak := strings.TrimSpace(mustReadExisting(t, filepath.Join(o.conf, "kr.key.bak"))); bak != spec.Key {
		t.Fatalf("key .bak: %q", bak)
	}
	if bak := strings.TrimSpace(mustReadExisting(t, filepath.Join(o.conf, "kr.token.bak"))); bak != oldTok {
		t.Fatalf("token .bak: %q", bak)
	}
	if !fu.did("kr:restart") {
		t.Fatal("unit was not restarted on the new key")
	}
	// second rotation with no token file: rebuilt from the yml fields instead (same shape)
	os.Remove(filepath.Join(o.conf, "kr.token"))
	p2, code := o.KeyRotate("kr")
	if code != wat.CodeOK {
		t.Fatalf("second rotation: %d %v", code, p2)
	}
	got = tokenFields(t, p2["token"].(string))
	if len(got) != 7 || got[0] != "udp" || got[1] != "198.51.100.7" || got[2] != p2["key"] || got[6] != "20030,443" {
		t.Fatalf("yml-composed token: %v", got)
	}
	// rejections: the channel's own unit, a missing tunnel
	if p, code = o.KeyRotate("self"); code != wat.CodeBadRequest || p["self"] != "self" {
		t.Fatalf("self rotate: %d %v", code, p)
	}
	if _, code = o.KeyRotate("nope"); code != wat.CodeNotFound {
		t.Fatalf("missing tunnel: %d", code)
	}
}

// The keyrotate rollback drill: the unit refuses to come up with the new key → CodeInternal rolled_back,
// the old key is back in yml + key + token, and the unit was restarted on it.
func TestFileScepterOpsKeyRotateRollback(t *testing.T) {
	o, fu, _ := testOps2(t)
	spec := wat.ScepterTunnelSpec{Name: "rb", Carrier: "udp", Ports: "20030",
		Params: map[string]string{"peer": "198.51.100.7"}, Key: "k1234567890123456789012345678901234567890"}
	if p, code := o.Create(spec); code != wat.CodeOK {
		t.Fatalf("create: %d %v", code, p)
	}
	oldTok := strings.TrimSpace(mustReadExisting(t, filepath.Join(o.conf, "rb.token")))
	fu.dead["rb"] = true
	p, code := o.KeyRotate("rb")
	if code != wat.CodeInternal || p["rolled_back"] != true {
		t.Fatalf("rollback: %d %v", code, p)
	}
	y := mustReadExisting(t, filepath.Join(o.conf, "rb.yml"))
	if !strings.Contains(y, "key: "+spec.Key) {
		t.Fatalf("rollback did not restore the old yml:\n%s", y)
	}
	if kf := strings.TrimSpace(mustReadExisting(t, filepath.Join(o.conf, "rb.key"))); kf != spec.Key {
		t.Fatalf("rollback key file: %q", kf)
	}
	if tf := strings.TrimSpace(mustReadExisting(t, filepath.Join(o.conf, "rb.token"))); tf != oldTok {
		t.Fatalf("rollback token file: %q", tf)
	}
	if fu.count("rb:restart") < 2 {
		t.Fatal("rollback did not restart the unit on the restored key")
	}
}

// The stale-token refusal (fix round 3, 2026-11-23): a token file that cannot be parsed and a yml
// without a peer (nothing to compose a token from) would otherwise survive the rotate holding the DEAD
// key — the rotate refuses BEFORE any file moves: no .bak set, yml + key + token untouched, no restart.
func TestFileScepterOpsKeyRotateStaleToken(t *testing.T) {
	o, fu, _ := testOps2(t)
	spec := wat.ScepterTunnelSpec{Name: "st", Carrier: "udp", Ports: "20031",
		Params: map[string]string{"peer": "198.51.100.7"}, Key: "k1234567890123456789012345678901234567890"}
	if p, code := o.Create(spec); code != wat.CodeOK {
		t.Fatalf("create: %d %v", code, p)
	}
	// strip the peer (bare yml: no compose source) and corrupt the token file
	y := strings.ReplaceAll(mustReadExisting(t, filepath.Join(o.conf, "st.yml")), "peer: 198.51.100.7\n", "")
	if err := o.writeAtomic(filepath.Join(o.conf, "st.yml"), y); err != nil {
		t.Fatalf("strip peer: %v", err)
	}
	stale := "not a wat1: token at all"
	if err := o.writeAtomic(filepath.Join(o.conf, "st.token"), stale+"\n"); err != nil {
		t.Fatalf("corrupt token: %v", err)
	}
	p, code := o.KeyRotate("st")
	if code != wat.CodeInternal {
		t.Fatalf("stale-token rotate: %d %v", code, p)
	}
	why, _ := p["why"].(string)
	if !strings.Contains(why, "unparsable") || !strings.Contains(why, "st.token") {
		t.Fatalf("refusal names the file: %d %v", code, p)
	}
	// all files untouched
	if kf := strings.TrimSpace(mustReadExisting(t, filepath.Join(o.conf, "st.key"))); kf != spec.Key {
		t.Fatalf("key file moved: %q", kf)
	}
	if !strings.Contains(mustReadExisting(t, filepath.Join(o.conf, "st.yml")), "key: "+spec.Key) {
		t.Fatal("yml was moved")
	}
	if tf := strings.TrimSpace(mustReadExisting(t, filepath.Join(o.conf, "st.token"))); tf != stale {
		t.Fatalf("token file was moved: %q", tf)
	}
	if _, err := os.Stat(filepath.Join(o.conf, "st.key.bak")); err == nil {
		t.Fatal("the backup set was created")
	}
	if fu.did("st:restart") {
		t.Fatal("the unit was restarted")
	}
}

// PairRotate (U0 audit): the store is rewritten in the manager's pairing_store_write shape — the watp1:
// credential line first, then the # created / # oldkey / # oldkey_expires comments; same UUID+caps, new
// 32-byte key; the original creation time survives; a missing or broken store refuses.
func TestFileScepterOpsPairRotate(t *testing.T) {
	o, _, _ := testOps2(t)
	fullCaps, _ := wat.CapFromName("full") // the cumulative mask, as ParsePairingLine issues it
	old := &wat.PairingConfig{Ver: 1, Caps: fullCaps}
	for i := range old.UUID {
		old.UUID[i] = byte(i + 3)
	}
	for i := range old.Key {
		old.Key[i] = byte(200 - i)
	}
	if err := writePairingFile(filepath.Join(o.conf, ".pairing"), old); err != nil {
		t.Fatal(err)
	}
	p, code := o.PairRotate(3600)
	if code != wat.CodeOK {
		t.Fatalf("rotate: %d %v", code, p)
	}
	line, _ := p["watp1"].(string)
	np, err := wat.ParsePairingLine(line)
	if err != nil {
		t.Fatalf("returned line: %v", err)
	}
	if np.UUIDString() != old.UUIDString() || np.Caps != old.Caps || np.Key == old.Key {
		t.Fatalf("rotated credential: uuid %s caps %d", np.UUIDString(), np.Caps)
	}
	// the store contract, pinned: line 1 is the returned credential, the old key only as the comment
	s := mustReadExisting(t, filepath.Join(o.conf, ".pairing"))
	if !strings.HasPrefix(s, line+"\n") {
		t.Fatalf("store line 1 is not the returned credential:\n%s", s)
	}
	if strings.Contains(strings.SplitN(s, "\n", 2)[1], "watp1:") {
		t.Fatalf("a second credential line smuggled into the store:\n%s", s)
	}
	if !strings.Contains(s, "# oldkey="+base64.StdEncoding.EncodeToString(old.Key[:])) {
		t.Fatalf("store lost the oldkey comment:\n%s", s)
	}
	created := ""
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "# created=") {
			created = strings.TrimPrefix(l, "# created=")
		}
	}
	if created == "" {
		t.Fatalf("store has no created comment:\n%s", s)
	}
	// second rotation (window omitted → the 24 h default): created preserved, oldkey is the FIRST new key
	firstKey := np.Key
	p2, code := o.PairRotate(0)
	if code != wat.CodeOK || p2["window_s"] != pairRotateWindowDefault {
		t.Fatalf("default window: %d %v", code, p2)
	}
	np2, err := wat.ParsePairingLine(p2["watp1"].(string))
	if err != nil || np2.UUIDString() != old.UUIDString() {
		t.Fatalf("second rotation: %v %v", err, p2)
	}
	if np2.Key == firstKey {
		t.Fatal("the second rotation minted the same key")
	}
	s2 := mustReadExisting(t, filepath.Join(o.conf, ".pairing"))
	if !strings.Contains(s2, "# created="+created+"\n") {
		t.Fatalf("the second rotation lost the original creation time:\n%s", s2)
	}
	if !strings.Contains(s2, "# oldkey="+base64.StdEncoding.EncodeToString(firstKey[:])) {
		t.Fatalf("the second rotation kept the wrong oldkey:\n%s", s2)
	}
	// no store: nothing to rotate (a token-bootstrap pair rotates by issuing a new token)
	o2, _, _ := testOps2(t)
	if _, code := o2.PairRotate(0); code != wat.CodeNotFound {
		t.Fatalf("rotate without a store: %d", code)
	}
	// a broken store refuses too (it may hold the only copy of the credential)
	if err := os.WriteFile(filepath.Join(o2.conf, ".pairing"), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, code := o2.PairRotate(0); code != wat.CodeNotFound || p["why"] == "" {
		t.Fatalf("rotate over a broken store: %d %v", code, p)
	}
}

// scepterTestMetrics is a stand-in for the tunnel's own metrics server: the /stats carriers list plus the
// two POST endpoints the bash console and the ops talk to (/carrier/toggle, /quota/reset). The returned
// closures are the observation seams.
func scepterTestMetrics(t *testing.T, carriers []map[string]any) (addr string, toggleCalls func() int, posted func() []string) {
	t.Helper()
	mu := sync.Mutex{}
	muted := map[string]bool{}
	calls := 0
	var posts []string
	mux := http.NewServeMux()
	for _, c := range carriers { // seed the live muted state from the initial carriers
		if b, _ := c["muted"].(bool); b {
			muted[c["name"].(string)] = true
		}
	}
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		out := make([]map[string]any, 0, len(carriers))
		for _, c := range carriers {
			out = append(out, map[string]any{"name": c["name"], "alive": c["alive"],
				"muted": muted[c["name"].(string)]})
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"carriers": out})
	})
	mux.HandleFunc("/carrier/toggle", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		c := r.URL.Query().Get("carrier")
		mu.Lock()
		muted[c] = !muted[c]
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"path":0,"carrier":%q,"muted":%t}`+"\n", c, muted[c])
	})
	mux.HandleFunc("/quota/reset", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("port")
		mu.Lock()
		posts = append(posts, p)
		mu.Unlock()
		if p == "20999" {
			http.Error(w, "unknown port", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"port":%s,"reset":true}`+"\n", p)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, mux)
	return ln.Addr().String(),
		func() int { mu.Lock(); defer mu.Unlock(); return calls },
		func() []string { mu.Lock(); defer mu.Unlock(); return append([]string{}, posts...) }
}

// scepterBondedYML writes a bonded tunnel's yml (the mute ops' input).
func scepterBondedYML(t *testing.T, path, metrics string) {
	t.Helper()
	yml := "# created by scepter tunnel.create\nmode: server\nkey: k1234567890123456789012345678901234567890\n" +
		"carrier: udp+udp\nmetrics: " + metrics + "\nports:\n  - 20030\n"
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
}

// carrier.mute (U0 audit): the mute flips a bonded path over the tunnel's own metrics server (the bash
// console's carrier_toggle_cmd), the aligned no-op does not toggle, non-bond tunnels and unknown paths are
// refused, and a mute answered muted:false is a refusal — the bash interpretation.
func TestFileScepterOpsMute(t *testing.T) {
	o, _, _ := testOps2(t)
	addr, toggleCalls, _ := scepterTestMetrics(t, []map[string]any{
		{"name": "udp", "alive": true, "muted": false},
		{"name": "udp:up", "alive": false, "muted": false},
	})
	scepterBondedYML(t, filepath.Join(o.conf, "b.yml"), addr)
	// mute → flip
	p, code := o.Mute("b", "udp", true)
	if code != wat.CodeOK || p["muted"] != true || p["changed"] != true {
		t.Fatalf("mute: %d %v", code, p)
	}
	if toggleCalls() != 1 {
		t.Fatalf("toggle calls: %d", toggleCalls())
	}
	// already muted: aligned, no flip
	if p, code = o.Mute("b", "udp", true); code != wat.CodeOK || p["changed"] != false {
		t.Fatalf("aligned mute: %d %v", code, p)
	}
	if toggleCalls() != 1 {
		t.Fatal("the aligned mute toggled anyway")
	}
	// unmute; the suffixed duplicate leg is a valid path too (names come from /stats, not the yml split)
	if p, code = o.Mute("b", "udp", false); code != wat.CodeOK || p["muted"] != false {
		t.Fatalf("unmute: %d %v", code, p)
	}
	if p, code = o.Mute("b", "udp:up", true); code != wat.CodeOK || p["muted"] != true {
		t.Fatalf("suffixed leg: %d %v", code, p)
	}
	// unknown path, non-bond tunnel, no metrics endpoint, dead metrics server, missing tunnel
	if p, code = o.Mute("b", "gre", true); code != wat.CodeBadRequest || p["why"] == "" {
		t.Fatalf("unknown path: %d %v", code, p)
	}
	if err := os.WriteFile(filepath.Join(o.conf, "s.yml"),
		[]byte("mode: server\nkey: k\ncarrier: udp\nmetrics: "+addr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, code = o.Mute("s", "udp", true); code != wat.CodeBadRequest || p["why"] == "" {
		t.Fatalf("non-bond: %d %v", code, p)
	}
	scepterBondedYML(t, filepath.Join(o.conf, "nm.yml"), "")
	if p, code = o.Mute("nm", "udp", true); code != wat.CodeBadRequest || p["why"] == "" {
		t.Fatalf("no metrics: %d %v", code, p)
	}
	scepterBondedYML(t, filepath.Join(o.conf, "dead.yml"), "127.0.0.1:1")
	if _, code = o.Mute("dead", "udp", true); code != wat.CodeInternal {
		t.Fatalf("dead metrics: %d", code)
	}
	if _, code = o.Mute("nope", "udp", true); code != wat.CodeNotFound {
		t.Fatalf("missing tunnel: %d", code)
	}
	// the muted:false refusal (the single-carrier engine's answer) via the seams
	ors, _, _ := testOps2(t)
	ors.httpGet = func(string, string) (map[string]any, error) {
		return map[string]any{"carriers": []any{map[string]any{"name": "udp", "muted": false}}}, nil
	}
	ors.httpPost = func(string, string) (map[string]any, int, error) {
		return map[string]any{"muted": false}, 200, nil // ToggleMute's single-carrier answer
	}
	scepterBondedYML(t, filepath.Join(ors.conf, "r.yml"), "127.0.0.1:19700")
	if p, code := ors.Mute("r", "udp", true); code != wat.CodeBadRequest || p["why"] == "" {
		t.Fatalf("muted:false refusal: %d %v", code, p)
	}
}

// limits.reset (U0 audit): every quota'd port of the limits: list is reset over the tunnel's own metrics
// server (the bash console's quota reset), a single port can be picked, a 404 (no counter) is tolerated,
// and the refusals are typed.
func TestFileScepterOpsResetLimits(t *testing.T) {
	o, _, _ := testOps2(t)
	addr, _, posted := scepterTestMetrics(t, nil)
	yml := "# created by scepter tunnel.create\nmode: server\nkey: k\ncarrier: udp\n" +
		"metrics: " + addr + "\nports:\n  - 20030\n  - 20031\n  - 20032\nlimits:\n" +
		"  - 20030 rate=5MB quota=100GB\n  - 20031 rate=1MB\n  - 20032 quota=1GB period=day\n"
	if err := os.WriteFile(filepath.Join(o.conf, "q.yml"), []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	p, code := o.ResetLimits("q", 0)
	if code != wat.CodeOK {
		t.Fatalf("reset all: %d %v", code, p)
	}
	if got := fmt.Sprint(p["reset"]); got != "[20030 20032]" {
		t.Fatalf("reset ports: %s (want the two quota'd ports, in order)", got)
	}
	if got := posted(); len(got) != 2 || got[0] != "20030" || got[1] != "20032" {
		t.Fatalf("posted ports: %v", got)
	}
	// a single port resets just that one (even a non-quota'd limit: the counter exists)
	if p, code = o.ResetLimits("q", 20031); code != wat.CodeOK || fmt.Sprint(p["reset"]) != "[20031]" {
		t.Fatalf("single port: %d %v", code, p)
	}
	// 404 = no counter for that port: tolerated, nothing reported
	if p, code = o.ResetLimits("q", 20999); code != wat.CodeOK || len(p["reset"].([]int)) != 0 {
		t.Fatalf("404 port: %d %v", code, p)
	}
	// refusals
	if p, code = o.ResetLimits("nope", 0); code != wat.CodeNotFound {
		t.Fatalf("missing tunnel: %d %v", code, p)
	}
	if err := os.WriteFile(filepath.Join(o.conf, "nm.yml"), []byte("mode: server\nkey: k\ncarrier: udp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, code = o.ResetLimits("nm", 0); code != wat.CodeBadRequest || p["why"] == "" {
		t.Fatalf("no metrics: %d %v", code, p)
	}
	// a dead metrics server with an actual quota to reset: the POST fails, the op answers internal
	if err := os.WriteFile(filepath.Join(o.conf, "dead.yml"),
		[]byte("mode: server\nkey: k\ncarrier: udp\nmetrics: 127.0.0.1:1\nlimits:\n  - 20030 quota=1GB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code = o.ResetLimits("dead", 0); code != wat.CodeInternal {
		t.Fatalf("dead metrics: %d", code)
	}
}
