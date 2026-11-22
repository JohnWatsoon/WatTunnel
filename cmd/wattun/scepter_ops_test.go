// Scepter write-side cmd tests (3.5.0, phase B): the REAL fileScepterOps against a temp CONF dir with real
// files — the full validate → backup → apply → verify → rollback flow without systemd (a fake unit runner
// records actions and can kill starts at will), plus the -scepter-call argument contract the Go manager uses.
// The handler/protocol layer is pinned in wat/scepter_test.go against the fake ops.

package main

import (
	"encoding/base64"
	"fmt"
	"net"
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
	if _, err := os.Stat(userYML); err != nil {
		t.Fatal("sweep removed a user tunnel named probe-*")
	}
	os.Remove(userYML)
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
