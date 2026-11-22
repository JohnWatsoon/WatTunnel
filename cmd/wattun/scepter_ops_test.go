// Scepter write-side cmd tests (3.5.0, phase B): the REAL fileScepterOps against a temp CONF dir with real
// files — the full validate → backup → apply → verify → rollback flow without systemd (a fake unit runner
// records actions and can kill starts at will), plus the -scepter-call argument contract the Go manager uses.
// The handler/protocol layer is pinned in wat/scepter_test.go against the fake ops.

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

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
