// Scepter write side (3.5.0, phase B): the REAL wat.ScepterOps over the tunnel directory (/etc/wattun in
// production, the -config dir in dev) and systemd, plus the one-shot -scepter-call client action the Go
// manager shells out to (its scepterDial seam).
//
// Every write command is validate → backup → apply → verify → report, and failures roll back (plan B.1): a
// tunnel file is written atomically (tmp + rename, the manager-file discipline), the previous yml stays as
// NAME.yml.bak — the same convention the Go manager's auto_apply uses on Iran — and a unit that fails its
// liveness verify has its files restored and restarted before the answer says rolled_back. Deletes move the
// files aside to .bak (reversible by construction, plan D3) instead of destroying anything.
//
// Validation is Kharej's (plan B.2): name rules (the manager's v_name rule, shared via wat.ValidScepterName),
// port collisions against the other tunnels' listen/metrics ports and this process's own metrics listener, a
// per-host tunnel cap (the connlimit pattern), the carrier's platform needs, and a denylist of config keys the
// cockpit may not set (the keys the ops write themselves, plus the standalone action flags). Every rejection
// is a machine code with params, never prose.
//
// Handlers call the ops with the command queue held (wat.ScepterState's qmu), so nothing here needs locks of
// its own.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// scepterMaxTunnels caps how many tunnel units one host may hold (the connlimit pattern: bound the resource a
// cockpit can sprawl). 64 units is far past anything the owner runs; the memory defaults already split per
// config (memDefaults). // shortcut: static count, no per-unit memory math yet — raise when a fleet needs it
const scepterMaxTunnels = 64

// scepterVerify is how long a unit op waits for the liveness verify: systemd start/stop is sub-second, 6 s
// covers a loaded host.
const scepterVerify = 6 * time.Second

// fileScepterOps implements wat.ScepterOps against the tunnel directory and systemd. unit/active are function
// fields so tests run the whole validate→backup→apply→verify→rollback flow without systemd: they record the
// actions and can fail starts at will. known is the config-key checker (main passes its flag.Lookup closure,
// the same `known` the cfgWatcher uses; a test passes its own set — flag.Lookup is only populated once main
// has registered the flags).
type fileScepterOps struct {
	conf       string // the tunnel dir: /etc/wattun in production, the -config dir in dev
	self       string // this unit's own config name; write ops refuse it — the cockpit channel rides this unit
	maxTunnels int
	unit       func(name, action string) error // systemd action: start | stop | restart
	active     func(name string) bool          // unit liveness (systemctl is-active equivalent)
	known      func(key string) bool           // is key a config key this binary accepts (nil = accept all)
	logf       func(string, ...any)
}

// newFileScepterOps wires the production ops: the systemd template wattun@NAME, exactly the unit install.sh
// and the manager create. self is this process's own unit ("" when run without -config, e.g. a flag-run dev
// server, which owns no yml the cockpit could collide with by name).
func newFileScepterOps(conf, self string, known func(string) bool, logf func(string, ...any)) *fileScepterOps {
	return &fileScepterOps{
		conf: conf, self: self, maxTunnels: scepterMaxTunnels, known: known, logf: logf,
		unit: func(name, action string) error {
			u := "wattun@" + name
			switch action {
			case "start": // enable --now: covers a disabled unit too, idempotent when already up
				return runSystemctl("enable", "--now", u)
			case "stop":
				return runSystemctl("stop", u)
			case "restart":
				return runSystemctl("restart", u)
			}
			return fmt.Errorf("scepter ops: unknown unit action %q", action)
		},
		active: func(name string) bool {
			return exec.Command("systemctl", "is-active", "--quiet", "wattun@"+name).Run() == nil
		},
	}
}

func runSystemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil && len(out) > 0 {
		return fmt.Errorf("%s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return err
}

func (o *fileScepterOps) path(name, ext string) string {
	return filepath.Join(o.conf, name+"."+ext)
}

func (o *fileScepterOps) exists(name string) bool {
	_, err := os.Stat(o.path(name, "yml"))
	return err == nil
}

// writeAtomic: tmp + rename in the target directory, 0600 — the manager-file discipline. The cfgWatcher of a
// running unit polls these files every 3 s, so a half-written yml would be read as broken config.
func (o *fileScepterOps) writeAtomic(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// refuseSelf: the ops never edit, delete or restart the unit the cockpit's own channel rides — cutting it
// strands the very session that issued the command. The local console (or SSH) handles that one tunnel.
func (o *fileScepterOps) refuseSelf(name string) (map[string]any, int) {
	if o.self != "" && name == o.self {
		return map[string]any{"self": o.self,
			"why": "this is the unit the cockpit channel rides; use the local console for it"}, wat.CodeBadRequest
	}
	return nil, wat.CodeOK
}

// ---- tunnel.create ----

func (o *fileScepterOps) Create(spec wat.ScepterTunnelSpec) (map[string]any, int) {
	name := spec.Name
	if name == "" {
		name = o.suggestName()
	}
	if !wat.ValidScepterName(name) {
		return map[string]any{"name": name}, wat.CodeBadRequest
	}
	if o.exists(name) {
		// covers the self name too: this unit's own yml always exists
		return map[string]any{"name": name}, wat.CodeNameTaken
	}
	ports, err := parseScepterPortItems(spec.Ports)
	if err != nil {
		return map[string]any{"ports": err.Error()}, wat.CodeBadRequest
	}
	if code, p := o.checkCarrier(spec.Carrier); code != wat.CodeOK {
		return p, code
	}
	if code, p := o.checkCreateParams(spec.Params); code != wat.CodeOK {
		return p, code
	}
	if code, p := o.checkBindCollisions(name, scepterBinds(spec.Carrier, scepterIsReverse(spec.Params),
		func(k string) string { return spec.Params[k] }, spec.Params["metrics"])); code != wat.CodeOK {
		return p, code
	}
	if n := o.tunnelCount(); n >= o.maxTunnels {
		return map[string]any{"resource": "tunnels", "cap": o.maxTunnels}, wat.CodeRateLimited
	}
	metrics := o.pickMetricsPort(name) // best effort: a busy host creates without a private /stats
	// apply: files first (atomic), then the unit, then the liveness verify; any failure removes what was
	// written — the original state of a create is "nothing there", so the rollback is a clean removal.
	if err := o.writeTunnel(name, spec, ports, metrics); err != nil {
		o.removeFiles(name)
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	if err := o.unit(name, "start"); err != nil {
		o.unit(name, "stop") // best effort: the unit may be in auto-restart despite the failed command
		o.removeFiles(name)
		return map[string]any{"detail": err.Error(), "rolled_back": true}, wat.CodeInternal
	}
	if !o.waitActive(name, true) {
		o.unit(name, "stop")
		o.removeFiles(name)
		return map[string]any{"detail": "unit did not come up", "rolled_back": true}, wat.CodeInternal
	}
	p := map[string]any{"name": name, "carrier": spec.Carrier, "key": spec.Key}
	if metrics != "" {
		p["metrics"] = metrics
	}
	if tok := scepterToken(spec, ports); tok != "" {
		p["token"] = tok // the token a client-facing tunnel needs; empty peer = the cockpit fills it itself
	}
	o.logf("scepter ops: created tunnel %s (carrier %s, ports %s)", name, spec.Carrier, spec.Ports)
	return p, wat.CodeOK
}

// suggestName mirrors the manager's suggest_name: base, base-2, base-3 … first free.
func (o *fileScepterOps) suggestName() string {
	for i := 1; i < 1000; i++ {
		n := "tunnel"
		if i > 1 {
			n = fmt.Sprintf("tunnel-%d", i)
		}
		if !o.exists(n) {
			return n
		}
	}
	return fmt.Sprintf("tunnel-%d", time.Now().Unix()%100000)
}

func (o *fileScepterOps) tunnelCount() int {
	m, _ := filepath.Glob(filepath.Join(o.conf, "*.yml"))
	return len(m)
}

// writeTunnel writes NAME.yml (+ NAME.key, and NAME.token when the token is derivable) atomically. The yml
// carries a provenance comment so an owner can tell a remote create from a hand-written config.
func (o *fileScepterOps) writeTunnel(name string, spec wat.ScepterTunnelSpec, ports []portSpec, metrics string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# created by scepter tunnel.create %s (wat %s)\n", time.Now().UTC().Format(time.RFC3339), wat.Version)
	b.WriteString("mode: server\n")
	fmt.Fprintf(&b, "key: %s\n", spec.Key)
	fmt.Fprintf(&b, "carrier: %s\n", spec.Carrier)
	if metrics != "" {
		fmt.Fprintf(&b, "metrics: %s\n", metrics)
	}
	ks := make([]string, 0, len(spec.Params))
	for k := range spec.Params {
		ks = append(ks, k)
	}
	sort.Strings(ks) // deterministic file: the cfgWatcher's restart-needed diff must not jitter
	for _, k := range ks {
		fmt.Fprintf(&b, "%s: %s\n", k, scepterYMLValue(spec.Params[k]))
	}
	b.WriteString("ports:\n")
	for _, p := range ports {
		fmt.Fprintf(&b, "  - %s\n", portItemStr(p))
	}
	if err := o.writeAtomic(o.path(name, "yml"), b.String()); err != nil {
		return err
	}
	if err := o.writeAtomic(o.path(name, "key"), spec.Key+"\n"); err != nil {
		return err
	}
	if tok := scepterToken(spec, ports); tok != "" { // the manager keeps NAME.token on Kharej too
		if err := o.writeAtomic(o.path(name, "token"), tok+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func (o *fileScepterOps) removeFiles(name string) {
	for _, ext := range []string{"yml", "key", "token"} {
		os.Remove(o.path(name, ext))
	}
}

// parseScepterPortItems parses the intent's ports string with the config parser's own rules — a remote create
// accepts exactly what a yml ports: list accepts, duplicates included in the rejection.
func parseScepterPortItems(s string) ([]portSpec, error) {
	var out []portSpec
	seen := map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("empty port item")
		}
		ps, err := parsePortItem(item)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			k := fmt.Sprintf("%d/%v", p.Port, p.UDP)
			if seen[k] {
				return nil, fmt.Errorf("duplicate port %s", k)
			}
			seen[k] = true
			out = append(out, p)
		}
	}
	return out, nil
}

func portItemStr(p portSpec) string {
	s := strconv.Itoa(p.Port)
	if p.Target != p.Port {
		s += ":" + strconv.Itoa(p.Target)
	}
	if p.UDP {
		s += "/udp"
	}
	return s
}

// checkCarrier: the name must be one the binary itself accepts (validCarrier is the -carrier table, so a
// shape the engine ships can never stay rejected here), and the raw-socket carriers need Linux + CAP_NET_RAW —
// carrier_needs answers with what is missing instead of creating a unit that can never come up.
func (o *fileScepterOps) checkCarrier(carrier string) (int, map[string]any) {
	for _, leg := range strings.Split(carrier, "+") {
		base, _ := wat.LegDirection(leg)
		if !validCarrier[base] {
			return wat.CodeBadRequest, map[string]any{"carrier": carrier}
		}
		if rawIPCarrier[base] && runtime.GOOS != "linux" {
			return wat.CodeCarrierNeeds, map[string]any{"carrier": base, "ver": wat.Version, "need": "linux+CAP_NET_RAW"}
		}
	}
	return wat.CodeOK, nil
}

// scepterParamDeny: keys the ops write themselves (a duplicate would fail the unit's own yml parse at start),
// repeatable keys set semantics break (header), and the standalone action flags, which have no business in a
// created tunnel. carrier is denied on create (the ops write it) but allowed in edit patches.
var scepterParamDeny = map[string]bool{
	"mode": true, "key": true, "carrier": true, "ports": true, "limits": true, "header": true,
	"config": true, "version": true, "pair": true, "pair-to": true, "pairing": true,
	"latch-port": true, "latch-dial": true, "scepter-call": true, "scepter-args": true,
	"state-dir": true, // M8: a unit's CWD is /, a hand-set relative state-dir would scatter state files
}

// checkCreateParams: every param key must be one the unit's own config parser accepts (the `known` set, the
// same check the cfgWatcher enforces on a hand-edited yml) and must not fight a key the ops write themselves.
func (o *fileScepterOps) checkCreateParams(params map[string]string) (int, map[string]any) {
	ks := make([]string, 0, len(params))
	for k := range params {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		if scepterParamDeny[k] {
			return wat.CodeBadRequest, map[string]any{"key": k, "why": "owned by tunnel.create itself"}
		}
		if o.known != nil && !o.known(k) {
			return wat.CodeBadRequest, map[string]any{"key": k, "why": "unknown config key"}
		}
	}
	return wat.CodeOK, nil
}

// checkEditParams: the edit patch may switch the carrier (phase C adds the link-verified change around it)
// but fights none of the other owned keys; limits go through limits.set.
func (o *fileScepterOps) checkEditParams(patch wat.ScepterPatch) (int, map[string]any) {
	ks := make([]string, 0, len(patch.Set))
	for k := range patch.Set {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		if scepterParamDeny[k] && k != "carrier" {
			return wat.CodeBadRequest, map[string]any{"key": k, "why": "owned key; use its own command"}
		}
		if o.known != nil && !o.known(k) {
			return wat.CodeBadRequest, map[string]any{"key": k, "why": "unknown config key"}
		}
	}
	return wat.CodeOK, nil
}

func scepterIsReverse(params map[string]string) bool {
	return params["reverse"] == "true" || params["reverse"] == "1"
}

func scepterPortOf(addr string) int {
	_, p, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || p == "" {
		p = strings.TrimSpace(addr)
	}
	n, _ := strconv.Atoi(p)
	return n
}

// scepterBinds returns the ports a tunnel would BIND on this host, each labeled with what binds it: one entry
// per listening leg (explicit listen-<c>:, else listen:, else the carrier default — 4443, or an F19 UDP
// shape's conventional port), plus the metrics port. Ports the tunnel only dials or merely allows (the ports:
// targets) are not here: they bind nothing.
func scepterBinds(carrier string, reverse bool, lookup func(key string) string, metrics string) map[int]string {
	out := map[int]string{}
	if reverse {
		return out // a reverse tunnel dials from here; nothing binds (udp -reverse binds on the client, Iran)
	}
	for _, leg := range strings.Split(carrier, "+") {
		base, _ := wat.LegDirection(leg)
		if base == "" || carrierNoListen[base] || !validCarrier[base] {
			continue
		}
		v := lookup("listen-" + base)
		if v == "" {
			v = lookup("listen")
		}
		def := 4443 // the -listen default of every port-binding carrier
		if sp := wat.UDPShapePort(base); sp > 0 {
			def = sp
		}
		if v == "" {
			v = fmt.Sprintf(":%d", def)
		}
		if p := scepterPortOf(v); p > 0 {
			out[p] = base
		}
	}
	if p := scepterPortOf(metrics); p > 0 {
		out[p] = "metrics"
	}
	return out
}

// checkBindCollisions rejects a create/edit whose bind ports collide with another tunnel's or this process's
// own metrics listener. Target-port overlap is deliberately NOT a collision: several tunnels forwarding to
// the same local service is the normal shape (the allowlist is per tunnel).
func (o *fileScepterOps) checkBindCollisions(name string, binds map[int]string) (int, map[string]any) {
	taken := o.portUsers(name)
	ps := make([]int, 0, len(binds))
	for p := range binds {
		ps = append(ps, p)
	}
	sort.Ints(ps) // deterministic answer: the lowest colliding port is reported
	for _, p := range ps {
		if user, busy := taken[p]; busy {
			return wat.CodePortBusy, map[string]any{"port": p, "user": user}
		}
	}
	return wat.CodeOK, nil
}

// portUsers scans the tunnel dir: for every OTHER yml, the ports its listening carriers would bind (explicit
// listen keys, else the carrier defaults) and its metrics port, plus this process's own metrics port (the
// latch port is not yet visible here; the kernel refuses a double bind and the rollback catches it).
// parseConfig with a nil known-set: these files were accepted by their own units at start.
func (o *fileScepterOps) portUsers(exclude string) map[int]string {
	out := map[int]string{}
	if m := int(metricsPort.Load()); m > 0 {
		out[m] = "this unit's metrics"
	}
	files, _ := filepath.Glob(filepath.Join(o.conf, "*.yml"))
	for _, f := range files {
		n := strings.TrimSuffix(filepath.Base(f), ".yml")
		if n == exclude {
			continue // an edit re-listens its own ports
		}
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		cfg, err := parseConfig(string(b), nil)
		if err != nil {
			continue
		}
		if v, _ := cfg.get("metrics"); v != "" {
			if p := scepterPortOf(v); p > 0 {
				out[p] = n + " (metrics)"
			}
		}
		carrier, _ := cfg.get("carrier")
		rev, _ := cfg.get("reverse")
		for p := range scepterBinds(carrier, rev == "true" || rev == "1",
			func(k string) string { v, _ := cfg.get(k); return v }, "") {
			out[p] = n
		}
	}
	return out
}

// pickMetricsPort finds a free loopback metrics port for a created tunnel (19700.., the manager's range),
// avoiding the ports every other tunnel claims and probing the bind — a silent collision would fail the
// unit's start and trigger a pointless rollback.
func (o *fileScepterOps) pickMetricsPort(name string) string {
	taken := o.portUsers(name)
	for p := 19700; p < 19800; p++ {
		if _, busy := taken[p]; busy {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		ln.Close()
		return fmt.Sprintf("127.0.0.1:%d", p)
	}
	return ""
}

// scepterToken builds the wat1: token a client-facing created tunnel needs — the manager's make_token shape
// (base64 of carrier|peer|key|path|sni|icmp-type|ports|reverse, trailing empty fields dropped). Empty when no
// peer is known: the response still carries the key, and the cockpit (which knows Kharej's address from its
// own paired tunnel) fills the peer itself.
func scepterToken(spec wat.ScepterTunnelSpec, ports []portSpec) string {
	peer := spec.Params["peer"]
	if peer == "" {
		return ""
	}
	p := spec.Params
	f := []string{spec.Carrier, peer, spec.Key, p["path"], p["sni"], p["icmp-type"], scepterAllowStr(ports)}
	if scepterIsReverse(p) {
		f = append(f, "1")
	}
	return "wat1:" + base64.StdEncoding.EncodeToString([]byte(strings.Join(f, "|")))
}

// scepterAllowStr is the token's field 7: the allowlist, i.e. the TARGET ports, comma list, deduplicated.
func scepterAllowStr(ports []portSpec) string {
	var out []string
	seen := map[int]bool{}
	for _, p := range ports {
		if seen[p.Target] {
			continue
		}
		seen[p.Target] = true
		out = append(out, strconv.Itoa(p.Target))
	}
	return strings.Join(out, ",")
}

// scepterYMLValue quotes a config value the yml-subset parser would misread (unquoted, `#` after whitespace
// starts a comment, and unquote() only strips matching outer quotes — no escape sequences, the manager's
// set_value writes raw too).
func scepterYMLValue(v string) string {
	if !strings.ContainsAny(v, "\"'#") && strings.TrimSpace(v) == v && !strings.Contains(v, ": ") {
		return v
	}
	if !strings.Contains(v, "\"") {
		return `"` + v + `"`
	}
	if !strings.Contains(v, "'") {
		return `'` + v + `'`
	}
	return v // both quote kinds: unusable in this yml subset; the re-parse below rejects the result
}

// waitActive polls the liveness verify; want=false waits for the unit to LEAVE active (stop).
func (o *fileScepterOps) waitActive(name string, want bool) bool {
	deadline := time.Now().Add(scepterVerify)
	for {
		if o.active(name) == want {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ---- tunnel.edit / preset.apply ----

func (o *fileScepterOps) Edit(name string, patch wat.ScepterPatch) (map[string]any, int) {
	if p, code := o.refuseSelf(name); code != wat.CodeOK {
		return p, code
	}
	if patch.Set == nil && patch.Drop == nil && patch.Ports == "" {
		return map[string]any{"why": "empty patch"}, wat.CodeBadRequest // the handler checks too; the ops never trust their caller
	}
	f := o.path(name, "yml")
	old, err := os.ReadFile(f)
	if err != nil { // a missing tunnel is the more precise answer than a param complaint about it
		return map[string]any{"name": name}, wat.CodeNotFound
	}
	if code, p := o.checkEditParams(patch); code != wat.CodeOK {
		return p, code
	}
	newText, err := scepterPatchYML(string(old), patch)
	if err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeBadRequest
	}
	cfg, err := parseConfig(newText, nil)
	if err != nil { // the patched file must still parse: the unit would refuse it at restart
		return map[string]any{"detail": err.Error()}, wat.CodeBadRequest
	}
	carrier, _ := cfg.get("carrier")
	rev, _ := cfg.get("reverse")
	metrics, _ := cfg.get("metrics")
	listen := func(k string) string { v, _ := cfg.get(k); return v }
	if code, p := o.checkBindCollisions(name, scepterBinds(carrier, rev == "true" || rev == "1",
		listen, metrics)); code != wat.CodeOK {
		return p, code
	}
	// backup → apply → verify → rollback: the .bak is what the auto-apply flow leaves on Iran, so an owner
	// finds the same shape here.
	if err := o.writeAtomic(f+".bak", string(old)); err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	if err := o.writeAtomic(f, newText); err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	if err := o.unit(name, "restart"); err != nil {
		o.rollback(f, string(old))
		return map[string]any{"detail": err.Error(), "rolled_back": true}, wat.CodeInternal
	}
	if !o.waitActive(name, true) {
		o.rollback(f, string(old))
		return map[string]any{"detail": "unit did not come up with the new config", "rolled_back": true}, wat.CodeInternal
	}
	p := map[string]any{"name": name}
	if _, is := patch.Set["carrier"]; is { // the handler turns this into the carrier_switched event
		p["carrier"] = carrier
	}
	o.logf("scepter ops: edited tunnel %s (%d key(s), ports %q)", name, len(patch.Set), patch.Ports)
	return p, wat.CodeOK
}

// rollback restores the pre-edit yml and restarts the unit; both best-effort — the response already says
// rolled_back, and the .bak stays on disk either way for a human.
func (o *fileScepterOps) rollback(f, old string) {
	o.writeAtomic(f, old)
	o.unit(filepath.Base(strings.TrimSuffix(f, ".yml")), "restart")
}

// scepterPatchYML applies a patch with the manager's line-surgery semantics (set_value/unset_value/write_ports):
// top-level keys only; a set key replaces every existing line and is inserted before metrics:/ports: (else
// appended); a ports: value replaces the whole list block. The caller re-parses the result before any file is
// touched, so a patch that would break the yml is a bad_request, not a dead unit.
func scepterPatchYML(text string, patch wat.ScepterPatch) (string, error) {
	lines := strings.Split(text, "\n")
	for _, k := range patch.Drop {
		if k == "ports" || k == "limits" {
			lines = dropBlock(lines, k+":")
			continue
		}
		lines = dropKeyLines(lines, k)
	}
	ks := make([]string, 0, len(patch.Set))
	for k := range patch.Set {
		ks = append(ks, k)
	}
	sort.Strings(ks) // deterministic file content
	for _, k := range ks {
		lines = dropKeyLines(lines, k)
		entry := k + ": " + scepterYMLValue(patch.Set[k])
		out := make([]string, 0, len(lines)+1)
		done := false
		for _, l := range lines {
			if !done && (strings.HasPrefix(l, "metrics:") || strings.HasPrefix(l, "ports:")) {
				out = append(out, entry) // the manager's set_value position: plain keys before the blocks
				done = true
			}
			out = append(out, l)
		}
		if !done {
			out = append(out, entry)
		}
		lines = out
	}
	if patch.Ports != "" {
		ports, err := parseScepterPortItems(patch.Ports)
		if err != nil {
			return "", err
		}
		items := make([]string, 0, len(ports))
		for _, p := range ports {
			items = append(items, "  - "+portItemStr(p))
		}
		lines = replaceBlock(lines, "ports:", items)
	}
	return strings.Join(lines, "\n"), nil
}

func isTopKey(l, key string) bool {
	s := strings.TrimRight(l, " \t")
	return !strings.HasPrefix(s, " ") && !strings.HasPrefix(s, "\t") && strings.HasPrefix(s, key+":")
}

func dropKeyLines(lines []string, key string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if isTopKey(l, key) {
			continue
		}
		out = append(out, l)
	}
	return out
}

// dropBlock removes a `key:` list block (the key line plus its indented items).
func dropBlock(lines []string, key string) []string {
	out := make([]string, 0, len(lines))
	skipping := false
	for _, l := range lines {
		if isTopKey(l, strings.TrimSuffix(key, ":")) {
			skipping = true
			continue
		}
		if skipping {
			if t := strings.TrimSpace(l); t == "" || strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") {
				continue
			}
			skipping = false
		}
		out = append(out, l)
	}
	return out
}

// replaceBlock replaces a `key:` list block in place (or inserts it before metrics:/limits:, else appends —
// the same position rule set_value uses for plain keys).
func replaceBlock(lines []string, key string, items []string) []string {
	block := append([]string{key}, items...)
	start, end := findBlock(lines, key)
	if start >= 0 {
		out := make([]string, 0, len(lines)-end+start+len(block))
		out = append(out, lines[:start]...)
		out = append(out, block...)
		out = append(out, lines[end:]...)
		return out
	}
	pos := len(lines)
	for i, l := range lines {
		if strings.HasPrefix(l, "metrics:") || strings.HasPrefix(l, "limits:") {
			pos = i
			break
		}
	}
	out := make([]string, 0, len(lines)+len(block))
	out = append(out, lines[:pos]...)
	out = append(out, block...)
	out = append(out, lines[pos:]...)
	return out
}

// findBlock locates a `key:` list block: (start, end) with end past the block's indented items, or (-1,-1).
func findBlock(lines []string, key string) (int, int) {
	k := strings.TrimSuffix(key, ":")
	for i, l := range lines {
		if !isTopKey(l, k) {
			continue
		}
		j := i + 1
		for j < len(lines) {
			t := strings.TrimSpace(lines[j])
			if t == "" || strings.HasPrefix(lines[j], " ") || strings.HasPrefix(lines[j], "\t") {
				j++
				continue
			}
			break
		}
		return i, j
	}
	return -1, -1
}

// ---- tunnel.delete / tunnel.start|stop|restart ----

func (o *fileScepterOps) Delete(name string) (map[string]any, int) {
	if p, code := o.refuseSelf(name); code != wat.CodeOK {
		return p, code
	}
	if !o.exists(name) {
		return map[string]any{"name": name}, wat.CodeNotFound
	}
	// the unit first: a delete that cannot stop its tunnel deletes nothing
	if err := o.unit(name, "stop"); err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	if !o.waitActive(name, false) {
		return map[string]any{"detail": "unit would not stop"}, wat.CodeInternal
	}
	runSystemctl("disable", "wattun@"+name) // best effort: a never-enabled unit is fine
	// reversible by construction (plan D3): everything moves aside to .bak, nothing is destroyed. Undone
	// (renamed back) if any step fails, so a half-deleted tunnel cannot exist.
	var moved []string
	for _, ext := range []string{"key", "token", "yml"} { // yml LAST: it is what makes the unit runnable
		src := o.path(name, ext)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.Rename(src, src+".bak"); err != nil {
			for _, m := range moved {
				os.Rename(m+".bak", m)
			}
			return map[string]any{"detail": err.Error(), "rolled_back": true}, wat.CodeInternal
		}
		moved = append(moved, src)
	}
	o.logf("scepter ops: deleted tunnel %s (files kept as .bak)", name)
	return map[string]any{"name": name, "stopped": true, "backup": o.path(name, "yml") + ".bak"}, wat.CodeOK
}

func (o *fileScepterOps) Unit(name, action string) (map[string]any, int) {
	if p, code := o.refuseSelf(name); code != wat.CodeOK {
		return p, code
	}
	if action != "start" && action != "stop" && action != "restart" {
		return map[string]any{"action": action}, wat.CodeBadRequest
	}
	if !o.exists(name) {
		return map[string]any{"name": name}, wat.CodeNotFound
	}
	if err := o.unit(name, action); err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	want := action != "stop"
	if !o.waitActive(name, want) {
		return map[string]any{"detail": "unit did not reach the expected state"}, wat.CodeInternal
	}
	state := "inactive"
	if want {
		state = "active"
	}
	return map[string]any{"name": name, "state": state}, wat.CodeOK
}

// ---- limits.set ----

// SetLimits rewrites the yml's `limits:` list (the parseLimitItem syntax). No unit op: the limits list is
// hot-reloaded by the unit's cfgWatcher within 3 s (config.go), so a limit change never drops a stream.
func (o *fileScepterOps) SetLimits(name string, items []string) (map[string]any, int) {
	if !o.exists(name) {
		return map[string]any{"name": name}, wat.CodeNotFound
	}
	clean := make([]string, 0, len(items))
	seen := map[int]bool{}
	for _, it := range items {
		it = strings.TrimSpace(it)
		ls, err := parseLimitItem(it)
		if err != nil {
			return map[string]any{"detail": err.Error()}, wat.CodeBadRequest
		}
		if seen[ls.Port] {
			return map[string]any{"detail": fmt.Sprintf("port %d listed twice", ls.Port)}, wat.CodeBadRequest
		}
		seen[ls.Port] = true
		clean = append(clean, it)
	}
	f := o.path(name, "yml")
	old, err := os.ReadFile(f)
	if err != nil { // raced with a delete: report what the client would see on a retry
		return map[string]any{"name": name}, wat.CodeNotFound
	}
	block := make([]string, 0, len(clean))
	for _, it := range clean {
		block = append(block, "  - "+it)
	}
	newText := strings.Join(replaceBlock(strings.Split(string(old), "\n"), "limits:", block), "\n")
	if err := o.writeAtomic(f, newText); err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	o.logf("scepter ops: set %d limit(s) on tunnel %s (hot-reloaded)", len(clean), name)
	return map[string]any{"name": name, "limits": len(clean)}, wat.CodeOK
}

// ---- -scepter-call: the one-shot client action ----

// parseScepterCallArgs parses -scepter-args: a JSON object; a top-level "id" is lifted as the command id (so
// a retried call reuses it and the server journal answers at-most-once) and removed from the args.
func parseScepterCallArgs(s string) (map[string]any, string, error) {
	args := map[string]any{}
	if strings.TrimSpace(s) == "" {
		return args, "", nil
	}
	if err := json.Unmarshal([]byte(s), &args); err != nil {
		return nil, "", err
	}
	id := ""
	if v, ok := args["id"].(string); ok && v != "" {
		id = v
		delete(args, "id")
	}
	return args, id, nil
}

// runScepterCall is the -scepter-call action: dial the paired session's reserved stream (the tunnel context
// comes from the ordinary -config/-pair-to machinery, exactly like the run itself), run ONE command and print
// every raw response line (chunks included) as JSONL on stdout. Exit code: 0 when the command was answered —
// the machine code rides the JSON, the caller parses it — 1 on a transport failure (stderr).
func runScepterCall(tun *tunnel, cmd, argsJSON string) int {
	args, id, err := parseScepterCallArgs(argsJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "-scepter-args: %v\n", err)
		return 1
	}
	c, err := wat.DialScepter(tun.pick())
	if err != nil {
		fmt.Fprintf(os.Stderr, "scepter-call: %v (pairing needs %s on both ends)\n", err, wat.Version)
		return 1
	}
	defer c.Close()
	if _, err := c.CallRaw(cmd, args, id, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "scepter-call: %v\n", err)
		return 1
	}
	return 0
}
