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
	"archive/tar"
	"bytes"
	"context"
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JohnWatsoon/WatTunnel/cmd/wattun/mgr"
	"github.com/JohnWatsoon/WatTunnel/wat"
)

// scepterMaxTunnels caps how many tunnel units one host may hold (the connlimit pattern: bound the resource a
// cockpit can sprawl). 64 units is far past anything the owner runs; the memory defaults already split per
// config (memDefaults). // shortcut: static count, no per-unit memory math yet — raise when a fleet needs it
const scepterMaxTunnels = 64

// scepterUnitsPerTunnel bounds every unit, auto helpers included, at this many per allowed tunnel.
const scepterUnitsPerTunnel = 4

// scepterVerify is how long a unit op waits for the liveness verify: systemd start/stop is sub-second, 6 s
// covers a loaded host.
const scepterVerify = 6 * time.Second

// fileScepterOps implements wat.ScepterOps against the tunnel directory and systemd. unit/active are function
// fields so tests run the whole validate→backup→apply→verify→rollback flow without systemd: they record the
// actions and can fail starts at will. known is the config-key checker (main passes its flag.Lookup closure,
// the same `known` the cfgWatcher uses; a test passes its own set — flag.Lookup is only populated once main
// has registered the flags).
//
// The phase C seams (runProbe, linkCheck, nowf and the probe ttl bounds) fall back to their production
// implementations when nil, so a struct-literal test can stub one seam without rebuilding the rest.
type fileScepterOps struct {
	conf       string // the tunnel dir: /etc/wattun in production, the -config dir in dev
	self       string // this unit's own config name; write ops refuse it — the cockpit channel rides this unit
	maxTunnels int
	unit       func(name, action string) error // systemd action: start | stop | restart | disable
	active     func(name string) bool          // unit liveness (systemctl is-active equivalent)
	known      func(key string) bool           // is key a config key this binary accepts (nil = accept all)
	sshdConf   string                          // the port guard's sshd_config ("" = /etc/ssh/sshd_config; tests point it elsewhere)
	denyExtra  string                          // -scepter-deny-ports: the owner's own guarded targets (Kharej-local)
	logf       func(string, ...any)

	probeMu     sync.Mutex               // guards probes and autoRun: timers and the auto-test goroutine run outside the command queue
	probes      map[string]*scepterProbe // live probe listeners (test.open); closed at ttl expiry or test.close
	autoRun     autoRunState             // the last (or running) fleet auto-test run
	runProbe    func(pr *scepterProbe) (down float64, ok bool, why string)
	linkCheck   func(carrier string, binds map[int]string) error
	nowf        func() time.Time
	probeMinS   int // probe ttl clamps; 0 = the documented defaults (10 / 3600 / 300)
	probeMaxS   int
	probeDefS   int
	orphanSweep bool // true once the constructor swept restart-orphaned probes (once per process)

	// U0 audit coverage (2026-11-23) seams — nil falls back to the production loopback clients (the phase C
	// convention). carrier.mute and limits.reset talk to the tunnel's OWN metrics server (GET /stats, POST
	// /carrier/toggle and /quota/reset), exactly the bash console's mute/unmute and quota-reset actions.
	httpGet  func(addr, path string) (map[string]any, error)      // metrics GET (nil = probeGetJSON)
	httpPost func(addr, path string) (map[string]any, int, error) // metrics POST (nil = probePostJSON; the status is separate so ResetLimits can tolerate a 404)

	// Phase D (update orchestration) seams — nil falls back to the production implementation, so a
	// struct-literal test can stub one seam without rebuilding the rest (the phase C convention).
	updRunning atomic.Bool // one update at a time per process (the journal replay of a retried id never reaches here)
	updRun     string      // the running (or last accepted) update.run command id
	updGrace   time.Duration
	exePath    func() (string, error)              // the swap target; nil = os.Executable + EvalSymlinks
	updFetch   func(dir, to string) error          // stage a verified release into dir (wattun.new)
	updProbe   func(newBin string) (string, error) // sanity-run the staged binary; returns its -version
	updLaunch  func(stage, bin string) error       // hand the job to systemd (production: systemd-run)
	updPrevVer func(prev string) string            // -version of the wattun.prev binary ("" when it will not run)
}

// scepterProbe is one live probe listener: a short-lived server unit (NAME = the probe id) that exists only so
// a throw-away client can measure a carrier shape. It forwards nothing: the yml carries a bare `ports:` (an
// explicit empty allowlist) and target port 0 — the built-in speed test — is answered before the allowlist
// check (main.go serve()), so the probe can never reach a local service.
type scepterProbe struct {
	id      string // the probe tunnel name; doubles as the test.close id
	carrier string
	port    int    // the listen port on Kharej (all interfaces), from the 20500-20999 test range
	key     string // the probe's own PSK, delivered to the cockpit inside the session AEAD
	metrics string // the probe unit's private /stats ("" when no port was free)
	timer   *time.Timer
}

// autoRow is one ranked row of a fleet auto-test run (auto.rows). Rank is the 1-based position in the ranked
// order — exactly what auto.apply's row argument names.
type autoRow struct {
	Rank     int     `json:"rank"`
	Carrier  string  `json:"carrier"`
	Port     int     `json:"port,omitempty"`
	OK       bool    `json:"ok"`
	DownMbps float64 `json:"down_mbps,omitempty"`
	Why      string  `json:"why,omitempty"`
}

// autoRunState is the stored result of the last auto.test (and the in-flight run's progress).
type autoRunState struct {
	id      string
	mode    string
	running bool
	rows    []autoRow
}

// autoTestShapes is the auto-test catalog: shapes a Kharej can serve with no external material (self-signed
// TLS in memory, the shared /wat default path). Raw-IP carriers (icmp, gre, ipip, raw shaped) have no probe
// listener and are excluded; mode "" means plain.
var autoTestShapes = map[string][]string{
	"plain": {"udp", "tcp", "ws", "h2c"},
	"tls":   {"udp", "tcp", "ws", "h2c", "tls", "wss", "h2", "grpc"},
}

// scepterLinkWait is how long the link check retries a bind dial after the unit reported active: the fresh
// process binds within a moment of systemd's verdict.
const scepterLinkWait = 4 * time.Second

// newFileScepterOps wires the production ops: the systemd template wattun@NAME, exactly the unit install.sh
// and the manager create. self is this process's own unit ("" when run without -config, e.g. a flag-run dev
// server, which owns no yml the cockpit could collide with by name).
func newFileScepterOps(conf, self string, known func(string) bool, logf func(string, ...any)) *fileScepterOps {
	o := &fileScepterOps{
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
			case "disable": // the rollback half of start (F10, 2026-11-22); Delete's best-effort disable
				return runSystemctl("disable", u)
			}
			return fmt.Errorf("scepter ops: unknown unit action %q", action)
		},
		active: func(name string) bool {
			return exec.Command("systemctl", "is-active", "--quiet", "wattun@"+name).Run() == nil
		},
	}
	o.sweepOrphanProbes() // an engine restart forgets its timers: probes from the previous life must not linger
	return o
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
	unlock, err := mgr.WriteLock() // plan D3: the console and the web panel write these files too
	if err != nil {
		os.Remove(tmp)
		return err
	}
	defer unlock()
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

// createAuto: carrier "auto" is the manager's Kharej auto tunnel (every carrier at once plus the test plan in its
// token), so Kharej runs its own manager unattended and hands back the token; Iran then tests and picks (3.6.1).
func (o *fileScepterOps) createAuto(name, ports string) (map[string]any, int) {
	if p := o.capFull(16); p != nil { // an auto tunnel brings up to 15 helpers
		return p, wat.CodeRateLimited
	}
	bin, err := os.Executable()
	if err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "kharej", "--carrier", "auto", "--name", name, "--ports", ports, "--yes")
	cmd.Env = append(os.Environ(), "WAT_CONF="+o.conf, "NONINTERACTIVE=1", "NO_COLOR=1", "WAT_NO_ANIM=1")
	out, err := cmd.CombinedOutput()
	tok := ""
	for _, l := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "TOKEN="); ok {
			tok = v
		}
	}
	if err != nil || tok == "" {
		last := strings.TrimSpace(string(out))
		if i := strings.LastIndex(last, "\n"); i >= 0 {
			last = last[i+1:]
		}
		return map[string]any{"name": name, "detail": "the auto wizard failed: " + last}, wat.CodeInternal
	}
	return map[string]any{"name": name, "carrier": "auto", "allow": ports, "token": tok}, wat.CodeOK
}

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
	if p, code := o.checkTargets(ports); code != wat.CodeOK {
		return p, code
	}
	if spec.Carrier == "auto" {
		return o.createAuto(name, spec.Ports)
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
	if p := o.capFull(1); p != nil {
		return p, wat.CodeRateLimited
	}
	metrics := o.pickMetricsPort(name) // best effort: a busy host creates without a private /stats
	yml := scepterTunnelYML(spec, ports, metrics)
	// round-2 F5 (2026-11-22): applyEdit re-parses the composed yml before writing; Create wrote blind — a
	// value containing ` #` was silently truncated by stripComment and the unit ran with a different value
	// than the cockpit asked for. Re-parse here: a parse error, or a value that does not survive the
	// round trip, fails BEFORE any file moves (nothing to roll back).
	if cfg, err := parseConfig(yml, nil); err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeBadRequest
	} else {
		for _, k := range sortedParamKeys(spec.Params) {
			if got, _ := cfg.get(k); got != spec.Params[k] {
				return map[string]any{"key": k,
						"detail": fmt.Sprintf("value does not survive the yml round trip (%q became %q)", spec.Params[k], got)},
					wat.CodeBadRequest
			}
		}
	}
	// apply: files first (atomic), then the unit, then the liveness verify; any failure removes what was
	// written — the original state of a create is "nothing there", so the rollback is a clean removal.
	if err := o.writeTunnel(name, spec, ports, metrics, yml); err != nil {
		o.removeFiles(name)
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	if err := o.unit(name, "start"); err != nil {
		o.unit(name, "stop") // best effort: the unit may be in auto-restart despite the failed command
		o.disableUnit(name)
		o.removeFiles(name)
		return map[string]any{"detail": err.Error(), "rolled_back": true}, wat.CodeInternal
	}
	if !o.waitActive(name, true) {
		o.unit(name, "stop")
		o.disableUnit(name)
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
	// what the cockpit needs to build that token itself (Handoff 4 R4): the carrier port Iran dials and the
	// allowlist; the cockpit knows Kharej's host from its own paired tunnel
	if b := scepterBinds(spec.Carrier, scepterIsReverse(spec.Params),
		func(k string) string { return spec.Params[k] }, ""); len(b) == 1 {
		for port := range b {
			p["listen_port"] = port // a bond has several binds: no single peer port, the token stays manual
		}
	}
	p["allow"] = scepterAllowStr(ports)
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

// tunnelCount counts tunnels toward the cap: an auto tunnel's hidden helpers (NAME-e-*, marked by a .autoext
// sidecar) belong to their parent and do not count, or four auto tunnels (14 units each) filled a 64 cap and
// every later create was refused. unitCount is every unit, helpers included; scepterMaxUnits bounds that.
func (o *fileScepterOps) tunnelCount() int {
	m, _ := filepath.Glob(filepath.Join(o.conf, "*.yml"))
	n := 0
	for _, f := range m {
		if _, err := os.Stat(strings.TrimSuffix(f, ".yml") + ".autoext"); err != nil {
			n++
		}
	}
	return n
}

func (o *fileScepterOps) unitCount() int {
	m, _ := filepath.Glob(filepath.Join(o.conf, "*.yml"))
	return len(m)
}

// capFull answers a create that would pass either cap (extra = the units this create adds), in the shape
// Iran reads: resource "tunnels", the cap, and how many there are (have, 3.6.1+).
func (o *fileScepterOps) capFull(extra int) map[string]any {
	if n := o.tunnelCount(); n >= o.maxTunnels {
		return map[string]any{"resource": "tunnels", "cap": o.maxTunnels, "have": n}
	}
	if u := o.unitCount(); u+extra > o.maxTunnels*scepterUnitsPerTunnel {
		return map[string]any{"resource": "units", "cap": o.maxTunnels * scepterUnitsPerTunnel, "have": u}
	}
	return nil
}

// scepterTunnelYML composes the tunnel.create yml body: a provenance comment line 1 (the sweep and every
// owner can tell a remote create from a hand-written config), then the fixed keys, then the params in
// sorted order. Separated from writeTunnel so Create can re-parse the exact text it is about to write
// (round-2 F5, 2026-11-22).
func scepterTunnelYML(spec wat.ScepterTunnelSpec, ports []portSpec, metrics string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# created by scepter tunnel.create %s (wat %s)\n", time.Now().UTC().Format(time.RFC3339), wat.Version)
	b.WriteString("mode: server\n")
	fmt.Fprintf(&b, "key: %s\n", spec.Key)
	fmt.Fprintf(&b, "carrier: %s\n", spec.Carrier)
	if metrics != "" {
		fmt.Fprintf(&b, "metrics: %s\n", metrics)
	}
	for _, k := range sortedParamKeys(spec.Params) { // deterministic file: the cfgWatcher's restart-needed diff must not jitter
		fmt.Fprintf(&b, "%s: %s\n", k, scepterYMLValue(spec.Params[k]))
	}
	b.WriteString("ports:\n")
	for _, p := range ports {
		fmt.Fprintf(&b, "  - %s\n", portItemStr(p))
	}
	return b.String()
}

// sortedParamKeys is the deterministic param order both the yml composition (here) and the create-path
// validation iterate in.
func sortedParamKeys(params map[string]string) []string {
	ks := make([]string, 0, len(params))
	for k := range params {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// writeTunnel writes NAME.yml (+ NAME.key, and NAME.token when the token is derivable) atomically. yml is
// the text Create already composed and re-parsed (round-2 F5) — never a second composition.
func (o *fileScepterOps) writeTunnel(name string, spec wat.ScepterTunnelSpec, ports []portSpec, metrics, yml string) error {
	if err := o.writeAtomic(o.path(name, "yml"), yml); err != nil {
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

// disableUnit is the rollback half of "start" (F10, 2026-11-22): start is enable --now, so a failed create
// or probe whose stop+removeFiles just ran would leave wattun@NAME still ENABLED with no yml — failing every
// boot until someone disables it (Delete always disabled; the rollbacks forgot). Best effort, like Delete's.
func (o *fileScepterOps) disableUnit(name string) {
	o.unit(name, "disable")
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
		if (rawIPCarrier[base] || hopCarrier[base]) && runtime.GOOS != "linux" {
			return wat.CodeCarrierNeeds, map[string]any{"carrier": base, "ver": wat.Version, "need": "linux+CAP_NET_RAW"}
		}
	}
	return wat.CodeOK, nil
}

// scepterParamDeny: keys the ops write themselves (a duplicate would fail the unit's own yml parse at start),
// repeatable keys set semantics break (header), and the standalone action flags, which have no business in a
// created tunnel. carrier is denied on create (the ops write it) but allowed in edit patches. update-job
// (F3, 2026-11-22) is a standalone action flag too, and the nastiest one: the yml parser flag.Set()s config
// keys, so a planted `update-job: X` re-enters the update-job path and exits on every unit start — a crash
// loop.
var scepterParamDeny = map[string]bool{
	"mode": true, "key": true, "carrier": true, "ports": true, "limits": true, "header": true,
	"config": true, "version": true, "pair": true, "pair-to": true, "pairing": true, "update-job": true,
	"latch-port": true, "latch-dial": true, "scepter-call": true, "scepter-args": true,
	"metrics":            true, // round-2 F4 (2026-11-22): the ops write metrics themselves (pickMetricsPort); a param
	"key-file":           true, // one would double the key, and a key-file one would shadow the ops-written key
	"scepter-deny-ports": true, // Handoff 4 R5: the port guard's owner list is Kharej-local, never set remotely
	"state-dir":          true, // M8: a unit's CWD is /, a hand-set relative state-dir would scatter state files
}

// checkCreateParams: every param key must be one the unit's own config parser accepts (the `known` set, the
// same check the cfgWatcher enforces on a hand-edited yml), must not fight a key the ops write themselves,
// and its value must be one line — a \n or \r would let a value plant arbitrary yml lines (a provenance
// comment, a second key) in the composed file (round-2 F1, 2026-11-22).
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
		if strings.ContainsAny(params[k], "\n\r") {
			return wat.CodeBadRequest, map[string]any{"key": k, "why": "a param value must be one line"}
		}
		if o.known != nil && !o.known(k) {
			return wat.CodeBadRequest, map[string]any{"key": k, "why": "unknown config key"}
		}
	}
	return wat.CodeOK, nil
}

// checkEditParams: the edit patch may switch the carrier (phase C adds the link-verified change around it)
// but fights none of the other owned keys; limits go through limits.set. Same one-line value rule as
// checkCreateParams (round-2 F1, 2026-11-22): scepterPatchYML writes the value raw.
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
		if strings.ContainsAny(patch.Set[k], "\n\r") {
			return wat.CodeBadRequest, map[string]any{"key": k, "why": "a param value must be one line"}
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
	return o.applyEdit(name, patch, false)
}

// applyEdit is the edit flow (validate → backup → apply → restart → verify → rollback). linkVerify upgrades
// the liveness verify into a link check: every port the patched config would bind is dialed (phase C — a
// carrier.switch that binds nothing serves nobody), and a failure restores the .bak.
func (o *fileScepterOps) applyEdit(name string, patch wat.ScepterPatch, linkVerify bool) (map[string]any, int) {
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
	if patch.Ports != "" {
		ports, err := parseScepterPortItems(patch.Ports)
		if err != nil {
			return map[string]any{"ports": err.Error()}, wat.CodeBadRequest
		}
		if p, code := o.checkTargets(ports); code != wat.CodeOK {
			return p, code
		}
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
	binds := scepterBinds(carrier, rev == "true" || rev == "1", listen, metrics)
	if code, p := o.checkBindCollisions(name, binds); code != wat.CodeOK {
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
	if linkVerify {
		if err := o.checkLink(carrier, binds); err != nil {
			o.rollback(f, string(old))
			return map[string]any{"detail": err.Error(), "rolled_back": true}, wat.CodeInternal
		}
	}
	p := map[string]any{"name": name}
	if _, is := patch.Set["carrier"]; is { // the handler turns this into the carrier_switched event
		p["carrier"] = carrier
		if port := listenPort(binds); port > 0 {
			p["listen"] = port // what the Iran side must dial after its own restart (TECHNICAL.md contract)
		}
	}
	o.logf("scepter ops: edited tunnel %s (%d key(s), ports %q)", name, len(patch.Set), patch.Ports)
	return p, wat.CodeOK
}

// listenPort picks the carrier's own bind port out of a scepterBinds map (the metrics entry is not it).
func listenPort(binds map[int]string) int {
	ps := make([]int, 0, len(binds))
	for p, what := range binds {
		if what == "metrics" {
			continue
		}
		ps = append(ps, p)
	}
	sort.Ints(ps)
	if len(ps) == 0 {
		return 0
	}
	return ps[0]
}

// CarrierChange: carrier.change {name, carrier, params} (plan C.1) — the auto_apply discipline remotely:
// validate the target shape, apply the patch through the edit path with a LINK check, and let applyEdit roll
// everything back (config restored, unit restarted) when the new carrier does not come up.
func (o *fileScepterOps) CarrierChange(name, carrier string, params map[string]string) (map[string]any, int) {
	if code, p := o.checkCarrier(carrier); code != wat.CodeOK { // a shape the host cannot serve fails before any file moves
		return p, code
	}
	set := make(map[string]string, len(params)+1)
	for k, v := range params {
		set[k] = v
	}
	set["carrier"] = carrier
	p, code := o.applyEdit(name, wat.ScepterPatch{Set: set}, true)
	if code == wat.CodeOK {
		o.logf("scepter ops: carrier change on %s -> %s (link check ok)", name, carrier)
	}
	return p, code
}

// checkLink verifies the new carrier's listeners actually accept: every non-metrics bind is probed on
// loopback (TCP: connect; UDP: a bind conflict test, see dialBindPort). Retried until scepterLinkWait because
// the fresh process binds within a moment of systemd's verdict. Raw carriers bind no port — the unit liveness
// verify is all Kharej can see of them. This is the SERVER-side half of the link check: the pass-traffic
// verdict comes from the cockpit restarting its own tunnel and re-checking (docs/TECHNICAL.md, the Iran-side
// restart contract).
func (o *fileScepterOps) checkLink(carrier string, binds map[int]string) error {
	if o.linkCheck != nil { // test seam
		return o.linkCheck(carrier, binds)
	}
	deadline := o.now().Add(scepterLinkWait)
	for {
		var err error
		for p, what := range binds {
			if what == "metrics" {
				continue
			}
			if e := dialBindPort(p, isUDPBindName(what), 2*time.Second); e != nil {
				err = e
				break
			}
		}
		if err == nil {
			return nil
		}
		if o.now().After(deadline) {
			return fmt.Errorf("link check: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// isUDPBindName: scepterBinds labels each port with the carrier leg that binds it; a udp-tier leg gets a UDP
// probe, everything else TCP.
func isUDPBindName(what string) bool {
	return what == "udp" || shapedUDPCarrier[what]
}

// dialBindPort checks one bound port on loopback. TCP: a connect — the pool listener accepts and waits, so a
// successful connect is exactly "the new carrier is serving". UDP: a socket bind on the same loopback address
// — a live listener makes the bind fail (the port is held, healthy), an unbound port binds (and the probe
// socket is closed immediately). The bind probe replaces the classic junk-datagram probe: Windows does not
// reliably surface ICMP port-unreachable on a connected UDP socket (measured 2026-11-22, TestDialBindPort),
// while the bind conflict is exact on every OS. Assumes the tunnel binds a wildcard or loopback-reachable
// address — the shape these ops and the manager write.
func dialBindPort(port int, udp bool, d time.Duration) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if !udp {
		c, err := net.DialTimeout("tcp", addr, d)
		if err != nil {
			return err
		}
		c.Close()
		return nil
	}
	c, err := net.ListenPacket("udp", addr)
	if err == nil {
		c.Close()
		return fmt.Errorf("udp :%d is not bound", port)
	}
	return nil // bind conflict: the port is held
}

// rollback restores the pre-edit yml and restarts the unit; both best-effort — the response already says
// rolled_back, and the .bak stays on disk either way for a human.
func (o *fileScepterOps) rollback(f, old string) {
	o.writeAtomic(f, old)
	o.unit(filepath.Base(strings.TrimSuffix(f, ".yml")), "restart")
}

// now is the clock seam (tests shrink the probe ttl and the link wait).
func (o *fileScepterOps) now() time.Time {
	if o.nowf != nil {
		return o.nowf()
	}
	return time.Now()
}

func (o *fileScepterOps) probeTTLBounds() (minS, maxS, defS int) {
	minS, maxS, defS = o.probeMinS, o.probeMaxS, o.probeDefS
	if minS <= 0 {
		minS = 10
	}
	if maxS <= 0 {
		maxS = 3600
	}
	if defS <= 0 {
		defS = 300
	}
	return minS, maxS, defS
}

// ---- test.open / test.close: probe listeners (phase C) ----

// sweepOrphanProbes removes probes left by a previous engine life: the process that created them is gone, so
// their timers are gone, and a leaked listener would sit on its port forever. Only ymls carrying the probe
// provenance line are swept — a user tunnel merely named probe-something is left alone. Best effort: a sweep
// that cannot stop a unit leaves the files (the next boot tries again).
func (o *fileScepterOps) sweepOrphanProbes() {
	if o.orphanSweep {
		return
	}
	o.orphanSweep = true
	files, _ := filepath.Glob(filepath.Join(o.conf, "probe-*.yml"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil || !probeProvenanceFirst(b) {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(f), ".yml")
		o.unit(name, "stop")
		o.disableUnit(name) // start was enable --now: the sweep must leave no enabled unit behind either
		o.removeFiles(name)
		o.logf("scepter ops: swept orphaned probe %s (left by a previous engine run)", name)
	}
}

// probeProvenanceFirst reports whether the yml's FIRST non-empty line is the probe provenance comment —
// exactly where openProbe writes it (line 1). Matching only line 1 (round-2 F1, 2026-11-22) closes the
// injection hole strings.Contains had: a param value with an embedded newline could plant the provenance
// text mid-file and get a user tunnel destroyed on the next restart. The value-side half of the fix is the
// one-line rule in checkCreateParams/checkEditParams.
func probeProvenanceFirst(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		return strings.HasPrefix(t, "# "+probeProvenance)
	}
	return false
}

// probeProvenance marks a yml as this machinery's product (the sweep reads it; the count is what keeps a
// hand-made tunnel named probe-x safe).
const probeProvenance = "probe tunnel created by scepter test.open"

func (o *fileScepterOps) TestOpen(carrier string, ttlS int) (map[string]any, int) {
	if strings.Contains(carrier, "+") {
		return map[string]any{"carrier": carrier, "why": "a probe takes one carrier, not a bond"}, wat.CodeBadRequest
	}
	if code, p := o.checkCarrier(carrier); code != wat.CodeOK {
		return p, code
	}
	if carrierNoListen[carrier] { // icmp/gre/ipip/raw shaped bind no port: nothing for a throw-away client to dial
		return map[string]any{"carrier": carrier, "why": "raw carriers have no probe listener"}, wat.CodeBadRequest
	}
	minS, maxS, defS := o.probeTTLBounds()
	switch {
	case ttlS <= 0:
		ttlS = defS
	case ttlS < minS:
		ttlS = minS
	case ttlS > maxS:
		ttlS = maxS
	}
	pr, code, detail := o.openProbe(carrier, ttlS)
	if code != wat.CodeOK {
		if code == wat.CodeRateLimited { // F7: same params shape as tunnel.create's cap answer
			return map[string]any{"resource": "probes", "cap": o.maxTunnels}, code
		}
		return map[string]any{"detail": detail, "rolled_back": code == wat.CodeInternal}, code
	}
	p := map[string]any{"id": pr.id, "carrier": carrier, "port": pr.port, "key": pr.key, "ttl": ttlS}
	if pr.metrics != "" {
		p["metrics"] = pr.metrics
	}
	if httpCarrier[carrier] {
		p["path"] = "/wat" // the shared default path (normPath), so the cockpit has every dial parameter in one answer
	}
	o.logf("scepter ops: probe %s up (%s :%d, ttl %ds)", pr.id, carrier, pr.port, ttlS)
	return p, wat.CodeOK
}

// openProbe is the probe machinery both test.open and the auto-test core use: validate nothing (callers
// did), pick a port, write the speed-test-only yml, start the unit, verify liveness AND that the listener
// accepts, then arm the ttl timer. Failures remove everything they wrote (and disable what they enabled).
func (o *fileScepterOps) openProbe(carrier string, ttlS int) (*scepterProbe, int, string) {
	// F7 (2026-11-22): probes are units too — their ymls live in the conf dir, so tunnelCount already counts
	// them, but nothing here ever CHECKED, and sustained test.open held probe units far past the cap the
	// create path respects. Same answer shape as tunnel.create's cap (rate_limited, resource=probes).
	if o.capFull(1) != nil {
		return nil, wat.CodeRateLimited, fmt.Sprintf("tunnel cap %d reached (probes count toward it)", o.maxTunnels)
	}
	name := fmt.Sprintf("probe-%d", o.now().Unix())
	for i := 0; o.exists(name); i++ { // same-second collision: suffix up
		name = fmt.Sprintf("probe-%d-%d", o.now().Unix(), i+2)
		if i > 100 {
			return nil, wat.CodeInternal, "no free probe name"
		}
	}
	key := wat.ScepterNewKey()
	if key == "" {
		return nil, wat.CodeInternal, "key generation failed"
	}
	port, err := o.freeProbePort(isUDPBindName(carrier))
	if err != nil {
		return nil, wat.CodeInternal, err.Error()
	}
	metrics := o.pickMetricsPort(name) // best effort: a probe without /stats still serves speed tests
	yml := fmt.Sprintf("# %s %s (wat %s); removed at ttl expiry or test.close\n"+
		"mode: server\nkey: %s\ncarrier: %s\nlisten: :%d\n", probeProvenance, o.now().UTC().Format(time.RFC3339), wat.Version,
		key, carrier, port)
	if metrics != "" {
		yml += "metrics: " + metrics + "\n"
	}
	yml += "ports:\n" // bare ports: = an explicit EMPTY allowlist; only target 0 (the speed test) is ever answered
	if err := o.writeAtomic(o.path(name, "yml"), yml); err != nil {
		return nil, wat.CodeInternal, err.Error()
	}
	if err := o.writeAtomic(o.path(name, "key"), key+"\n"); err != nil {
		o.removeFiles(name)
		return nil, wat.CodeInternal, err.Error()
	}
	if err := o.unit(name, "start"); err != nil {
		o.unit(name, "stop")
		o.disableUnit(name)
		o.removeFiles(name)
		return nil, wat.CodeInternal, err.Error()
	}
	if !o.waitActive(name, true) {
		o.unit(name, "stop")
		o.disableUnit(name)
		o.removeFiles(name)
		return nil, wat.CodeInternal, "probe unit did not come up"
	}
	if err := o.checkLink(carrier, map[int]string{port: carrier}); err != nil {
		o.unit(name, "stop")
		o.disableUnit(name)
		o.removeFiles(name)
		return nil, wat.CodeInternal, err.Error()
	}
	pr := &scepterProbe{id: name, carrier: carrier, port: port, key: key, metrics: metrics}
	o.probeMu.Lock()
	if o.probes == nil {
		o.probes = map[string]*scepterProbe{}
	}
	o.probes[name] = pr
	// under probeMu: a concurrent test.close reads pr.timer once it finds pr in the map
	pr.timer = time.AfterFunc(time.Duration(ttlS)*time.Second, func() { o.expireProbe(name, "ttl") })
	o.probeMu.Unlock()
	return pr, wat.CodeOK, ""
}

// freeProbePort finds a free port in 20500-20999 (the manager's at_free_port range) for the given protocol,
// avoiding every port another tunnel or listener claims. Probes count toward the tunnel cap like any unit,
// and their listen ports are visible to portUsers, so a live probe also blocks its own port.
func (o *fileScepterOps) freeProbePort(udp bool) (int, error) {
	taken := o.portUsers("")
	for p := 20500; p < 21000; p++ {
		if _, busy := taken[p]; busy {
			continue
		}
		var c io.Closer
		var err error
		if udp {
			c, err = net.ListenPacket("udp", fmt.Sprintf(":%d", p))
		} else {
			c, err = net.Listen("tcp", fmt.Sprintf(":%d", p))
		}
		if err != nil {
			continue
		}
		c.Close()
		return p, nil
	}
	return 0, fmt.Errorf("no free probe port in 20500-20999")
}

func (o *fileScepterOps) TestClose(id string) (map[string]any, int) {
	o.probeMu.Lock()
	pr, ok := o.probes[id]
	if ok {
		delete(o.probes, id)
	}
	o.probeMu.Unlock()
	if !ok {
		return map[string]any{"id": id, "why": "no such probe listener"}, wat.CodeNotFound
	}
	o.closeProbe(pr)
	o.logf("scepter ops: probe %s closed by test.close", id)
	return map[string]any{"id": id, "closed": true}, wat.CodeOK
}

// expireProbe fires from the ttl timer: the probe is gone either way, files included (a probe is engine
// machinery, not owner data — nothing to keep as .bak).
func (o *fileScepterOps) expireProbe(id, why string) {
	o.probeMu.Lock()
	pr, ok := o.probes[id]
	if ok {
		delete(o.probes, id)
	}
	o.probeMu.Unlock()
	if !ok {
		return // already closed by test.close
	}
	o.closeProbe(pr)
	o.logf("scepter ops: probe %s expired (%s)", id, why)
}

func (o *fileScepterOps) closeProbe(pr *scepterProbe) {
	if pr.timer != nil {
		pr.timer.Stop()
	}
	o.unit(pr.id, "stop")
	o.disableUnit(pr.id) // round-2 F2 (2026-11-22): openProbe's start was enable --now, so ttl expiry,
	// test.close and auto-test done must disable too — a stop+removeFiles alone left an enabled fileless
	// unit failing every boot (the F10 rollback rule; the sweep below had the same hole)
	o.removeFiles(pr.id)
}

// ---- auto.test / auto.rows / auto.apply: the fleet auto-test core (phase C) ----
//
// The pre-existing auto tester is wattun-manager bash logic on IRAN (at_probe/at_curl in wattun-manager):
// throw-away clients, /stats alive wait, /speedtest measurement. This core is the triggerable engine-side
// twin, per the plan's "implement the triggerable core in the engine ops": Kharej measures which shapes it
// can SERVE and how fast (a throw-away client of itself against the probe listener — the same measurement
// method the fast preset uses). The DPI verdict stays Iran's: the cockpit runs its own fast preset locally
// and applies a row via auto.apply or carrier.change (docs/TECHNICAL.md).

func (o *fileScepterOps) AutoTest(mode string, done func(ok, total int)) (map[string]any, int) {
	if mode == "" {
		mode = "plain"
	}
	shapes, known := autoTestShapes[mode]
	if !known {
		return map[string]any{"modes": "plain,tls"}, wat.CodeBadRequest
	}
	o.probeMu.Lock()
	if o.autoRun.running {
		run := o.autoRun.id
		o.probeMu.Unlock()
		return map[string]any{"run": run, "already_running": true}, wat.CodeOK
	}
	run := fmt.Sprintf("at-%d", o.now().Unix())
	o.autoRun = autoRunState{id: run, mode: mode, running: true}
	o.probeMu.Unlock()
	go func() { // async: a run takes ~1 min (one probe + one throw-away client per shape); the command
		// queue must not be held that long, and the answer is read via auto.rows / EvAutoTested.
		_, _, defS := o.probeTTLBounds()
		rows := make([]autoRow, 0, len(shapes))
		ok := 0
		for _, carrier := range shapes {
			row := o.measureShape(carrier, defS) // the default ttl, not the floor: the measurement (alive
			// wait up to 15 s + one speedtest) must never be cut short by its own probe's timer; the
			// explicit close below does the cleanup, the ttl is only the abandoned-run safety net
			if row.OK {
				ok++
			}
			rows = append(rows, row)
		}
		rankRows(rows)
		o.probeMu.Lock()
		o.autoRun.rows = rows
		o.autoRun.running = false
		o.probeMu.Unlock()
		if done != nil {
			done(ok, len(shapes))
		}
	}()
	return map[string]any{"run": run, "mode": mode, "shapes": len(shapes)}, wat.CodeOK
}

// measureShape opens one probe, runs the measurement seam against it, closes the probe. The ttl floor (not
// the default) bounds an abandoned probe when the run dies mid-way.
func (o *fileScepterOps) measureShape(carrier string, ttlS int) autoRow {
	pr, code, detail := o.openProbe(carrier, ttlS)
	if code != wat.CodeOK {
		return autoRow{Carrier: carrier, Why: "probe open failed: " + detail}
	}
	down, ok, why := o.runProbeFn()(pr)
	o.expireProbe(pr.id, "auto-test done")
	return autoRow{Carrier: carrier, Port: pr.port, OK: ok, DownMbps: down, Why: why}
}

func (o *fileScepterOps) runProbeFn() func(pr *scepterProbe) (float64, bool, string) {
	if o.runProbe != nil {
		return o.runProbe
	}
	return o.spawnProbeClient
}

// rankRows orders the table for auto.rows/auto.apply: servable shapes first by measured rate, failures last
// in catalog order (stable: two runs of the same host rank deterministically).
func rankRows(rows []autoRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].OK != rows[j].OK {
			return rows[i].OK
		}
		if rows[i].OK && rows[i].DownMbps != rows[j].DownMbps {
			return rows[i].DownMbps > rows[j].DownMbps
		}
		return false
	})
	for i := range rows {
		rows[i].Rank = i + 1
	}
}

func (o *fileScepterOps) AutoRows() (map[string]any, int) {
	o.probeMu.Lock()
	defer o.probeMu.Unlock()
	r := o.autoRun
	rows := make([]autoRow, len(r.rows))
	copy(rows, r.rows)
	ok := 0
	for _, row := range rows {
		if row.OK {
			ok++
		}
	}
	return map[string]any{"run": r.id, "mode": r.mode, "done": !r.running, "ok": ok, "rows": rows}, wat.CodeOK
}

func (o *fileScepterOps) ApplyRow(name string, row int) (map[string]any, int) {
	o.probeMu.Lock()
	rs, running := o.autoRun.rows, o.autoRun.running
	o.probeMu.Unlock()
	if running || row < 1 || row > len(rs) {
		p := map[string]any{"row": row, "why": "no such row (auto.rows is the table; rows rank from 1)"}
		if running {
			p["why"] = "the run is still going"
		}
		return p, wat.CodeNotFound
	}
	pick := rs[row-1]
	if !pick.OK {
		// round-2 F3 (2026-11-22): a failed row has Port 0, and CarrierChange over an empty bind map made
		// the link check trivially pass — applying it would switch the carrier to a shape this host
		// measurably cannot serve. The cockpit picks from auto.rows: refuse the row instead.
		return map[string]any{"row": row, "carrier": pick.Carrier,
			"why": fmt.Sprintf("row %d is a failed measurement", row)}, wat.CodeBadRequest
	}
	p, code := o.CarrierChange(name, pick.Carrier, map[string]string{"listen": fmt.Sprintf(":%d", pick.Port)})
	if code == wat.CodeOK {
		p["row"] = row
	}
	return p, code
}

// spawnProbeClient is the production measurement: a throw-away client process of THIS binary (the fast
// preset's at_start shape) dialing the probe listener over loopback, driven through its private metrics
// address — wait for /stats alive, then one down-direction /speedtest. Loopback only, killed after.
func (o *fileScepterOps) spawnProbeClient(pr *scepterProbe) (float64, bool, string) {
	bin, err := os.Executable()
	if err != nil {
		return 0, false, "no binary: " + err.Error()
	}
	mp := o.pickMetricsPort(pr.id)
	if mp == "" {
		return 0, false, "no free metrics port"
	}
	dmapPort, err := o.freeProbePort(false) // the dummy -map is a TCP listener; portUsers already holds pr.port
	if err != nil {
		return 0, false, err.Error()
	}
	args := probeClientArgs(pr, mp, dmapPort)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	if err := cmd.Start(); err != nil {
		return 0, false, "client start: " + err.Error()
	}
	defer func() { cancel(); cmd.Wait() }() // the kill is the timeout's job (a passing measure finishes first)

	statsURL := fmt.Sprintf("http://%s/stats", mp)
	deadline := o.now().Add(15 * time.Second)
	for {
		if m, err := probeGetJSON(statsURL, 2*time.Second); err == nil && m["alive"] == true {
			break
		}
		if o.now().After(deadline) {
			return 0, false, "no link in 15 s"
		}
		time.Sleep(300 * time.Millisecond)
	}
	res, err := probeGetJSON(fmt.Sprintf("http://%s/speedtest?dir=down&mb=4&streams=4", mp), 70*time.Second)
	if err != nil {
		return 0, false, "speedtest: " + err.Error()
	}
	if res["ok"] != true {
		why, _ := res["error"].(string)
		return 0, false, "speedtest failed: " + why
	}
	down, _ := res["mb_per_s"].(float64)
	return down, true, ""
}

// probeClientArgs is the throw-away client command line (pure; the test asserts the shape). The dummy map
// keeps the engine's "client without -map" refusal quiet while publishing nothing on a real interface.
func probeClientArgs(pr *scepterProbe, metrics string, dmapPort int) []string {
	return []string{
		"-mode", "client", "-carrier", pr.carrier,
		"-key", pr.key,
		"-peer", net.JoinHostPort("127.0.0.1", strconv.Itoa(pr.port)),
		"-metrics", metrics,
		"-map", fmt.Sprintf("%d:1@127.0.0.1", dmapPort),
	}
}

// probeGetJSON fetches one small JSON document from a loopback metrics address.
func probeGetJSON(url string, timeout time.Duration) (map[string]any, error) {
	c := &http.Client{Timeout: timeout}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
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
	o.disableUnit(name) // best effort: a never-enabled unit is fine (round-2 F6, 2026-11-22: through the
	// o.unit seam like every other unit action — Delete was the one direct runSystemctl caller left)
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

// ---- U0 audit coverage (2026-11-23): keyrotate, pair.rotate, mute, limits.reset ----

// KeyRotate: tunnel.keyrotate {name} — the tunnel PSK rotates, the edit drill over the three-file set
// (yml + key + token): backup → mint → rewrite atomically → restart → verify, and the edit path's rollback
// (the .bak set restored, unit restarted) when the new key does not come up. The response carries the new
// key and the rebuilt wat1: token mirroring the manager's make_token with the NEW key and the tunnel's
// existing fields — the cockpit needs it to update the Iran side, which still runs on the old key and is
// otherwise cut off at the restart. Self-unit refusal applies: the channel rides this unit.
func (o *fileScepterOps) KeyRotate(name string) (map[string]any, int) {
	if p, code := o.refuseSelf(name); code != wat.CodeOK {
		return p, code
	}
	ymlPath := o.path(name, "yml")
	oldYml, err := os.ReadFile(ymlPath)
	if err != nil {
		return map[string]any{"name": name}, wat.CodeNotFound
	}
	cfg, err := parseConfig(string(oldYml), nil)
	if err != nil { // a tunnel whose yml no longer parses is not rotatable blind: a human reads the .bak
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	oldKey, _ := cfg.get("key")
	if oldKey == "" {
		return map[string]any{"detail": "tunnel yml has no key to rotate"}, wat.CodeInternal
	}
	newKey := wat.ScepterNewKey()
	if newKey == "" {
		return map[string]any{"detail": "key generation failed"}, wat.CodeInternal
	}
	// rebuild the token FIRST, from the old artifacts: nothing has moved yet, and whether a token is
	// derivable decides the response shape before any file changes
	newTok := o.rotateToken(name, cfg, newKey)
	if _, err := os.Stat(o.path(name, "token")); err == nil && newTok == "" {
		// fix round 3 (2026-11-23): a token file that exists but cannot be rebuilt (unparsable, and the
		// yml has no carrier/peer to compose from) would survive the drill holding the DEAD key — the
		// success path skips the token rewrite when newTok is empty and the response omits it. Refuse
		// BEFORE any file moves (the edit path's rollback discipline); a human removes the stale file
		// or repairs the token.
		return map[string]any{"why": "existing token is unparsable; remove " + name + ".token and retry"}, wat.CodeInternal
	}
	newYml, err := scepterPatchYML(string(oldYml), wat.ScepterPatch{Set: map[string]string{"key": newKey}})
	if err != nil { // a single-key patch cannot fail the ports parse; kept for the never-trust-caller shape
		return map[string]any{"detail": err.Error()}, wat.CodeBadRequest
	}
	if cfg2, err := parseConfig(newYml, nil); err != nil { // round-2 F5 discipline: re-parse before writing
		return map[string]any{"detail": err.Error()}, wat.CodeBadRequest
	} else if k, _ := cfg2.get("key"); k != newKey {
		return map[string]any{"detail": "the new key does not survive the yml round trip"}, wat.CodeBadRequest
	}
	// backup → apply → verify → rollback, the edit flow's shape over yml+key+token
	hadToken := false
	for _, ext := range []string{"yml", "key", "token"} {
		if b, err := os.ReadFile(o.path(name, ext)); err == nil {
			if ext == "token" {
				hadToken = true // a rotate may CREATE a token file (yml-derived): the rollback must remove it
			}
			if err := o.writeAtomic(o.path(name, ext)+".bak", string(b)); err != nil {
				return map[string]any{"detail": err.Error()}, wat.CodeInternal
			}
		}
	}
	if err := o.writeAtomic(ymlPath, newYml); err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	if err := o.writeAtomic(o.path(name, "key"), newKey+"\n"); err != nil {
		o.rotateRollback(name, oldYml, oldKey, hadToken)
		return map[string]any{"detail": err.Error(), "rolled_back": true}, wat.CodeInternal
	}
	if newTok != "" {
		if err := o.writeAtomic(o.path(name, "token"), newTok+"\n"); err != nil {
			o.rotateRollback(name, oldYml, oldKey, hadToken)
			return map[string]any{"detail": err.Error(), "rolled_back": true}, wat.CodeInternal
		}
	}
	if err := o.unit(name, "restart"); err != nil {
		o.rotateRollback(name, oldYml, oldKey, hadToken)
		return map[string]any{"detail": err.Error(), "rolled_back": true}, wat.CodeInternal
	}
	if !o.waitActive(name, true) {
		o.rotateRollback(name, oldYml, oldKey, hadToken)
		return map[string]any{"detail": "unit did not come up with the new key", "rolled_back": true}, wat.CodeInternal
	}
	p := map[string]any{"name": name, "key": newKey}
	if newTok != "" {
		p["token"] = newTok // "" when nothing is derivable: the cockpit knows the peer itself
	}
	o.logf("scepter ops: rotated the key of tunnel %s (token %s)", name, map[bool]string{true: "rebuilt", false: "not derivable"}[newTok != ""])
	return p, wat.CodeOK
}

// rotateToken builds the rotated tunnel's token: the .token file's existing fields with the key swapped in
// when one exists (the manager-minted tokens carry per-leg and auto fields this side cannot rebuild), else
// the make_token twin over the yml's own fields (scepterToken over the parsed config). "" when neither is
// derivable (no token file, no peer in the yml).
func (o *fileScepterOps) rotateToken(name string, cfg *fileConfig, newKey string) string {
	if b, err := os.ReadFile(o.path(name, "token")); err == nil {
		if tok := scepterTokenSwapKey(strings.TrimSpace(string(b)), newKey); tok != "" {
			return tok
		}
	}
	carrier, _ := cfg.get("carrier")
	peer, _ := cfg.get("peer")
	if carrier == "" || peer == "" {
		return ""
	}
	params := map[string]string{}
	for _, k := range []string{"peer", "path", "sni", "icmp-type", "reverse"} {
		v, _ := cfg.get(k)
		params[k] = v
	}
	spec := wat.ScepterTunnelSpec{Carrier: carrier, Key: newKey, Params: params}
	return scepterToken(spec, cfg.Ports)
}

// scepterTokenSwapKey swaps field 3 (the PSK) of a wat1: token, preserving every other field byte-for-byte
// (the manager's make_token/read_token layout; parseTokenKey in pairing.go is the parser reference, including
// the unpadded-base64 tolerance). "" when the line is not a parsable token with a key field.
func scepterTokenSwapKey(tok, newKey string) string {
	b64 := strings.TrimPrefix(tok, "wat1:")
	d, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		if d, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(b64, "=")); err != nil {
			return ""
		}
	}
	f := strings.Split(string(d), "|")
	if len(f) < 3 || f[2] == "" {
		return ""
	}
	f[2] = newKey
	return "wat1:" + base64.StdEncoding.EncodeToString([]byte(strings.Join(f, "|")))
}

// rotateRollback restores the pre-rotation files (yml and key from the parsed originals, token from its
// .bak, or removed when the rotation created one) and restarts the unit on the old key — the edit path's
// rollback over the three-file set, best effort: the response already says rolled_back and the .baks stay
// on disk for a human.
func (o *fileScepterOps) rotateRollback(name string, oldYml []byte, oldKey string, hadToken bool) {
	o.writeAtomic(o.path(name, "yml"), string(oldYml))
	o.writeAtomic(o.path(name, "key"), oldKey+"\n")
	if b, err := os.ReadFile(o.path(name, "token") + ".bak"); err == nil {
		o.writeAtomic(o.path(name, "token"), string(b))
	} else if !hadToken {
		os.Remove(o.path(name, "token")) // the rotation minted it; the old tunnel had none
	}
	o.unit(name, "restart")
}

// pairRotateWindowDefault is the rotation window the store's oldkey_expires comment carries when the intent
// omits window_s: the bash console's own default (scepter_rotate, 86400 = 24 h). The window is bookkeeping
// only — the engine accepts only the current credential and reloads from the store within the poll
// interval (TECHNICAL.md accepted limits) — so it is recorded, never enforced.
const pairRotateWindowDefault = 86400

// PairRotate: pair.rotate {window_s?} — the pairing credential rotates ITSELF (a credential may always
// rotate at its own tier; caps CHANGES stay a Kharej-console action, plan D3). The store is rewritten
// atomically in the manager's pairing_store_write shape: the watp1: line first (same UUID, same caps, new
// 32-byte key), then the # created / # oldkey / # oldkey_expires comments — the engine's parser skips the
// comments (readPairingFile), the manager's console reads them. The engine handler adopts the returned
// credential (ReloadPairing), so THIS channel keeps working and the response line is for the OTHER cockpits.
// pair.revoke stays Kharej-local BY DESIGN (plan D3): the channel must not be able to revoke itself.
func (o *fileScepterOps) PairRotate(windowS int) (map[string]any, int) {
	if windowS <= 0 {
		windowS = pairRotateWindowDefault
	}
	ppath := filepath.Join(o.conf, ".pairing") // main wires the ops conf to filepath.Dir(pairPath): the store
	old, err := readPairingFile(ppath)         // sits exactly there, file-backed or not
	if err != nil {
		// the console's rotate refuses the same way (pairing_active/pairing_check_readable): a
		// token-bootstrap pair rotates by issuing a new token, a broken store needs a human
		return map[string]any{"why": "no parsable .pairing store to rotate (" + err.Error() + ")"}, wat.CodeNotFound
	}
	kb := make([]byte, 32)
	if _, err := crand.Read(kb); err != nil {
		return map[string]any{"detail": "key generation failed"}, wat.CodeInternal
	}
	np := &wat.PairingConfig{UUID: old.UUID, Caps: old.Caps, Ver: 1}
	copy(np.Key[:], kb)
	line := np.Line()
	created := strconv.FormatInt(o.now().Unix(), 10)
	if b, err := os.ReadFile(ppath); err == nil { // a rotation keeps the original creation time (the manager)
		for _, l := range strings.Split(string(b), "\n") {
			if t := strings.TrimSpace(l); strings.HasPrefix(t, "# created=") {
				created = strings.TrimPrefix(t, "# created=")
				break
			}
		}
	}
	store := line + "\n# created=" + created + "\n" +
		"# oldkey=" + base64.StdEncoding.EncodeToString(old.Key[:]) + "\n" +
		"# oldkey_expires=" + strconv.FormatInt(o.now().Unix()+int64(windowS), 10) + "\n"
	if err := o.writeAtomic(ppath, store); err != nil { // writeAtomic is tmp+rename 0600: the manager's umask 077 shape
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	o.logf("scepter ops: pairing %s rotated (window %ds); the channel adopts the new key immediately", old.UUIDString(), windowS)
	return map[string]any{"watp1": line, "uuid": old.UUIDString(), "window_s": windowS}, wat.CodeOK
}

// ---- carrier.mute / limits.reset: the tunnel's own metrics server ----
//
// Both ride the LOCAL metrics endpoint, exactly the bash console (carrier_toggle_cmd / the limits menu):
// the engine process runs where the metrics server is (loopback), so a scepter command is the same HTTP
// call the manager makes with curl. The httpGet/httpPost seams stand in for the clients in tests.

func (o *fileScepterOps) metricsGet(addr, path string) (map[string]any, error) {
	if o.httpGet != nil {
		return o.httpGet(addr, path)
	}
	return probeGetJSON("http://"+addr+path, 3*time.Second)
}

func (o *fileScepterOps) metricsPost(addr, path string) (map[string]any, int, error) {
	if o.httpPost != nil {
		return o.httpPost(addr, path)
	}
	return probePostJSON("http://"+addr+path, 3*time.Second)
}

// probePostJSON is the POST twin of probeGetJSON: one empty-body POST to a loopback metrics endpoint.
// Non-200 answers carry the status separately (ResetLimits tolerates a 404: no counter, nothing to reset)
// with the server's short error text in the error.
func probePostJSON(url string, timeout time.Duration) (map[string]any, int, error) {
	c := &http.Client{Timeout: timeout}
	resp, err := c.Post(url, "application/json", nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, resp.StatusCode, fmt.Errorf("%s: HTTP %d %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var m map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, resp.StatusCode, err
	}
	return m, resp.StatusCode, nil
}

// tunnelCfg loads and parses one tunnel's yml: the shared front door of the metrics-backed ops (mute,
// limits.reset) and keyrotate.
func (o *fileScepterOps) tunnelCfg(name string) (*fileConfig, int, map[string]any) {
	b, err := os.ReadFile(o.path(name, "yml"))
	if err != nil {
		return nil, wat.CodeNotFound, map[string]any{"name": name}
	}
	cfg, err := parseConfig(string(b), nil)
	if err != nil {
		return nil, wat.CodeInternal, map[string]any{"detail": err.Error()}
	}
	return cfg, wat.CodeOK, nil
}

// Mute: carrier.mute {name, carrier, mute} — bonded-path mute/unmute over POST /carrier/toggle. The engine
// endpoint TOGGLES, so the current state is read from /stats first and a no-op request is answered without
// a flip (the bash console's aligned check). A mute answered muted:false is a REFUSAL, not a success (the
// bash interpretation, 2026-11-20 review F2): the engine's ToggleMute answers it on a single-carrier server
// too. Deliberately NO self-unit refusal: muting a path of the channel's own unit re-routes the bond (the
// session survives; the bash console has the same power over the same tunnel). Non-bond tunnels are
// refused: muting a single-carrier tunnel would cut it with no way back from here.
func (o *fileScepterOps) Mute(name, carrier string, mute bool) (map[string]any, int) {
	if carrier == "" {
		return nil, wat.CodeBadRequest
	}
	cfg, code, p := o.tunnelCfg(name)
	if code != wat.CodeOK {
		return p, code
	}
	cr, _ := cfg.get("carrier")
	if !strings.Contains(cr, "+") {
		return map[string]any{"name": name, "why": "muting needs a bonded tunnel (carrier with + legs)"}, wat.CodeBadRequest
	}
	metrics, _ := cfg.get("metrics")
	if metrics == "" {
		return map[string]any{"name": name, "why": "tunnel has no metrics endpoint in its yml"}, wat.CodeBadRequest
	}
	st, err := o.metricsGet(metrics, "/stats")
	if err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	cur, found := statsCarrierMuted(st, carrier)
	if !found {
		return map[string]any{"carrier": carrier, "why": "no such path on this tunnel"}, wat.CodeBadRequest
	}
	if cur == mute { // already in the wanted state: no flip (the endpoint toggles)
		return map[string]any{"name": name, "carrier": carrier, "muted": mute, "changed": false}, wat.CodeOK
	}
	res, _, err := o.metricsPost(metrics, "/carrier/toggle?carrier="+url.QueryEscape(carrier))
	if err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	got, _ := res["muted"].(bool)
	if got != mute {
		return map[string]any{"carrier": carrier, "muted": got,
			"why": "the engine refused (muted:false): muting needs a bonded tunnel"}, wat.CodeBadRequest
	}
	o.logf("scepter ops: path %s of tunnel %s muted=%t", carrier, name, got)
	return map[string]any{"name": name, "carrier": carrier, "muted": got, "changed": true}, wat.CodeOK
}

// statsCarrierMuted finds one carrier leg in a /stats document's "carriers" list and returns its muted
// state (the names are exactly what /carrier/toggle matches: the leg names as /stats lists them,
// suffixed for duplicate legs).
func statsCarrierMuted(st map[string]any, carrier string) (muted, found bool) {
	cs, ok := st["carriers"].([]any)
	if !ok {
		return false, false
	}
	for _, c := range cs {
		m, ok := c.(map[string]any)
		if !ok || m["name"] != carrier {
			continue
		}
		b, _ := m["muted"].(bool)
		return b, true
	}
	return false, false
}

// ResetLimits: limits.reset {name, port?} — quota reset over POST /quota/reset?port=N
// (quotaResetHandler, loopback + POST only), the bash console's "reset a port quota". port == 0 resets
// every quota'd port of the tunnel's limits: list. A port the engine has no counter for answers 404:
// nothing to reset, not a failure — the quota that would be cleared does not exist.
func (o *fileScepterOps) ResetLimits(name string, port int) (map[string]any, int) {
	cfg, code, p := o.tunnelCfg(name)
	if code != wat.CodeOK {
		return p, code
	}
	metrics, _ := cfg.get("metrics")
	if metrics == "" {
		return map[string]any{"name": name, "why": "tunnel has no metrics endpoint in its yml"}, wat.CodeBadRequest
	}
	var ports []int
	if port > 0 {
		ports = []int{port}
	} else {
		for _, l := range cfg.Limits {
			if l.Quota > 0 {
				ports = append(ports, l.Port)
			}
		}
		sort.Ints(ports) // deterministic response order
	}
	reset := []int{}
	for _, pt := range ports {
		if _, status, err := o.metricsPost(metrics, fmt.Sprintf("/quota/reset?port=%d", pt)); err != nil {
			if status == http.StatusNotFound {
				continue // no counter for that port: its quota is already "reset" (nothing used)
			}
			return map[string]any{"detail": err.Error()}, wat.CodeInternal
		}
		reset = append(reset, pt)
	}
	o.logf("scepter ops: reset quota on tunnel %s for port(s) %v", name, reset)
	return map[string]any{"name": name, "reset": reset}, wat.CodeOK
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
func runScepterCall(tun *tunnel, cmd, argsJSON, claimsFile string) int {
	args, id, err := parseScepterCallArgs(argsJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "-scepter-args: %v\n", err)
		return 1
	}
	c, err := wat.DialScepter(tun.pick(), readClaims(claimsFile)...) // a claimed box proves its own credential (Handoff 4 R2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scepter-call: %v (pairing needs %s on both ends)\n", err, wat.Version)
		return 1
	}
	defer c.Close()
	// a one-shot call can be the first contact (add-kharej asks before the unit's own channel is up): keep the
	// claim like the unit does, or every later dial proves the token's key, which Kharej no longer takes (3.6.1)
	keepClaim(claimsFile, c, func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) })
	if _, err := c.CallRaw(cmd, args, id, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "scepter-call: %v\n", err)
		return 1
	}
	return 0
}

// ---- phase D: update orchestration ----
//
// update.status / update.run: the scariest remote op (plan D.1), so the design is conservative at every step.
//
// Mechanism (the choice the plan left open, evidence for it in docs/TECHNICAL.md): the ENGINE does the
// network part — download the release binary + SHA256SUMS + SHA256SUMS.sig from GitHub, verify the RSA
// signature natively (crypto/rsa against scepterSigPub, the byte-identical third copy of the installer's
// pinned key; a test pins it against install.sh) and the binary's sha256 line, sanity-run the staged binary —
// and then hands the SWAP to a transient systemd unit: `systemd-run` re-executes this binary as
// `wattun -update-job <stagedir>`. That job is the rollback watchdog: parented by PID 1 (it survives the
// engine restart that it itself performs), NOT sandboxed like the engine unit (ProtectSystem=strict keeps the
// engine from writing /usr/local/bin — a child of the engine could not do the swap either), and it follows
// backup wattun.prev → install → restart the previously-active units → watch them stay up → restore
// wattun.prev and restart again when the new engine dies. An in-engine watchdog cannot work (the engine is
// the thing being replaced) and neither can a watchdog child (it dies with the engine's cgroup).
//
// The channel survives by construction: the update.run response is journaled and flushed BEFORE anything
// moves (the worker's first action is a grace sleep, and the restart waits for the whole download), the
// latch covers the dead window if the new engine never comes back (arm delay 30 s < the job's watch window),
// and the job's phase transitions travel to the revived engine in the .update.status mailbox, whose watcher
// (wat.ScepterState) fires the update_applied/update_failed events.

const (
	scepterUpdateDirF   = ".update"        // staging dir under the config dir
	scepterJobFile      = "job.json"       // the staged job's parameters, read by -update-job
	scepterUpdateGrace  = 3 * time.Second  // response-flush grace before the worker touches anything
	scepterUpdateWatch  = 40 * time.Second // job liveness watch window (latch arm delay is 30 s — must exceed it)
	scepterUpdateStable = 10 * time.Second // the units must stay active this long before "applied"

	// updatePhaseStaged is a reserved mailbox phase the launch-time re-arm may adopt once wat's watcher
	// learns it (round-2 F7, 2026-11-22): the swap restarts this engine, and the revived engine's update.run
	// gate must count from the swap, not from an accept-time Ts a long download left behind. updateJobInFlight
	// already trusts it, but the worker re-arms the STARTED record instead for now — the watcher treats every
	// fresh non-started phase as a failure event, so "staged" would fire a spurious update_failed per
	// successful update until a wat-side follow-up teaches it the phase (then the flip is one line).
	updatePhaseStaged    = "staged"
	scepterUpdateMax     = 64 << 20 // staged binary download cap (release binaries are ~10-15 MB)
	scepterRepo          = "JohnWatsoon/WatTunnel"
	scepterUpdateUnitPfx = "wattun-update-" // transient unit name prefix
)

// scepterSigPub is the release-signing public key, byte-identical to the SIG_PUB copies in install.sh and
// wattun-manager (TestScepterUpdateSigPubMatchesInstallSh pins it against install.sh so the three cannot
// drift). A third copy is the price of native RSA verification in the engine — no openssl dependency.
const scepterSigPub = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0j+yK26CzKRD+am5rQZJ
v8zChkZ5HuwQ4uBtj2mKfFRG8mrj7XN3iW60QEj7Le/fAYtk4hHvqsxb6Xhxw303
+rFCBxKr+mwc3GOB/zVh/fzNqN2pXzKCT+mSKiaDfwUmCizKFNUUCCnhNVpEx9hl
A4B4n5iBgxW0G/ks4hOujx6teaKUN44+cZNgPshPSQ5KdiqQBi0rFCiSAKBCh1vL
j07u5S/mvU8L8u9M6sUzST0mXcGw9WKQmAiIOCqAwLiyV1RtDodgaCIxLPJ93Qo/
uK4DzYX3Ker8lW6MRKXgX3fAVXoyj/ZaE3oh1ZibVefAy6w7qB74JvQPv4nFvS/Y
VJXpxiHiqE/YMdHbS9eCQnqjHVKmGWvBVPo/IlUiJFbl8nIEFZVij32Cp8A4awO2
IORyD7iC8bA7AZHruzVfiUtrYA5XhBTRJplqws8kM0Ig4sLrws0HPOY4xOBRtSVh
vgY6Qw/EWglth/K24PEC8AiuJYIRRkn/Kq+SBIRu8qVrAgMBAAE=
-----END PUBLIC KEY-----
`

// scepterUpdateJob is the staged job's parameter file (conf/.update/job.json): everything -update-job needs
// to run without asking the (possibly dying) engine anything. Paths are absolute; watch/stable are seconds.
type scepterUpdateJob struct {
	Bin     string   `json:"bin"`      // the running binary (the swap target; wattun.prev sits next to it)
	New     string   `json:"new"`      // the staged, verified release binary
	Status  string   `json:"status"`   // the .update.status mailbox path
	From    string   `json:"from"`     // engine version at accept time
	To      string   `json:"to"`       // the staged binary's reported version
	Run     string   `json:"run"`      // the update.run command id (evidence in the status file)
	Units   []string `json:"units"`    // the units that were active pre-update (all restarted, self included)
	WatchS  int      `json:"watch_s"`  // liveness watch window
	StableS int      `json:"stable_s"` // stable-active requirement inside the window
}

// writeUpdateStatus records one mailbox transition (atomic tmp+rename, 0600 — the manager-file discipline).
func writeUpdateStatus(conf string, st wat.ScepterUpdateStatus) {
	if st.Ts == 0 {
		st.Ts = time.Now().Unix()
	}
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	p := filepath.Join(conf, wat.ScepterUpdateStatusFile)
	tmp := p + ".tmp"
	if os.WriteFile(tmp, append(b, '\n'), 0o600) == nil {
		os.Rename(tmp, p)
	}
}

// readUpdateStatus loads the mailbox record, if any.
func readUpdateStatus(conf string) (*wat.ScepterUpdateStatus, error) {
	b, err := os.ReadFile(filepath.Join(conf, wat.ScepterUpdateStatusFile))
	if err != nil {
		return nil, err
	}
	var st wat.ScepterUpdateStatus
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// UpdateStatus (update.status, CapManage): engine version, wattun.prev evidence, unit states, the update
// mailbox and the staging state. Deliberately NO network fetch — the engine never goes looking for releases;
// deciding to update is the cockpit's (a release check would also make a read command slow and flaky).
func (o *fileScepterOps) UpdateStatus() (map[string]any, int) {
	p := map[string]any{
		"ver": wat.Version, "goos": runtime.GOOS, "arch": runtime.GOARCH,
		"systemd": systemdAvailable(), "conf": o.conf,
	}
	if bin, err := o.selfBinPath(); err == nil {
		p["bin"] = bin
		prev := bin + ".prev"
		if fi, err := os.Stat(prev); err == nil {
			ver := ""
			if o.updPrevVer != nil {
				ver = o.updPrevVer(prev)
			} else {
				ver = execPrevVersion(prev)
			}
			p["prev"] = map[string]any{"present": true, "path": prev,
				"bytes": fi.Size(), "mtime": fi.ModTime().Unix(), "ver": ver}
		} else {
			p["prev"] = map[string]any{"present": false}
		}
	}
	units := []map[string]any{}
	for _, f := range mustGlobYMLs(o.conf) {
		name := strings.TrimSuffix(filepath.Base(f), ".yml")
		units = append(units, map[string]any{"name": name, "active": o.active(name)})
	}
	p["units"] = units
	if st, err := readUpdateStatus(o.conf); err == nil {
		p["update"] = st
	}
	if fi, err := os.Stat(filepath.Join(o.conf, scepterUpdateDirF, "wattun.new")); err == nil {
		p["staged"] = map[string]any{"bytes": fi.Size()}
	}
	return p, wat.CodeOK
}

// execPrevVersion runs the wattun.prev binary's -version (3 s cap) for update.status evidence. Memoized per
// path+size+mtime: the prev binary never changes within one engine life (the JOB replaces it, which ends
// this life), and an exec per update.status call would be waste.
var prevVerMemo struct {
	mu         sync.Mutex
	path, iden string
	ver        string
}

func execPrevVersion(prev string) string {
	var iden string
	if fi, err := os.Stat(prev); err == nil {
		iden = fmt.Sprintf("%d:%d", fi.Size(), fi.ModTime().UnixNano())
	}
	prevVerMemo.mu.Lock()
	defer prevVerMemo.mu.Unlock()
	if prevVerMemo.path == prev && prevVerMemo.iden == iden {
		return prevVerMemo.ver
	}
	ver := ""
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, prev, "-version").CombinedOutput(); err == nil {
		f := strings.Fields(string(out))
		if len(f) >= 2 {
			ver = f[len(f)-1]
		}
	}
	prevVerMemo.path, prevVerMemo.iden, prevVerMemo.ver = prev, iden, ver
	return ver
}

// systemdAvailable reports whether this host can run the update job (a systemd-run-able systemd). Cheap
// probes, called from update.status and update.run only.
func systemdAvailable() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return false
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return false
	}
	return true
}

func mustGlobYMLs(conf string) []string {
	m, _ := filepath.Glob(filepath.Join(conf, "*.yml"))
	return m
}

// scepterNormTag normalizes a validated version argument to the release tag form ("3.6.0" -> "v3.6.0").
// Callers validated the shape first (wat.ValidScepterTag; the ops never trust their caller).
func scepterNormTag(s string) (string, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return "", false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return "", false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return "", false
			}
		}
	}
	return "v" + s, true
}

// UpdateRun (update.run {to}, CapFull ONLY): accept the intent, record it in the mailbox BEFORE anything
// moves, and start the worker. Returns phase=started immediately — the response is journaled and flushed
// while the worker is still inside its grace sleep; the restart itself waits for the whole download. The
// unit carrying the cockpit channel IS restarted (that is the point); the latch covers the gap if the new
// engine never returns.
func (o *fileScepterOps) UpdateRun(to string) (map[string]any, int) {
	if runtime.GOOS != "linux" {
		// the gate is a capability of the host, not a build tag: the same binary runs dev servers on Windows
		// (the ops' own checkCarrier precedent), and only a linux+systemd host can run the update job.
		return map[string]any{"why": "update.run needs a linux host with systemd"}, wat.CodeBadRequest
	}
	if !systemdAvailable() {
		return map[string]any{"why": "systemd (systemd-run) not available; update the binary over SSH"}, wat.CodeBadRequest
	}
	if o.updRunning.Load() {
		return map[string]any{"run": o.updRun, "already_running": true}, wat.CodeOK
	}
	if run, busy := updateJobInFlight(o.conf); busy {
		// a previous life's job may still be mid-flight (the engine restarted around it): a fresh started
		// record inside the job's watch window means a job owns the swap — never a second one.
		return map[string]any{"run": run, "already_running": true}, wat.CodeOK
	}
	bin, err := o.selfBinPath()
	if err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	toN := "latest"
	if to != "" {
		t, ok := scepterNormTag(to) // the handler validated the shape; the ops re-validate (never trust the caller)
		if !ok {
			return map[string]any{"to": to, "why": "want a dotted version, optionally v-prefixed (v3.6.0)"}, wat.CodeBadRequest
		}
		toN = t
	}
	run := fmt.Sprintf("upd-%d", o.now().Unix())
	o.updRun = run
	o.updRunning.Store(true)
	// the intent hits the mailbox FIRST (atomic): whatever happens now — the engine dying, the host
	// rebooting — the revived engine and the cockpit see that an update was accepted and by whom.
	writeUpdateStatus(o.conf, wat.ScepterUpdateStatus{Phase: wat.UpdatePhaseStarted, Run: run,
		From: wat.Version, To: toN, Ts: o.now().Unix()})
	go o.updateWorker(run, bin, toN)
	return map[string]any{"run": run, "to": toN, "phase": wat.UpdatePhaseStarted,
		"grace_s": int(scepterUpdateGrace / time.Second)}, wat.CodeOK
}

// selfBinPath resolves the running binary (the swap target and the .prev anchor). The seam exists for the
// update drills: the test binary's path is not a wattun, so the sandbox points the ops at fake files.
func (o *fileScepterOps) selfBinPath() (string, error) {
	if o.exePath != nil {
		return o.exePath()
	}
	bin, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(bin)
}

// updateJobInFlight reports whether a mailbox record says an update job is (or may be) mid-flight: a
// started or staged record is trusted for the job's whole watch window (watch + two rollback passes) from
// its Ts and never longer — a record that old belongs to a job that died, and the next update.run must be
// able to proceed. Round-2 F7 (2026-11-22): staged counts because the worker rewrites the record at LAUNCH
// with a fresh Ts — the gate then covers the swap, the engine restart and the job's watch that follow it,
// where the started record's accept-time Ts had already gone stale after a long download.
func updateJobInFlight(conf string) (string, bool) {
	st, err := readUpdateStatus(conf)
	if err != nil || (st.Phase != wat.UpdatePhaseStarted && st.Phase != updatePhaseStaged) {
		return "", false
	}
	if time.Now().Unix()-st.Ts >= int64((scepterUpdateWatch+2*scepterUpdateStable)/time.Second) {
		return "", false
	}
	return st.Run, true
}

// updateWorker is the engine half: grace (the response flush), stage a verified release, sanity-run it,
// record the job parameters and launch the job. Every failure lands in the mailbox as failed — the engine
// stays up (nothing was swapped), the watcher fires update_failed, and the cockpit can retry.
func (o *fileScepterOps) updateWorker(run, bin, toN string) {
	defer o.updRunning.Store(false)
	time.Sleep(o.updGraceOr(scepterUpdateGrace)) // the update.run response is flushed (and journaled) inside this window
	stage := filepath.Join(o.conf, scepterUpdateDirF)
	fail := func(why string) {
		writeUpdateStatus(o.conf, wat.ScepterUpdateStatus{Phase: wat.UpdatePhaseFailed, Run: run,
			From: wat.Version, To: toN, Detail: why, Ts: o.now().Unix()})
		os.RemoveAll(stage) // nothing was swapped: a failed staging leaves no half-state behind
		o.logf("scepter ops: update %s failed before the swap: %s", run, why)
	}
	os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		fail("staging dir: " + err.Error())
		return
	}
	if err := o.fetchFn()(stage, toN); err != nil {
		fail("download/verify: " + err.Error())
		return
	}
	newBin := filepath.Join(stage, "wattun.new")
	got, err := o.probeFn()(newBin)
	if err != nil {
		fail("staged binary does not run on this host: " + err.Error())
		return
	}
	if got == wat.Version {
		fail("release " + got + " is the running version (nothing to do)")
		return
	}
	if toN != "latest" && got != toN && got != strings.TrimPrefix(toN, "v") {
		// the staged binary's own -version is the honest evidence: a mis-tagged release asset must not
		// install something the cockpit did not ask for
		fail("release tag " + toN + " contains binary " + got)
		return
	}
	// the units to restart are the ones that were ACTIVE pre-update (self included — that is the point);
	// inactive units are simply started by their owner when needed, on whatever binary is then installed.
	var units []string
	for _, f := range mustGlobYMLs(o.conf) {
		name := strings.TrimSuffix(filepath.Base(f), ".yml")
		if o.active(name) {
			units = append(units, name)
		}
	}
	job := scepterUpdateJob{Bin: bin, New: newBin, Status: filepath.Join(o.conf, wat.ScepterUpdateStatusFile),
		From: wat.Version, To: got, Run: run, Units: units,
		WatchS: int(scepterUpdateWatch / time.Second), StableS: int(scepterUpdateStable / time.Second)}
	jb, err := json.Marshal(job)
	if err == nil {
		err = atomicWriteFile(filepath.Join(stage, scepterJobFile), jb, 0o600)
	}
	if err != nil {
		fail("job file: " + err.Error())
		return
	}
	// round-2 F7 (2026-11-22): the launch moment RE-ARMS the mailbox — same phase, fresh Ts. The started
	// record's Ts is accept time, but the job only launches after a download that can outlive
	// updateJobInFlight's watch+2*stable window — and the swap restarts THIS engine, whose revived process
	// would find the started record stale and accept a second update.run while the job still owns the swap
	// (wattun.prev overwritten mid-watch). Re-writing started (not a new phase) is deliberate: the status
	// watcher (wat) treats every fresh non-started phase as a failure event, so a "staged" phase would fire
	// a spurious update_failed per successful update until the watcher learns it (updatePhaseStaged is
	// already trusted by the gate below, so the flip is a one-line wat-side follow-up). A launch failure
	// still lands in fail() as failed.
	writeUpdateStatus(o.conf, wat.ScepterUpdateStatus{Phase: wat.UpdatePhaseStarted, Run: run,
		From: wat.Version, To: got, Ts: o.now().Unix()})
	if err := o.launchFn()(stage, bin); err != nil {
		fail("launch: " + err.Error())
		return
	}
	o.logf("scepter ops: update %s launched (to %s, units %v); the job owns the swap, watch and rollback now",
		run, got, units)
}

func (o *fileScepterOps) updGraceOr(d time.Duration) time.Duration {
	if o.updGrace > 0 {
		return o.updGrace
	}
	return d
}

func (o *fileScepterOps) fetchFn() func(dir, to string) error {
	if o.updFetch != nil {
		return o.updFetch
	}
	return o.fetchRelease
}

func (o *fileScepterOps) probeFn() func(newBin string) (string, error) {
	if o.updProbe != nil {
		return o.updProbe
	}
	return probeStagedBinary
}

func (o *fileScepterOps) launchFn() func(stage, bin string) error {
	if o.updLaunch != nil {
		return o.updLaunch
	}
	return o.launchUpdateJob
}

// fetchRelease downloads and verifies one release binary into dir/wattun.new. base is
// releases/latest/download or releases/download/<tag>; the RSA-verified SHA256SUMS is the trust anchor (the
// .sha256 sidecar alone would only prove transport integrity, not release authenticity). The version comes
// from the caller's sanity probe of the staged binary — one exec, not two.
func (o *fileScepterOps) fetchRelease(dir, to string) error {
	asset := "wattun-linux-" + runtime.GOARCH
	base := "https://github.com/" + scepterRepo + "/releases/latest/download"
	if to != "" && to != "latest" {
		base = "https://github.com/" + scepterRepo + "/releases/download/" + to
	}
	newBin := filepath.Join(dir, "wattun.new")
	if err := httpToFile(base+"/"+asset, newBin, scepterUpdateMax); err != nil {
		return err
	}
	sums, err := httpToBytes(base+"/SHA256SUMS", 1<<20)
	if err != nil {
		return fmt.Errorf("SHA256SUMS: %w", err)
	}
	sig, err := httpToBytes(base+"/SHA256SUMS.sig", 64<<10)
	if err != nil {
		return fmt.Errorf("SHA256SUMS.sig: %w", err)
	}
	return verifyReleaseSignature(sums, sig, asset, newBin)
}

// verifyReleaseSignature checks the RSA-SHA256 signature over SHA256SUMS (against scepterSigPub, or the
// WAT_SIG_PUB override the installer also honors for forks), then the asset's hash line against the staged
// file. Both checks fail closed.
func verifyReleaseSignature(sums, sig []byte, asset, newBin string) error {
	pubPEM := scepterSigPub
	if p := os.Getenv("WAT_SIG_PUB"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			pubPEM = string(b)
		}
	}
	blk, _ := pem.Decode([]byte(pubPEM))
	if blk == nil {
		return fmt.Errorf("signature public key: no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return fmt.Errorf("signature public key: %v", err)
	}
	rsaKey, ok := k.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("signature public key: not RSA")
	}
	h := sha256.Sum256(sums)
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, h[:], sig); err != nil {
		return fmt.Errorf("release RSA signature failed verification (download tampered with?)")
	}
	got, err := fileSHA256(newBin)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == asset {
			if f[0] != got {
				return fmt.Errorf("checksum mismatch for %s (want %s, got %s)", asset, f[0], got)
			}
			return nil
		}
	}
	return fmt.Errorf("binary hash missing from signed SHA256SUMS")
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// httpToFile streams one URL to a local file under a hard size cap (a release mirror serving garbage must
// fill a disk only up to scepterUpdateMax). HTTPS via the default transport (WAT_PROXY-style proxies come
// through the standard environment variables).
func httpToFile(url, dst string, capBytes int64) error {
	c := &http.Client{Timeout: 15 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, capBytes+1))
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if n > capBytes {
		os.Remove(tmp)
		return fmt.Errorf("%s: larger than the %d MB cap", url, capBytes>>20)
	}
	return os.Rename(tmp, dst)
}

func httpToBytes(url string, capBytes int64) ([]byte, error) {
	c := &http.Client{Timeout: 2 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, capBytes))
}

// probeStagedBinary sanity-runs the staged binary (-version), exactly install.sh's "retrieved binary failed
// execution on this host" check. It also yields the resolved version: a latest-run that resolves to the
// running version is a nothing-to-do, not an update.
func probeStagedBinary(newBin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, newBin, "-version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	// the -version output is "wattun <ver>"; take the last field so a prefixed banner cannot fool it
	f := strings.Fields(string(out))
	if len(f) < 2 {
		return "", fmt.Errorf("-version printed %q", strings.TrimSpace(string(out)))
	}
	return f[len(f)-1], nil
}

// launchUpdateJob hands the staged job to systemd: a transient one-shot unit, parented by PID 1 (it
// outlives the engine restart it performs), with NO unit sandbox of its own (the engine's
// ProtectSystem=strict is why the swap cannot happen inside the engine). Fire-and-forget: the job's outcome
// travels in the .update.status mailbox, not in this call's exit code.
func (o *fileScepterOps) launchUpdateJob(stage, bin string) error {
	unit := fmt.Sprintf("%s%d", scepterUpdateUnitPfx, o.now().Unix())
	out, err := exec.Command("systemd-run", "--collect", "--unit="+unit,
		"--description=wattun scepter update job", bin, "-update-job", stage).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-run %s: %v: %s", unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runUpdateJobMain is the -update-job standalone mode (wired in main): read the staged job.json and run the
// job with the real systemctl. Exit 0 once the job reached ANY recorded terminal phase (the outcome lives in
// the mailbox), 1 when the job could not even start (no/broken job file).
func runUpdateJobMain(stage string) int {
	jb, err := os.ReadFile(filepath.Join(stage, scepterJobFile))
	if err != nil {
		log.Printf("update job: %v", err)
		return 1
	}
	var job scepterUpdateJob
	if err := json.Unmarshal(jb, &job); err != nil || job.Bin == "" || job.New == "" || job.Status == "" {
		log.Printf("update job: bad job file: %v", err)
		return 1
	}
	e := scepterUpdateEnv{
		Job:     job,
		Prev:    job.Bin + ".prev",
		restart: func(u string) error { return runSystemctl("restart", "wattun@"+u) },
		isActive: func(u string) bool {
			return exec.Command("systemctl", "is-active", "--quiet", "wattun@"+u).Run() == nil
		},
		logf: log.Printf,
		nowf: time.Now,
	}
	phase := runUpdateJob(e)
	log.Printf("update job %s: %s", job.Run, phase)
	return 0
}

// scepterUpdateEnv abstracts what the job touches, so the drill tests run the REAL job logic over fake
// units and fake binary paths (the manager tests' sandbox pattern).
type scepterUpdateEnv struct {
	Job      scepterUpdateJob
	Prev     string // the backup path (Job.Bin + ".prev" in production)
	restart  func(unit string) error
	isActive func(unit string) bool
	logf     func(string, ...any)
	nowf     func() time.Time
}

// runUpdateJob is the rollback watchdog itself: backup → install → restart the pre-active units → watch
// them stay up → restore wattuv.prev and restart again when the new engine does not. The backup is FIRST
// and its failure aborts untouched: refusing without a wattun.prev-compatible backup path is the hard gate
// (plan D.1). Every transition lands in the mailbox; the last write wins and the revived engine reports it.
func runUpdateJob(e scepterUpdateEnv) string {
	now := func() time.Time {
		if e.nowf != nil {
			return e.nowf()
		}
		return time.Now()
	}
	say := func(phase, detail string) {
		writeUpdateStatus(filepath.Dir(e.Job.Status), wat.ScepterUpdateStatus{Phase: phase, Run: e.Job.Run,
			From: e.Job.From, To: e.Job.To, Detail: detail, Ts: now().Unix()})
	}
	record := func(phase, detail string) string {
		if detail != "" {
			e.logf("update job %s: %s (%s)", e.Job.Run, phase, detail)
		} else {
			e.logf("update job %s: %s", e.Job.Run, phase)
		}
		say(phase, detail)
		return phase
	}
	// 1. the backup gate: no wattun.prev-compatible path → abort with the running binary untouched.
	if err := copyBinary(e.Job.Bin, e.Prev); err != nil {
		return record(wat.UpdatePhaseFailed, "no backup path for wattun.prev, aborting untouched: "+err.Error())
	}
	// 2. install the staged binary (tmp + rename next to the target, 0755).
	if err := copyBinary(e.Job.New, e.Job.Bin); err != nil {
		return record(wat.UpdatePhaseFailed, "install failed, wattun.prev is in place: "+err.Error())
	}
	// 3. restart every unit that was active pre-update (the channel unit included — the response is long
	// since flushed; the latch covers the window if this goes wrong).
	for _, u := range e.Job.Units {
		if err := e.restart(u); err != nil {
			e.logf("update job %s: restart wattun@%s: %v", e.Job.Run, u, err)
		}
	}
	// 4. watch: every recorded unit must be active and STAY active for the stable window. Type=simple makes
	// one is-active verdict worthless (a crash-looping unit flickers), so stability is the verdict.
	deadline := now().Add(time.Duration(e.Job.WatchS) * time.Second)
	stable := time.Duration(e.Job.StableS) * time.Second
	var upSince time.Time
	for {
		allUp := true
		for _, u := range e.Job.Units {
			if !e.isActive(u) {
				allUp = false
				break
			}
		}
		if allUp {
			if upSince.IsZero() {
				upSince = now()
			}
			if now().Sub(upSince) >= stable {
				return record(wat.UpdatePhaseApplied, "")
			}
		} else {
			upSince = time.Time{}
		}
		if now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	// 5. rollback: the new engine did not stay up — restore wattun.prev (already verified writable in step 1)
	// and restart the units on it. Best effort: if even this fails, the mailbox says so and the latch plus
	// the local console are the way back in.
	if err := copyBinary(e.Prev, e.Job.Bin); err != nil {
		return record(wat.UpdatePhaseFailed, "rollback FAILED (wattun.prev restore: "+err.Error()+"); the latch and the local console are the way back")
	}
	for _, u := range e.Job.Units {
		if err := e.restart(u); err != nil {
			e.logf("update job %s: rollback restart wattun@%s: %v", e.Job.Run, u, err)
		}
	}
	return record(wat.UpdatePhaseRolledBack, "the new engine did not stay up; wattun.prev restored and restarted")
}

// copyBinary copies src to dst atomically (tmp + rename in the target dir), mode 0755 — the installer's
// install -m 755 + mv discipline.
func copyBinary(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil { // umask may have stripped bits from WriteFile's mode
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// atomicWriteFile: tmp + rename in the target directory (the manager-file discipline; used for the job file).
func atomicWriteFile(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---- phase D: ops reads (doctor.fetch / backup.export / audit.tail) ----

// Doctor is the ops-side doctor.fetch fragment, merged into the state document (the state owns the core:
// ver, pair, tunnels, recent). latchNow is the live monitor (nil = pairing without -latch-port), exactly
// what the loopback /scepter endpoint serves — this is the same data, packaged for the cockpit.
func (o *fileScepterOps) Doctor() (map[string]any, int) {
	p := map[string]any{"latch": latchNow.Load().status()}
	if o.self != "" {
		p["unit"] = map[string]any{"name": o.self, "active": o.active(o.self)}
	}
	if st, err := readUpdateStatus(o.conf); err == nil {
		p["update"] = st
	}
	if fi, err := os.Stat(filepath.Join(o.conf, ".pairing.journal")); err == nil {
		p["journal"] = map[string]any{"bytes": fi.Size()}
	}
	return p, wat.CodeOK
}

// backupExclude names the one state file backup.export deliberately leaves out: the command journal is
// machine replay state (id -> recorded response), not restore data — a rebuilt Kharej does not need it and
// it is the one file that grows with command traffic.
const backupExclude = ".pairing.journal"

// backupExcludePairing is the pairing credential itself (F3b, owner decision 2026-11-22): backup.export
// serves ANY manage-tier credential, and shipping .pairing (the pairing KEY) in the tarball would let a
// manage holder re-mint the pairing elsewhere — a manage→full escalation. The holder keeps running with
// this pairing's channel but cannot take it home; a Kharej rebuild re-pairs from the console. .pairing.audit
// stays included: it is evidence (the who-did-what record), not a secret.
const backupExcludePairing = ".pairing"

// BackupExport builds a tarball of the config dir: every regular file except the journal and the pairing
// credential (above), the staging dir (engine machinery) and tmp files. Keys are INCLUDED on purpose: the
// tarball exists to restore a Kharej after a host rebuild, a config dir without keys restores nothing, and
// keys already travel this channel (tunnel.create returns them inside the session AEAD). Caps: one file
// > 4 MB and a total > 5 MB are refused (code=too_large) — the chunked transfer tops out at 512 x 16 KiB.
func (o *fileScepterOps) BackupExport() (map[string]any, int) {
	const perFileCap, totalCap = 4 << 20, 5 << 20
	entries, err := os.ReadDir(o.conf)
	if err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	files, total := 0, int64(0)
	for _, e := range entries {
		if e.IsDir() { // dirs are skipped wholesale: the only dir here is .update (engine staging)
			continue
		}
		name := e.Name()
		// F9 (2026-11-22): ".tmp" anywhere in the basename, not just a suffix — the manager's crashed
		// rewrites leave ".tmp.XXXXXX"-prefixed partials, and a partial .pairing must never travel.
		if name == backupExclude || name == backupExcludePairing || name == scepterUpdateDirF || strings.Contains(name, ".tmp") {
			continue
		}
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if fi.Size() > perFileCap {
			return map[string]any{"file": name, "why": fmt.Sprintf("larger than the %d MB per-file cap", perFileCap>>20)}, wat.CodeTooLarge
		}
		total += fi.Size()
		if total > totalCap {
			return map[string]any{"why": fmt.Sprintf("config dir larger than the %d MB export cap", totalCap>>20)}, wat.CodeTooLarge
		}
		b, err := os.ReadFile(filepath.Join(o.conf, name))
		if err != nil {
			continue // raced with a delete: the file is gone, the tarball is a moment-in-time snapshot
		}
		hdr := &tar.Header{Name: name, Mode: int64(fi.Mode().Perm()), Size: int64(len(b)), ModTime: fi.ModTime()}
		if tw.WriteHeader(hdr) == nil {
			if _, werr := tw.Write(b); werr == nil {
				files++
			}
		}
	}
	tw.Close()
	sum := sha256.Sum256(buf.Bytes())
	doc, err := json.Marshal(map[string]any{"b64": base64.StdEncoding.EncodeToString(buf.Bytes()),
		"sha256": hex.EncodeToString(sum[:]), "size": buf.Len(), "files": files})
	if err != nil {
		return map[string]any{"detail": err.Error()}, wat.CodeInternal
	}
	return map[string]any{"logs": []string{string(doc)}}, wat.CodeOK
}

// AuditTail (audit.tail {n}) reads the two audit sources — .pairing.audit (the Kharej console's credential
// audit, "<RFC3339> <event> <detail>" lines) and .pairing.journal (the scepter command journal, journalRec
// JSON lines) — and returns the last n of each as raw lines. Parse-free on purpose: the audit's schema is
// the manager's, and re-encoding it here would couple the engine to it. Two newline-free JSON docs, one per
// source, in the chunked-logs convention (the cockpit parses logs[0]/logs[1]).
func (o *fileScepterOps) AuditTail(n int) (map[string]any, int) {
	a := tailFile(filepath.Join(o.conf, ".pairing.audit"), n, 2<<20)
	j := tailFile(filepath.Join(o.conf, ".pairing.journal"), n, 2<<20)
	da, _ := json.Marshal(map[string]any{"src": "audit", "entries": a})
	dj, _ := json.Marshal(map[string]any{"src": "journal", "entries": j})
	return map[string]any{"logs": []string{string(da), string(dj)}}, wat.CodeOK
}

// tailFile returns the last n lines of a file, reading at most capBytes from the end (the journal rotates
// at 1 MB; the audit is bounded by its console's rewrite). A truncated read aligns to the next full line.
func tailFile(path string, n int, capBytes int64) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{}
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return []string{}
	}
	off := fi.Size()
	if off > capBytes {
		off = capBytes
	}
	buf := make([]byte, off)
	if _, err := f.ReadAt(buf, fi.Size()-off); err != nil {
		return []string{}
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if off < fi.Size() && len(lines) > 0 {
		lines = lines[1:] // the first line of a truncated read may be partial: drop it
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
