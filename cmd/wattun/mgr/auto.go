// auto.go — port of wattun-manager's auto mode (P4 of the manager port).
// Source of truth: wattun-manager functions wizard_kharej_auto, auto_pick_ports,
// auto_pick_rplan, auto_ext_*, companion_create, auto_sync_companion,
// auto_set_carriers, auto_needs_reopen, auto_reopen, auto_migrate_all,
// auto_variants, at_* test runner, auto_apply, auto_test_cmd, auto_retest,
// auto_menu, carrier_ok_here. Screen-for-screen, key-for-key, text-for-text.
//
// Build tag mgrp4: remove at integration. This file consumes the P1 core
// (conf/sysd/token/theme, untagged) and the P3 shared AV layer (variant/result/
// avKey/avAnti/atRank/atTable/atLbl/atProbeMB, mgrp3), so it compiles together
// with them: go vet -tags "mgrp2 mgrp3 mgrp4" ./cmd/wattun/mgr/

package mgr

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// =====================================================================================
// P4 env adapters — system interactions no other part owns (P2 has its own p2* set).
// Defaults are inert/dev-safe; integration swaps them for live probes.
// =====================================================================================

var (
	envRandOpenPort    = func(proto string, excl []string) (int, error) { return 0, fmt.Errorf("no free port") } // bash rand_open_port
	envFreeMetricsPort = func() int { return 19750 }                                                             // bash free_metrics_port
	envPublicIP        = func() string { return "" }                                                             // bash public_ip
	envFWOpen          = func(specs ...string) {}                                                                // bash fw_open
	envFWClose         = func(specs ...string) {}                                                                // bash fw_close
	envSystemdRun      = func(unit string, maxSec int, args ...string) error { return fmt.Errorf("systemd-run") }
	envLogger          = func(tag, msg string) {} // bash logger -t
	envSpawnClient     = func(args []string, logFile string) (clientProc, error) {
		return nil, fmt.Errorf("client spawn")
	}
)

type clientProc interface{ Kill() error }

// engineVer mirrors bin_ver(): $BIN -version (BinVersion in sysd.go); a var so
// tests can pin the version.
var engineVer = func() string { return BinVersion() }

// bin_ver_ok + carrier_ok_here: version gating the plan builders and auto_apply use (B2).

// NL: the newline string spelled via const to avoid quoting hazards in generated calls).
const NL = "\n"

// The tuning grids of at_tune (bash AUTO_TUNE_*, wattun-manager 4982-4987):
// "key:value,value ..." in test order. The old placeholder values here were
// version strings, which made atTune's knob split panic — caught by the
// wizardIran auto-token test (2026-11-20).
const autoTuneUDP = "sessions:1,2,4"
const autoTuneBondDGRAM = "conns:4,8,32,64"
const autoTuneBondPool = "conns:4,8,32,64"
const autoTuneReverse = "conns:4,8,32" // -sessions is refused in reverse mode
const autoTunePool = "sessions:1,2,4,8,16 conns:4,8,32,64"

const autoVarDirect = "icmp udp tcp tls ws h2c gre ipip"
const autoVarCDN = "wss grpc"
const autoVarReverse = "icmp tcp tls ws wss h2 h2c grpc"
const autoVarAnti = "tcp tls wss h2 grpc ws h2c"
const acAllModes = "rst synrst paws seq seqsum sum ttl split hlen0 fakeip ff all auto"
const acSNIs = "mci.ir,irancell.ir,tci.ir,divar.ir"

// The anti-censor fast preset's cut of the grid (2026-11-21): the two desync modes that clear a permit-list
// filter in the field (rst, synrst — see the anti grid's field note) against the two operator allowlist SNIs
// and the Cloudflare edge name — 6 rows per direct pool carrier instead of the full grid's ~28.
const acFastModes = "rst synrst"
const acFastSNIs = "mci.ir irancell.ir cloudflare.com"

// at_preset time estimates shown in the Test mode menu (one table so they can be tuned without touching the
// box rows): screening rows x ~20 s a row at the 8-16 MB probe sizes and the ~8 MB/s budget rate, rounded to
// a range. normal ~14 rows -> ~1-3 min; fast ~14 + 7x6 rows -> ~4-6 min; anti ~200 rows -> ~15-40 min;
// reverse ~8 rows -> ~1-2 min.
const (
	atEstNormal  = "~1-3 min"
	atEstFast    = "~4-6 min"
	atEstAnti    = "~15-40 min"
	atEstReverse = "~1-2 min"
	atEstExt     = "~4-7 min"
)

const atScreenMBStart = 8
const atScreenCapMB = 16
const atFinalMBMax = 40
const atTuneProbesMax = 8
const atTuneProbeMB = 20

func isShapedCarrierName(c string) bool {
	switch c {
	case "sit", "6to4", "xfrm-ipsec", "etherip", "l2tpv3",
		"fou-gre", "gue-ipip", "vxlan", "geneve", "dnscrypt-udp", "ntp-direct", "openvpn-dco", "srtp-direct":
		return true
	}
	return false
}

func binVerOK(min string) bool { return verGE(engineVer(), min) }

func carrierOkHere(c string) bool { return binVerOK(carrierMinVer(c)) }

// carrier_min_ver: which engine version first accepts this carrier.
func carrierMinVer(c string) string {
	switch {
	case strings.HasSuffix(c, ":up") || strings.HasSuffix(c, ":down"):
		return "3.3.9"
	case c == "ptcp" || c == "spray":
		return "3.4.3"
	case c == "gre" || c == "ipip":
		return "3.2.0"
	case isShapedRaw(c) || isShapedUDP(c):
		return "3.3.0"
	default:
		return "2.1.0"
	}
}

// bash rproto(): transport of the carrier port — shaped-UDP tier rides UDP.
// (status.go's rproto covers the dashboard's plain carriers; this one is the
// bash-exact form the plan builders and firewall rules need.)
func rprotoOf(c string) string {
	if c == "udp" || isShapedUDP(c) {
		return "udp"
	}
	return "tcp"
}

// bash is_rpool(): a carrier that dials a listen port in reverse mode.
func isRpool(c string) bool { return IsPool(c) || c == "udp" }

// bash is_shaped_list(): any leg of the list is a shaped carrier. P1's conf.go isShapedList is
// the owner after integration; this thin wrapper keeps P4 call sites stable.
func isShapedListAuto(list string) bool { return isShapedListP1(list) }

// isShapedListP1 is conf.go's is_shaped_list port (P1 owns the shaped tables).
func isShapedListP1(list string) bool {
	for _, c := range strings.Split(list, "+") {
		if isShapedCarrierName(c) {
			return true
		}
	}
	return false
}

// bash is_cdn_carrier(): carriers that can ride Cloudflare.
func isCDNCarrier(c string) bool {
	switch c {
	case "ws", "wss", "h2", "h2c", "grpc":
		return true
	}
	return false
}

// bash is_rev_capable(): carriers with a reverse mode.
func isRevCapable(c string) bool { return c == "icmp" || isRpool(c) }

// bash cf_port_ok(): Cloudflare-proxyable port for this carrier.
func cfPortOK(carrier, port string) bool {
	switch port {
	case "443", "2053", "2083", "2087", "2096", "8443", "80", "8080", "8880", "2052", "2082", "2086", "2095":
		return true
	}
	return false
}

func runDir() string { return P.Run }

// mustRead reads a file, "" when missing (the bash `cat ... 2>/dev/null`).
func mustRead(p string) string { b, _ := os.ReadFile(p); return string(b) }

// writeFile0600 — tmp + rename, like every manager-written state file.
func writeFile0600(p, s string) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(s), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path2(p))
}

func path2(p string) string { return p } // keep rename target explicit

// readTokFile — NAME.token -> Token (error when missing/unreadable, like the bash).
// readAutoTok reads NAME.auto, the auto plan token an auto Iran tunnel keeps.
func readAutoTok(name string) (Token, error) {
	return ReadToken(strings.TrimSpace(mustRead(filepath.Join(P.Conf, name+".auto"))))
}

func readTokFile(name string) (Token, error) {
	return ReadToken(strings.TrimSpace(mustRead(filepath.Join(P.Conf, name+".token"))))
}

// =====================================================================================
// Plan parsing (pure)
// =====================================================================================

// plan_part — plan "d=...;r=..." -> the d or r part.
func planPart(plan, side string) string {
	for _, x := range strings.Split(plan, ";") {
		if strings.SplitN(x, "=", 2)[0] == side {
			return strings.SplitN(x, "=", 2)[1]
		}
	}
	return ""
}

// plan_has — 0 when the plan has that carrier (bare `gre` or `vxlan:4789`).
func planHas(list, carrier string) bool {
	for _, x := range strings.Split(list, ",") {
		if strings.SplitN(x, ":", 2)[0] == carrier {
			return true
		}
	}
	return false
}

// plan_entry_port — one plan entry's port, "" for a port-less raw entry (B1).
func planEntryPort(e string) string {
	if i := strings.LastIndex(e, ":"); i >= 0 {
		return e[i+1:]
	}
	return ""
}

// plan_port — list carrier -> port ("" for a bare raw entry).
func planPort(list, carrier string) string {
	for _, x := range strings.Split(list, ",") {
		if strings.SplitN(x, ":", 2)[0] == carrier {
			return planEntryPort(x)
		}
	}
	return ""
}

// auto_plan_standard — its non-shaped carrier names in plan order.
func autoPlanStandard(d string) string {
	var out []string
	for _, c := range strings.Split(d, ",") {
		n := strings.SplitN(c, ":", 2)[0]
		if isShapedRaw(n) || isShapedUDP(n) {
			continue
		}
		out = append(out, n)
	}
	return strings.Join(out, " ")
}

// auto_plan_extnames — its shaped carrier names in plan order ("" for a normal token).
func autoPlanExtNames(d string) string {
	var out []string
	for _, c := range strings.Split(d, ",") {
		n := strings.SplitN(c, ":", 2)[0]
		if isShapedRaw(n) || isShapedUDP(n) {
			out = append(out, n)
		}
	}
	return strings.Join(out, " ")
}

// auto_plan_intro — human lines for the test screen (A6).
func autoPlanIntro(d string) string {
	std, ext := autoPlanStandard(d), autoPlanExtNames(d)
	s := fmt.Sprintf("standard carriers: %s\n", orNone(std))
	if ext != "" {
		s += fmt.Sprintf("extended carriers: %s (both ends must run 3.3.0; shaped transports, not the real protocols)\n", ext)
	}
	return s
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func orOld(v string) string {
	if v == "" {
		return "an old version"
	}
	return v
}

func joinNonEmpty(a, sep string, items ...string) string {
	var out []string
	for _, s := range append([]string{a}, items...) {
		if s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, sep)
}

func appendUnique(a []string, v string) []string {
	for _, x := range a {
		if x == v {
			return a
		}
	}
	return append(a, v)
}

// =====================================================================================
// Kharej side: plan builders
// =====================================================================================

// auto_rplan_build [base] — sequential from base; base 0 = caller uses autoPickRplan.
func autoRplanBuild(base int) string {
	var out []string
	p := base
	for _, c := range strings.Fields(autoVarReverse) {
		if c == "icmp" {
			continue
		}
		if p > 0 {
			out = append(out, fmt.Sprintf("%s:%d", c, p))
			p++
		}
	}
	return strings.Join(out, ",")
}

// auto_pick_rplan — unique random open ports across AUTO_VAR_REVERSE, avoiding ports
// already claimed by other tokens' reverse plans.
func autoPickRplan(excl []string) (string, error) {
	used := map[string]bool{}
	for _, p := range excl {
		used[p] = true
	}
	if ents, err := filepath.Glob(filepath.Join(P.Conf, "*.token")); err == nil {
		for _, tf := range ents {
			tok, err := ReadToken(strings.TrimSpace(mustRead(tf)))
			if err != nil || tok.Auto == "" {
				continue
			}
			for _, c := range strings.Split(planPart(tok.Auto, "r"), ",") {
				if p := planEntryPort(c); p != "" {
					used[p] = true
				}
			}
		}
	}
	var out []string
	for _, c := range strings.Fields(autoVarReverse) {
		if c == "icmp" {
			continue
		}
		p, err := envRandOpenPort(rprotoOf(c), keys(used))
		if err != nil {
			return "", err
		}
		used[strconv.Itoa(p)] = true
		out = append(out, fmt.Sprintf("%s:%d", c, p))
	}
	return strings.Join(out, ","), nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func intKeys(m map[int]bool) []string {
	var out []string
	for k := range m {
		out = append(out, strconv.Itoa(k))
	}
	return out
}

// auto_pick_ports result — AUTO_D / AUTO_USED_PORTS / AUTO_NOTE / AUTO_FAIL.
type autoPickPortsResult struct {
	D    string // "udp:P1,tcp:P2,...,gre,ipip"
	Used []int
	Note string
	Skip string
	FAIL string // the carrier (proto) that found no port
}

// bash auto_pick_ports [cdn_mode] — the standard direct plan, order = test order. Direct
// mode always picks random open ports; raw carriers (gre/ipip) get a bare entry; CDN
// mode picks non-443/80 Cloudflare-proxyable ports for CDN carriers.
func autoPickPorts(cdnMode bool) autoPickPortsResult {
	var r autoPickPortsResult
	var list []string
	used := map[int]bool{}
	for _, c := range strings.Fields(autoVarDirect) {
		if c == "icmp" {
			continue
		}
		if !carrierOkHere(c) {
			r.Skip = joinNonEmpty(r.Skip, ", ", c)
			r.Note += fmt.Sprintf("  %s needs wattun %s; this server runs %s - skipped.\n", c, carrierMinVer(c), orOld(engineVer()))
			continue
		}
		if IsRawCarrier(c) { // B1: raw carrier, no port/listen line
			list = append(list, c)
			continue
		}
		pick, err := envRandOpenPort(rprotoOf(c), intKeys(used))
		if err != nil {
			r.FAIL = fmt.Sprintf("%s (%s)", c, rprotoOf(c))
			return r
		}
		used[pick] = true
		list = append(list, fmt.Sprintf("%s:%d", c, pick))
	}
	r.D = strings.Join(list, ",")
	for p := range used {
		r.Used = append(r.Used, p)
	}
	sort.Ints(r.Used)
	return r
}

// =====================================================================================
// Hidden extended units (B3): NAME-e-<shape>
// =====================================================================================

func isAutoExt(name string) bool {
	_, err := os.Stat(filepath.Join(P.Conf, name+".autoext"))
	return err == nil
}

// auto_ext_names — units whose .autoext names this parent (M1: NAME-e-* owned by a user
// tunnel is not a child).
func autoExtNames(parent string) []string {
	var out []string
	ents, _ := filepath.Glob(filepath.Join(P.Conf, parent+"-e-*.yml"))
	for _, f := range ents {
		b := strings.TrimSuffix(filepath.Base(f), ".yml")
		if mustRead(filepath.Join(P.Conf, b+".autoext")) == parent {
			out = append(out, b)
		}
	}
	return out
}

// auto_ext_space_taken — is any NAME-e-* config present (namespace stays reserved).
func autoExtSpaceTaken(name string) bool {
	ents, _ := filepath.Glob(filepath.Join(P.Conf, name+"-e-*.yml"))
	return len(ents) > 0
}

func autoExtChild(name, shape string) string { return name + "-e-" + shape }

// auto_ext_plan_entries — "vxlan:P1,...,sit,..." for every shaped carrier (random open
// UDP ports for the UDP tier, bare entries for the raw tier).
func autoExtPlanEntries(excl []string) (entries, note string) {
	used := append([]string{}, excl...)
	var out []string
	for _, c := range strings.Fields(shapedUDPList) {
		q, err := envRandOpenPort("udp", used)
		if err != nil {
			note += fmt.Sprintf("  %s: no free UDP port, skipped.\n", c)
			continue
		}
		used = append(used, strconv.Itoa(q))
		out = append(out, fmt.Sprintf("%s:%d", c, q))
	}
	out = append(out, strings.Fields(shapedRawList)...)
	return strings.Join(out, ","), note
}

// helperKeysYml — the shared server settings block auto_ext_write_units and
// auto_sync_helper_settings copy from the parent (H2). Mirrors the awk filters.
func helperKeysYml(name string) []string {
	var out []string
	on := false
	for _, l := range strings.Split(mustRead(filepath.Join(P.Conf, name+".yml")), "\n") {
		k := yamlKey(l)
		if k != "" && isHelperKey(k) {
			on = true
		} else if on && k != "" && !strings.HasPrefix(l, " ") {
			on = false
		}
		if on {
			out = append(out, l)
		}
	}
	return out
}

func yamlKey(line string) string {
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, " ") {
		return ""
	}
	if i := strings.Index(line, ":"); i > 0 {
		return line[:i]
	}
	return ""
}

func isHelperKey(k string) bool {
	switch k {
	case "limits", "max-mbps", "fec", "fec-on-loss", "fec-off-loss", "win-max", "loss-ceiling",
		"shape-data", "noise", "noise-bps", "noise-window", "state-dir", "state-save",
		"allow-clients", "allow-clients-file":
		return true
	}
	return false
}

// auto_ext_write_units — write the hidden per-shape server configs + sidecars and open
// their UDP ports. M1: never overwrite a .yml that is not already a child of this parent.
func autoExtWriteUnits(name, entries string, mapsBlock []string) error {
	for _, e := range strings.Split(entries, ",") {
		u := autoExtChild(name, strings.SplitN(e, ":", 2)[0])
		p := filepath.Join(P.Conf, u+".yml")
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if mustRead(filepath.Join(P.Conf, u+".autoext")) != name {
			return fmt.Errorf("Refusing to overwrite %s: it is not an extended listener of '%s'.", p, name)
		}
	}
	keyf := filepath.Join(P.Conf, name+".key")
	var fw []string
	for _, e := range strings.Split(entries, ",") {
		c := strings.SplitN(e, ":", 2)[0]
		p := planEntryPort(e)
		u := autoExtChild(name, c)
		m := portOf(Cfg(u, "metrics"))
		if m == "" {
			m = strconv.Itoa(envFreeMetricsPort())
		}
		var b strings.Builder
		fmt.Fprintf(&b, "# WatTunnel - Kharej extended test listener for auto tunnel '%s' (%s). Hidden; created by wattun-manager.\n", name, c)
		b.WriteString("mode: server\n")
		b.WriteString("key-file: " + keyf + "\n")
		b.WriteString("carrier: " + c + "\n")
		if p != "" {
			b.WriteString("listen: \":" + p + "\"\n")
		}
		if m != "" && m != "0" { // F25: write no invalid metrics: line when the range is exhausted
			b.WriteString("metrics: 127.0.0.1:" + m + "\n")
		}
		for _, l := range mapsBlock { // H2: without the parent's allowlist the engine falls back to 1-65535
			b.WriteString(l + "\n")
		}
		for _, l := range helperKeysYml(name) { // H2: inherit limits, allowlist, shared tunables
			b.WriteString(l + "\n")
		}
		if err := writeFile0600(filepath.Join(P.Conf, u+".yml"), b.String()); err != nil {
			return err
		}
		os.WriteFile(filepath.Join(P.Conf, u+".autoext"), []byte(name+"\n"), 0o600)
		if p != "" {
			fw = append(fw, p+"/udp")
		}
	}
	if len(fw) > 0 {
		envFWOpen(fw...)
	}
	return nil
}

// auto_ext_start — (re)enable+restart every extended listener.
func autoExtStart(parent string) {
	for _, n := range autoExtNames(parent) {
		_ = Enable(Unit(n))
	}
	for _, n := range autoExtNames(parent) {
		_ = Restart(Unit(n))
	}
}

// auto_ext_live — child units with a live client; status 1 when a running child's
// /stats cannot be read (unknown keeps every shape instead of guessing; H1), 2 when
// the parent has no children at all.
func autoExtLive(parent string) (live []string, status int) {
	any, bad := false, false
	for _, n := range autoExtNames(parent) {
		any = true
		if !IsActive(Unit(n)) {
			continue
		}
		s := StatsRaw(n)
		if s != "" && strings.Contains(s, `"clients"`) {
			if strings.Contains(jsonFieldArray(s, "clients"), `"ip"`) {
				live = append(live, n)
			}
		} else {
			bad = true
		}
	}
	if !any {
		return nil, 2
	}
	if bad {
		return live, 1
	}
	return live, 0
}

// auto_ext_sig — the live hidden pick ("e:vxlan"), "" when no child is provably in use.
func autoExtSig(parent string) string {
	live, st := autoExtLive(parent)
	if st != 0 {
		return ""
	}
	var out []string
	for _, n := range live {
		out = append(out, "e:"+strings.TrimPrefix(n, parent+"-e-"))
	}
	return strings.Join(out, ",")
}

func jsonFieldArray(s, field string) string {
	i := strings.Index(s, `"`+field+`"`)
	if i < 0 {
		return ""
	}
	j := strings.Index(s[i:], "[")
	k := strings.Index(s[i:], "]")
	if j < 0 || k < 0 || k < j {
		return ""
	}
	return s[i+j : i+k+1]
}

func jsonString(s, key string) string {
	re := `"` + key + `": "`
	i := strings.Index(s, re)
	if i < 0 {
		return ""
	}
	rest := s[i+len(re):]
	if j := strings.Index(rest, `"`); j >= 0 {
		return rest[:j]
	}
	return ""
}

func portOf(hostport string) string {
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		return hostport[i+1:]
	}
	return ""
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// =====================================================================================
// auto helpers enumeration
// =====================================================================================

// auto_helpers — parent's hidden internal helper units ($parent-r and $parent-e-*).
func autoHelpers(parent string) []string {
	var out []string
	r := parent + "-r"
	if fileExists(filepath.Join(P.Conf, r+".yml")) && CompanionOf(r) == parent {
		out = append(out, r)
	}
	return append(out, autoExtNames(parent)...)
}

// state_files — every state file the engine can leave for a tunnel.

func randPath() string { return randPathLive() } // bash rand_path

// =====================================================================================
// Kharej wizard: wizard_kharej_auto — the plan builders and unit creation
// =====================================================================================

// wizard_kharej_auto options (NI_* in the bash).
type autoWizardOpts struct {
	Name     string // NI_NAME
	CDN      string // NI_CDN (--cdn-domain)
	Addr     string // NI_ADDR
	Ports    string // NI_PORTS
	Extended bool   // NI_EXTENDED
}

type autoWizardResult struct {
	Name  string
	Plan  string
	Token string
	Units []string // parent + hidden helpers, in creation order
	Error error
}

// buildAutoPlan — the pure plan builder: which carriers Kharej opens, in order.
// Returns the plan "d=...;r=..." and the direct list.
func buildAutoPlan(ver string, randPorts func(proto string, excl []string) (int, error)) (plan, dpart string, err error) {
	saved, savedVer := envRandOpenPort, engineVer
	envRandOpenPort, engineVer = randPorts, func() string { return ver }
	defer func() { envRandOpenPort, engineVer = saved, savedVer }()
	res := autoPickPorts(false)
	if res.FAIL != "" {
		return "", res.D, fmt.Errorf("Could not find a free port for %s on this server.", res.FAIL)
	}
	excl := make([]string, 0, len(res.Used))
	for _, p := range res.Used {
		excl = append(excl, strconv.Itoa(p))
	}
	rplan, err := autoPickRplan(excl)
	if err != nil {
		return "", res.D, fmt.Errorf("Could not find free reverse ports on this server.")
	}
	return "d=" + res.D + ";r=" + rplan, res.D, nil
}

// wizard_kharej_auto — called from wizard_kharej when the carrier is "auto".
func wizardKharejAuto(suggested string, o autoWizardOpts) autoWizardResult {
	var res autoWizardResult
	name := suggested
	if !verGE(engineVer(), "2.1.0") {
		res.Error = fmt.Errorf("Auto needs wattun 2.1.0 or newer on this server (found %s).", orOld(engineVer()))
		return res
	}
	taken := func() bool {
		return fileExists(filepath.Join(P.Conf, name+".yml")) ||
			fileExists(filepath.Join(P.Conf, name+"-r.yml")) || autoExtSpaceTaken(name)
	}
	if o.Name != "" {
		name = o.Name
		if taken() {
			res.Error = fmt.Errorf("A tunnel named '%s', '%s-r' or '%s-e-*' already exists.", name, name, name)
			return res
		}
	} else {
		for n := 1; taken() && n < 99; n++ {
			name = fmt.Sprintf("kharej-%d", n)
		}
	}
	cdn := o.CDN
	cdnMode := cdn != ""
	pick := autoPickPorts(cdnMode)
	if pick.FAIL != "" {
		res.Error = fmt.Errorf("Could not find a free port for %s on this server.", pick.FAIL)
		return res
	}
	var maps []string
	if o.Ports != "" {
		maps = strings.Split(o.Ports, ",")
	}
	allow := MapsAllowStr(maps)
	addr := o.Addr
	if addr == "" {
		addr = envPublicIP()
	}
	if addr == "" {
		res.Error = fmt.Errorf("Could not detect this server's public IP.")
		return res
	}
	// owner decision 2026-11-24: every auto Kharej that can run the shaped carriers plans and runs them always
	// (~10 MB per idle listener, ~130-200 MB for all); Iran picks them with the Extended test preset, not a prompt.
	// --extended stays as the explicit form that fails loudly on an old engine.
	extended := o.Extended || carrierOkHere("vxlan")
	if o.Extended && !carrierOkHere("vxlan") {
		res.Error = fmt.Errorf("--extended needs wattun 3.3.0 on this server (found %s); both ends must run 3.3.0. Run: wattun-manager update", orOld(engineVer()))
		return res
	}
	excl := make([]string, 0, len(pick.Used))
	for _, p := range pick.Used {
		excl = append(excl, strconv.Itoa(p))
	}
	rplan, err := autoPickRplan(excl)
	if err != nil {
		res.Error = fmt.Errorf("Could not find free reverse ports on this server.")
		return res
	}
	extD, extNote := "", ""
	if extended {
		extD, extNote = autoExtPlanEntries(excl)
		if extD == "" { // "No extended carrier could be planned; continuing with the standard set."
			extended = false
		}
	}
	plan := "d=" + pick.D + ";r=" + rplan
	if extD != "" {
		plan += "," + extD
	}
	if extended {
		plan += ";e=1"
	}
	_ = extNote

	key := p2NewKey()
	m := envFreeMetricsPort()
	apath := randPath()
	cars := ""
	for _, c := range strings.Split(pick.D, ",") {
		cars += "+" + strings.SplitN(c, ":", 2)[0]
	}
	os.MkdirAll(P.Conf, 0o700)
	os.WriteFile(filepath.Join(P.Conf, name+".key"), []byte(key+"\n"), 0o600)
	var b strings.Builder
	b.WriteString("# WatTunnel - Kharej (server), auto: every carrier at once. Created by wattun-manager.\n")
	b.WriteString("mode: server\n")
	b.WriteString("key-file: " + filepath.Join(P.Conf, name+".key") + "\n")
	b.WriteString("carrier: icmp" + cars + "\n")
	for _, c := range strings.Split(pick.D, ",") {
		if p := planEntryPort(c); p != "" {
			fmt.Fprintf(&b, "listen-%s: \":%s\"\n", strings.SplitN(c, ":", 2)[0], p)
		}
	}
	b.WriteString("path: " + apath + "\n")
	if m != 0 { // F25: free_metrics_port found no port; write no invalid line
		fmt.Fprintf(&b, "metrics: 127.0.0.1:%d\n", m)
	}
	if len(maps) > 0 {
		b.WriteString("ports:\n")
		for _, it := range maps {
			b.WriteString("  - \"" + it + "\"\n")
		}
	}
	if err := writeFile0600(filepath.Join(P.Conf, name+".yml"), b.String()); err != nil {
		res.Error = err
		return res
	}
	tok := MakeToken("auto", addr, key, apath, cdn, "", allow, "", plan)
	os.WriteFile(filepath.Join(P.Conf, name+".token"), []byte(tok+"\n"), 0o600)

	res.Name, res.Plan, res.Token = name, plan, tok
	res.Units = append(res.Units, name)
	_ = EnableNow(Unit(name)) // start_unit

	var fwl []string
	for _, c := range strings.Split(pick.D, ",") {
		p := planEntryPort(c)
		if p == "" {
			continue // B1: raw carriers have no listen port/firewall rule
		}
		cn := strings.SplitN(c, ":", 2)[0]
		if cn == "udp" || isShapedUDP(cn) {
			fwl = append(fwl, p+"/udp")
		} else {
			fwl = append(fwl, p+"/tcp")
		}
	}
	envFWOpen(fwl...)
	if extended { // B3: one hidden single-carrier listener per extended shape
		if err := autoExtWriteUnits(name, extD, strings.Split(MapsYamlBlock(maps), NL)); err != nil {
			// F16: this tunnel is fresh, so a child-write failure rolls it back instead of
			// leaving a running parent whose token promises `;e=1` shapes with no listeners.
			_ = Disable(Unit(name))
			for _, s := range stateFiles(name) {
				os.Remove(s)
			}
			ents, _ := filepath.Glob(filepath.Join(P.Conf, name+"-e-*"))
			for _, e := range ents {
				os.Remove(e)
			}
			envFWClose(fwl...)
			os.Remove(filepath.Join(P.Conf, name+".yml"))
			os.Remove(filepath.Join(P.Conf, name+".key"))
			os.Remove(filepath.Join(P.Conf, name+".token"))
			res.Error = fmt.Errorf("Could not write the extended listeners; the new tunnel was removed and nothing is running.")
			return res
		}
		autoExtStart(name)
		res.Units = append(res.Units, autoExtNames(name)...)
	}
	startWatcher(name)
	ensureHealTimer()
	res.Units = append(res.Units, autoHelpers(name)...)
	return res
}

// start_watcher — transient unit that waits for Iran's first connection, then writes NAME-r.
func startWatcher(name string) {
	u := P.Prefix + "-autowatch-" + name
	_ = Systemctl("stop", u+".service")
	_ = Systemctl("reset-failed", u+".service")
	_ = envSystemdRun(u, 3600, "auto-watch", name)
}

// =====================================================================================
// Reverse companion
// =====================================================================================

// companion_create — name ip [no_start]: writes/updates hidden NAME-r.
func companionCreate(name, ip string, noStart bool) error {
	ip = strings.Trim(ip, "[]")
	r := name + "-r"
	f := filepath.Join(P.Conf, r+".yml")
	os.WriteFile(filepath.Join(P.Conf, name+".iranip"), []byte(ip+"\n"), 0o600)
	if fileExists(f) && mustRead(filepath.Join(P.Conf, name+".iranip")) == ip &&
		(Cfg(r, "peer-icmp") == ip || strings.Contains(mustRead(f), "Iran "+ip+")")) {
		return nil
	}
	tok, err := readTokFile(name)
	if err != nil || tok.Auto == "" {
		return fmt.Errorf("No auto token for '%s'.", name)
	}
	rp := planPart(tok.Auto, "r")
	m := portOf(Cfg(r, "metrics"))
	if m == "" {
		m = strconv.Itoa(envFreeMetricsPort())
	}
	cars := ""
	if isIPv4(ip) {
		cars = "icmp"
	}
	for _, c := range strings.Split(rp, ",") {
		cars = joinPlus(cars, strings.SplitN(c, ":", 2)[0])
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# WatTunnel - Kharej reverse side of auto tunnel '%s' (Iran %s). Hidden; written by wattun-manager.\n", name, ip)
	b.WriteString("mode: server\n")
	b.WriteString("key-file: " + filepath.Join(P.Conf, name+".key") + "\n")
	b.WriteString("carrier: " + cars + "\n")
	b.WriteString("reverse: true\n")
	if isIPv4(ip) {
		b.WriteString("peer-icmp: " + ip + "\n")
	}
	for _, c := range strings.Split(rp, ",") {
		fmt.Fprintf(&b, "peer-%s: %s\n", strings.SplitN(c, ":", 2)[0], JoinHP(ip, planEntryPort(c)))
	}
	path := tok.Path
	if path == "" {
		path = "/wat"
	}
	b.WriteString("path: " + path + "\n")
	b.WriteString("pool-rotate: 30m\n")
	if m != "" && m != "0" { // F25: write no invalid metrics: line when the range is exhausted
		b.WriteString("metrics: 127.0.0.1:" + m + "\n")
	}
	for _, l := range strings.Split(MapsYamlBlock(YmlMaps(name)), NL) {
		b.WriteString(l + "\n")
	}
	if err := writeFile0600(f, b.String()); err != nil {
		return err
	}
	autoSyncHelperSettings(name, r)
	if !noStart {
		_ = Enable(Unit(r))
		_ = Restart(Unit(r))
	}
	envLogger("wattun-auto", fmt.Sprintf("learned Iran IP %s for %s; synced %s (hidden reverse companion)", ip, name, Unit(r)))
	return nil
}

func joinPlus(a, b string) string {
	if a == "" {
		return b
	}
	return a + "+" + b
}

// auto_detect_iran_ip — first usable Iran client IP (prefers non-CDN clients).
func autoDetectIranIP(name, cdn string) string {
	units := append([]string{name}, autoExtNames(name)...)
	var cdnIP string
	for _, u := range units {
		if !IsActive(Unit(u)) {
			continue
		}
		s := StatsRaw(u)
		if s == "" {
			continue
		}
		for _, obj := range strings.Split(strings.ReplaceAll(jsonFieldArray(s, "clients"), "},", "}\n"), "\n") {
			car := jsonString(obj, "carrier")
			ip := jsonString(obj, "ip")
			if ip == "" || (!isIPv4(ip) && !strings.Contains(ip, ":")) {
				continue
			}
			if isCDNCarrier(car) {
				if cdn == "" && cdnIP == "" {
					cdnIP = ip
				}
			} else {
				return ip
			}
		}
	}
	return cdnIP
}

// auto_sync_companion — called by heal() on Kharej: create/update NAME-r whenever
// Iran's IP appears or changes.
func autoSyncCompanion(name string) {
	if !IsAutoKharej(name) || !IsActive(Unit(name)) {
		return
	}
	tok, _ := readTokFile(name)
	ip := autoDetectIranIP(name, tok.SNI)
	if ip == "" {
		return
	}
	curIP := strings.SplitN(mustRead(filepath.Join(P.Conf, name+".iranip")), "\n", 2)[0]
	if !fileExists(filepath.Join(P.Conf, name+"-r.yml")) || curIP != ip {
		_ = companionCreate(name, ip, false)
		_ = Systemctl("stop", P.Prefix+"-autowatch-"+name+".service")
		_ = Systemctl("reset-failed", P.Prefix+"-autowatch-"+name+".service")
	}
}

// auto_ip — manual fallback: set/update Iran's IP for the hidden companion.
func autoIP(name, ip string) error {
	ip = strings.Trim(ip, "[]")
	if !IsAutoKharej(name) {
		return fmt.Errorf("'%s' is not an auto Kharej tunnel.", name)
	}
	if !isIPv4(ip) && !strings.Contains(ip, ":") {
		return fmt.Errorf("Usage: wattun-manager auto-ip %s IRAN_IP", name)
	}
	if err := companionCreate(name, ip, false); err != nil {
		return err
	}
	_ = Systemctl("stop", P.Prefix+"-autowatch-"+name+".service")
	ensureHealTimer()
	Ok(fmt.Sprintf("Reverse side for '%s' is set for Iran %s. Run the test again on Iran.", name, ip))
	return nil
}

// =====================================================================================
// auto_live / auto_set_carriers / reopen (3.3.8+ always-open lifecycle)
// =====================================================================================

// auto_live — live carrier picks: direct, reverse companion, extended shapes.
func autoLive(name string) (anD, anR, anE []string) {
	if s := StatsRaw(name); s != "" {
		var live []string
		for _, m := range []string{"clients", "carriers"} {
			for _, obj := range strings.Split(strings.ReplaceAll(jsonFieldArray(s, m), "},", "}\n"), "\n") {
				if m == "carriers" && !strings.Contains(obj, `"alive": true`) {
					continue
				}
				v := jsonString(obj, "carrier")
				if v == "" {
					v = jsonString(obj, "name")
				}
				if v != "" {
					live = appendUnique(live, v)
				}
			}
		}
		// 3.3.8: a finalized single-carrier tunnel has empty carriers[]
		if len(live) == 0 && strings.Contains(s, `"alive": true`) {
			if one := Cfg(name, "carrier"); one != "" && !strings.Contains(one, "+") {
				live = []string{one}
			}
		}
		if IsReverse(name) {
			anR = live
		} else {
			anD = live
		}
	}
	if s := StatsRaw(name + "-r"); s != "" {
		var live []string
		for _, obj := range strings.Split(strings.ReplaceAll(jsonFieldArray(s, "carriers"), "},", "}\n"), "\n") {
			if strings.Contains(obj, `"alive": true`) {
				if v := jsonString(obj, "name"); v != "" {
					live = appendUnique(live, v)
				}
			}
		}
		if len(live) == 0 && strings.Contains(s, `"alive": true`) {
			if one := Cfg(name+"-r", "carrier"); one != "" && !strings.Contains(one, "+") {
				live = []string{one}
			}
		}
		anR = live
	}
	if live, st := autoExtLive(name); st == 0 {
		for _, u := range live {
			anE = append(anE, strings.TrimPrefix(u, name+"-e-"))
		}
	}
	return
}

// in_use — the types Iran is connected through ("udp", "tcp+wss", "r:icmp", "vxlan").
func inUse(name string) string {
	anD, anR, anE := autoLive(name)
	var parts []string
	parts = append(parts, anD...)
	for _, c := range anR {
		parts = append(parts, "r:"+c)
	}
	parts = append(parts, anE...)
	return strings.Join(parts, "+")
}

// auto_set_carriers — rewrite the carrier lists of NAME and NAME-r from the token plan.
func autoSetCarriers(name, direct, reverse string) error {
	tok, err := readTokFile(name)
	if err != nil || tok.Auto == "" {
		return fmt.Errorf("No auto token for '%s'.", name)
	}
	d, r := planPart(tok.Auto, "d"), planPart(tok.Auto, "r")
	if direct != "" {
		var cars, blk []string
		for _, c := range strings.Fields(direct) {
			cars = append(cars, c)
			if p := planPort(d, c); p != "" {
				blk = append(blk, fmt.Sprintf("listen-%s: \":%s\"", c, p))
			}
		}
		replaceCarrierBlock(filepath.Join(P.Conf, name+".yml"), strings.Join(cars, "+"), blk, nil)
	}
	if reverse != "" {
		f := filepath.Join(P.Conf, name+"-r.yml")
		if !fileExists(f) {
			return nil
		}
		ip := Cfg(name+"-r", "peer-icmp")
		if ip == "" {
			ip = strings.SplitN(mustRead(filepath.Join(P.Conf, name+".iranip")), "\n", 2)[0]
		}
		var cars, blk []string
		for _, c := range strings.Fields(reverse) {
			if c == "icmp" && !isIPv4(ip) {
				continue
			}
			cars = append(cars, c)
			if p := planPort(r, c); p != "" && ip != "" {
				blk = append(blk, fmt.Sprintf("peer-%s: %s", c, JoinHP(ip, p)))
			}
		}
		replaceCarrierBlock(f, strings.Join(cars, "+"), blk, []string{"peer-icmp"})
	}
	return nil
}

// replaceCarrierBlock — the awk rewrite of `carrier:` + listen-*/peer-* lines.
func replaceCarrierBlock(path, carrierLine string, extra []string, keepPeers []string) {
	var out []string
	done := false
	keep := func(k string) bool {
		for _, p := range keepPeers {
			if p == k {
				return true
			}
		}
		return false
	}
	for _, l := range strings.Split(mustRead(path), "\n") {
		k := yamlKey(l)
		switch {
		case k == "carrier" && !done:
			out = append(out, "carrier: "+carrierLine)
			out = append(out, extra...)
			done = true
		case strings.HasPrefix(k, "listen-") || strings.HasPrefix(k, "peer-"):
			if keep(k) {
				out = append(out, l)
			}
		default:
			out = append(out, l)
		}
	}
	_ = writeFile0600(path, strings.Join(out, "\n"))
}

// fw_port_list — "4443/udp 4443/tcp ..." for the direct carriers.
func fwPortList(carriers []string, planD string) []string {
	var out []string
	for _, c := range carriers {
		p := planPort(planD, c)
		if p == "" {
			continue
		}
		proto := "tcp"
		if c == "udp" {
			proto = "udp"
		}
		out = append(out, p+"/"+proto)
	}
	return out
}

// auto_plan_lists — AP_D, AP_R; shaped entries are hidden units, not bond legs (B3).
func autoPlanLists(plan string) (apD, apR []string) {
	apD, apR = []string{"icmp"}, []string{"icmp"}
	for _, c := range strings.Split(planPart(plan, "d"), ",") {
		n := strings.SplitN(c, ":", 2)[0]
		if isShapedRaw(n) || isShapedUDP(n) || n == "icmp" || n == "" {
			continue
		}
		apD = append(apD, n)
	}
	for _, c := range strings.Split(planPart(plan, "r"), ",") {
		n := strings.SplitN(c, ":", 2)[0]
		if n == "icmp" || n == "" {
			continue
		}
		apR = append(apR, n)
	}
	return
}

// auto_drop_unit — stop, disable and delete one internal helper unit (F17 keeps a port
// another tunnel also owns).
func autoDropUnit(u string) {
	_ = Disable(Unit(u))
	p := portOf(Cfg(u, "listen"))
	if p != "" && isAutoExt(u) && isShapedUDP(Cfg(u, "carrier")) {
		envFWClose(p + "/udp")
	}
	for _, s := range stateFiles(u) {
		os.Remove(s)
	}
	os.Remove(filepath.Join(P.Conf, u+".yml"))
	os.Remove(filepath.Join(P.Conf, u+".ech"))
	os.Remove(filepath.Join(P.Conf, u+".autoext"))
}

// auto_sync_helper_settings — propagate shared server settings & limits to hidden helpers.
func autoSyncHelperSettings(parent, only string) {
	if !fileExists(filepath.Join(P.Conf, parent+".yml")) {
		return
	}
	blk := helperKeysYml(parent)
	var targets []string
	if only != "" {
		targets = []string{only}
	} else {
		targets = autoHelpers(parent)
	}
	for _, u := range targets {
		f := filepath.Join(P.Conf, u+".yml")
		if !fileExists(f) {
			continue
		}
		var out []string
		inBlock := false
		for _, l := range strings.Split(mustRead(f), "\n") {
			k := yamlKey(l)
			if k != "" && isHelperKey(k) {
				inBlock = true
				continue
			}
			if inBlock && strings.HasPrefix(l, " ") {
				continue
			}
			inBlock = false
			out = append(out, l)
		}
		for _, l := range blk {
			if u == parent+"-r" && (strings.HasPrefix(l, "allow-clients:") || strings.HasPrefix(l, "allow-clients-file:")) {
				continue
			}
			out = append(out, l)
		}
		_ = writeFile0600(f, strings.Join(out, "\n"))
	}
}

// autoNeedsReopen — 0 when a tunnel was narrowed/finalized (legacy 3.3.0-3.3.8 markers)
// or is missing planned carriers/helpers. Pure decision over the given snapshot.
func autoNeedsReopen(n string) bool {
	if !IsAutoKharej(n) {
		return false
	}
	for _, m := range []string{n + ".finalized", n + ".keepopen"} {
		if fileExists(filepath.Join(P.Conf, m)) {
			return true
		}
	}
	for _, m := range []string{n + ".autoprune.done", n + ".autoprune", n + ".autowiden", n + ".autowiden.down", n + ".abandoned"} {
		if fileExists(filepath.Join(P.Run, m)) {
			return true
		}
	}
	if IsReverse(n) || isShapedRaw(Cfg(n, "carrier")) || isShapedUDP(Cfg(n, "carrier")) || Cfg(n, "listen") != "" {
		return true
	}
	tok, err := readTokFile(n)
	if err != nil || tok.Auto == "" {
		return false
	}
	apD, apR := autoPlanLists(tok.Auto)
	curD := Cfg(n, "carrier")
	for _, c := range apD {
		if !strings.Contains("+"+curD+"+", "+"+c+"+") {
			return true
		}
	}
	if fileExists(filepath.Join(P.Conf, n+"-r.yml")) {
		curR := Cfg(n+"-r", "carrier")
		rip := strings.SplitN(mustRead(filepath.Join(P.Conf, n+".iranip")), "\n", 2)[0]
		for _, c := range apR {
			if c == "icmp" && rip != "" && !isIPv4(rip) {
				continue
			}
			if !strings.Contains("+"+curR+"+", "+"+c+"+") {
				return true
			}
		}
	}
	if planPart(tok.Auto, "e") == "1" {
		for _, c := range strings.Split(planPart(tok.Auto, "d"), ",") {
			exp := strings.SplitN(c, ":", 2)[0]
			if !isShapedRaw(exp) && !isShapedUDP(exp) {
				continue
			}
			u := autoExtChild(n, exp)
			if !fileExists(filepath.Join(P.Conf, u+".yml")) ||
				mustRead(filepath.Join(P.Conf, u+".autoext")) != n {
				return true
			}
		}
	}
	return false
}

// auto_reopen — reopen all planned carriers (migration from 3.3.0-3.3.8 narrowed/finalized).
func autoReopen(n string) error {
	if !fileExists(filepath.Join(P.Conf, n+".token")) {
		rebuildKharejToken(n)
	}
	if !IsAutoKharej(n) {
		return fmt.Errorf("'%s' is not an auto Kharej tunnel.", n)
	}
	tok, err := readTokFile(n)
	if err != nil || tok.Auto == "" {
		return fmt.Errorf("No auto token for '%s'.", n)
	}
	wasOn := IsActive(Unit(n)) || IsEnabled(Unit(n))
	if IsReverse(n) && fileExists(filepath.Join(P.Conf, n+".iranip")) {
		pip := Cfg(n, "peer-icmp")
		if pip == "" {
			if h, _ := SplitHP(Cfg(n, "peer")); h != "" {
				pip = h
			}
		}
		if pip == "" {
			if h, _ := SplitHP(Cfg(n, "peer-tcp")); h != "" {
				pip = h
			}
		}
		if pip != "" {
			os.WriteFile(filepath.Join(P.Conf, n+".iranip"), []byte(pip+"\n"), 0o600)
		}
	}
	f := filepath.Join(P.Conf, n+".yml")
	if fileExists(filepath.Join(P.Conf, n+".finalized")) || IsReverse(n) ||
		isShapedRaw(Cfg(n, "carrier")) || isShapedUDP(Cfg(n, "carrier")) || Cfg(n, "listen") != "" {
		var out []string
		for _, l := range strings.Split(mustRead(f), "\n") {
			k := yamlKey(l)
			if k == "peer-icmp" || isReopenDropKey(k) {
				continue
			}
			out = append(out, l)
		}
		_ = writeFile0600(f, strings.Join(out, "\n"))
		if Cfg(n, "path") == "" {
			p := tok.Path
			if p == "" {
				p = "/wat"
			}
			_ = SetValue(n, "path", p)
		}
	}
	for _, m := range []string{n + ".autoprune", n + ".autoprune.done"} {
		os.Remove(filepath.Join(P.Run, m))
	}
	os.Remove(filepath.Join(P.Conf, n+".finalized"))
	os.Remove(filepath.Join(P.Conf, n+".keepopen"))
	for _, m := range []string{n + ".autowiden", n + ".autowiden.down", n + ".abandoned"} {
		os.Remove(filepath.Join(P.Run, m))
	}
	d := planPart(tok.Auto, "d")
	apD, apR := autoPlanLists(tok.Auto)
	if err := autoSetCarriers(n, strings.Join(apD, " "), strings.Join(apR, " ")); err != nil {
		return err
	}
	envFWOpen(fwPortList(apD, d)...)
	if fileExists(filepath.Join(P.Conf, n+"-r.yml")) {
		autoSyncHelperSettings(n, n+"-r")
	} else if ip := strings.TrimSpace(mustRead(filepath.Join(P.Conf, n+".iranip"))); ip != "" {
		_ = companionCreate(n, ip, !wasOn)
	}
	if planPart(tok.Auto, "e") == "1" {
		var extD []string
		for _, c := range strings.Split(d, ",") {
			cn := strings.SplitN(c, ":", 2)[0]
			if isShapedRaw(cn) || isShapedUDP(cn) {
				extD = append(extD, c)
			}
		}
		if len(extD) > 0 {
			_ = autoExtWriteUnits(n, strings.Join(extD, ","), strings.Split(MapsYamlBlock(YmlMaps(n)), NL))
		}
	}
	if wasOn {
		_ = Enable(Unit(n))
		_ = Restart(Unit(n))
		for _, u := range autoHelpers(n) {
			_ = Enable(Unit(u))
			_ = Restart(Unit(u))
		}
		if !fileExists(filepath.Join(P.Conf, n+"-r.yml")) {
			startWatcher(n)
		}
	}
	ensureHealTimer()
	envLogger("wattun-auto", "migrated auto tunnel "+n+" to always-open carriers")
	return nil
}

// the keys auto_reopen strips from a narrowed/finalized config (the bash awk list)
func isReopenDropKey(k string) bool {
	switch k {
	case "reverse", "peer", "listen", "sni", "host", "pool-rotate", "pool-rotate-bytes",
		"fake-sni", "fake-mode", "fake-ttl", "ech", "ech-cache":
		return true
	}
	return strings.HasPrefix(k, "peer-")
}

// auto_migrate_all — migrate any legacy narrowed/finalized auto Kharej tunnels.
func autoMigrateAll(announce bool) {
	for _, n := range Tunnels() {
		if Role(n) != "Kharej" {
			continue
		}
		if !fileExists(filepath.Join(P.Conf, n+".token")) {
			rebuildKharejToken(n) // 3.3.3-3.3.7 finalize removed it
		}
		if !IsAutoKharej(n) {
			continue
		}
		if !autoNeedsReopen(n) {
			continue
		}
		if err := autoReopen(n); err == nil && announce {
			Ok(fmt.Sprintf("Reopened all carriers on '%s' (always-open mode).", n))
		}
	}
}

// =====================================================================================
// Iran side: variant table and test runner (AV/AR use P3's shared variant/result types)
// =====================================================================================

var av []variant // AV_* — the token's plan is the source (B1/B2/B4)
var ar []result  // AR_* — one measurement per variant
var avTok Token  // T_* of the auto token under test

// at state (mirrors the AT_* globals).
var (
	atAddr, atPath, atSkip, atAct string
	atQuiet                       bool
	atMB, atStreams               int
	atPeak                        float64
	atMovedMB                     int
	atStop                        bool
	atGSkip                       string
	atSecs                        int
	atNote, atPlan                string
	atPreset                      = "normal"
	atTunnel                      string
	atVerify                      bool
	atScreenSkipped               string // AT_SKIPPED (B2)
)

func avAdd(label, car, kind, peer, port, sni, fp, ech, frag, fs, fm, extra string) {
	av = append(av, variant{Label: label, Car: car, Kind: kind, Peer: peer, Port: port,
		SNI: sni, FP: fp, ECH: ech, Frag: frag, FS: fs, FM: fm, X: extra})
	ar = append(ar, result{}) // keeps AR_* as long as AV_* for variants added while testing
}

// auto_variants_anti — the anti-censor preset grid.
func autoVariantsAnti(d string) {
	first := strings.SplitN(acSNIs, ",", 2)[0]
	others := strings.Join(append(strings.Split(acSNIs, ",")[1:], "www.cloudflare.com"), ",")
	for _, c := range strings.Fields(autoVarAnti) {
		p := planPort(d, c)
		if p == "" {
			continue
		}
		hp := JoinHP(atAddr, p)
		for _, fm := range strings.Fields(acAllModes) {
			avAdd(c+" "+fm+" "+first, c, "d", hp, "", "", "", "", "", first, fm, "")
		}
		for _, fs := range strings.Split(others, ",") {
			for _, fm := range []string{"rst", "synrst", "paws"} {
				avAdd(c+" "+fm+" "+strings.TrimPrefix(fs, "www."), c, "d", hp, "", "", "", "", "", fs, fm, "")
			}
		}
		switch c {
		case "tls", "wss", "h2", "grpc":
			avAdd(c+" tls-frag mid-SNI", c, "d", hp, "", "", "", "", "-1", "", "", "")
			avAdd(c+" tls-frag 40", c, "d", hp, "", "", "", "", "40", "", "", "")
			for _, fm := range []string{"chrome", "firefox", "safari"} {
				avAdd(c+" fp "+fm, c, "d", hp, "", "", fm, "", "", "", "", "")
			}
			if avTok.SNI != "" {
				avAdd(c+" chrome+ech", c, "d", hp, "", avTok.SNI, "chrome", "auto", "", "", "", "")
			}
		}
	}
}

// auto_variants_fast — the fast preset's cut of the anti grid: every direct pool carrier x acFastModes x
// acFastSNIs. The rows are ordinary anti variants (avAnti sees the fake-sni/fake-mode pair), so the ranked
// table, the 8 % rank margin and atToT's fake-sni/fake-mode lines all apply unchanged — no separate apply path.
func autoVariantsFast(d string) {
	for _, c := range strings.Fields(autoVarAnti) {
		p := planPort(d, c)
		if p == "" {
			continue
		}
		hp := JoinHP(atAddr, p)
		for _, fs := range strings.Fields(acFastSNIs) {
			for _, fm := range strings.Fields(acFastModes) {
				avAdd(c+" "+fm+" "+fs, c, "d", hp, "", "", "", "", "", fs, fm, "")
			}
		}
	}
}

// auto_variants — T_* from the auto token -> AV_* (B1/B2/B4).
func autoVariants(tok Token) {
	av, ar = nil, nil
	avTok = tok
	atAddr = hostOf(tok.Peer)
	atPath = tok.Path
	if atPath == "" {
		atPath = "/wat"
	}
	atScreenSkipped = ""
	d, r := planPart(tok.Auto, "d"), planPart(tok.Auto, "r")
	// reverse preset: only the plan's r= variants — for routes where nothing but reverse passes
	if atPreset != "reverse" {
		if isIPv4(atAddr) {
			avAdd("icmp", "icmp", "d", atAddr, "", "", "", "", "", "", "", "")
		}
		for _, c := range strings.Split(d, ",") {
			name := strings.SplitN(c, ":", 2)[0]
			p := planEntryPort(c)
			if name == "icmp" {
				continue // the bare-IP icmp variant is the first row, added above
			}
			if IsRawCarrier(name) && !isIPv4(atAddr) {
				continue
			}
			if !carrierOkHere(name) { // B2: Iran skips what it cannot run
				atScreenSkipped = joinNonEmpty(atScreenSkipped, ", ", name)
				continue
			}
			if (isShapedRaw(name) || isShapedUDP(name)) && atPreset != "extended" {
				continue // the 13 shaped carriers are the Extended preset's rows (3.6.0)
			}
			switch {
			case isShapedRaw(name):
				avAdd(name+" (shape only)", name, "d", atAddr, "", "", "", "", "", "", "", "")
			case isShapedUDP(name):
				avAdd(name+" (shape only)", name, "d", JoinHP(atAddr, p), "", "", "", "", "", "", "", "")
			case p != "":
				avAdd(name, name, "d", JoinHP(atAddr, p), "", "", "", "", "", "", "", "")
				// Wraith (3.3.9, Iran side only): the same udp port from a new source port every 12-18 packets
				if name == "udp" && binVerOK("3.3.9") {
					avAdd("udp hop", "udp", "d", JoinHP(atAddr, p), "", "", "", "", "", "", "", "-udp-hop="+atHop)
				}
			default:
				avAdd(name, name, "d", atAddr, "", "", "", "", "", "", "", "")
			}
		}
		switch atPreset {
		case "anti":
			autoVariantsAnti(d)
		case "fast":
			autoVariantsFast(d)
		}
		if tok.SNI != "" {
			for _, c := range strings.Fields(autoVarCDN) { // h2 never connects through Cloudflare
				p := planPort(d, c)
				if p == "" || !cfPortOK(c, p) {
					continue
				}
				if binVerOK("2.2.0") {
					if e := csLast.Edges; len(e) > 0 { // the best Cloudflare edges, from autoTest's scan
						avAdd(fmt.Sprintf("%s · chrome+ech · %d edges", c, len(e)), c, "c", cdnPeerList(e, p), "", tok.SNI, "chrome", "auto", "", "", "", "")
					} else {
						avAdd(c+" · chrome+ech", c, "c", tok.SNI+":"+p, "", tok.SNI, "chrome", "auto", "", "", "", "")
					}
				} else {
					avAdd(c+" via CDN", c, "c", tok.SNI+":"+p, "", tok.SNI, "", "", "", "", "", "")
				}
			}
		}
	}
	if isIPv4(atAddr) {
		avAdd("icmp reverse", "icmp", "r", atAddr, "", "", "", "", "", "", "", "")
	}
	for _, c := range strings.Split(r, ",") { // reverse plan: icmp first, then pool legs
		name := strings.SplitN(c, ":", 2)[0]
		p := planEntryPort(c)
		if name == "icmp" || p == "" {
			continue
		}
		if !carrierOkHere(name) {
			atScreenSkipped = joinNonEmpty(atScreenSkipped, ", ", name)
			continue
		}
		avAdd(name+" reverse", name, "r", JoinHP(atAddr, p), p, "", "", "", "", "", "", "")
	}
	ar = make([]result, len(av))
}

// hostOf — the dial host of a peer (first endpoint of a bond token, brackets stripped).
func hostOf(peer string) string {
	h, _ := SplitHP(strings.SplitN(peer, ",", 2)[0])
	return strings.Trim(h, "[]")
}

// at_budget — true worst case, MB + rough minutes (H2).
func atBudget(n, screenMB, finalMB, probes, tuneMB int) string {
	mb := n*2*screenMB + 3*2*finalMB + probes*2*tuneMB
	m := (mb + 479) / 480
	if m < 1 {
		m = 1
	}
	return fmt.Sprintf("up to %d MB, about %d min", mb, m)
}

// at_tune_probe_count — 1 baseline + one probe per value.
func atTuneProbeCount(knobs string) int {
	out := 1
	for _, kv := range strings.Fields(knobs) {
		for _, v := range strings.Split(strings.SplitN(kv, ":", 2)[1], ",") {
			if v != "" {
				out++
			}
		}
	}
	return out
}

// the widest reduced grid, used by at_budget (H2)

// at_best_rate — the fastest measured direction so far.
func atBestRate(best float64, idx ...int) float64 {
	for _, i := range idx {
		if !ar[i].OK {
			continue
		}
		if v := maxF(ar[i].Down, ar[i].Up); v > best {
			best = v
		}
	}
	return best
}

// at_score — i -> down+up
func atScore(i int) float64 { return ar[i].Down + ar[i].Up }

// at_skipped_hint — B2: one clear sentence for carriers the Iran engine cannot run.
func atSkippedHint() string {
	if atScreenSkipped == "" {
		return ""
	}
	return fmt.Sprintf("Token includes %s; this server runs %s and cannot test them (both ends need newer wattun for these transports).",
		atScreenSkipped, orOld(engineVer()))
}

// at_to_t — AT_SEL (one index, or several = bond) -> the chosen variant fields.
type atChoice struct {
	Carrier, Peer, Path, SNI, Rev, Extra, Label, Key string
}

func atToT(sel []int) (atChoice, error) {
	var c atChoice
	if len(sel) > 1 {
		if av[sel[0]].Kind == "r" {
			var cars, extra []string
			for _, i := range sel {
				car := av[i].Car
				cars = append(cars, car)
				if av[i].Port != "" {
					extra = append(extra, fmt.Sprintf("listen-%s: \":%s\"", car, av[i].Port))
				}
			}
			carrier := strings.Join(cars, "+")
			if !VCarrierList(carrier) { // B4: shaped carriers are single-carrier only
				return c, fmt.Errorf("Cannot join %s: shaped carriers are single-carrier only.", carrier)
			}
			c.Carrier, c.Peer, c.Path, c.Rev = carrier, atAddr, atPath, "1"
			c.Extra = strings.Join(extra, "\n")
			c.Label, c.Key = "reverse bond "+carrier, "bond/r"
			return c, nil
		}
		var cars, extra []string
		cdn := -1
		for _, i := range sel {
			car := av[i].Car
			cars = append(cars, car)
			extra = append(extra, fmt.Sprintf("peer-%s: %s", car, av[i].Peer))
			if av[i].Kind == "c" && cdn < 0 {
				cdn = i
				c.SNI = av[i].SNI
			}
		}
		carrier := strings.Join(cars, "+")
		// B4/D7: a joined list must be a valid bond; the engine refuses a shaped leg.
		if !VCarrierList(carrier) {
			return c, fmt.Errorf("Cannot join %s: shaped carriers are single-carrier only.", carrier)
		}
		c.Extra = strings.Join(extra, "\n")
		if cdn >= 0 {
			c.Extra = joinNonEmpty(c.Extra, "\n", atCdnLines(cdn))
		}
		c.Carrier, c.Peer, c.Path = carrier, atAddr, atPath
		c.Extra = joinNonEmpty(c.Extra, "\n", atHopLine(sel))
		c.Label, c.Key = "bond "+carrier, "bond"
		return c, nil
	}
	i := sel[0]
	car := av[i].Car
	c.Carrier, c.Peer = car, av[i].Peer
	if isCDNCarrier(car) || strings.Contains(car, "+") {
		c.Path = atPath
	}
	if av[i].Kind == "c" {
		c.SNI = av[i].SNI
		c.Extra = atCdnLines(i)
	}
	if avAnti(av[i]) {
		c.SNI = av[i].SNI
		c.Extra = atCdnLines(i)
		if av[i].FS != "" {
			fm := av[i].FM
			if fm == "" {
				fm = "seq"
			}
			c.Extra = joinNonEmpty(c.Extra, "\n", "fake-sni: "+av[i].FS, "fake-mode: "+fm)
		}
	}
	if av[i].Kind == "r" {
		c.Rev = "1"
	}
	c.Extra = joinNonEmpty(c.Extra, "\n", atHopLine(sel))
	c.Label, c.Key = av[i].Label, avKey(av[i])
	return c, nil
}

// atHop: Wraith packets per source port in the auto test (field cut ~30 per flow; 12-18 leaves a margin).
const atHop = "12"

// avHop: a variant's -udp-hop value, "" = none.
func avHop(v variant) string {
	for _, w := range strings.Fields(v.X) {
		if h, ok := strings.CutPrefix(w, "-udp-hop="); ok {
			return h
		}
	}
	return ""
}

// atHopLine: "udp-hop: N" when a chosen row hops.
func atHopLine(sel []int) string {
	for _, i := range sel {
		if h := avHop(av[i]); h != "" {
			return "udp-hop: " + h
		}
	}
	return ""
}

// at_cdn_lines — the fp / ech / tls-frag config lines of variant i.
func atCdnLines(i int) string {
	var l []string
	if av[i].FP != "" {
		l = append(l, "fp: "+av[i].FP)
	}
	if av[i].ECH != "" {
		l = append(l, "ech: "+av[i].ECH)
	}
	if av[i].Frag != "" && av[i].Frag != "0" {
		l = append(l, "tls-frag: "+av[i].Frag)
	}
	return strings.Join(l, "\n")
}

// at_joinable_summary — joinable direct/CDN and reverse row numbers (1-based).
func atJoinableSummary(rank []int) (jd, jr []int) {
	for k, i := range rank {
		if strings.Contains(av[i].Car, "+") || isShapedRaw(av[i].Car) || isShapedUDP(av[i].Car) || avAnti(av[i]) {
			continue
		}
		if av[i].Kind == "r" {
			jr = append(jr, k+1)
		} else {
			jd = append(jd, k+1)
		}
	}
	return
}

// at_rows — "1 3 4" / "1,3,4" / "1+3+4" -> selected variant indices.
func atRows(rank []int, spec string) ([]int, error) {
	var sel []int
	seen := map[int]bool{}
	cars := map[string]bool{}
	hasR, hasD := false, false
	for _, r := range strings.Fields(strings.NewReplacer(",", " ", "+", " ", ";", " ").Replace(spec)) {
		n, err := strconv.Atoi(r)
		if err != nil || n < 1 || n > len(rank) {
			return nil, fmt.Errorf("No row %s in the table.", r)
		}
		i := rank[n-1]
		if seen[i] {
			continue
		}
		seen[i] = true
		sel = append(sel, i)
	}
	if len(sel) == 0 {
		return nil, fmt.Errorf("Enter at least one row number.")
	}
	if len(sel) == 1 {
		return sel, nil
	}
	for _, i := range sel {
		if strings.Contains(av[i].Car, "+") {
			return nil, fmt.Errorf("%s is already a joined bond; pick individual rows to join.", av[i].Label)
		}
		if avAnti(av[i]) {
			return nil, fmt.Errorf("%s is an anti-censor variant; it cannot be joined with others. Pick it alone.", av[i].Label)
		}
		if av[i].Kind == "r" {
			hasR = true
		} else {
			hasD = true
		}
		if cars[av[i].Car] {
			return nil, fmt.Errorf("Two rows use %s; a joined tunnel can use each type once.", av[i].Car)
		}
		cars[av[i].Car] = true
	}
	if hasR && hasD {
		jd, jr := atJoinableSummary(rank)
		msg := "Cannot mix direct and reverse rows in one tunnel."
		if len(jd) > 0 {
			var es []string
			for _, v := range jd {
				es = append(es, strconv.Itoa(v))
			}
			msg += " Direct rows: " + strings.Join(es, " ") + "."
		}
		if len(jr) > 0 {
			var rs []string
			for _, v := range jr {
				rs = append(rs, strconv.Itoa(v))
			}
			msg += " Reverse rows: " + strings.Join(rs, " ") + "."
		}
		return nil, fmt.Errorf("%s", msg)
	}
	for c := range cars { // B4: a shaped row cannot be joined
		if isShapedRaw(c) || isShapedUDP(c) {
			return nil, fmt.Errorf("Cannot join: shaped carriers are single-carrier only.")
		}
	}
	return sel, nil
}

// at_tune_knobs — carrier|bond|reverse -> "key:value,value ..." in test order (D8 data).
func atTuneKnobs(kind, carrier string) string {
	hasDgram := func(list string) bool {
		for _, c := range strings.Split(list, "+") {
			if IsRawCarrier(c) || c == "udp" {
				return true
			}
		}
		return false
	}
	switch kind {
	case "icmp":
		return "" // no sessions/conns to tune on a raw-IP carrier
	case "udp":
		return autoTuneUDP
	case "bond":
		if hasDgram(carrier) {
			return autoTuneBondDGRAM
		}
		return autoTuneBondPool
	case "reverse":
		return autoTuneReverse
	case "tcp", "tls", "ws", "wss", "h2", "h2c", "grpc":
		return autoTunePool
	}
	return ""
}

// auto_current_key — carrier/kind of the running config (d/c/r) or bond / bond/r.
func autoCurrentKey(name string) string {
	c := Cfg(name, "carrier")
	if strings.Contains(c, "+") {
		if IsReverse(name) {
			return "bond/r"
		}
		return "bond"
	}
	if IsReverse(name) {
		return c + "/r"
	}
	if Cfg(name, "sni") != "" {
		return c + "/c"
	}
	if Cfg(name, "udp-hop") != "" {
		return c + "/d/hop"
	}
	return c + "/d"
}

// auto_test — run the screening over all variants (duration-based 8-16 MB probes; the
// 3.3.8+ always-open lifecycle: NO auto-narrow/prune). Probing goes through the
// spawnClient adapter; ranking is P3's atRank.
func autoTest(tok Token) {
	if kd, err := atPrep(tok.Key); err == nil { // the probes dial with the tunnel key
		defer kd.cleanup()
		atKeyFile, atTok = kd.dir+"/key", tok
		defer func() { atKeyFile = "" }()
	}
	csLast, ctSNI, ctFull = cdnScanRes{}, tok.SNI, false
	if tok.SNI != "" && cdnOK() { // one scan for all CDN carriers with a Cloudflare-proxyable port
		d := planPart(tok.Auto, "d")
		for _, c := range strings.Fields(autoVarCDN) {
			if p := planPort(d, c); p != "" && cfPortOK(c, p) {
				_ = spin("Cloudflare edges", func() error {
					csLast, _ = cdnScan(tok.SNI, p, orStr(tok.Path, "/wat"), c)
					return nil
				})
				break
			}
		}
	}
	autoVariants(tok)
	n := len(av)
	if NonInteractive {
		fmt.Fprintf(Stdout, "ATPLAN=%d\n", n)
	}
	if atScreenSkipped != "" {
		Warn("Skipped (needs newer wattun): " + atScreenSkipped)
	}
	atPlan = atBudget(n, atScreenCapMB, atFinalMBMax, atTuneProbesMax, atTuneProbeMB)
	atMB = atScreenMBStart
	bestRate := 0.0
	for i := 0; i < n; i++ {
		if atStop {
			av, ar = av[:i], ar[:i] // at_truncate
			break
		}
		if avAnti(av[i]) && atGSkip != "" && av[i].Car == atGSkip {
			ar[i] = result{Why: "skipped"}
			continue
		}
		w := 8
		if av[i].Kind == "r" && av[i].Car == "icmp" {
			w = 30 // Kharej's companion needs a few seconds to start
		}
		atMB = atProbeMB(bestRate, 1.5, atScreenCapMB) // H3: duration-based size
		atProbe(i, w)
		atEmit(i)
		if ar[i].OK {
			atMovedMB += 2 * atMB
		}
		bestRate = atBestRate(bestRate, i)
		if !atQuiet {
			atPrint(Stdout, i, av, ar, atMB)
		}
		// after the last chrome+ech row: the other TLS variants of each CDN carrier whose chrome+ech failed
		// (cdnTry probes and prints them itself; they land after n, so this loop does not run them again)
		if av[i].Kind == "c" && cdnOK() && (i+1 >= n || av[i+1].Kind != "c") {
			cdnAutoExtras()
		}
		switch atAct {
		case "group":
			if avAnti(av[i]) {
				atGSkip = av[i].Car
			}
		case "stop":
			atStop = true
			ar[i].Why = "skipped"
		}
		atAct = ""
	}
}

// atEmit writes one line per probe for the web panel's job view (non-interactive runs only):
// ATROW=ok|label|down|up|rtt or ATROW=fail|label|why. It prints even when atQuiet hides the table.
func atEmit(i int) {
	if !NonInteractive {
		return
	}
	if ar[i].OK {
		fmt.Fprintf(Stdout, "ATROW=ok|%s|%.1f|%.1f|%.0f\n", av[i].Label, ar[i].Down, ar[i].Up, ar[i].RTT)
	} else {
		fmt.Fprintf(Stdout, "ATROW=fail|%s|%s\n", av[i].Label, ar[i].Why)
	}
}

// at_probe — one throw-away client probe via the adapters.
func atProbe(i, waitSecs int) {
	ar[i] = result{}
	if atStop {
		ar[i].Why = "skipped"
		return
	}
	if atSkip != "" && strings.Contains(" "+atSkip+" ", " "+avKey(av[i])+" ") {
		ar[i].Why = "in use by this tunnel"
		return
	}
	args := []string{"-mode", "client", "-carrier", av[i].Car, "-peer", av[i].Peer}
	if atKeyFile != "" {
		args = append(args, "-key-file", atKeyFile)
	}
	if hasHTTPLeg(av[i].Car) {
		args = append(args, "-path", orStr(atTok.Path, "/wat"))
	}
	if atTok.Icmp != "" && strings.Contains("+"+av[i].Car+"+", "+icmp+") {
		args = append(args, "-icmp-type", atTok.Icmp)
	}
	args = append(args, probeArgs(av[i])...)
	mp := envFreeMetricsPort()
	dmap, ok := atFreePort(mp+1, map[int]bool{mp: true})
	if !ok {
		ar[i].Why = "no free test port"
		return
	}
	// the engine refuses a client without any -map: a loopback-only dummy mapping publishes nothing
	args = append(args, "-map", fmt.Sprintf("%d:1@127.0.0.1", dmap))
	if av[i].Kind == "r" {
		args = append(args, "-reverse")
		if IsPool(av[i].Car) && av[i].Port != "" {
			// Kharej picked this port; if something here holds it the probe cannot listen and would only time out
			if pn, _ := strconv.Atoi(av[i].Port); pn > 0 && p2PortBusy(pn, p2Rproto(av[i].Car)) {
				ar[i].Why = "port " + av[i].Port + " busy here"
				if u := p2PortUser(pn, p2Rproto(av[i].Car)); u != "" {
					ar[i].Why += " (" + u + ")"
				}
				return
			}
			args = append(args, "-listen", ":"+av[i].Port)
		}
	}
	proc, err := envSpawnClient(append(args, "-metrics", "127.0.0.1:"+strconv.Itoa(mp)), "")
	if err != nil {
		ar[i].Why = "no free test port"
		return
	}
	defer proc.Kill()
	if !atWaitAlive(mp, waitSecs) {
		ar[i].Why = fmt.Sprintf("no link in %d s", waitSecs)
		return
	}
	atMeasure(i, mp)
}

// at_wait — wait for the link on the probe's metrics port.
func atWaitAlive(mp, secs int) bool {
	for t := 0; t < secs*2; t++ {
		if strings.Contains(p1FetchStats("127.0.0.1:"+strconv.Itoa(mp)), `"alive":true`) {
			return true
		}
		timeSleep(500)
	}
	return false
}

var timeSleep = func(ms int) {}

// atKeyFile and atTok: the key file and token the auto-test probes dial with.
var (
	atKeyFile string
	atTok     Token
)

// p1Speedtest: one direction of a probe client's built-in speed test; the live
// form is speedtestLive (sysd.go wiring), the var default keeps tests inert.
var p1Speedtest = func(mp int, dir string) (ok bool, mbps float64) { return false, 0 }

// at_measure — speed test on a running client (down then up).
func atMeasure(i, mp int) {
	ar[i] = result{}
	if ok, mb := p1Speedtest(mp, "down"); ok {
		ar[i].Down = mb
		if ok, mb := p1Speedtest(mp, "up"); ok {
			ar[i].Up = mb
			ar[i].RTT = statsRTTOf(mp)
			ar[i].OK = true
		}
	}
	if !ar[i].OK {
		ar[i].Why = "speed test failed/stalled"
	}
	if atAct != "" {
		ar[i].OK = false
		ar[i].Why = "skipped"
	}
}

func statsRTTOf(mp int) float64 {
	s := p1FetchStats("127.0.0.1:" + strconv.Itoa(mp))
	if v := Jget("{"+s, "rtt_ms"); v != "" {
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

// at_failed — indices of variants that failed the test; ok=false when none did.
func atFailed() ([]int, bool) {
	var f []int
	for i := range av {
		if !ar[i].OK {
			f = append(f, i)
		}
	}
	return f, len(f) > 0
}

// at_none — nothing worked.
func atNone() {
	Err(fmt.Sprintf("No carrier reached %s", orNone(atAddr)))
	if atTunnel != "" {
		if s, err := statsOf(atTunnel); err == nil && get(s, "alive") == "true" {
			// the live tunnel works, so the route and the key are fine: Kharej's test listeners are not where
			// Iran's saved plan says (a token rebuilt on Kharej moves them) — the field case of 2026-11-15/22
			Warn("Your running tunnel works, but none of Kharej's test carriers answered on the ports this server saved.")
			Hint(" · Kharej's test ports most likely changed. On Kharej: " + P.Self + ", open the tunnel, t (token); paste it here with t, then test again")
		}
	}
	// nothing direct linked, so Kharej may never have learned this server's IP for its reverse companion
	Hint(" · Reverse didn't start? On Kharej run:  " + P.Self + " auto-ip <kharej tunnel name> " + orStr(envPublicIP(), "<this server's IP>"))
	Hint(" · Check that the Kharej tunnel runs, that the token is current, and Kharej's cloud firewall")
}

// at_preset_ask — normal | fast | anti | reverse | CDN domain. Non-interactive path takes NI_TEST.
// Time estimates per preset (one table, see atEst* above): rows x ~20 s, rounded to a range.
func atPresetAsk(nonInteractive bool, niTest string) (string, error) {
	if nonInteractive {
		if niTest != "" {
			return niTest, nil
		}
		return "normal", nil
	}
	// Interactive box (Test mode): [Enter] Standard / [f] Anti-censor fast / [a] + Anti-censor / [x] + Extended /
	// [r] Reverse only / [d] domain / [q] Cancel.
	domLbl := avTok.SNI
	if domLbl == "" {
		domLbl = "none (optional)"
	}
	for t := 0; t < 6; t++ {
		Hint(fmt.Sprintf("Kharej %s · any port", atAddr))
		Box(Stdout, "Test mode",
			keyLabel("Enter")+"  Standard carriers     "+GRY+"Direct, CDN, Reverse        "+atEstNormal+RST,
			keyLabel("f")+"      Anti-censor fast      "+GRY+"rst/synrst x 3 SNIs,       "+atEstFast+RST,
			"                               "+GRY+"best row applied"+RST,
			keyLabel("a")+"      + Anti-censor         "+GRY+"full grid, fake-SNI, fp   "+atEstAnti+RST,
			keyLabel("x")+"      + Extended            "+GRY+"13 shaped carriers         "+atEstExt+RST,
			keyLabel("r")+"      Reverse only          "+GRY+"just the r= plan carriers "+atEstReverse+RST,
			keyLabel("d")+"      Cloudflare domain     "+GRY+domLbl+RST,
			keyLabel("q")+"      Cancel")
		k, _, _ := KeyRead(0)
		switch k {
		case "enter":
			return "normal", nil
		case "f", "F":
			return "fast", nil
		case "a", "A":
			return "anti", nil
		case "x", "X":
			if autoPlanExtNames(planPart(avTok.Auto, "d")) == "" {
				Warn("This token has no extended carriers: Kharej made it before 3.6.0 or cannot run them. Update Kharej, show its token (t) and paste it here.")
				continue
			}
			return "extended", nil
		case "r", "R":
			return "reverse", nil
		case "d", "D":
			Hint("Domain proxied to Kharej via Cloudflare (orange cloud, SSL Full).")
			avTok.SNI = Ask("Cloudflare domain", avTok.SNI)
			domLbl = avTok.SNI
			if domLbl == "" {
				domLbl = "none (optional)"
			}
		case "q", "Q", "esc":
			return "", fmt.Errorf("cancelled")
		}
	}
	return "", fmt.Errorf("cancelled")
}

// auto_iran_front — token: test everything, ranked table, choose.
func autoIranFront(tok Token) (atChoice, error) {
	var c atChoice
	if tok.Auto == "" {
		return c, fmt.Errorf("This auto token has no test plan. Make a new token on Kharej (wattun 2.1.0 or newer).")
	}
	preset, err := atPresetAsk(NonInteractive, NI.Test)
	if err != nil {
		return c, fmt.Errorf("Cancelled.")
	}
	atPreset = preset
	atQuiet = false
	atMB = 8
	atSkip = ""
	autoTest(tok)
	rank := autoRefine(atRank(av, ar, ""))
	if len(rank) == 0 {
		atNone()
		return c, fmt.Errorf("no carrier worked")
	}
	atTable(Stdout, av, ar, rank, atMB, atSecs)
	sel, err := atChoose(rank, NonInteractive, NI.Pick)
	if err != nil {
		return c, fmt.Errorf("Cancelled.")
	}
	ch, err := atToT(sel)
	if err != nil {
		return c, err
	}
	Ok("Selected: " + ch.Label)
	if NonInteractive {
		fmt.Fprintf(Stdout, "ATPICK=%s\n", ch.Label)
	}
	tune, _, _ := atTune(sel)
	atTuneExtra(&ch, tune)
	return ch, nil
}

// auto_refine — re-measure the top 3 with 16 streams and a sustained run, re-rank.
func autoRefine(rank []int) []int {
	if len(rank) == 0 {
		return rank
	}
	top := rank
	if len(top) > 3 {
		top = top[:3]
	}
	saved, savedStreams := atMB, atStreams
	atStreams = 16
	for _, i := range top {
		rate := maxF(ar[i].Down, ar[i].Up)
		mb := atProbeMB(rate, 1.5, atFinalMBMax)
		if mb < atFinalMBMin {
			mb = atFinalMBMin
		}
		atMB = mb
		atProbe(i, 8)
		atEmit(i)
	}
	atMB, atStreams = saved, savedStreams
	return atRank(av, ar, "")
}

// at_choose — pick from the table. Non-interactive: --pick best|bond|rbond|N|N,N.
func atChoose(rank []int, nonInteractive bool, niPick string) ([]int, error) {
	best := rank[0]
	var bond, rbond []int
	for _, i := range rank {
		if strings.Contains(av[i].Car, "+") || isShapedRaw(av[i].Car) || isShapedUDP(av[i].Car) {
			continue
		}
		if av[i].Kind == "d" && !avAnti(av[i]) {
			bond = append(bond, i)
		} else if av[i].Kind == "r" {
			rbond = append(rbond, i)
		}
	}
	if nonInteractive {
		pick := niPick
		if pick == "" {
			pick = "best"
		}
		switch {
		case pick == "best":
			return []int{best}, nil
		case pick == "bond":
			if len(bond) >= 2 {
				return bond, nil
			}
			if len(rbond) >= 2 {
				return rbond, nil
			}
			return []int{best}, nil
		case pick == "rbond":
			if len(rbond) >= 2 {
				return rbond, nil
			}
			return []int{best}, nil
		case strings.ContainsAny(pick, ",+"):
			return atRows(rank, pick)
		default:
			n, err := strconv.Atoi(pick)
			if err != nil || n < 1 || n > len(rank) {
				return nil, fmt.Errorf("--pick must be best, bond, a row number of the table, or several joined with commas or + (1,3)")
			}
			return []int{rank[n-1]}, nil
		}
	}
	jd, jr := atJoinableSummary(rank)
	canJoin := len(jd) >= 2 || len(jr) >= 2
	fmt.Fprintln(Stdout)
	fmt.Fprintf(Stdout, "  %s  Use #1 %s(%s · %.1f / %.1f MB/s)%s\n", keyLabel("Enter"), GRY, av[best].Label, ar[best].Down, ar[best].Up, RST)
	if len(bond) >= 2 {
		fmt.Fprintf(Stdout, "  %s      Bond all %d direct carriers %s(failover + aggregate)%s\n", keyLabel("b"), len(bond), GRY, RST)
	} else if len(rbond) >= 2 {
		fmt.Fprintf(Stdout, "  %s      Bond all %d reverse carriers %s(failover + aggregate)%s\n", keyLabel("b"), len(rbond), GRY, RST)
	}
	var opts []string
	if len(rank) > 1 {
		opts = append(opts, fmt.Sprintf("1-%d", len(rank)), "pick row")
		if canJoin {
			opts = append(opts, "c", "custom join")
		}
	}
	if _, any := atFailed(); any {
		opts = append(opts, "f", "force failed")
	}
	menuLine(Stdout, append(opts, "q", "cancel")...)
	for {
		k, _, ok := KeyRead(0)
		if !ok { // EOF: the loop would spin on "" forever
			return nil, fmt.Errorf("cancelled")
		}
		switch k {
		case "enter":
			return []int{best}, nil
		case "b", "B":
			if len(bond) >= 2 {
				return bond, nil
			}
			if len(rbond) >= 2 {
				return rbond, nil
			}
			Warn("Bonding needs two or more working direct or reverse carriers.")
		case "c", "C": // custom join (bash at_custom): rows of one kind, each carrier once
			if !canJoin {
				Warn("Joining needs at least two compatible direct rows or two reverse rows.")
				continue
			}
			var hs []string
			if len(jd) >= 2 {
				hs = append(hs, "Direct: "+intsJoin(jd))
			}
			if len(jr) >= 2 {
				hs = append(hs, "Reverse: "+intsJoin(jr))
			}
			Hint(strings.Join(hs, "  ·  ") + " (cannot mix)")
			v := Ask("Join rows (e.g. 1+3, Enter = cancel)", "")
			if v == "" {
				continue
			}
			sel, err := atRows(rank, v)
			if err != nil {
				Warn(err.Error())
				continue
			}
			return sel, nil
		case "f", "F":
			f, any := atFailed()
			if !any {
				Warn("Every type passed.")
				continue
			}
			Warn("Failed variants (may not connect until route opens):")
			for j, i := range f {
				Hint(fmt.Sprintf("    %d %-24s %s", j+1, atLbl(av[i].Label, 24), ar[i].Why))
			}
			v := Ask("Number (Enter = cancel)", "")
			n, err := strconv.Atoi(v)
			if v == "" || err != nil || n < 1 || n > len(f) {
				Warn("No number " + v + ".")
				continue
			}
			return []int{f[n-1]}, nil
		case "1", "2", "3", "4", "5", "6", "7", "8", "9":
			if len(rank) > 9 { // two-digit rows: finish the number on a line
				k = Ask("Row", k)
			}
			n, _ := strconv.Atoi(k)
			if n >= 1 && n <= len(rank) {
				return []int{rank[n-1]}, nil
			}
			Warn("No row " + k + ".")
		case "q", "Q", "esc":
			return nil, fmt.Errorf("cancelled")
		default:
			Warn("Press Enter, b, c, f, a row number or q.")
		}
	}
}

func intsJoin(v []int) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, " ")
}

// at_skip_reverse_keys — space-padded AT_SKIP of active reverse leg keys.
func atSkipReverseKeys(name string) string {
	if !IsReverse(name) {
		return ""
	}
	out := " "
	for _, c := range strings.Split(Cfg(name, "carrier"), "+") {
		if c != "" {
			out += c + "/r "
		}
	}
	return out
}

// auto_apply — write the chosen variant into NAME.yml, restart, wait for the link.
func autoApply(name string, ch atChoice, tuneKeys []string) error {
	for _, c := range strings.Split(ch.Carrier, "+") {
		if !carrierOkHere(c) {
			return fmt.Errorf("Carrier '%s' needs wattun %s on this server; not writing it into '%s'.", c, carrierMinVer(c), name)
		}
	}
	f := filepath.Join(P.Conf, name+".yml")
	bak := f + ".bak"
	if b, err := os.ReadFile(f); err != nil {
		return fmt.Errorf("Could not back up %s; not applying.", f)
	} else if err := os.WriteFile(bak, b, 0o600); err != nil {
		return fmt.Errorf("Could not back up %s; not applying.", f)
	}
	// strip the variant keys, then write the new ones
	drop := map[string]bool{"carrier": true, "peer": true, "path": true, "sni": true,
		"host": true, "reverse": true, "listen": true, "fp": true, "ech": true,
		"ech-cache": true, "tls-frag": true, "udp-hop": true}
	var out []string
	for _, l := range strings.Split(mustRead(f), "\n") {
		k := yamlKey(l)
		if drop[k] || strings.HasPrefix(k, "peer-") || strings.HasPrefix(k, "listen-") {
			continue
		}
		out = append(out, l)
	}
	_ = writeFile0600(f, strings.Join(out, "\n")+"\n")
	_ = SetValue(name, "carrier", ch.Carrier)
	if IsPoolList(ch.Carrier) {
		// a working fake-SNI/pool-rotate combination survives a type switch only while the
		// new carrier set has a pool leg and this side is the dialer
		keep := false
		if ch.Rev == "1" {
			keep = Role(name) == "Kharej"
		} else {
			keep = Role(name) == "Iran"
		}
		if !keep {
			var o2 []string
			for _, l := range strings.Split(mustRead(f), "\n") {
				k := yamlKey(l)
				if k == "fake-sni" || k == "fake-mode" || k == "fake-ttl" || k == "pool-rotate" || k == "pool-rotate-bytes" {
					continue
				}
				o2 = append(o2, l)
			}
			_ = writeFile0600(f, strings.Join(o2, "\n"))
		}
	}
	_ = SetValue(name, "peer", ch.Peer)
	if ch.Path != "" {
		_ = SetValue(name, "path", ch.Path)
	}
	if ch.SNI != "" {
		_ = SetValue(name, "sni", ch.SNI)
		_ = SetValue(name, "host", ch.SNI)
	}
	if ch.Rev == "1" {
		_ = SetValue(name, "reverse", "true")
		if !strings.Contains(ch.Carrier, "+") && isRpool(ch.Carrier) {
			if rport := portOf(ch.Peer); rport != "" {
				_ = SetValue(name, "listen", "\""+rport+"\"")
			}
		}
	}
	for _, l := range strings.Split(ch.Extra, "\n") {
		if l == "" {
			continue
		}
		k, v, _ := strings.Cut(l, ": ")
		_ = SetValue(name, k, v)
	}
	for _, k := range tuneKeys {
		_ = UnsetValue(name, k)
	}
	_ = Restart(Unit(name))
	// AT_QUIET=1 applies without waiting unless AT_VERIFY=1 (auto_retest verifies and rolls back).
	if atQuiet && !atVerify {
		os.Remove(bak)
		return nil
	}
	if linkAlive(name) {
		Ok(fmt.Sprintf("CONNECTED — %s", ch.Label))
		os.Remove(bak)
		return nil
	}
	Warn("Not connected yet; restoring the previous config.")
	if b, err := os.ReadFile(bak); err == nil {
		_ = os.WriteFile(f, b, 0o600)
		os.Remove(bak)
		_ = Restart(Unit(name))
		if atVerify {
			return fmt.Errorf("link check failed")
		}
		return nil
	}
	return fmt.Errorf("Could not restore %s; the backup is kept at %s", f, bak)
}

func linkAlive(name string) bool {
	return strings.Contains(StatsRaw(name), `"alive": true`)
}

// at_tune — try the settings that actually moved speed in the field, one setting at a
// time, each value against the best so far. A value is kept only when it beats that by
// 10 % (one run is noisy). Probes are fixed at AT_TUNE_PROBE_MB each way (D8).
func atTune(sel []int) (tune string, keys []string, mb int) {
	tune, keys, mb = "", nil, 0
	if len(sel) == 0 {
		return
	}
	var kind string
	target := sel[0]
	if len(sel) == 1 {
		if av[target].Kind == "r" {
			kind = "reverse"
		} else {
			kind = av[target].Car
		}
	} else if av[sel[0]].Kind == "r" {
		kind = "reverse"
	} else {
		kind = "bond"
	}
	knobs := atTuneKnobs(kind, av[target].Car)
	if knobs == "" {
		return
	}
	// AT_SKIP only skips the live variant during screening; tuning must measure that very
	// variant as its baseline.
	savedSkip, savedMB := atSkip, atMB
	atSkip, atMB = "", atTuneProbeMB
	atProbe(target, 8)
	mb += 2 * atMB
	if !ar[target].OK { // no baseline, no comparison: keep engine auto values
		Warn("Baseline did not come up — keeping engine auto values")
		atSkip, atMB = savedSkip, savedMB
		return
	}
	best := atScore(target)
	var extra []string
	for _, kv := range strings.Fields(knobs) {
		k := strings.SplitN(kv, ":", 2)[0]
		keys = append(keys, k)
		kept := ""
		for _, v := range strings.Split(strings.SplitN(kv, ":", 2)[1], ",") {
			// one synthetic probe variant per value, cloned from the target
			avAdd(k+" "+v, av[target].Car, av[target].Kind, av[target].Peer, av[target].Port,
				av[target].SNI, av[target].FP, av[target].ECH, av[target].Frag, av[target].FS, av[target].FM,
				strings.Join(append(append([]string{}, extra...), "-"+k+"="+v), " "))
			i := len(av) - 1
			atProbe(i, 8)
			mb += 2 * atMB
			if ar[i].OK && atScore(i) > best*1.1 {
				best = atScore(i)
				kept = v
			}
		}
		if kept != "" {
			extra = append(extra, "-"+k+"="+kept)
			tune += k + ": " + kept + "\n"
		}
	}
	tune = strings.TrimSuffix(tune, "\n")
	atSkip, atMB = savedSkip, savedMB
	if tune != "" {
		Ok("Tuned: " + strings.ReplaceAll(tune, "\n", ", ") + fmt.Sprintf("  (%d MB)", mb))
	} else {
		Ok(fmt.Sprintf("Engine auto values are fastest  (%d MB)", mb))
	}
	return
}

// at_tune_extra — after atToT the tuned lines go into the config with the rest.
func atTuneExtra(ch *atChoice, tune string) {
	if tune != "" {
		ch.Extra = joinNonEmpty(ch.Extra, "\n", tune)
	}
}

// auto_test_cmd — re-run the test for an existing auto Iran tunnel, offer to switch.
func autoTestCmd(name string) error {
	if Role(name) != "Iran" || !fileExists(filepath.Join(P.Conf, name+".auto")) {
		return fmt.Errorf("'%s' is not an auto Iran tunnel (it has no %s.auto). Create it with the token from an auto Kharej tunnel.", name, name)
	}
	tok, err := readAutoTok(name)
	if err != nil || tok.Auto == "" {
		return fmt.Errorf("%s.auto is not a valid auto token.", filepath.Join(P.Conf, name+".auto"))
	}
	atTunnel = name
	atSkip = atSkipReverseKeys(name)
	atQuiet = false
	atMB = 8
	Hint("Current: " + autoCurrentKey(name) + " · live tunnel untouched")
	if NonInteractive { // the panel and scripts: which tunnel the result rows belong to
		fmt.Fprintf(Stdout, "TUNNEL=%s\n", name)
	}
	preset, perr := atPresetAsk(NonInteractive, NI.Test)
	if perr != nil {
		Warn("Cancelled.")
		return nil
	}
	atPreset = preset
	autoTest(tok)
	atProbeLiveTunnel(name, 8)
	rank := autoRefine(atRank(av, ar, ""))
	if len(rank) == 0 {
		atNone()
		return fmt.Errorf("no carrier worked")
	}
	atTable(Stdout, av, ar, rank, atMB, atSecs)
	sel, cerr := atChoose(rank, NonInteractive, NI.Pick)
	if cerr != nil {
		Warn("No change.")
		return nil
	}
	if NonInteractive {
		for _, i := range sel {
			fmt.Fprintf(Stdout, "ATPICK=%s\n", av[i].Label)
		}
	}
	ch, terr := atToT(sel)
	if terr != nil {
		return terr
	}
	if !Confirm(fmt.Sprintf("Switch '%s' to %s? (open connections drop)", name, ch.Label), true) {
		Warn("No change.")
		return nil
	}
	tune, tuneKeys, _ := atTune(sel)
	atTuneExtra(&ch, tune)
	return autoApply(name, ch, tuneKeys)
}

// autoUse applies tested variants by their result labels ("tcp :443", or several joined with "," for a bond)
// without testing again: the variants come from the tunnel's auto plan, so the panel can switch to a row of a
// finished test. No tuning pass; the engine's auto values apply.
func autoUse(name, labels string) error {
	if Role(name) != "Iran" || !fileExists(filepath.Join(P.Conf, name+".auto")) {
		return fmt.Errorf("'%s' is not an auto Iran tunnel.", name)
	}
	tok, err := readAutoTok(name)
	if err != nil || tok.Auto == "" {
		return fmt.Errorf("%s.auto is not a valid auto token.", filepath.Join(P.Conf, name+".auto"))
	}
	want := strings.Split(labels, ",")
	atTunnel = name
	// the labels may come from any test preset; the first preset that has them all wins
	for _, pr := range []string{"normal", "extended", "anti", "fast", "reverse"} {
		atPreset = pr
		autoVariants(tok)
		var sel []int
		for _, w := range want {
			for i := range av {
				if av[i].Label == strings.TrimSpace(w) {
					sel = append(sel, i)
					break
				}
			}
		}
		if len(sel) != len(want) {
			continue
		}
		ch, terr := atToT(sel)
		if terr != nil {
			return terr
		}
		Ok("Switching " + name + " to " + ch.Label)
		return autoApply(name, ch, nil)
	}
	return fmt.Errorf("'%s' is not a variant of this tunnel's auto plan.", labels)
}

// auto_retest — unattended (auto-heal or auto-optimize): same duration-based screening;
// switch only when the current variant no longer works (no flapping), unless optimize
// or an SLA breach triggered it. 3.3.8+ lifecycle: no auto-narrow/prune.
func autoRetest(name string) error {
	if !fileExists(filepath.Join(P.Conf, name+".auto")) {
		if cdnTunnelP(name) { // not an auto tunnel: a plain CDN tunnel only gets a fresh edge scan
			cdnRefreshEdges(name)
			return nil
		}
		return fmt.Errorf("not an auto tunnel")
	}
	tok, err := readAutoTok(name)
	if err != nil || tok.Auto == "" {
		return fmt.Errorf("not an auto tunnel")
	}
	atTunnel = name
	atQuiet = true
	atMB = 1
	atSkip = atSkipReverseKeys(name)
	atPreset = "normal"
	autoTest(tok)
	atProbeLiveTunnel(name, atScreenMBStart)
	rank := atRank(av, ar, "")
	if len(rank) == 0 {
		envLogger("wattun-heal", "retest of "+name+": no connection type works right now")
		return nil
	}
	cur := autoCurrentKey(name)
	winner := rank[0]
	if NonInteractive {
		fmt.Fprintf(Stdout, "ATPICK=%s\n", av[winner].Label)
	}
	if avKey(av[winner]) == cur {
		envLogger("wattun-heal", "retest of "+name+": current variant "+cur+" is already the top-ranked carrier, no switch")
		os.Remove(filepath.Join(P.Run, name+".sla_triggered"))
		if cur == Cfg(name, "carrier")+"/c" { // same carrier through the CDN: replace dead edge IPs
			cdnRefreshEdges(name)
		}
		return nil
	}
	// If off-peak optimization or SLA breach triggered this, always upgrade to the winner!
	// Otherwise (connection recovery), if the current variant still works, avoid flapping.
	if os.Getenv("AUTO_OPTIMIZE") != "1" && !fileExists(filepath.Join(P.Run, name+".sla_triggered")) {
		for _, best := range rank {
			if avKey(av[best]) == cur {
				envLogger("wattun-heal", "retest of "+name+": current variant "+cur+" still works, no switch")
				if cur == Cfg(name, "carrier")+"/c" {
					cdnRefreshEdges(name)
				}
				return nil
			}
		}
	}
	pol := strings.TrimSpace(mustRead(filepath.Join(P.Conf, name+".policy")))
	sel := []int{winner}
	if pol == "bond" {
		var bondC, rbondC []int
		for _, i := range rank {
			if strings.Contains(av[i].Car, "+") || isShapedRaw(av[i].Car) || isShapedUDP(av[i].Car) {
				continue // B4: shaped carriers never join a bond
			}
			if av[i].Kind == "d" && !avAnti(av[i]) {
				bondC = append(bondC, i)
			} else if av[i].Kind == "r" {
				rbondC = append(rbondC, i)
			}
		}
		if len(bondC) >= 2 {
			sel = bondC
		} else if len(rbondC) >= 2 {
			sel = rbondC
		}
	}
	ch, terr := atToT(sel)
	if terr != nil {
		return terr
	}
	atVerify = true
	if aerr := autoApply(name, ch, nil); aerr != nil {
		envLogger("wattun-heal", "switch of "+name+" from "+cur+" to "+ch.Key+" failed link check; restored previous config")
	} else {
		envLogger("wattun-heal", "switched "+name+" from "+cur+" to "+ch.Key)
	}
	os.Remove(filepath.Join(P.Run, name+".sla_triggered"))
	return nil
}

// =====================================================================================
// Auto menu (tunnel page)
// =====================================================================================

// autoMenu — the Auto mode screen (policy / SLA / daily retest / retest now).
func autoMenu(name string) {
	isAuto := false
	if tok, err := readAutoTok(name); err == nil && tok.Auto != "" {
		isAuto = true
	}
	for {
		cur := autoCurrentKey(name)
		pol := strings.TrimSpace(mustRead(filepath.Join(P.Conf, name+".policy")))
		if pol == "" {
			pol = "speed"
		}
		if !isAuto {
			Hint("Fixed-type token: policy and retest need a new token (tunnel page, t).")
		}
		Say(fmt.Sprintf("      %-13s %s", "in use", orNone(cur)))
		SetRow("p", "policy", pol, "", "")
		SetRow("s", "heal when", "", "", "the link is down")
		SetRow("o", "daily retest", "", "", "off")
		k, _, _ := KeyRead(0)
		switch k {
		case "p":
			if !isAuto {
				Warn("The selection policy is read only by auto tunnels; this one was made with a fixed type.")
				Hint("For an auto tunnel: make one on Kharej, paste its token here (t), run auto-test.")
				Pause()
				continue
			}
			Say("  Choose carrier selection policy:")
			Say("    1 speed    (rank by Down+Up throughput, lowest RTT tiebreak)")
			Say("    2 latency  (rank by lowest round-trip latency)")
			Say("    3 direct   (prioritize direct unproxied paths over CDN)")
			Say("    4 bond     (automatically bond top direct performers)")
			v := Ask("Choice", "1")
			var p string
			switch v {
			case "1", "speed":
				p = "speed"
			case "2", "latency":
				p = "latency"
			case "3", "direct":
				p = "direct"
			case "4", "bond":
				p = "bond"
			default:
				Warn("Unknown policy '" + v + "'.")
				continue
			}
			os.WriteFile(filepath.Join(P.Conf, name+".policy"), []byte(p+"\n"), 0o600)
			Ok("Policy saved: " + p)
			Pause()
		case "s":
			min := Ask("Minimum required throughput in kbps (0 = none)", "0")
			rtt := Ask("Maximum tolerable RTT in ms (0 = none, e.g. 300)", "0")
			loss := Ask("Maximum tolerable packet loss % (0 = none, e.g. 10)", "0")
			os.WriteFile(filepath.Join(P.Conf, name+".sla"), []byte(
				"sla_min_rate_kbps="+min+"\nsla_max_rtt_ms="+rtt+"\nsla_max_loss_pct="+loss+"\n"), 0o600)
			Ok("SLA configured.")
			Pause()
		case "r":
			if !isAuto {
				Hint("Nothing to re-rank: this tunnel was made with a fixed type. To switch types, make a new tunnel or use an auto token.")
				Pause()
				continue
			}
			Say("  Running auto-test & policy re-evaluation...")
			_ = autoRetest(name)
			Pause()
		case "o":
			_ = Systemctl("is-active", P.Prefix+"-auto-optimize.timer") // toggled via the optimize timer (P1 timers)
		case "b", "0", "q", "enter", "esc":
			return
		}
	}
}

// p1FetchStats adapter: P4 uses the raw string fetch (grep-style access).
var p1FetchStats = func(addr string) string {
	raw, _ := FetchStatsRaw(addr)
	return raw
}

// probeArgs: the per-variant TLS / desync / tuning flags of a throw-away client (bash at_start).
func probeArgs(v variant) []string {
	var a []string
	if v.SNI != "" {
		a = append(a, "-sni", v.SNI, "-host", v.SNI)
	}
	if v.FP != "" {
		a = append(a, "-fp", v.FP)
	}
	if v.ECH != "" {
		a = append(a, "-ech", v.ECH)
	}
	if v.Frag != "" && v.Frag != "0" {
		a = append(a, "-tls-frag", v.Frag)
	}
	if v.FS != "" {
		a = append(a, "-fake-sni", v.FS)
		if v.FM != "" {
			a = append(a, "-fake-mode", v.FM)
		}
	}
	return append(a, strings.Fields(v.X)...) // auto tuning: -key=value words
}

// atProbeLiveTunnel measures a running reverse tunnel through its own /speedtest, since its
// port was skipped in the screening (bash at_probe_live_tunnel). Without it the current
// variant never ranks and every retest switches away from it.
func atProbeLiveTunnel(n string, mb int) {
	if !IsReverse(n) {
		return
	}
	_, mp := SplitHP(Cfg(n, "metrics"))
	if !isDigits(mp) {
		return
	}
	if s, err := statsOf(n); err != nil || get(s, "alive") != "true" {
		return
	}
	cur, idx := autoCurrentKey(n), -1
	if cur == "bond/r" {
		avAdd("reverse bond "+Cfg(n, "carrier")+" (current)", Cfg(n, "carrier"), "r", atAddr, "", "", "", "", "", "", "", "")
		idx = len(av) - 1
	} else {
		for i := range av {
			if avKey(av[i]) == cur {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		return
	}
	save := atMB
	atMB = mb
	atMeasure(idx, atoi(mp))
	atMB = save
	if !atQuiet {
		atPrint(Stdout, idx, av, ar, atMB)
	}
}
