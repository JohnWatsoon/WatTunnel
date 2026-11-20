package mgr

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Paths mirrors the bash startup block (wattun-manager L24-82): WAT_PREFIX moves
// every path and unit name; WAT_CONF/WAT_BIN/WAT_RUN override single paths.
type Paths struct {
	Prefix  string // WAT_PREFIX (default wattun)
	Sandbox bool   // WAT_PREFIX != wattun
	Conf    string // /etc/$PREFIX or $WAT_CONF
	Run     string // /run/$PREFIX or $WAT_RUN
	Bin     string // /usr/local/bin/wattun, /opt/$PREFIX/wattun in a sandbox, or $WAT_BIN
	Mgr     string // this manager's own path ($0 in a sandbox)
	Self    string // the command a user types to start the manager
	MConf   string // $CONF/.manager.conf
	Heal    string // $PREFIX-heal
}

// P is the process-wide path set, filled by InitPaths.
var P Paths

// InitPaths computes P from the environment; the bash validates WAT_PREFIX the
// same way and refuses a sandbox that shares a production path.
func InitPaths() error {
	P = Paths{}
	P.Prefix = envOr("WAT_PREFIX", "wattun")
	if !prefixOK(P.Prefix) {
		return fmt.Errorf("WAT_PREFIX must be letters, digits, \"_\" or \".\" and may contain \"-\" inside (got %q).", P.Prefix)
	}
	P.Sandbox = P.Prefix != "wattun"
	P.Conf = envOr("WAT_CONF", "/etc/"+P.Prefix)
	P.Run = envOr("WAT_RUN", "/run/"+P.Prefix)
	if P.Sandbox {
		P.Bin = envOr("WAT_BIN", "/opt/"+P.Prefix+"/wattun")
		P.Mgr = selfPath()
		if P.Conf == "/etc/wattun" || P.Bin == "/usr/local/bin/wattun" || P.Run == "/run/wattun" {
			return fmt.Errorf("Sandbox %s refuses to use a production path (CONF=%s BIN=%s RUN=%s MGR=%s).",
				P.Prefix, P.Conf, P.Bin, P.Run, P.Mgr)
		}
	} else {
		P.Bin = envOr("WAT_BIN", "/usr/local/bin/wattun")
		P.Mgr = "/usr/local/bin/wattun-manager"
	}
	P.MConf = P.Conf + "/.manager.conf"
	P.Heal = P.Prefix + "-heal"
	if P.Sandbox {
		P.Self = "WAT_PREFIX=" + P.Prefix + " " + P.Mgr
	} else {
		P.Self = "wattun"
	}
	if os.Getenv("WAT_GO_MGR") == "1" { // without it, the command we print opens the bash manager
		P.Self = "WAT_GO_MGR=1 " + P.Self
	}
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func prefixOK(p string) bool {
	if p == "" || strings.HasPrefix(p, "-") || strings.HasSuffix(p, "-") {
		return false
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') && c != '-' {
			return false
		}
	}
	return true
}

func selfPath() string {
	if p, err := filepath.Abs(os.Args[0]); err == nil {
		return p
	}
	return os.Args[0]
}

// ConfGet reads a key from .manager.conf (last wins, like the bash tail -1).
func ConfGet(key, def string) string {
	data, err := os.ReadFile(P.MConf)
	if err != nil {
		return def
	}
	val := ""
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			val = v
		}
	}
	if val == "" {
		return def
	}
	return val
}

// ConfSet writes a key to .manager.conf (delete the old line, append; 0600).
func ConfSet(key, val string) error {
	if err := os.MkdirAll(P.Conf, 0o755); err != nil {
		return err
	}
	data, _ := os.ReadFile(P.MConf)
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, key+"=") {
			continue
		}
		out = append(out, line)
	}
	out = append(out, key+"="+val)
	return atomicWrite(P.MConf, []byte(strings.Join(out, "\n")+"\n"), 0o600)
}

// Cfg mirrors cfg(): first "key: value" line of NAME.yml, quotes stripped.
func Cfg(name, key string) string {
	data, err := os.ReadFile(filepath.Join(P.Conf, name+".yml"))
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `:[ \t]*`)
	for _, line := range strings.Split(string(data), "\n") {
		loc := re.FindStringIndex(line)
		if loc == nil {
			continue
		}
		v := strings.TrimSpace(line[loc[1]:])
		if i := strings.Index(v, " #"); i >= 0 { // trailing comment, like sed leaving the raw value then the engine trimming — engine trims at '#'
			v = strings.TrimSpace(v[:i])
		}
		return strings.Trim(v, `"'`)
	}
	return ""
}

// Role mirrors role(): "Kharej" for a server config, "Iran" otherwise.
func Role(name string) string {
	if Cfg(name, "mode") == "server" {
		return "Kharej"
	}
	return "Iran"
}

// IsReverse mirrors is_reverse().
func IsReverse(name string) bool { return Cfg(name, "reverse") == "true" }

// ---- tunnel discovery ----

// IsAutoHelper mirrors is_auto_helper(): hidden per-shape listeners (-e-*) and
// reverse companions (-r) stay invisible in the dashboard lists.
func IsAutoHelper(name string) bool {
	if _, err := os.Stat(filepath.Join(P.Conf, name+".autoext")); err == nil {
		return true
	}
	return CompanionOf(name) != ""
}

// CompanionOf mirrors companion_of(): parent name when NAME is an auto reverse
// companion (NAME-r), "" otherwise.
func CompanionOf(name string) string {
	p := strings.TrimSuffix(name, "-r")
	if p != name && fileExists(filepath.Join(P.Conf, p+".yml")) && IsAutoKharej(p) {
		return p
	}
	return ""
}

// IsAutoKharej mirrors is_auto_kharej(): does NAME.token carry carrier "auto"?
func IsAutoKharej(name string) bool {
	raw, err := os.ReadFile(filepath.Join(P.Conf, name+".token"))
	if err != nil {
		return false
	}
	tok, err := ReadToken(string(raw))
	if err != nil {
		return false
	}
	return tok.Carrier == "auto"
}

// Tunnels mirrors tunnels(): every visible tunnel, sorted by filename.
func Tunnels() []string {
	var out []string
	entries, err := os.ReadDir(P.Conf)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		b := strings.TrimSuffix(e.Name(), ".yml")
		if b == e.Name() || IsAutoHelper(b) {
			continue
		}
		out = append(out, b)
	}
	sort.Strings(out)
	return out
}

// TunnelsAll mirrors tunnels_all(): every config, hidden helpers included.
func TunnelsAll() []string {
	var out []string
	entries, err := os.ReadDir(P.Conf)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if b := strings.TrimSuffix(e.Name(), ".yml"); b != e.Name() {
			out = append(out, b)
		}
	}
	sort.Strings(out)
	return out
}

// NeedTunnel mirrors need_tunnel().
func NeedTunnel(name string) bool {
	if !fileExists(filepath.Join(P.Conf, name+".yml")) {
		Err(fmt.Sprintf("No tunnel named '%s'. See: %s status", name, P.Self))
		return false
	}
	return true
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ---- atomic writes (bash: mktemp in the same dir + chmod + mv -f) ----

// atomicWrite writes data to a temp file in the same directory and renames it
// over path: the 3 s hot-reloader must never see an interleaved rewrite.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// SetValue mirrors set_value(): set or add a top-level key. Like the bash awk,
// the new "key: value" line goes right before the first metrics:/ports: line
// (or at the end), and any old "key:" line is dropped.
func SetValue(name, key, val string) error {
	f := filepath.Join(P.Conf, name+".yml")
	data, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	var out []string
	inserted := false
	newLine := key + ": " + val
	for _, line := range lines {
		if strings.HasPrefix(line, key+":") {
			continue
		}
		if !inserted && (strings.HasPrefix(line, "metrics:") || strings.HasPrefix(line, "ports:")) {
			out = append(out, newLine)
			inserted = true
		}
		out = append(out, line)
	}
	if !inserted {
		// append at the end, keeping the trailing newline shape
		for len(out) > 0 && out[len(out)-1] == "" {
			out = out[:len(out)-1]
		}
		out = append(out, newLine, "")
	}
	return atomicWrite(f, []byte(strings.Join(out, "\n")), 0o600)
}

// UnsetValue mirrors unset_value(): drop a top-level key, same tmp+mv pattern.
func UnsetValue(name, key string) error {
	f := filepath.Join(P.Conf, name+".yml")
	data, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, key+":") {
			continue
		}
		out = append(out, line)
	}
	return atomicWrite(f, []byte(strings.Join(out, "\n")), 0o600)
}

// ---- port specs (bash norm_spec/spec_*/yml_maps/maps_allow_str) ----

// NormSpec canonicalizes "8443->443/udp", "443", "53/both" into one or two
// "L:T/proto" items ("both" expands to tcp+udp). rc 1 + message on bad input.
func NormSpec(s string) ([]string, error) {
	r := strings.NewReplacer("->", ":", "→", ":", "=>", ":", "=", ":")
	s = strings.Map(func(c rune) rune {
		if c == ' ' || c == '\t' {
			return -1
		}
		return c
	}, r.Replace(s))
	if s == "" {
		return nil, fmt.Errorf("empty entry")
	}
	body, proto := s, "tcp"
	if i := strings.Index(s, "/"); i >= 0 {
		body, proto = s[:i], s[i+1:]
	}
	proto = strings.ToLower(proto)
	switch proto {
	case "tcp", "udp", "both":
	case "tcp+udp", "udp+tcp", "tcpudp", "udptcp":
		proto = "both"
	default:
		return nil, fmt.Errorf("unknown protocol '%s' (use tcp, udp or both)", proto)
	}
	if strings.Count(body, ":") > 1 {
		return nil, fmt.Errorf("'%s' has too many ':'", s)
	}
	L, T := body, body
	if i := strings.Index(body, ":"); i >= 0 {
		L, T = body[:i], body[i+1:]
	}
	if !isPortStr(L) || !isPortStr(T) {
		return nil, fmt.Errorf("'%s' is not a port", s)
	}
	ln, _ := strconv.Atoi(L)
	tn, _ := strconv.Atoi(T)
	if ln < 1 || ln > 65535 || tn < 1 || tn > 65535 {
		return nil, fmt.Errorf("'%s': ports must be 1-65535", s)
	}
	c := fmt.Sprintf("%d:%d", ln, tn)
	if proto == "both" {
		return []string{c + "/tcp", c + "/udp"}, nil
	}
	return []string{c + "/" + proto}, nil
}

func isPortStr(s string) bool {
	if len(s) < 1 || len(s) > 5 || !isDigits(s) {
		return false
	}
	return true
}

func specPart(s, which string) string {
	x := s
	if i := strings.Index(x, "/"); i >= 0 {
		x = x[:i]
	}
	switch which {
	case "L":
		if i := strings.Index(x, ":"); i >= 0 {
			return x[:i]
		}
		return x
	case "T":
		if i := strings.LastIndex(x, ":"); i >= 0 {
			return x[i+1:]
		}
		return x
	}
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return "tcp"
}

// SpecL/SpecT/SpecP mirror spec_L/spec_T/spec_P.
func SpecL(s string) string { return specPart(s, "L") }
func SpecT(s string) string { return specPart(s, "T") }
func SpecP(s string) string { return specPart(s, "P") }

// SpecYaml mirrors spec_yaml(): "443" / "8443:443" / "53/udp".
func SpecYaml(s string) string {
	L, T, p := SpecL(s), SpecT(s), SpecP(s)
	out := L
	if L != T {
		out = L + ":" + T
	}
	if p == "udp" {
		out += "/udp"
	}
	return out
}

// SpecHuman mirrors spec_human(): "443" / "8443→443" / "53/udp".
func SpecHuman(s string) string {
	L, T, p := SpecL(s), SpecT(s), SpecP(s)
	out := L
	if L != T {
		out = L + "→" + T
	}
	if p == "udp" {
		out += "/udp"
	}
	return out
}

// YmlMaps mirrors yml_maps(): canonical port items of NAME.yml, in order.
func YmlMaps(name string) []string {
	data, err := os.ReadFile(filepath.Join(P.Conf, name+".yml"))
	if err != nil {
		return nil
	}
	var out []string
	inPorts := false
	for _, line := range strings.Split(string(data), "\n") {
		if regexp.MustCompile(`^ports:`).MatchString(line) {
			inPorts = true
			continue
		}
		if !inPorts {
			continue
		}
		trimmed := strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(trimmed, "-") {
			if strings.TrimSpace(line) == "" {
				continue // blank line inside the block (bash keeps skipping)
			}
			break // first non-list, non-blank line ends the block
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if i := strings.Index(item, " #"); i >= 0 {
			item = strings.TrimSpace(item[:i])
		}
		item = strings.Trim(item, `"'`)
		if item == "" {
			continue
		}
		items, err := NormSpec(item)
		if err != nil {
			continue
		}
		out = append(out, items...)
	}
	return out
}

// MapsAllowStr mirrors maps_allow_str(): "443,53/udp" — target ports only, as
// embedded in the token, duplicates removed.
func MapsAllowStr(maps []string) string {
	var out []string
	seen := map[string]bool{}
	for _, m := range maps {
		t := SpecT(m)
		if SpecP(m) == "udp" {
			t += "/udp"
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return strings.Join(out, ",")
}

// MapsYamlBlock mirrors maps_yaml_block(): the ports: block for the items.
func MapsYamlBlock(maps []string) string {
	if len(maps) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("ports:\n")
	for _, m := range maps {
		fmt.Fprintf(&sb, "  - %s\n", SpecYaml(m))
	}
	return sb.String()
}

// WritePorts mirrors write_ports(): replace the ports: block of NAME.yml.
func WritePorts(name string, maps []string) error {
	f := filepath.Join(P.Conf, name+".yml")
	data, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	var out []string
	skip := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ports:") {
			skip = true
			continue
		}
		if skip {
			t := strings.TrimLeft(line, " \t")
			if strings.HasPrefix(t, "-") || strings.HasPrefix(t, "#") || strings.TrimSpace(line) == "" {
				continue
			}
			skip = false
		}
		out = append(out, line)
	}
	// trim trailing empties, append the new block
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	body := strings.Join(out, "\n")
	if body != "" {
		body += "\n"
	}
	if blk := MapsYamlBlock(maps); blk != "" {
		body += blk
	} else {
		body += "\n"
	}
	return atomicWrite(f, []byte(body), 0o600)
}

// ---- host:port (bash split_hp/join_hp) ----

var ipv6Re = regexp.MustCompile(`^([0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}$|^([0-9A-Fa-f]{1,4}:)*:([0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{0,4}$`)

// Ipv6OK mirrors ipv6_ok (a practical subset: runs of hex groups).
func Ipv6OK(s string) bool {
	if s == "" || !strings.Contains(s, ":") {
		return false
	}
	return ipv6Re.MatchString(s)
}

// SplitHP mirrors split_hp(): addr -> host (unbracketed) and port (empty when
// bare host / bare IPv6 / [ipv6]).
func SplitHP(addr string) (host, port string) {
	if m := regexp.MustCompile(`^\[([^\]]+)\]:(\d+)$`).FindStringSubmatch(addr); m != nil {
		return m[1], m[2]
	}
	if m := regexp.MustCompile(`^\[([^\]]+)\]$`).FindStringSubmatch(addr); m != nil {
		return m[1], ""
	}
	if Ipv6OK(addr) {
		return addr, ""
	}
	if strings.Contains(addr, ":") && strings.Count(addr, ":") == 1 {
		i := strings.Index(addr, ":")
		return addr[:i], addr[i+1:]
	}
	return addr, ""
}

// JoinHP mirrors join_hp(): host:port or [ipv6]:port, bare host without a port.
func JoinHP(host, port string) string {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if port == "" {
		return host
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// ---- carrier classification (bash is_pool..carrier_has_listen) ----

// IsPool: the pool carriers (tcp-family).
func IsPool(c string) bool {
	switch c {
	case "tcp", "tls", "ws", "wss", "h2", "h2c", "grpc":
		return true
	}
	return false
}

// IsPoolList: any bond leg is a pool carrier.
func IsPoolList(list string) bool {
	for _, c := range strings.Split(list, "+") {
		if IsPool(c) {
			return true
		}
	}
	return false
}

// HasEchList: any leg carries ECH (tls/wss/h2/grpc).
func HasEchList(list string) bool {
	for _, c := range strings.Split(list, "+") {
		switch c {
		case "tls", "wss", "h2", "grpc":
			return true
		}
	}
	return false
}

// SHAPED_RAW / SHAPED_UDP (bash L1302-1304): the F19 wattun-internal shapes,
// kept in sync with cmd/wattun/main.go and wat/udpshape.go.
const (
	shapedRawList = "sit 6to4 xfrm-ipsec etherip l2tpv3"
	shapedUDPList = "fou-gre gue-ipip vxlan geneve dnscrypt-udp ntp-direct openvpn-dco srtp-direct"
)

var shapedRaw = map[string]bool{"sit": true, "6to4": true, "xfrm-ipsec": true, "etherip": true, "l2tpv3": true}

var shapedUDP = map[string]bool{
	"fou-gre": true, "gue-ipip": true, "vxlan": true, "geneve": true,
	"dnscrypt-udp": true, "ntp-direct": true, "openvpn-dco": true, "srtp-direct": true,
}

// isShapedRaw mirrors is_shaped_raw (bash F19 raw tier).
func isShapedRaw(c string) bool { return shapedRaw[c] }

// isShapedUDP mirrors is_shaped_udp (bash F19 UDP tier).
func isShapedUDP(c string) bool { return shapedUDP[c] }

// IsShapedCarrier mirrors is_shaped_carrier.
func IsShapedCarrier(c string) bool { return isShapedRaw(c) || isShapedUDP(c) }

// isShapedList mirrors is_shaped_list: any bond leg is a shaped carrier.
func isShapedList(list string) bool {
	for _, c := range strings.Split(list, "+") {
		if IsShapedCarrier(c) {
			return true
		}
	}
	return false
}

// IsRpool mirrors is_rpool(): a carrier that carries the tunnel as a reverse
// pool (the pool carriers plus udp).
func IsRpool(c string) bool { return IsPool(c) || c == "udp" }

// CarrierLegBase mirrors carrier_leg_base: a bond leg without its :up/:down
// direction suffix (3.3.9; no suffix = carries both directions).
func CarrierLegBase(c string) string {
	if strings.HasSuffix(c, ":up") || strings.HasSuffix(c, ":down") {
		return c[:strings.LastIndex(c, ":")]
	}
	return c
}

// CarrierLegDir mirrors carrier_leg_dir: up|down|"" (bidirectional).
func CarrierLegDir(c string) string {
	switch {
	case strings.HasSuffix(c, ":up"):
		return "up"
	case strings.HasSuffix(c, ":down"):
		return "down"
	}
	return ""
}

// CarrierOK mirrors carrier_ok: a single carrier name, including the F19
// shaped tier; a bond leg's :up/:down suffix is stripped and the base checked.
func CarrierOK(c string) bool {
	switch {
	case strings.HasSuffix(c, ":up"), strings.HasSuffix(c, ":down"):
		c = c[:strings.LastIndex(c, ":")]
	}
	switch c {
	case "icmp", "udp", "tcp", "tls", "ws", "wss", "h2", "h2c", "grpc", "gre", "ipip":
		return true
	}
	return shapedRaw[c] || shapedUDP[c]
}

// VCarrierList mirrors v_carrier_list: every leg a known carrier, no
// duplicates; "auto" only alone; bond legs may carry a :up/:down direction
// suffix (3.3.9, both ends): :down is udp-only, the suffix is bond-only, a
// bond must keep at least one leg able to carry each direction, and a shaped
// carrier never takes a suffix or a bond slot (D7). Prints and returns false
// like the bash.
func VCarrierList(v string) bool {
	if v == "" {
		Err("Choose a carrier.")
		return false
	}
	if v == "auto" {
		return true
	}
	if strings.Contains(v, "++") || strings.HasPrefix(v, "+") || strings.HasSuffix(v, "+") {
		Err(fmt.Sprintf("Carrier list '%s' has an empty leg.", v))
		return false
	}
	if strings.Contains(v, "+") {
		// D7: the engine refuses shaped carriers in a bond (untested,
		// per-protocol port defaults collide)
		var bases []string
		for _, c := range strings.Split(v, "+") {
			bases = append(bases, CarrierLegBase(c))
		}
		if isShapedList(strings.Join(bases, "+")) {
			Err(fmt.Sprintf("F19 shaped carriers are single-carrier only in 3.3.0; the engine refuses them in a '+'-bond ('%s').", v))
			return false
		}
	} else if strings.HasSuffix(v, ":up") || strings.HasSuffix(v, ":down") {
		Err(fmt.Sprintf("A :up/:down direction suffix only makes sense on a '+'-bond leg ('%s' alone would lose a direction).", v))
		return false
	}
	plain, sawUp, sawDown := false, false, false
	for _, c := range strings.Split(v, "+") {
		base := CarrierLegBase(c)
		if !CarrierOK(base) {
			Err(fmt.Sprintf("Unknown carrier '%s' (use icmp, udp, tcp, tls, ws, wss, h2, h2c, grpc, gre, ipip, ptcp, sit, 6to4, xfrm-ipsec, etherip, l2tpv3, fou-gre, gue-ipip, vxlan, geneve, dnscrypt-udp, ntp-direct, openvpn-dco, srtp-direct; join several with + to bond; a bond leg may end in :up or :down, 3.3.9 on both ends).", c))
			return false
		}
		switch CarrierLegDir(c) {
		case "down":
			if base != "udp" {
				Err(fmt.Sprintf("Carrier '%s': :down is udp-only in 3.3.9 (the engine refuses the rest).", c))
				return false
			}
			sawDown = true
		case "up":
			sawUp = true
		default:
			plain = true
		}
	}
	// a bond whose legs all point the same way has no leg left for the other
	// direction (checked before the duplicate pass so it names the real problem)
	if !plain {
		if !sawUp {
			Err(fmt.Sprintf("Carrier list '%s': every leg is :down, so nothing carries the uplink.", v))
			return false
		}
		if !sawDown {
			Err(fmt.Sprintf("Carrier list '%s': every leg is :up, so nothing carries the downlink.", v))
			return false
		}
	}
	seen := ""
	for _, c := range strings.Split(v, "+") {
		if strings.Contains(" "+seen+" ", " "+c+" ") && seen != "" {
			Err(fmt.Sprintf("Carrier '%s' appears twice in '%s'.", c, v))
			return false
		}
		seen += " " + c
	}
	return true
}

// AllowToArray mirrors allow_to_array: "443,53/udp" -> canonical items, one
// norm_spec expansion per comma part.
func AllowToArray(allow string) []string {
	var out []string
	for _, it := range strings.Split(allow, ",") {
		items, err := NormSpec(it)
		if err != nil {
			continue
		}
		out = append(out, items...)
	}
	return out
}

// cfgFileExists: does CONF/name.yml exist (the suggest_name scan)?
func cfgFileExists(name string) bool {
	return fileExists(filepath.Join(P.Conf, name+".yml"))
}

// IsRawCarrier: icmp/gre/ipip and the raw shaped tier.
func IsRawCarrier(c string) bool {
	switch c {
	case "icmp", "gre", "ipip":
		return true
	}
	return shapedRaw[c]
}

// confDir is the config directory accessor the screens use (P.Conf).
func confDir() string { return P.Conf }

// PortsSummary mirrors ports_summary(): "443 · 8443→443 · 53/udp", clamped to
// maxlen with a "+N" tail; Kharej shows target ports only; no ports yet on
// Iran, any port on Kharej.
func PortsSummary(name string, maxlen int) string {
	if maxlen <= 0 {
		maxlen = 50
	}
	out := ""
	cnt, total := 0, 0
	kharej := Role(name) == "Kharej"
	for _, it := range YmlMaps(name) {
		total++
		piece := SpecHuman(it)
		if kharej {
			piece = SpecT(it)
			if SpecP(it) == "udp" {
				piece += "/udp"
			}
		}
		if len(out)+len(piece)+5 > maxlen {
			continue
		}
		if out != "" {
			out += " · "
		}
		out += piece
		cnt++
	}
	if total == 0 {
		if kharej {
			return "any port"
		}
		return "no ports yet"
	}
	if cnt < total {
		out += fmt.Sprintf(" +%d", total-cnt)
	}
	return out
}

// CarrierHasListen mirrors carrier_has_listen(): !IsRawCarrier.
func CarrierHasListen(c string) bool { return !IsRawCarrier(c) }

// UndisguisedLegs mirrors undisguised_legs(): non-pool legs of a bond.
func UndisguisedLegs(list string) string {
	var out []string
	for _, c := range strings.Split(list, "+") {
		if !IsPool(c) {
			out = append(out, c)
		}
	}
	return strings.Join(out, " ")
}
