// Package mgr — P2: tunnel page (deck), port & limits editors, delete and
// change_key. Faithful port of wattun-manager (bash): same prompts, same
// validation texts, same defaults, same key order. Bash functions cited per
// block; the bash file stays the source of truth. Depends only on the P1 core
// (untagged) plus the p2* adapters below; the p2* layer is wired once the
// passes merge.

package mgr

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	Register("tunnel_page", func(args ...string) int { tunnelPage(arg(args, 0)); return 0 })
	Register("edit_ports", func(args ...string) int { editPorts(arg(args, 0)); return 0 })
	Register("limits_menu", func(args ...string) int { limitsMenu(arg(args, 0)); return 0 })
	Register("delete_tunnel", func(args ...string) int { return b2i(runDelete(arg(args, 0))) })
	Register("change_key", func(args ...string) int { changeKey(arg(args, 0)); return 0 })
}

func b2i(b bool) int {
	if b {
		return 0
	}
	return 1
}

// ======================================================================================
// P2 adapters — system interactions the P1 core does not own (fw, port probes,
// link wait, metrics port, public IP). Defaults are inert so the screens run
// anywhere; integration swaps them for the live probes (auto.go env* convention).
// ======================================================================================

var (
	p2FWOpen            = func(specs ...string) {}                               // bash fw_open
	p2FWClose           = func(specs ...string) {}                               // bash fw_close
	p2PortBusy          = func(port int, proto string) bool { return false }     // bash port_busy
	p2PortUser          = func(port int, proto string) string { return "" }      // bash port_user
	p2TunnelUsingPublic = func(port, proto, exclude string) string { return "" } // bash tunnel_using_public
	p2LocalAnswers      = func(port string) bool { return true }                 // bash </dev/tcp probe
	p2WaitLink          = func(name string, secs int) bool { return false }      // bash wait_link
	p2QuotaReset        = func(metrics, port string) error { return fmt.Errorf("no metrics") }
	p2PublicIP          = func() string { return "" }                       // bash public_ip
	p2FreeMetricsPort   = func() int { return 19750 }                       // bash free_metrics_port
	p2DefaultListen     = func(carrier string) string { return "20443" }    // bash default_listen
	p2ShapedSupported   = func(c string) (bool, string) { return true, "" } // bash shaped_supported_here
	p2ShapedWarn        = func(c string) {}                                 // bash shaped_warn
	// bash systemctl: every systemctl call the tunnel screens make routes through
	// this var so tests can record the sequence.
	p2Systemctl = systemctlQ
)

// bash rproto(): transport of the carrier port, for firewall and busy-port checks.
func p2Rproto(c string) string {
	switch c {
	case "udp", "fou-gre", "gue-ipip", "vxlan", "geneve", "dnscrypt-udp", "ntp-direct", "openvpn-dco", "srtp-direct":
		return "udp"
	}
	return "tcp"
}

// bash new_key: 40 base64 chars, no /+=; 48 bytes (64 chars) so stripping /+ never leaves fewer than 40
func p2NewKey() string {
	b := make([]byte, 48)
	if _, err := cryptoRead(b); err != nil {
		return "wattun-devkey-wattun-devkey-wattun"
	}
	s := base64StdEncode(string(b))
	s = strings.NewReplacer("/", "", "+", "", "=", "", "\n", "").Replace(s)
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// bash rand_path: /api/<12 hex>
func p2RandPath() string {
	b := make([]byte, 6)
	cryptoRead(b)
	return "/api/" + fmt.Sprintf("%x", b)
}

// bash suggest_name: kharej, kharej-2, kharej-3 ...
func suggestName(base string) string {
	c := base
	for n := 1; fileExists(filepath.Join(P.Conf, c+".yml")) && n < 99; n++ {
		c = fmt.Sprintf("%s-%d", base, n+1)
	}
	return c
}

// bash ports_summary (2049)
func p2PortsSummary(n string, max int) string {
	r := Role(n)
	var out []string
	total := 0
	for _, it := range YmlMaps(n) {
		total++
		piece := SpecHuman(it)
		if r == "Kharej" {
			piece = SpecT(it)
			if SpecP(it) == "udp" {
				piece += "/udp"
			}
		}
		if len(strings.Join(out, " · "))+len(piece)+5 > max {
			continue
		}
		out = append(out, piece)
	}
	if total == 0 {
		if r == "Kharej" {
			return "any port"
		}
		return "no ports yet"
	}
	s := strings.Join(out, " · ")
	if len(out) < total {
		s += fmt.Sprintf(" +%d", total-len(out))
	}
	return s
}

// bash show_token (6998): token + hint.
func p2ShowToken(n string) {
	tok := strings.TrimSpace(p2ReadText(filepath.Join(P.Conf, n+".token")))
	if tok == "" {
		Err("No token stored for '" + n + "' (tokens exist only on Kharej tunnels).")
		return
	}
	_ = RefreshToken(n) // keep the allowed ports in step (bash refresh_token)
	tok = strings.TrimSpace(p2ReadText(filepath.Join(P.Conf, n+".token")))
	fmt.Fprintf(Stdout, "  %s%s%s\n", BOLD+YEL, tok, RST)
	Hint("Contains secret key — share privately.")
}

// ======================================================================================
// Validators (bash v_* — error texts byte-identical, printed via theme.Err)
// ======================================================================================

func vPort(s string) bool {
	if !regexp.MustCompile(`^[0-9]{1,5}$`).MatchString(s) {
		Err("Enter a port between 1 and 65535.")
		return false
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		Err("Enter a port between 1 and 65535.")
		return false
	}
	return true
}

func vName(s string) bool {
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`).MatchString(s) {
		Err("Use 1-32 letters, digits, - or _.")
		return false
	}
	if fileExists(filepath.Join(P.Conf, s+".yml")) {
		Err("A tunnel named '" + s + "' already exists.")
		return false
	}
	return true
}

func vHost(s string) bool {
	bad := func() bool { Err("Enter an IP address or a domain name."); return false }
	if s == "" || len(s) > 253 {
		return bad()
	}
	h, p := SplitHP(s)
	if p != "" && !vPort(p) {
		return bad()
	}
	if ipOK(h) || regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`).MatchString(h) {
		return true
	}
	return bad()
}

func vIPv4(s string) bool {
	if regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`).MatchString(s) {
		return true
	}
	Err("Enter the server's IPv4 address, such as 198.51.100.20.")
	return false
}

func vIcmp(s string) bool {
	if s == "echo" || s == "timestamp" {
		return true
	}
	Err("Use echo or timestamp (Linux does not answer info/mask).")
	return false
}

func vMbps(s string) bool {
	if s == "" {
		return true
	}
	if regexp.MustCompile(`^[0-9]{1,4}$`).MatchString(s) {
		if n, _ := strconv.Atoi(s); n >= 1 {
			return true
		}
	}
	Err("Enter a number of MB/s (1-9999).")
	return false
}

func vMbpsAdv(s string) bool {
	if s == "-" || s == "0" || s == "default" {
		return true
	}
	return vMbps(s)
}

func vBind(s string) bool {
	h := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if h == "::" || ipOK(h) {
		return true
	}
	Err("Enter an IPv4 or IPv6 address such as 0.0.0.0, :: (dual-stack) or 10.0.0.5.")
	return false
}

func vPath(s string) bool {
	if regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`).MatchString(s) {
		return true
	}
	Err("The path must start with / (example: /wat).")
	return false
}

func vToken(s string) bool {
	if _, err := ReadToken(s); err == nil {
		return true
	}
	Err("That is not a valid token. It starts with wat1: and is one long line.")
	return false
}

func vKey(s string) bool {
	if len(s) >= 8 && !strings.ContainsAny(s, " \t") {
		return true
	}
	Err("The key is at least 8 characters, no spaces.")
	return false
}

func vFec(s string) bool {
	if s == "off" || s == "auto" {
		return true
	}
	Err("Use off or auto.")
	return false
}

func vPoolBytes(s string) bool {
	l := strings.ToLower(s)
	if l == "" || l == "0" || l == "0b" || l == "off" {
		return true
	}
	if regexp.MustCompile(`^[0-9]+(\.[0-9]+)?(k|m|g|t)b?$`).MatchString(l) {
		return true
	}
	Err("Enter a byte count such as 500MB, 4G or 300k (or 0 to turn it off).")
	return false
}

func vQuotaPeriod(s string) bool {
	switch strings.ToLower(s) {
	case "", "-", "none", "day", "week", "month":
		return true
	}
	Err("Enter day, week or month (or - for a quota that never resets).")
	return false
}

// carrier_write_listen (bash 1310): does the config need a global listen: key.
// (Not in the P1 core; bond-level listen policy stays here.)
func carrierWriteListen(c string) bool {
	if strings.Contains(c, "+") {
		for _, l := range strings.Split(c, "+") {
			switch CarrierLegBase(l) {
			case "udp", "tcp", "tls", "ws", "wss", "h2", "h2c", "grpc":
				return true
			}
		}
		return false
	}
	return CarrierHasListen(c)
}

// ipOK: a valid IPv4 or IPv6 address (bash ipv4_ok 606 / ipv6_ok 1616 are
// pragmatic syntax checks; net.ParseIP is the same authority the engine uses).
func ipOK(h string) bool {
	return net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")) != nil
}

// ======================================================================================
// Allowlist helpers (bash allow_to_array / allowed_has / maps_allow_str)
// ======================================================================================

// allowToArray: "443,53/udp" -> canonical items (443:443/tcp 53:53/udp).
func allowToArray(allow string) []string {
	var out []string
	for _, it := range strings.FieldsFunc(allow, func(r rune) bool { return r == ',' || r == ' ' }) {
		if items, err := NormSpec(it); err == nil {
			out = append(out, items...)
		}
	}
	return out
}

// allowedHas: target proto allowed, or the allow list unknown/empty.
func allowedHas(allow []string, target, proto string) bool {
	if len(allow) == 0 {
		return true
	}
	for _, a := range allow {
		if SpecT(a) == target && SpecP(a) == proto {
			return true
		}
	}
	return false
}

// allowOfMaps: MAPS -> "443,53/udp" (target ports only, as embedded in the token).
func allowOfMaps(maps []string) string {
	var out []string
	for _, m := range maps {
		t := SpecT(m)
		if SpecP(m) == "udp" {
			t += "/udp"
		}
		dup := false
		for _, o := range out {
			if o == t {
				dup = true
			}
		}
		if !dup {
			out = append(out, t)
		}
	}
	return strings.Join(out, ",")
}

// ======================================================================================
// Port editor (bash pe_* / port_editor, 2398-2593)
// ======================================================================================

type portEditor struct {
	Maps   []string
	Role   string // Iran | Kharej
	Tunnel string
	Allow  []string
	Owned  []string
	Msg    []string
	Head   func(io.Writer) // a wizard step bar in place of the Ports page title
}

func (pe *portEditor) msg(s string) { pe.Msg = append(pe.Msg, s) }

func (pe *portEditor) ownedHas(o string) bool {
	for _, x := range pe.Owned {
		if x == o {
			return true
		}
	}
	return false
}

// pe_try_add: validate and add/replace; the message texts are the bash ones.
func (pe *portEditor) tryAdd(item string, idx int) bool {
	L, T, P := SpecL(item), SpecT(item), SpecP(item)
	if pe.Role == "Kharej" && L != T {
		pe.msg(RED + "✗" + RST + " " + SpecHuman(item) + ": on Kharej list only the port your service uses (like 443 or 53/udp).")
		return false
	}
	for i := range pe.Maps {
		if i == idx {
			continue
		}
		if pe.Role == "Iran" {
			if SpecL(pe.Maps[i]) == L && SpecP(pe.Maps[i]) == P {
				pe.msg(RED + "✗" + RST + " Iran port " + L + "/" + P + " is already mapped (row " + strconv.Itoa(i+1) + ").")
				return false
			}
		} else if SpecT(pe.Maps[i]) == T && SpecP(pe.Maps[i]) == P {
			pe.msg(RED + "✗" + RST + " Port " + T + "/" + P + " is already in the list (row " + strconv.Itoa(i+1) + ").")
			return false
		}
	}
	if pe.Role == "Iran" {
		pn, _ := strconv.Atoi(L)
		if !pe.ownedHas(L+"/"+P) && p2PortBusy(pn, P) {
			u := p2PortUser(pn, P)
			ex := ""
			if u != "" {
				ex = " by " + u
			}
			pe.msg(RED + "✗" + RST + " Port " + L + "/" + P + " is already in use on this server" + ex + ". Pick another Iran port.")
			return false
		}
		if who := p2TunnelUsingPublic(L, P, pe.Tunnel); who != "" {
			pe.msg(RED + "✗" + RST + " Port " + L + "/" + P + " is already published by tunnel '" + who + "'.")
			return false
		}
		if !allowedHas(pe.Allow, T, P) {
			pe.msg(YEL + "!" + RST + " Kharej does not allow " + T + "/" + P + ". Add it to Kharej's ports or it will be refused.")
		}
	} else if P == "tcp" && !p2LocalAnswers(T) {
		pe.msg(YEL + "!" + RST + " Nothing answers on 127.0.0.1:" + T + " yet. Fine if you start your service later.")
	}
	if idx >= 0 {
		pe.Maps[idx] = item
	} else {
		pe.Maps = append(pe.Maps, item)
	}
	return true
}

// pe_bulk
func (pe *portEditor) bulk(line string) {
	before := len(pe.Maps)
	for _, tok := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if items, err := NormSpec(tok); err == nil {
			for _, it := range items {
				pe.tryAdd(it, -1)
			}
		} else {
			pe.msg(RED + "✗" + RST + " " + err.Error())
		}
	}
	if len(pe.Maps) > before {
		pe.msg(GRN + "✓" + RST + " Added " + strconv.Itoa(len(pe.Maps)-before) + ".")
	}
}

// pe_draw
func (pe *portEditor) draw() {
	tun := pe.Tunnel
	if tun == "" {
		tun = "new tunnel"
	}
	if pe.Head != nil {
		ClearScreen()
		pe.Head(Stdout)
	} else {
		Page("Ports", tun+" · "+pe.Role)
	}
	if pe.Role == "Iran" {
		fmt.Fprintf(Stdout, "  %s%3s  %-19s      %-23s %s%s\n", GRY, "#", "Listen", "Target", "Proto", RST)
	} else {
		fmt.Fprintf(Stdout, "  %s%3s  %-31s %s%s\n", GRY, "#", "Port", "Proto", RST)
	}
	if len(pe.Maps) == 0 {
		if pe.Role == "Kharej" {
			fmt.Fprintf(Stdout, "  %s     all ports allowed%s\n", GRY, RST)
		} else {
			fmt.Fprintf(Stdout, "  %s     none yet%s\n", GRY, RST)
		}
	}
	warned := false
	for i, it := range pe.Maps {
		L, T, P := SpecL(it), SpecT(it), SpecP(it)
		if pe.Role == "Iran" {
			mark := " "
			if !allowedHas(pe.Allow, T, P) {
				mark = YEL + "!" + RST
				warned = true
			}
			fmt.Fprintf(Stdout, "  %s%3d%s  %-19s ──►  %-23s %-5s %s\n", GRY, i+1, RST, L, T, P, mark)
		} else {
			fmt.Fprintf(Stdout, "  %s%3d%s  %-31s %s\n", GRY, i+1, RST, T, P)
		}
	}
	if warned {
		Hint("! Port not in Kharej allowlist")
	}
	if pe.Role == "Iran" && len(pe.Allow) > 0 {
		var bad []string
		for _, it := range pe.Allow {
			bad = append(bad, SpecT(it)+"/"+SpecP(it))
		}
		Hint("Kharej allows:" + strings.ReplaceAll(strings.Join(bad, " "), "/tcp", ""))
	}
	fmt.Fprintln(Stdout)
	if len(pe.Msg) > 0 {
		for _, m := range pe.Msg {
			fmt.Fprintln(Stdout, "  "+m)
		}
		fmt.Fprintln(Stdout)
		pe.Msg = nil
	}
	if pe.Role == "Iran" {
		Hint("Add: 443 · 8443:443 · 53/udp")
		Hint("Note: encrypts Iran <-> Kharej only; use TLS, Reality or Shadowsocks on panel inbound.")
	} else {
		Hint("Add: 443 · 8443 · 53/udp")
	}
	MenuLine(Stdout, "Enter", "save", "a", "add", "e #", "edit", "r #", "remove", "c", "clear", "f NAME", "copy", "q", "cancel")
}

// pe_guided_add
func (pe *portEditor) guidedAdd() {
	var l, t string
	fmt.Fprintln(Stdout)
	if pe.Role == "Iran" {
		if !AskOK("Iran port (users connect here)", "", vPort) {
			pe.msg("Cancelled.")
			return
		}
		l = ReplyV
		if !AskOK("Kharej port (where your service listens)", l, vPort) {
			pe.msg("Cancelled.")
			return
		}
		t = ReplyV
	} else {
		if !AskOK("Port of your service on this server", "", vPort) {
			pe.msg("Cancelled.")
			return
		}
		t, l = ReplyV, ReplyV
	}
	p := strings.ToLower(Ask("Protocol: tcp, udp or both", "tcp"))
	if items, err := NormSpec(l + ":" + t + "/" + p); err == nil {
		for _, it := range items {
			pe.tryAdd(it, -1)
		}
	} else {
		pe.msg(RED + "✗" + RST + " " + err.Error())
	}
}

// pe_pick_index + pe_edit
func (pe *portEditor) pickIndex(arg string) int {
	if arg == "" {
		arg = Ask("Row number", "")
	}
	if n, err := strconv.Atoi(strings.TrimSpace(arg)); err == nil && n >= 1 && n <= len(pe.Maps) {
		return n - 1
	}
	pe.msg(RED + "✗" + RST + " No such row '" + arg + "'.")
	return -1
}

func (pe *portEditor) edit(arg string) {
	idx := pe.pickIndex(arg)
	if idx < 0 {
		return
	}
	cur := pe.Maps[idx]
	p := SpecP(cur)
	fmt.Fprintln(Stdout)
	var l, t string
	if pe.Role == "Iran" {
		if !AskOK("Iran port", SpecL(cur), vPort) {
			return
		}
		l = ReplyV
		if !AskOK("Kharej port", SpecT(cur), vPort) {
			return
		}
		t = ReplyV
	} else {
		if !AskOK("Port", SpecT(cur), vPort) {
			return
		}
		t, l = ReplyV, ReplyV
	}
	p = strings.ToLower(Ask("Protocol: tcp or udp", p))
	if p != "tcp" && p != "udp" {
		pe.msg(RED + "✗" + RST + " Protocol must be tcp or udp here (to get both, add a second row).")
		return
	}
	if items, err := NormSpec(l + ":" + t + "/" + p); err == nil {
		if pe.tryAdd(items[0], idx) {
			pe.msg(GRN + "✓" + RST + " Row " + strconv.Itoa(idx+1) + " updated.")
		}
	}
}

// pe_remove
func (pe *portEditor) remove(arg string) {
	if arg == "" {
		arg = Ask("Row number(s) to remove (e.g. 2 or 1,3)", "")
	}
	if arg == "" {
		return
	}
	var drop []int
	for _, x := range strings.Split(arg, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil && n >= 1 && n <= len(pe.Maps) {
			drop = append(drop, n)
		} else {
			pe.msg(RED + "✗" + RST + " No such row '" + x + "'.")
		}
	}
	if len(drop) == 0 {
		return
	}
	var out []string
	for i, m := range pe.Maps {
		keep := true
		for _, d := range drop {
			if d == i+1 {
				keep = false
			}
		}
		if keep {
			out = append(out, m)
		}
	}
	pe.Maps = out
	pe.msg(GRN + "✓" + RST + " Removed.")
}

// port_editor: true = done (Maps ready), false = cancelled.
func (pe *portEditor) run() bool {
	for {
		pe.draw()
		fmt.Fprintf(Stdout, "  %s▸%s ", CYN, RST)
		line, _ := ReadLine(0)
		line = strings.TrimSpace(line)
		cmd, arg := line, ""
		if i := strings.Index(line, " "); i >= 0 {
			cmd, arg = line[:i], line[i+1:]
		}
		switch strings.ToLower(cmd) {
		case "", "d", "done", "ok":
			if pe.Role == "Iran" && len(pe.Maps) == 0 {
				pe.msg(YEL + "!" + RST + " Add at least one port first (example: 443).")
				continue
			}
			if pe.Role == "Kharej" && len(pe.Maps) == 0 {
				if !Confirm("No list: Iran can reach any port on this server. Save?", false) {
					continue
				}
			}
			return true
		case "q", "quit", "cancel", "esc", "b", "back":
			return false
		case "a", "add":
			pe.guidedAdd()
		case "e", "edit":
			pe.edit(arg)
		case "r", "rm", "remove", "del", "delete":
			pe.remove(arg)
		case "c", "clear":
			pe.Maps = nil
			pe.msg("Cleared.")
		case "f", "from", "copy":
			pe.copyFrom(arg)
		case "?", "h", "help":
			pe.msg("Examples: 443   8443:443   8443->443/udp   53/both   (several at once: 443, 8443:443, 53/udp)")
			pe.msg("Iran port = what users connect to on this server. Kharej port = your service.")
		default:
			if strings.ContainsAny(line, "0123456789") {
				pe.bulk(line)
			} else {
				pe.msg(YEL + "!" + RST + " Not understood: '" + line + "'. Type ports like 443 or 8443:443, or ? for help.")
			}
		}
	}
}

// pe_from (the optional move onto the other tunnel stays with the bonding work).
func (pe *portEditor) copyFrom(n string) {
	if n == "" {
		pe.msg("Type: " + BOLD + "from NAME" + RST + "   (NAME = another tunnel on this server)")
		return
	}
	if n == pe.Tunnel {
		pe.msg(YEL + "!" + RST + " That is this tunnel.")
		return
	}
	src := YmlMaps(n)
	if len(src) == 0 {
		pe.msg(YEL + "!" + RST + " '" + n + "' publishes no ports.")
		return
	}
	if !Confirm(fmt.Sprintf("Add the %d port(s) of '%s' to this list? (the rows you already have stay)", len(src), n), true) {
		return
	}
	added := 0
	for _, it := range src {
		dup := false
		for _, m := range pe.Maps {
			if SpecL(m) == SpecL(it) && SpecP(m) == SpecP(it) {
				dup = true
			}
		}
		if dup {
			continue
		}
		if who := p2TunnelUsingPublic(SpecL(it), SpecP(it), pe.Tunnel); who != "" && who != n {
			pe.msg(RED + "✗" + RST + " " + SpecL(it) + "/" + SpecP(it) + " is published by '" + who + "'.")
			continue
		}
		pe.Maps = append(pe.Maps, it)
		added++
	}
	pe.msg(GRN + "✓" + RST + " " + strconv.Itoa(added) + " port(s) copied from '" + n + "'.")
}

// edit_ports (bash 7011): load, edit, save, hot-reload note, firewall for new rows.
func editPorts(n string) {
	r := Role(n)
	maps := YmlMaps(n)
	pe := &portEditor{Maps: maps, Role: r, Tunnel: n}
	if IsActive(Unit(n)) {
		for _, it := range maps {
			pe.Owned = append(pe.Owned, SpecL(it)+"/"+SpecP(it))
		}
	}
	if !pe.run() {
		Warn("No changes saved.")
		return
	}
	if err := WritePorts(n, pe.Maps); err != nil {
		Err("Could not write config.")
		return
	}
	if r == "Kharej" {
		_ = RefreshToken(n) // keep NAME.token in step with the allow list
	}
	Ok("Saved · " + p2PortsSummary(n, 60) + " (applies in 3 s, no drop)")
	if r == "Iran" {
		var pub []string
		for _, it := range pe.Maps {
			row := SpecL(it) + "/" + SpecP(it)
			if !pe.ownedHas(row) {
				pub = append(pub, row)
			}
		}
		if len(pub) > 0 {
			p2FWOpen(pub...)
		}
	}
}

// ======================================================================================
// Limits editor (bash limits_menu 9012 + set_port_limit 873)
// ======================================================================================

// setPortLimitYAML: the awk of set_port_limit in Go — item written only with a
// rate or quota; period only with a quota.
func setPortLimitYAML(yml, lp, lr, lq, lpd string) string {
	item := func() string {
		s := "  - " + lp
		if lr != "" && lr != "0" {
			s += " rate=" + lr
		}
		if lq != "" && lq != "0" {
			s += " quota=" + lq
			if lpd != "" {
				s += " period=" + lpd
			}
		}
		return s
	}
	has := (lr != "" && lr != "0") || (lq != "" && lq != "0")
	lines := strings.Split(strings.TrimRight(yml, "\n"), "\n")
	var out []string
	inLim, wrote := false, false
	topKey := regexp.MustCompile(`^[a-zA-Z0-9_-]+:`)
	itemRe := regexp.MustCompile(`^  - (\S+)(.*)$`)
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "limits:"):
			inLim = true
			out = append(out, line)
		case inLim && topKey.MatchString(line):
			if has && !wrote {
				out = append(out, item())
				wrote = true
			}
			inLim = false
			out = append(out, line)
		case inLim && strings.HasPrefix(line, "  - "):
			if m := itemRe.FindStringSubmatch(line); m != nil && m[1] == lp {
				if has && !wrote {
					out = append(out, item())
					wrote = true
				}
				continue
			}
			out = append(out, line)
		default:
			out = append(out, line)
		}
	}
	if has && !wrote {
		if !inLim {
			out = append(out, "limits:")
		}
		out = append(out, item())
	}
	return strings.Join(out, "\n") + "\n"
}

// limitsMenu (bash limits_menu): m speed, e set a port limit, r reset quota, 0 back.
func limitsMenu(n string) {
	for {
		Page("Limits", n)
		SetRow("m", "speed limit", Cfg(n, "max-mbps"), "MB/s", "none")
		fmt.Fprintln(Stdout)
		Say("  " + GRY + "per port" + RST)
		var pl []string
		for _, line := range strings.Split(p2ReadText(filepath.Join(P.Conf, n+".yml")), "\n") {
			if regexp.MustCompile(`^\s*-\s+[0-9]+`).MatchString(line) && (strings.Contains(line, "rate=") || strings.Contains(line, "quota=")) {
				pl = append(pl, line)
			}
		}
		if len(pl) > 0 {
			for _, it := range pl {
				Say("    " + it)
			}
		} else {
			Say("    " + GRY + "none" + RST)
		}
		fmt.Fprintln(Stdout)
		m := Cfg(n, "metrics")
		if m != "" {
			if body := FetchPorts(m); body != "" {
				Say("  " + GRY + "quota used" + RST)
				for _, pobj := range regexp.MustCompile(`\{[^{}]*\}`).FindAllString(body, -1) {
					lp := Jget(pobj, "port")
					qu, ql := Jget(pobj, "quota_used"), Jget(pobj, "quota_limit")
					qe := Jget(pobj, "quota_exceeded")
					if atoi(ql) > 0 {
						line := "    " + lp + "  " + Human(float64(atoi(qu))) + " of " + Human(float64(atoi(ql)))
						if qe == "true" {
							line += "  " + RED + "✗ used up" + RST
						}
						Say(line)
					}
				}
			}
		}
		fmt.Fprintln(Stdout)
		MenuLine(Stdout, "e", "set a port limit", "r", "reset a port quota", "0", "back")
		k, _, _ := KeyRead(0)
		switch k {
		case "m":
			fmt.Fprintln(Stdout)
			if !AskOK("Global speed ceiling in MB/s (- or 0 or default = unset)", Cfg(n, "max-mbps"), vMbpsAdv) {
				continue
			}
			switch ReplyV {
			case "-", "0", "default":
				ReplyV = ""
			}
			if ReplyV == "" {
				_ = UnsetValue(n, "max-mbps")
			} else {
				_ = SetValue(n, "max-mbps", ReplyV)
			}
			Ok("Saved. Restart '" + n + "' to apply.")
			Pause()
		case "e":
			fmt.Fprintln(Stdout)
			if !AskOK("Port to limit", "", vPort) {
				continue
			}
			lport := ReplyV
			if !AskOK("Rate limit (e.g. 5MB, 300k, 0 = none)", "0", vPoolBytes) {
				continue
			}
			lrate := ReplyV
			if !AskOK("Quota limit (e.g. 100GB, 500MB, 0 = none)", "0", vPoolBytes) {
				continue
			}
			lquota, lper := ReplyV, ""
			if lquota != "" && lquota != "0" {
				if !AskOK("Reset the quota every day, week or month (- = never)", "-", vQuotaPeriod) {
					continue
				}
				switch strings.ToLower(ReplyV) {
				case "day", "week", "month":
					lper = strings.ToLower(ReplyV)
				}
			}
			f := filepath.Join(P.Conf, n+".yml")
			if err := atomicWrite(f, []byte(setPortLimitYAML(p2ReadText(f), lport, lrate, lquota, lper)), 0o600); err != nil {
				Err("Could not write config.")
				continue
			}
			Ok("Saved limit for port " + lport + ". Hot-reloaded automatically by engine.")
			Pause()
		case "r":
			fmt.Fprintln(Stdout)
			if !AskOK("Port to reset quota for", "", vPort) {
				continue
			}
			rport := ReplyV
			if m != "" {
				if err := p2QuotaReset(m, rport); err == nil {
					Ok("Quota for port " + rport + " reset.")
				} else {
					Err("Failed to reset quota on metrics server http://" + m + ".")
				}
			} else {
				Warn("Tunnel '" + n + "' has no metrics endpoint configured.")
			}
			Pause()
		case "b", "0", "q", "enter", "esc":
			return
		}
	}
}

func p2ReadText(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

// ======================================================================================
// Delete (bash delete_tunnel 7187 + auto_drop_unit 4340)
// ======================================================================================

type sysdCall struct{ Args []string }

func (c sysdCall) String() string { return strings.Join(c.Args, " ") }

// deleteSequence: the systemctl calls in bash order — hidden helpers first
// (NAME-r companion, NAME-e-* listeners), then autowatch, then the tunnel itself.
func deleteSequence(n string) []sysdCall {
	var calls []sysdCall
	drop := func(u string) { calls = append(calls, sysdCall{[]string{"disable", "--now", Unit(u)}}) }
	if cfgFileExists(n + "-r") {
		drop(n + "-r")
	}
	for _, u := range extListenerNames(n) {
		drop(u)
	}
	calls = append(calls,
		sysdCall{[]string{"stop", P.Prefix + "-autowatch-" + n + ".service"}},
		sysdCall{[]string{"reset-failed", P.Prefix + "-autowatch-" + n + ".service"}},
		sysdCall{[]string{"disable", "--now", Unit(n)}},
	)
	return calls
}

// extListenerNames: the hidden NAME-e-* helper units (bash auto_ext_names).
func extListenerNames(n string) []string {
	var out []string
	ms, _ := filepath.Glob(filepath.Join(P.Conf, n+"-e-*.yml"))
	for _, m := range ms {
		out = append(out, strings.TrimSuffix(filepath.Base(m), ".yml"))
	}
	return out
}

// runDelete: execute the sequence — systemctl calls in order, then the file
// cleanup (configs, keys, tokens; H8: stop before the state files go).
func runDelete(n string) bool {
	extra := ""
	if cfgFileExists(n + "-r") {
		extra = ", companion " + n + "-r"
	}
	if cnt := len(extListenerNames(n)); cnt > 0 {
		extra += fmt.Sprintf(", %d extended listeners", cnt)
	}
	Warn("Stops '" + n + "' and deletes its config, key, and token" + extra + ".")
	if NonInteractive {
		ReplyV = n // --yes is the confirmation
	} else {
		Ask("Type "+n+" to confirm (Enter cancels)", "")
	}
	if ReplyV != n {
		Warn("Not deleted.")
		return false
	}
	units := []string{n}
	if cfgFileExists(n + "-r") {
		units = append(units, n+"-r")
	}
	units = append(units, extListenerNames(n)...)
	// read before the configs go: the listen ports (firewall) and the state files (state-dir)
	ports := listenPortsOf(n)
	var states []string
	for _, u := range units {
		states = append(states, stateFiles(u)...)
	}
	for _, c := range deleteSequence(n) {
		_ = p2Systemctl(c.Args...)
	}
	// H8: the unit is stopped first; the engine saves quota/totals on SIGTERM, so removing them earlier is undone
	for _, f := range states {
		os.Remove(f)
	}
	bondRetestDisable(n) // the bond-retest timer belongs to this tunnel
	for _, u := range units {
		for _, ext := range []string{".yml", ".ech", ".key", ".token", ".auto", ".autoext"} {
			os.Remove(filepath.Join(P.Conf, u+ext))
		}
	}
	for _, ext := range []string{".bondretest", ".bondretest.tmp", ".bondfail", ".bondfail.tmp", ".keepopen", ".finalized", ".iranip", ".repaste"} {
		os.Remove(filepath.Join(P.Conf, n+ext))
	}
	for _, ext := range []string{".down", ".cycles", ".retest", ".sla_triggered", ".autoprune", ".autoprune.done", ".autowiden", ".autowiden.down", ".abandoned"} {
		os.Remove(filepath.Join(P.Run, n+ext))
	}
	for _, p := range ports {
		if tunnelUsingListen(strings.SplitN(p, "/", 2)[0], n) == "" {
			p2FWClose(p)
		}
	}
	Ok("Tunnel '" + n + "' deleted.")
	if !kreplyUsersLeft() {
		kreplyRestore()
	}
	return true
}

// the listen: ports of a config (firewall rules to consider closing).
func listenPortsOf(n string) []string {
	var out []string
	car := Cfg(n, "carrier")
	for _, line := range strings.Split(p2ReadText(filepath.Join(P.Conf, n+".yml")), "\n") {
		m := regexp.MustCompile(`^listen(?:-[a-z0-9-]+)?:\s*"?([^"#\s]+)"?`).FindStringSubmatch(line)
		if m == nil {
			continue
		}
		_, port := SplitHP(m[1])
		if port == "" || !regexp.MustCompile(`^[0-9]+$`).MatchString(port) {
			continue
		}
		out = append(out, port+"/"+p2Rproto(car))
	}
	return out
}

// ======================================================================================
// change_key (bash 7088)
// ======================================================================================

func changeKey(n string) {
	if Role(n) == "Kharej" {
		Warn("Every Iran server on this tunnel disconnects until it gets the new token.")
		if !Confirm("Make a new key and token?", false) {
			return
		}
		k := p2NewKey()
		atomicWrite(filepath.Join(P.Conf, n+".key"), []byte(k+"\n"), 0o600)
		if tok := strings.TrimSpace(p2ReadText(filepath.Join(P.Conf, n+".token"))); tok != "" {
			if t, err := ReadToken(tok); err == nil {
				nt := MakeToken(t.Carrier, t.Peer, k, t.Path, t.SNI, t.Icmp, t.Ports, t.Rev, t.Auto)
				atomicWrite(filepath.Join(P.Conf, n+".token"), []byte(nt+"\n"), 0o600)
			}
		}
		_ = p2Systemctl("restart", Unit(n))
		// H3: hidden shaped listeners read key-file only at startup; disabled ones stay closed.
		for _, u := range extListenerNames(n) {
			if IsEnabled(Unit(u)) {
				_ = p2Systemctl("restart", Unit(u))
			}
		}
		fmt.Fprintln(Stdout)
		Ok("New token. Paste it on each Iran server (tunnel page, t):")
		fmt.Fprintln(Stdout)
		p2ShowToken(n)
		return
	}
	// Iran: paste the new Kharej token (bash 7108-7185)
	if !AskOK("Token from Kharej", "", vToken) {
		return
	}
	t, err := ReadToken(ReplyV)
	if err != nil {
		return
	}
	if !VCarrierList(t.Carrier) {
		return
	}
	if err := t.TokenBondLegs(); err != nil { // M1: same per-leg split as the wizard import
		Err(err.Error())
		return
	}
	if isShapedList(t.Carrier) {
		if t.Rev == "1" {
			Err("F19 shaped carriers do not support reverse.")
			return
		}
		if !shapedSupportedHere(t.Carrier) {
			return
		}
		p2ShapedWarn(t.Carrier)
	}
	oldrev := IsReverse(n)
	oldlisten := ""
	if oldrev {
		_, oldlisten = SplitHP(Cfg(n, "listen"))
	}
	keepres := IsPoolList(t.Carrier) && t.Rev != "1"
	atomicWrite(filepath.Join(P.Conf, n+".key"), []byte(t.Key+"\n"), 0o600)
	os.Remove(filepath.Join(P.Conf, n+".auto")) // a stale auto plan would let heal switch back
	// the token decides how the pair connects; drop every stale field instead of leaving a mismatch
	drop := []string{"carrier", "peer", "path", "udp-dns", "sni", "host", "icmp-type", "reverse", "listen", "ech-cache"}
	if !keepres {
		drop = append(drop, "fake-sni", "fake-mode", "fake-ttl", "pool-rotate", "pool-rotate-bytes", "fp", "ech", "tls-frag")
	}
	dropStaleKeys(n, drop)
	_ = SetValue(n, "carrier", t.Carrier)
	_ = SetValue(n, "peer", t.Peer)
	for i, lc := range t.LegC { // M1: a bond token keeps its per-leg endpoints
		_ = SetValue(n, "peer-"+CarrierLegBase(lc), t.LegP[i])
	}
	if t.Carrier == "udp" && t.Path == "dns" {
		_ = SetValue(n, "udp-dns", "true")
	} else if t.Path != "" {
		_ = SetValue(n, "path", t.Path)
	}
	if t.SNI != "" {
		_ = SetValue(n, "sni", t.SNI)
		_ = SetValue(n, "host", t.SNI)
	}
	if t.Icmp != "" && t.Icmp != "echo" {
		_ = SetValue(n, "icmp-type", t.Icmp)
	}
	rport := ""
	if t.Rev == "1" {
		_ = SetValue(n, "reverse", "true")
		if IsRpool(t.Carrier) {
			_, rport = SplitHP(t.Peer)
			_ = SetValue(n, "listen", "\":"+rport+"\"")
		}
	}
	if p2Systemctl("restart", Unit(n)) != nil {
		return
	}
	if rport != "" {
		p2FWOpen(rport + "/" + p2Rproto(t.Carrier))
	}
	if oldrev && oldlisten != "" && oldlisten != rport {
		p2FWClose(oldlisten + "/" + p2Rproto(Cfg(n, "carrier")))
	}
	if p2WaitLink(n, 20) {
		Ok("CONNECTED")
	} else {
		Warn("Not connected yet.")
	}
	// the new Kharej may allow a different set of targets
	var missing []string
	allow := allowToArray(t.Ports)
	for _, it := range YmlMaps(n) {
		if !allowedHas(allow, SpecT(it), SpecP(it)) {
			missing = append(missing, SpecT(it)+"/"+SpecP(it))
		}
	}
	if len(missing) > 0 {
		Warn("Kharej does not allow: " + strings.ReplaceAll(strings.Join(missing, " "), "/tcp", "") + " — those ports will be refused until you list them on Kharej (tunnel page, p).")
	}
}

// dropStaleKeys: remove top-level keys plus every peer-*/listen-* key (bash sed -i -E).
func dropStaleKeys(n string, keys []string) {
	f := filepath.Join(P.Conf, n+".yml")
	yml := p2ReadText(f)
	re := regexp.MustCompile(`^(peer|listen)-[a-z0-9-]+:`)
	var out []string
	for _, line := range strings.Split(yml, "\n") {
		drop := re.MatchString(line)
		for _, k := range keys {
			if strings.HasPrefix(line, k+":") {
				drop = true
			}
		}
		if !drop {
			out = append(out, line)
		}
	}
	atomicWrite(f, []byte(strings.Join(out, "\n")), 0o600)
}

// ======================================================================================
// Tunnel page (bash tunnel_page 9332 + tunnel_menu_* 9117-9310)
// ======================================================================================

type deckRow struct {
	Type      string // H header, I item
	Key, Lab  string
	Desc, Val string
}

type deck struct{ L, R []deckRow }

// tunnel_menu_build (bash 9117): the actual key list of the bash deck.
func buildDeck(n, r, run, car string) *deck {
	d := &deck{}
	stopLab, stopDesc := "Start", "stopped"
	if run == "active" {
		stopLab, stopDesc = "Stop", "active"
	}
	bootDesc := "off · toggle"
	if IsEnabled(Unit(n)) {
		bootDesc = "on · toggle"
	}
	pcnt := len(YmlMaps(n))
	psumm := ""
	if pcnt > 0 {
		psumm = fmt.Sprintf("%d rule", pcnt)
		if pcnt != 1 {
			psumm += "s"
		}
	} else if r == "Kharej" {
		psumm = "any"
	} else {
		psumm = "none"
	}
	bmode := Cfg(n, "bond-mode")
	acSt := ""
	if p2ZOK(car) {
		acSt = DetectPreset(n)
	}

	add := func(side byte, row deckRow) {
		if side == 'L' {
			d.L = append(d.L, row)
		} else {
			d.R = append(d.R, row)
		}
	}
	hdr := func(side byte, t string) { add(side, deckRow{Type: "H", Lab: t}) }
	item := func(side byte, k, lab, val, desc string) {
		add(side, deckRow{Type: "I", Key: k, Lab: lab, Val: val, Desc: desc})
	}

	hdr('L', "Observe")
	item('L', "l", "Logs", "", "Follow "+Unit(n)+" in journalctl (Ctrl+C returns)")
	item('L', "d", "Diagnose", "", "Check key, carrier, route, MTU and run speed test")
	item('L', "v", "Speed test", "", "Transfer 10 MB down/up through the live tunnel")
	item('L', "m", "Monitor", "", "Live throughput & RTT view (any key returns)")
	hdr('L', "Route")
	item('L', "p", "Ports", psumm, "Edit port mappings (reloads in 3 s, no drop)")
	item('L', "c", "Carrier", p2trunc(car, 12), "Change transport carrier (icmp, tcp, tls, wss...)")
	item('L', "q", "Limits", "", "Per-port bandwidth limits and traffic quotas")
	item('L', "b", "Bonding", bmode, "Bond multiple carriers or set bonding policy")
	if p2ZOK(car) {
		item('L', "z", "Anti-censor", acSt, "fake-SNI, ECH, rotation, presets and matrix")
	}

	hdr('R', "Service")
	item('R', "r", "Restart", "", "Restart service (drops active connections)")
	item('R', "s", stopLab, stopDesc, "Start or stop this service now")
	item('R', "e", "Boot", bootDesc, "Toggle automatic start at boot")
	item('R', "o", "Advanced", "", "MTU, FEC, batching, sessions, bind, direction")
	hdr('R', "Identity")
	if r == "Kharej" {
		item('R', "t", "Token", "", "Show token for Iran setup")
		item('R', "k", "New key", "", "Rotate PSK and regenerate token")
		if IsReverse(n) && CompanionOf(n) == "" {
			item('R', "h", "Iran IP", "", "Change Iran peer address (reverse tunnel)")
		}
	} else {
		item('R', "t", "New token", "", "Replace Kharej, key and carrier (ports stay)")
		if IsReverse(n) {
			if car != "icmp" {
				item('R', "h", "Listen port", "", "Change reverse carrier listen port")
			}
		} else {
			item('R', "h", "Kharej IP", "", "Change Kharej peer address")
		}
		item('R', "a", "Auto mode", "", "Probe carriers and pick fastest route")
	}
	return d
}

// z_ok (bash 9341): pool/icmp carrier — anti-censor applies.
func p2ZOK(car string) bool { return IsPoolList(car) || car == "icmp" }

func p2trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// tunnel_menu_keys (bash 9283): the full key map, for "?".
func tunnelMenuKeys(n string, d *deck) {
	Page("Keys", n)
	for _, rows := range [][]deckRow{d.L, d.R} {
		for _, r := range rows {
			if r.Type == "H" {
				fmt.Fprintf(Stdout, "  %s%s%s\n", BOLD, r.Lab, RST)
			} else {
				fmt.Fprintf(Stdout, "  %s %-14s %s%s%s\n", KeyLabel(r.Key), r.Lab, GRY, r.Desc, RST)
			}
		}
	}
	fmt.Fprintf(Stdout, "  %s %-14s %s%s%s\n", KeyLabel("x"), "Delete", GRY, "Remove tunnel and all files (confirms first)", RST)
	fmt.Fprintf(Stdout, "  %s %-14s %s%s%s\n", KeyLabel("s"), "Spoofing & shaping", GRY, "How each anti-censor option behaves", RST)
	fmt.Fprintln(Stdout)
	Hint("Press any key to go back")
	KeyRead(0)
}

// p2TunnelHeader: the tunnel_page status line (bash tunnel_header 9311):
// "WatTunnel · NAME  role" left, state + carrier + rate right, then a rule.
func p2TunnelHeader(n, r string) {
	term := "stopped"
	rate := 0.0
	if IsActive(Unit(n)) {
		term = "up"
		if st, err := ParseStats(StatsRaw(n)); err == nil {
			rate = st.RateBps
			if !st.Alive {
				term = "down"
			}
		}
	}
	right := GRY + "· " + Cfg(n, "carrier") + RST
	if term == "up" && rate > 0 {
		right += " " + GRY + "·" + RST + " ↓" + Human(rate) + "/s"
	} else if term == "up" {
		right += " " + GRY + "· idle" + RST
	}
	fmt.Fprintf(Stdout, "  %sWatTunnel ·%s %s%s%s  %s%s\n", GRY, RST, BOLD, n, RST, GRY, r)
	pad := UI_W - Vlen("  WatTunnel · "+n+"  "+r) - Vlen(right)
	if pad < 2 {
		pad = 2
	}
	fmt.Fprintf(Stdout, "  %s%s%s\n", p2trunc("", 0), Rep(" ", pad), right)
	Hr()
	fmt.Fprintln(Stdout)
}

// tunnelHead: the top of the tunnel page — name and state, a traffic graph,
// then only the /stats numbers this tunnel really reports.
func tunnelHead(w io.Writer, n, r, car string, ti *tunnelInfo) {
	col, dot, txt := stateCell(r, ti.State)
	Title(w, n, r+" · "+car+"  "+col+dot+" "+txt+RST)
	if ti.State == "stopped" {
		hintLine(w, "Not running. Start it below, or read its logs.")
		fmt.Fprintln(w)
		return
	}
	if ti.Why != "" && ti.State != "up" {
		warnLine(w, ti.Why)
		fmt.Fprintln(w)
	}
	down, up := sampleTunnel(n, ti)
	if s := samples[n]; s != nil {
		gw := uiW() - 10
		if gw > 72 {
			gw = 72
		}
		Graph(w, s.down, gw, 4, CYN, Rate)
	}
	fmt.Fprintf(w, "  %s↓%s %-14s %s↑%s %s\n\n", CYN, RST, Rate(down), YEL, RST, Rate(up))
	health := fmt.Sprintf("%.0f ms · %.1f %% loss", ti.RTT, ti.Loss)
	if ti.CarCount > 1 {
		health += fmt.Sprintf(" · %d/%d paths", ti.CarAlive, ti.CarCount)
	}
	users := fmt.Sprintf("%d streams · %d sessions", ti.Streams, ti.Sess)
	if ti.DgramFlows > 0 {
		users += fmt.Sprintf(" · %d udp flows", ti.DgramFlows)
	}
	fmt.Fprintln(w, "  "+kv("Health", health))
	if fileExists(filepath.Join(P.Conf, n+".repaste")) {
		fmt.Fprintln(w, "  "+YEL+"new token: press t and paste it on Iran"+RST)
	}
	fmt.Fprintln(w, "  "+kv("Users", users))
	fmt.Fprintln(w, "  "+kv("Usage", Human(ti.In)+" in · "+Human(ti.Out)+" out"))
	fmt.Fprintln(w, "  "+kv("Ports", PortsSummary(n, uiW()-16)))
	eng := BinVersion()
	if u := UptimeOf(n); u != "" {
		eng += " · up " + u
	}
	if eng != "" {
		fmt.Fprintln(w, "  "+kv("Engine", strings.TrimPrefix(eng, " · ")))
	}
	fmt.Fprintln(w)
}

// deckItems flattens the deck into one Choose list (section order kept) plus Delete.
func deckItems(d *deck) []Item {
	var items []Item
	for _, rows := range [][]deckRow{d.L, d.R} {
		for _, r := range rows {
			if r.Type != "I" {
				continue
			}
			lab := r.Lab
			if r.Val != "" {
				lab += "  " + GRY + r.Val + RST
			}
			items = append(items, Item{Key: r.Key, Label: lab, Desc: r.Desc})
		}
	}
	return append(items, Item{Key: "x", Label: RED + "Delete" + RST, Desc: "Remove tunnel and all files (confirms first)"})
}

// tunnel_page (bash 9332): live head + one action list; keys match the bash deck.
func tunnelPage(n string) {
	sel, first := 0, true
	for {
		if !cfgFileExists(n) {
			return
		}
		r := Role(n)
		run := "stopped"
		if IsActive(Unit(n)) {
			run = "active"
		}
		car := Cfg(n, "carrier")
		d := buildDeck(n, r, run, car)
		items := deckItems(d)
		ti := tinfo(n)
		if first { // land on what this state most likely needs
			first = false
			want := "l"
			switch ti.State {
			case "stopped":
				want = "s"
			case "down", "degraded":
				want = "d"
			}
			for i, it := range items {
				if it.Key == want {
					sel = i
				}
			}
		}
		i, k := Choose(func(w io.Writer) { tunnelHead(w, n, r, car, ti) }, items, &sel,
			[]string{"⏎", "open", "letter", "jump", "?", "keys", "esc", "back"}, time.Second)
		switch {
		case i >= 0:
			k = items[i].Key
		case k == "tick" || k == "move":
			continue
		case k == "eof":
			return
		}
		switch k {
		case "p":
			runFlow("edit_ports", n)
			Pause()
		case "q":
			runFlow("limits_menu", n)
		case "x":
			Page("Delete tunnel", n)
			fmt.Fprintln(Stdout)
			runFlow("delete_tunnel", n)
			Pause()
		case "t":
			if r == "Kharej" {
				par := CompanionOf(n)
				Page("Token", n)
				p2ShowToken(orStr(par, n))
			} else {
				Page("New token", n)
				Hint("Replaces Kharej, key and carrier; ports stay.")
				fmt.Fprintln(Stdout)
				runFlow("change_key", n)
			}
			Pause()
		case "k":
			if r == "Kharej" {
				par := CompanionOf(n)
				Page("New key", n)
				runFlow("change_key", orStr(par, n))
				Pause()
			} else {
				dispatch("anticensor_menu", n)
			}
		case "r":
			fmt.Fprintln(Stdout)
			if Confirm("Restart '"+n+"'? Open connections drop.", false) {
				_ = p2Systemctl("restart", Unit(n))
			}
		case "s":
			fmt.Fprintln(Stdout)
			if run == "active" {
				_ = p2Systemctl("stop", Unit(n))
				Ok("Stopped (it still starts at boot if enabled).")
			} else {
				p2StartUnit(n)
			}
		case "e":
			fmt.Fprintln(Stdout)
			if IsEnabled(Unit(n)) {
				_ = p2Systemctl("disable", Unit(n))
				Ok("Will NOT start at boot.")
			} else {
				_ = p2Systemctl("enable", Unit(n))
				Ok("Will start at boot.")
			}
		case "0", "esc":
			return
		case "?", "/":
			tunnelMenuKeys(n, d)
		case "l":
			Page("Logs", n)
			runFlow("logs_menu", n)
			Pause()
		case "d":
			Page("Diagnose", n)
			runFlow("test_tunnel", n)
			Pause()
		case "v":
			Page("Speed test", n)
			runFlow("speed_test", n)
			Pause()
		case "m":
			runFlow("live_monitor", n)
		case "c":
			Page("Connection type", n)
			runFlow("change_type", n)
			Pause()
		case "b":
			runFlow("bonding_menu", n)
		case "z":
			runFlow("anticensor_menu", n)
		case "o":
			runFlow("adv_menu", n)
		case "a":
			if r == "Iran" {
				runFlow("auto_menu", n)
			}
		case "h":
			title := ""
			switch {
			case r == "Kharej" && IsReverse(n) && CompanionOf(n) == "":
				title = "Iran address"
			case r == "Iran" && IsReverse(n) && Cfg(n, "carrier") != "icmp":
				title = "Carrier listen port"
			case r == "Iran" && !IsReverse(n):
				title = "Kharej address"
			}
			if title != "" {
				Page(title, n)
				fmt.Fprintln(Stdout)
				runFlow("change_peer", n)
				Pause()
			}
		}
	}
}

func orStr(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

// start_unit (bash 2366): the sandbox template, enable + wait for active, the
// hidden auto helpers, and the last log lines when it fails.
func p2StartUnit(n string) {
	if step("Starting "+Unit(n), func() bool { return unitUp(n) }) {
		if IsAutoKharej(n) {
			for _, u := range autoHelpers(n) {
				unitUp(u)
			}
		}
		return
	}
	Err("Tunnel '" + n + "' failed to start. Last log lines:")
	out, _ := exec.Command("journalctl", "-u", Unit(n), "-n", "15", "--no-pager", "-o", "cat").Output()
	Stdout.Write(out)
}
