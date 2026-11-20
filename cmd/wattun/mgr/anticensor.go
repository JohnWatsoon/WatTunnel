package mgr

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The anti-censor screens: the per-tunnel anti-censor page, its pickers, the
// connection test, and the blackout kit (blackout / arm-blackout / audit-blackout).

func init() {
	Register("anticensor_menu", func(a ...string) int { anticensorMenu(arg(a, 0)); return 0 })
	Register("anticensor_test", func(a ...string) int { return b2rc(anticensorTest(arg(a, 0))) })
	Register("blackout_cmd", func(a ...string) int { return b2rc(blackoutCmd(arg(a, 0), arg(a, 1))) })
	Register("arm_blackout_cmd", func(a ...string) int { return b2rc(armBlackoutCmd(arg(a, 0))) })
	Register("audit_blackout_cmd", func(a ...string) int { auditBlackoutCmd(arg(a, 0)); return 0 })
}

func b2rc(ok bool) int {
	if ok {
		return 0
	}
	return 1
}

// acKeys are the keys the anti-censor page's "edit any key" accepts (bash AC_KEYS).
var acKeys = strings.Fields("fake-sni fake-mode fake-ttl fake-ip fake-split fp tls-small-ch ech ech-cache tls-frag pool-rotate pool-rotate-bytes governor dns-listen src-ip conns loss-ceiling keep-slow")

func fakeModeDesc(m string) string {
	switch m {
	case "auto":
		return "tests the route at start, up to 18 s (3.0.0+)"
	case "seqsum":
		return "seq + bad checksum, SNI-allowlist filters (2.8.0+)"
	case "sum":
		return "bad checksum, stateful NATs (2.7.1+)"
	case "seq":
		return "out-of-window sequence (2.7.0+)"
	case "ttl":
		return "short TTL (2.7.0+)"
	case "rst":
		return "bad-checksum RST, recommended (2.9.0+)"
	case "synrst":
		return "when rst is filtered (2.10.5+)"
	case "paws":
		return "stale timestamp, filters that check checksums (3.0.2+)"
	case "split":
		return "split the ClientHello across segments"
	case "hlen0":
		return "zero-length record first"
	case "fakeip":
		return "fake-IP handshake variant"
	case "ff":
		return "flags-and-fragments mode"
	case "all":
		return "run every desync mode"
	}
	return "direct desync mode"
}

// ---- validators (bash v_*) ----

var (
	reFakeTTL  = regexp.MustCompile(`^[0-9]{1,3}$`)
	reSNI      = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
	reECH      = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{16,}$`)
	reDNSAddr  = regexp.MustCompile(`^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})$`)
	reRotate   = regexp.MustCompile(`^[0-9]+(ms|s|m|h)$`)
	reACValue  = regexp.MustCompile(`^[A-Za-z0-9._:/@+-]+$`)
	reListenLn = regexp.MustCompile(`^(listen(?:-[a-z0-9-]+)?):\s*["']?([^"'#\s]*)`)
)

func vFakeMode(s string) bool {
	if slices.Contains(strings.Fields(acAllModes), s) {
		return true
	}
	Err("Use one of: " + acAllModes + ".")
	return false
}

func vFakeTTL(s string) bool {
	if s == "" {
		return true
	}
	if v, _ := strconv.Atoi(s); reFakeTTL.MatchString(s) && v <= 255 {
		return true
	}
	Err("Enter a hop count 1-255 (or leave empty for auto).")
	return false
}

func vSNIName(s string) bool {
	parts := strings.Split(s, ",")
	for _, p := range parts {
		if !reSNI.MatchString(strings.TrimSpace(p)) {
			Err("Enter a server name such as mci.ir.")
			return false
		}
	}
	return true
}

func vEch(s string) bool {
	switch strings.ToLower(s) {
	case "", "off", "auto", "ladder":
		return true
	}
	if reECH.MatchString(s) {
		return true
	}
	Err("--ech: use off, auto, ladder or a base64 ECHConfigList (got '" + s + "').")
	return false
}

func vDNSListen(s string) bool {
	switch strings.ToLower(s) {
	case "", "0", "off":
		return true
	}
	if m := reDNSAddr.FindStringSubmatch(s); m != nil {
		if net.ParseIP(m[1]) == nil {
			Err("DNS listen IP is invalid.")
			return false
		}
		return vPort(m[2])
	}
	Err("--dns-listen: enter an address like 127.0.0.1:53 or 127.0.0.1:5353 (or off).")
	return false
}

func vSrcIP(s string) bool {
	switch strings.ToLower(s) {
	case "", "0", "off":
		return true
	}
	if ipOK(s) {
		return true
	}
	Err("--src-ip: enter a valid IPv4/IPv6 address (or off).")
	return false
}

func vPoolRotate(s string) bool {
	if s == "" || s == "0" || s == "off" || reRotate.MatchString(s) {
		return true
	}
	Err("Enter a lifetime such as 90s, 30m or 4h (or 0 to turn it off).")
	return false
}

// ---- pickers: one Choose list per setting; "" = cancelled ----

type acOpt struct{ v, desc string }

// pickValue shows opts as a list with def selected. A last "other" row asks
// for free text checked by valid (when valid is non-nil). NONINTERACTIVE
// returns $niEnv or def.
func pickValue(title, sub string, opts []acOpt, def, niEnv, otherPrompt string, valid func(string) bool) string {
	if NonInteractive {
		v := orStr(os.Getenv(niEnv), def)
		if valid != nil && !valid(v) {
			return ""
		}
		return v
	}
	items := make([]Item, 0, len(opts)+1)
	sel := 0
	for i, o := range opts {
		items = append(items, Item{Label: o.v, Desc: o.desc})
		if o.v == def {
			sel = i
		}
	}
	if valid != nil {
		items = append(items, Item{Key: "c", Label: "other", Desc: otherPrompt})
	}
	ClearScreen()
	for {
		i, k := Choose(func(w io.Writer) { Title(w, title, sub) }, items, &sel, []string{"⏎", "choose", "esc", "back"}, 0)
		switch {
		case i >= 0 && i < len(opts):
			return opts[i].v
		case i == len(opts):
			fmt.Fprintln(Stdout)
			if !AskOK(otherPrompt, def, valid) {
				return ""
			}
			return ReplyV
		case k == "esc" || k == "q" || k == "eof":
			return ""
		}
	}
}

func pickSNIPreset(def string) string {
	return pickValue("Fake SNI", "a domain the filter lets through", []acOpt{
		{"off", ""}, {"mci.ir", "MCI"}, {"shop.mci.ir", "MCI shop"}, {"irancell.ir", "Irancell"},
		{"my.irancell.ir", "MyIrancell"}, {"tci.ir", "TCI"}, {"rightel.ir", "RighTel"}, {"divar.ir", "Divar"},
		{"digikala.com", "Digikala"}, {"bale.ai", "Bale"}, {"srbiau.ac.ir", "university portal"},
	}, def, "NI_FAKESNI", "Allowlisted SNI domain", vSNIName)
}

func pickFakeMode(def string) string {
	modes := strings.Fields(acAllModes)
	opts := make([]acOpt, len(modes))
	for i, m := range modes {
		opts[i] = acOpt{m, fakeModeDesc(m)}
	}
	return pickValue("Desync mode", "how the decoy hello is made unusable for the real server", opts, def, "NI_FAKEMODE", "", vFakeMode)
}

func pickPoolRotate(def string) string {
	return pickValue("Rotate connections every", "", []acOpt{
		{"off", ""}, {"30m", "recommended"}, {"90s", "blackout"}, {"10m", ""}, {"2h", ""}, {"4h", ""},
	}, def, "NI_POOLROT", "Pool rotation lifetime (15m, 1h ...)", vPoolRotate)
}

func pickPoolRotateBytes(def string) string {
	return pickValue("Rotate connections after", "", []acOpt{
		{"off", ""}, {"500MB", "recommended"}, {"100MB", "blackout"}, {"1GB", ""}, {"4GB", ""},
	}, def, "NI_POOLBYTES", "Pool rotation byte budget (250MB, 2GB ...)", vPoolBytes)
}

func pickEch(def string) string {
	return pickValue("ECH", "hides the real server name inside the TLS hello", []acOpt{
		{"ladder", "looks up ECH through Kharej (2.9.0+)"},
		{"auto", "looks up ECH directly (Cloudflare, Google, Quad9)"},
		{"off", ""},
	}, def, "NI_ECH", "ECH config (ladder, auto, off, or base64)", vEch)
}

func pickDNSListen(def string) string {
	return pickValue("DNS forwarder", "answers DNS through the tunnel", []acOpt{
		{"off", ""}, {"127.0.0.1:53", "this server"}, {"127.0.0.1:5353", "this server, other port"},
		{"0.0.0.0:53", "every device on the LAN"},
	}, def, "NI_DNSLISTEN", "DNS listen address:port", vDNSListen)
}

func pickSrcIP(def string) string {
	opts := []acOpt{{"off", "the route picks"}}
	if out, err := exec.Command("ip", "-4", "-o", "addr", "show", "scope", "global").Output(); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) >= 4 {
				ip := strings.SplitN(f[3], "/", 2)[0]
				if ip != "127.0.0.1" {
					opts = append(opts, acOpt{ip, f[1]})
				}
			}
		}
	}
	return pickValue("Source IP", "which local address the tunnel leaves from", opts, def, "NI_SRCIP", "Source IPv4/IPv6 address", vSrcIP)
}

// ---- kernel ping replies on the ICMP receiver (bash kreply_*) ----

// kreplyWanted: this tunnel receives ICMP requests the kernel would answer too.
func kreplyWanted(n string) bool {
	if !strings.Contains("+"+Cfg(n, "carrier")+"+", "+icmp+") {
		return false
	}
	switch Cfg(n, "icmp-type") {
	case "", "echo", "timestamp":
	default:
		return false // info/mask: Linux does not answer
	}
	if Role(n) == "Iran" {
		return IsReverse(n)
	}
	return !IsReverse(n)
}

func kreplyUsersLeft() bool {
	for _, n := range Tunnels() {
		if kreplyWanted(n) {
			return true
		}
	}
	return false
}

func kreplyApply() bool {
	mask, lim := sysctlGet("net.ipv4.icmp_ratemask"), sysctlGet("net.ipv4.icmp_ratelimit")
	m, err := strconv.Atoi(mask)
	if err != nil || lim == "unknown" {
		return false
	}
	orig := filepath.Join(P.Conf, ".kreply.orig")
	if !fileExists(orig) {
		_ = os.WriteFile(orig, []byte("net.ipv4.icmp_ratemask = "+mask+"\nnet.ipv4.icmp_ratelimit = "+lim+"\n"), 0o644)
	}
	conf := "# wattun-manager: this server receives ICMP tunnel requests. The kernel's ping replies are rate-limited so it\n" +
		"# stops sending a copy of every tunnel packet. Removed when no such tunnel is left.\n" +
		fmt.Sprintf("net.ipv4.icmp_ratemask = %d\nnet.ipv4.icmp_ratelimit = 100\n", m|1|16384)
	if os.WriteFile(kreplyConf(), []byte(conf), 0o644) != nil {
		return false
	}
	return exec.Command("sysctl", "-q", "-p", kreplyConf()).Run() == nil
}

func kreplyOffer() {
	if fileExists(kreplyConf()) || sysctlGet("net.ipv4.icmp_echo_ignore_all") == "1" {
		return
	}
	Hint("Linux here also answers every tunnel packet with a full-size copy, doubling this server's ICMP upload.")
	if P.Sandbox {
		Warn("Sandbox: this changes GLOBAL kernel settings (net.ipv4.icmp_ratemask |= 16385, icmp_ratelimit = 100) via " + kreplyConf() + "; original values saved in " + P.Conf + "/.kreply.orig.")
	}
	if step("Limiting the kernel's ping replies (normal pings keep working)", kreplyApply) {
		Hint("Undo: remove " + kreplyConf() + " and run: sysctl --system (it is also undone when the last reverse Iran tunnel is deleted).")
	}
}

// ---- direction ----

func revSumRefused(n, mode string) bool {
	if IsReverse(n) && (mode == "sum" || mode == "seqsum") {
		Err("fake-mode " + mode + " does not work on a reverse tunnel (checksum markers can kill the flow there); use rst or synrst.")
		return true
	}
	return false
}

func listenConflictDesc(proto, port string) string {
	if t := tunnelUsingListen(port, ""); t != "" {
		return "tunnel '" + t + "'"
	}
	if t := tunnelUsingPublic(port, proto, ""); t != "" {
		return "tunnel '" + t + "' (public port)"
	}
	if t := tunnelUsingMisc(port, ""); t != "" {
		return "tunnel '" + t + "' (local service)"
	}
	p, _ := strconv.Atoi(port)
	if u := portUser(p, proto); u != "" {
		return u
	}
	return "another process or tunnel"
}

// setDirection flips a tunnel between normal and reverse on this side (bash set_direction).
func setDirection(n string) bool {
	r, cr := Role(n), Cfg(n, "carrier")
	pr := rproto(cr)
	reverseHint(cr)
	switch {
	case isRpool(cr) && IsReverse(n):
		if !Confirm("Switch '"+n+"' back to the normal direction (Iran connects to Kharej)?", false) {
			return false
		}
		if r == "Kharej" {
			_, pp := SplitHP(Cfg(n, "peer"))
			if !isPortStr(pp) {
				Err("Cannot read the carrier port from peer.")
				return false
			}
			SetValue(n, "listen", `":`+pp+`"`)
			UnsetValue(n, "peer")
			UnsetValue(n, "sni")
			UnsetValue(n, "host")
			fwOpen(pp + "/" + pr)
		} else {
			UnsetValue(n, "listen")
		}
		UnsetValue(n, "reverse")
	case isRpool(cr):
		if !Confirm("Switch '"+n+"' to reverse (Kharej connects out to Iran)?", false) {
			return false
		}
		if r == "Kharej" {
			_, pp := SplitHP(Cfg(n, "listen"))
			if !isPortStr(pp) {
				Err("Cannot read the carrier port from listen.")
				return false
			}
			if !AskOK("Iran server IP address (IPv4 or IPv6)", "", vIP) {
				return false
			}
			SetValue(n, "peer", JoinHP(ReplyV, pp))
			if cr != "udp" { // reverse udp keeps it: the source port of the punches
				UnsetValue(n, "listen")
			}
			if t, err := readTokFile(n); err == nil && t.SNI != "" {
				SetValue(n, "sni", t.SNI)
				SetValue(n, "host", t.SNI)
			}
		} else {
			_, pp := SplitHP(Cfg(n, "peer"))
			if !isPortStr(pp) {
				Err("The peer has no carrier port, so reverse cannot be set up.")
				return false
			}
			pp = strconv.Itoa(atoi(pp))
			if listenBlocked(pr, atoi(pp)) {
				Err("Port " + pp + "/" + pr + " is already in use here by " + listenConflictDesc(pr, pp) + ".")
				return false
			}
			SetValue(n, "listen", `":`+pp+`"`)
			fwOpen(pp + "/" + pr)
		}
		SetValue(n, "reverse", "true")
		if fm := Cfg(n, "fake-mode"); fm == "sum" || fm == "seqsum" {
			SetValue(n, "fake-mode", "rst")
			Warn("fake-mode " + fm + " changed to rst: checksum markers are refused on a reverse tunnel.")
		}
	case IsReverse(n):
		if !Confirm("Switch '"+n+"' back to the normal direction (Iran sends the pings)?", false) {
			return false
		}
		UnsetValue(n, "reverse")
		if r == "Kharej" {
			UnsetValue(n, "peer")
		}
	default:
		if !Confirm("Switch '"+n+"' to reverse (Kharej sends the pings)?", false) {
			return false
		}
		if r == "Kharej" {
			if !AskOK("Iran server IPv4 address", "", vIPv4) {
				return false
			}
			SetValue(n, "peer", ReplyV)
		}
		SetValue(n, "reverse", "true")
	}
	if cr == "icmp" {
		if kreplyWanted(n) {
			kreplyOffer()
		} else if !kreplyUsersLeft() {
			kreplyRestore()
		}
	}
	if r == "Kharej" {
		if t, err := readTokFile(n); err == nil {
			rev := ""
			if IsReverse(n) {
				rev = "1"
			}
			_ = writeFile0600(filepath.Join(P.Conf, n+".token"), MakeToken(t.Carrier, t.Peer, t.Key, t.Path, t.SNI, t.Icmp, t.Ports, rev, t.Auto)+"\n")
		}
	}
	other := "Kharej"
	if r == "Kharej" {
		other = "Iran"
	}
	Warn("Change it on the " + other + " server too (Advanced, d), or the link stays down.")
	return true
}

func vIP(s string) bool {
	if ipOK(s) {
		return true
	}
	Err("Enter an IPv4 or IPv6 address.")
	return false
}

// ---- the anti-censor page ----

func acOn(n string) bool {
	return Cfg(n, "fake-sni") != "" || Cfg(n, "governor") == "true" || Cfg(n, "pool-rotate") != ""
}

func spoofHelp(n string) {
	ClearScreen()
	Title(Stdout, "Spoofing & shaping", n)
	fmt.Fprintf(Stdout, "  %sSpoof%s    fake-sni          decoy TLS hello (peer drops it)\n", CYN, RST)
	fmt.Fprintf(Stdout, "  %sShape%s    tcp-mimic, tls-frag, ech, hdr-mask, udp-dns, pool-rotate, shape-data, noise\n", CYN, RST)
	fmt.Fprintf(Stdout, "  %sOther%s    fec (loss parity) · governor (ICMP pacing)\n\n", CYN, RST)
	Hint("Auto mode can also test the 13 F19 shaped carriers: --extended on Kharej (both ends 3.3.0).")
	Hint("Does not hide server IPs, traffic volume/timing, or Iran↔user plaintext (no VLESS/Trojan handshake mimicry).")
	fmt.Fprintln(Stdout)
	fmt.Fprintf(Stdout, "  %s%-30s %s%s\n", BOLD, "Symptom", "Use", RST)
	for _, r := range [][2]string{
		{"SNI allowlist cuts flow", "rst/synrst mode"},
		{"SNI black-holed after hello", "ech (wss/grpc via Cloudflare)"},
		{"Non-TLS first bytes cut", "tcp-mimic + hdr-mask"},
		{"UDP cut, DNS/53 passes", "udp-dns on both ends"},
		{"Flow time/byte cap", "pool-rotate / pool-rotate-bytes"},
		{"ICMP throttled at volume", "governor + max-mbps"},
	} {
		fmt.Fprintf(Stdout, "  %-30s %s\n", r[0], r[1])
	}
	fmt.Fprintln(Stdout)
	Hint("Full table: docs/TECHNICAL.md")
	Pause()
}

func offOr(v, def string) string {
	if v == "" {
		return GRY + def + RST
	}
	return v
}

func anticensorMenu(n string) {
	if !isLinuxHost() {
		return
	}
	cr, r := Cfg(n, "carrier"), Role(n)
	if !AcDialer(n) { // the listening end has nothing to configure
		ClearScreen()
		Title(Stdout, "Anti-censor", n+" · "+cr)
		other, dir := "Kharej", "normal"
		if r != "Iran" {
			other = "Iran"
		}
		if IsReverse(n) {
			dir = "reverse"
		}
		Say("  The " + other + " server dials this " + dir + " tunnel, so anti-censor is set there.")
		Hint("To change who dials: Advanced, d, on both servers.")
		Keys(Stdout, "h", "what spoofing and shaping mean", "any key", "back")
		if k, _, _ := KeyRead(0); k == "h" {
			spoofHelp(n)
		}
		return
	}
	changed := false
	sel := 0
	set := func(k, v, msg string) {
		if v == "" || v == "off" || v == "0" {
			UnsetValue(n, k)
		} else {
			SetValue(n, k, v)
		}
		Ok(msg)
		changed = true
	}
	for {
		fs, fm, ft := Cfg(n, "fake-sni"), orStr(Cfg(n, "fake-mode"), "seq"), Cfg(n, "fake-ttl")
		pr, pb, ech := Cfg(n, "pool-rotate"), Cfg(n, "pool-rotate-bytes"), Cfg(n, "ech")
		dl, sip := Cfg(n, "dns-listen"), Cfg(n, "src-ip")
		state := "off " + GRY + "plain tunnel, full speed" + RST
		if acOn(n) {
			state = GRN + "on" + RST + " · " + DetectPreset(n)
		}
		dir := "normal " + GRY + "Iran dials Kharej" + RST
		if IsReverse(n) {
			dir = "reverse " + GRY + "Kharej dials Iran" + RST
		}
		type row struct {
			it  Item
			act string
		}
		rows := []row{{Item{Key: "1", Label: "Anti-censor", Desc: state}, "toggle"}}
		if isRevCapable(cr) {
			rows = append(rows, row{Item{Key: "r", Label: "Direction", Desc: dir}, "dir"})
		}
		if IsPoolList(cr) {
			rows = append(rows, row{Item{Key: "2", Label: "Fake SNI", Desc: offOr(fs, "off")}, "sni"})
			if fs != "" {
				rows = append(rows, row{Item{Key: "3", Label: "Desync mode", Desc: fm}, "mode"})
				if fm == "ttl" {
					rows = append(rows, row{Item{Key: "4", Label: "Fake TTL", Desc: offOr(ft, "auto")}, "ttl"})
				}
			}
			rows = append(rows,
				row{Item{Key: "5", Label: "Rotate every", Desc: offOr(pr, "off")}, "rot"},
				row{Item{Key: "6", Label: "Rotate after", Desc: offOr(pb, "off")}, "rotb"})
		} else if cr == "icmp" {
			g := ""
			if Cfg(n, "governor") == "true" {
				g = "on"
			}
			rows = append(rows, row{Item{Key: "2", Label: "Governor", Desc: offOr(g, "off")}, "gov"})
		}
		if HasEchList(cr) {
			rows = append(rows, row{Item{Key: "7", Label: "ECH", Desc: offOr(ech, "off")}, "ech"})
		}
		rows = append(rows,
			row{Item{Key: "8", Label: "DNS forwarder", Desc: offOr(dl, "off")}, "dns"},
			row{Item{Key: "9", Label: "Source IP", Desc: offOr(sip, "default route")}, "sip"},
			row{Item{Key: "w", Label: "Presets", Desc: "one-key setups for known filters"}, "preset"},
			row{Item{Key: "t", Label: "Test now", Desc: "is the link up with these settings"}, "test"},
			row{Item{Key: "m", Label: "Test all modes", Desc: "try every desync mode, keep the best"}, "matrix"},
			row{Item{Key: "p", Label: "Save as profile", Desc: ""}, "profile"},
			row{Item{Key: "e", Label: "Edit any key", Desc: ""}, "edit"},
			row{Item{Key: "h", Label: "What these do", Desc: ""}, "help"})
		items := make([]Item, len(rows))
		for i := range rows {
			items[i] = rows[i].it
		}
		ClearScreen()
		i, k := Choose(func(w io.Writer) { Title(w, "Anti-censor", n+" · "+cr) }, items, &sel,
			[]string{"⏎", "change", "esc", "back"}, 0)
		if i < 0 {
			if k == "esc" || k == "q" || k == "eof" {
				break
			}
			continue
		}
		fmt.Fprintln(Stdout)
		switch rows[i].act {
		case "help":
			spoofHelp(n)
		case "toggle": // ApplyPreset restarts the tunnel itself
			if acOn(n) {
				if Confirm("Turn anti-censor OFF (plain tunnel, open connections drop)?", true) {
					ApplyPreset(n, "off")
				}
			} else if p := pickPreset("cloudflare"); p != "" {
				ApplyPreset(n, p)
			}
			sleep(time.Second)
		case "preset":
			if p := pickPreset("cloudflare"); p != "" {
				ApplyPreset(n, p)
			}
			sleep(time.Second)
		case "dir":
			if setDirection(n) {
				step("Restarting "+Unit(n), func() bool { return Restart(Unit(n)) == nil })
				Hint("Anti-censor now belongs to the dialing end: open this screen on the other server and press 1 there.")
				Pause()
				return
			}
			Pause()
		case "edit":
			Hint("Keys: " + strings.Join(acKeys, " "))
			key := Ask("Key to set", "")
			if key == "" {
				continue
			}
			if !slices.Contains(acKeys, key) {
				Err("Unknown key '" + key + "'.")
			} else if v := Ask("Value for "+key+" (- = remove)", Cfg(n, key)); v == "" || v == "-" {
				set(key, "", key+" removed.")
			} else if reACValue.MatchString(v) {
				set(key, v, key+" set to "+v+".")
			} else {
				Err("Value may only hold letters, digits and . _ : / @ + -")
			}
			sleep(time.Second)
		case "gov":
			if Cfg(n, "governor") == "true" {
				set("governor", "", "Volume governor turned OFF.")
			} else {
				set("governor", "true", "Volume governor turned ON.")
			}
		case "sni":
			v := pickSNIPreset(orStr(fs, "mci.ir"))
			switch v {
			case "":
			case "off", "0":
				for _, k := range []string{"fake-sni", "fake-mode", "fake-ttl"} {
					UnsetValue(n, k)
				}
				Ok("Fake-SNI turned OFF.")
				changed = true
			default:
				SetValue(n, "fake-sni", v)
				if Cfg(n, "fake-mode") == "" {
					SetValue(n, "fake-mode", "rst")
				}
				Ok("Fake-SNI set to " + v)
				changed = true
			}
		case "mode":
			if v := pickFakeMode(fm); v != "" && !revSumRefused(n, v) {
				SetValue(n, "fake-mode", v)
				if v != "ttl" {
					UnsetValue(n, "fake-ttl")
				}
				Ok("Fake mode set to " + v)
				changed = true
			}
		case "ttl":
			if v := Ask("Fake TTL (hop count, empty = auto-calibrate)", ft); v == "" {
				set("fake-ttl", "", "Fake TTL set to auto-calibrate.")
			} else if vFakeTTL(v) {
				set("fake-ttl", v, "Fake TTL set to "+v+".")
			}
		case "rot":
			if v := pickPoolRotate(orStr(pr, "30m")); v != "" {
				set("pool-rotate", v, "Pool rotate by time: "+v+".")
			}
		case "rotb":
			if v := pickPoolRotateBytes(orStr(pb, "500MB")); v != "" {
				set("pool-rotate-bytes", v, "Pool rotate by bytes: "+v+".")
			}
		case "ech":
			if v := pickEch(orStr(ech, "ladder")); v != "" {
				set("ech", v, "ECH: "+v+".")
			}
		case "dns":
			if v := pickDNSListen(orStr(dl, "off")); v != "" {
				set("dns-listen", v, "DNS forwarder: "+v+".")
			}
		case "sip":
			if v := pickSrcIP(orStr(sip, "off")); v != "" {
				set("src-ip", v, "Carrier source IP: "+v+".")
			}
		case "test":
			anticensorTest(n)
			Pause()
		case "matrix":
			dispatch("ac_matrix_cmd", n)
			Pause()
		case "profile":
			if p := Ask("Profile name to save", ""); p != "" {
				dispatch("profile_cmd", "save", p, n)
				sleep(time.Second)
			}
		}
	}
	if changed {
		Hint("Applying changes: restarting '" + n + "'...")
		step("Restarting "+Unit(n), func() bool { return Restart(Unit(n)) == nil })
	}
}

// ---- the connection test ----

func anticensorTest(n string) bool {
	if !cfgFileExists(n) {
		Err("No tunnel named '" + n + "'.")
		return false
	}
	r, cr := Role(n), Cfg(n, "carrier")
	if !AcDialer(n) {
		Err("'" + n + "' does not dial the carrier (anti-censorship verification runs on the dialing end).")
		return false
	}
	fmt.Fprintln(Stdout)
	Title(Stdout, "Anti-censor test", n+" · "+r+" · "+cr)
	if !IsActive(Unit(n)) {
		Warn(n + " is stopped. Starting it.")
		_ = Start(Unit(n))
		sleep(time.Second)
	}
	fks, fkm, fkt := Cfg(n, "fake-sni"), orStr(Cfg(n, "fake-mode"), "seq"), Cfg(n, "fake-ttl")
	if fks != "" {
		v := fks + " · " + fkm
		if fkt != "" {
			v += " · ttl " + fkt
		}
		Say("  " + kv("fake sni", v))
	} else {
		Say("  " + kv("fake sni", GRY+"off"+RST))
	}
	if rot := Cfg(n, "pool-rotate"); rot != "" {
		if b := Cfg(n, "pool-rotate-bytes"); b != "" {
			rot += " / " + b
		}
		Say("  " + kv("rotate", rot))
	}
	for _, kl := range [][2]string{{"ech", "ech"}, {"dns-listen", "dns relay"}, {"src-ip", "source ip"}} {
		if v := Cfg(n, kl[0]); v != "" {
			Say("  " + kv(kl[1], v))
		}
	}
	if Cfg(n, "governor") == "true" {
		Say("  " + kv("governor", "on"))
	}
	fmt.Fprintln(Stdout)

	wait := atoi(orStr(os.Getenv("ANTICENSOR_TEST_WAIT"), "6"))
	var m map[string]any
	alive := false
	_ = spin("Waiting for the link", func() error {
		for i := 0; i < wait; i++ {
			if s, err := statsOf(n); err == nil && get(s, "alive") == "true" {
				m, alive = s, true
				return nil
			}
			sleep(time.Second)
		}
		return nil
	})
	if !alive {
		Err(fmt.Sprintf("No link within %d s", wait))
		if fks != "" {
			Hint(" · Try blackout:  " + P.Self + " blackout " + n + " blackout")
			Hint(" · Try mode rst/synrst (anti-censor page, Desync mode) or another SNI (irancell.ir, divar.ir)")
		} else {
			Hint(" · Enable fake-SNI:  " + P.Self + " blackout " + n + " mci")
		}
		if cr == "icmp" {
			Hint(" · ICMP filtered? Turn the governor on (anti-censor page, Governor)")
		}
		return false
	}
	secHdr(Stdout, "Result")
	Ok(fmt.Sprintf("Connected · RTT %s ms · %s in / %s out", Ms(getFFlat(m, "rtt_ms", "srtt_ms")),
		orStr(get(m, "pkts_in"), "0"), orStr(get(m, "pkts_out"), "0")))
	if fp, ok := m["filter_profile"]; ok && fp != nil {
		Say("  " + kv("filter", strings.TrimPrefix(fmt.Sprint(fp), "map")))
	}
	if e := get(m, "ech"); e != "" {
		Say("  " + kv("ech", e))
	}
	if maps := YmlMaps(n); len(maps) > 0 {
		lp, proto := SpecL(maps[0]), SpecP(maps[0])
		if isDigits(lp) {
			if proto == "tcp" {
				if c, err := net.DialTimeout("tcp", "127.0.0.1:"+lp, 2*time.Second); err == nil {
					c.Close()
					Ok("Port :" + lp + "/" + proto + " answers")
				}
			} else if portBusy(atoi(lp), proto, false) {
				Ok("Port :" + lp + "/" + proto + " open")
			}
		}
	}
	return true
}

// ---- the blackout kit ----

// blackoutCmd turns the resilience kit on: a preset, or fake-sni with a custom allowlisted name.
func blackoutCmd(n, sni string) bool {
	if !isLinuxHost() {
		Err("The resilience kit is a Linux feature (fake-SNI needs CAP_NET_RAW, like the icmp carrier).")
		return false
	}
	if !cfgFileExists(n) {
		Err("No tunnel named '" + n + "'.")
		return false
	}
	if !AcDialer(n) {
		Err("'" + n + "' does not dial the carrier, so anti-censorship runs on its other end (Iran normally, Kharej when reverse).")
		return false
	}
	if sni == "" && !NonInteractive {
		if sni = pickPreset("mci"); sni == "" {
			return false
		}
		ClearScreen()
		Title(Stdout, "Blackout kit", n)
	}
	if sni == "" {
		Err("An allowlisted name or preset is required (blackout " + n + " mci.ir or blackout " + n + " mci).")
		return false
	}
	interactive := IsTTY && !NonInteractive
	if IsBuiltinPreset(sni) {
		if !ApplyPreset(n, sni) {
			return false
		}
		if interactive {
			anticensorTest(n)
		}
		return true
	}
	if Role(n) != "Iran" || !IsPool(Cfg(n, "carrier")) || IsReverse(n) {
		Err("'" + n + "' is not a direct Iran tunnel on a pool carrier (tcp, tls, ws, wss, h2, h2c, grpc); the kit is client-only and only attaches there.")
		return false
	}
	if !vSNIName(sni) {
		return false
	}
	if !binVerOK("2.7.0") {
		Err("fake-sni needs wattun 2.7.0 or newer on this server (run: " + P.Self + " update).")
		return false
	}
	SetValue(n, "fake-sni", sni)
	SetValue(n, "fake-mode", "rst")
	UnsetValue(n, "fake-ttl")
	Ok("Resilience kit on: fake-sni " + sni + " (rst mode). pool-rotate stays off; tune it on the anti-censor page.")
	if !step("Restarting "+Unit(n), func() bool { return Restart(Unit(n)) == nil }) {
		Err("Restart failed: run  systemctl restart " + Unit(n))
		return false
	}
	Ok("Restart applied. Watch whether the link comes back: " + P.Self + " test " + n)
	if interactive {
		anticensorTest(n)
	}
	return true
}

// dropListenLines removes every listen: and listen-*: line of n's config.
func dropListenLines(n string) {
	f := filepath.Join(P.Conf, n+".yml")
	var out []string
	for _, l := range strings.Split(p2ReadText(f), "\n") {
		if !reListenLn.MatchString(l) {
			out = append(out, l)
		}
	}
	_ = atomicWrite(f, []byte(strings.Join(out, "\n")), 0o600)
}

func armBlackoutCmd(n string) bool {
	if !cfgFileExists(n) {
		Err("No tunnel named '" + n + "'.")
		return false
	}
	if Role(n) != "Kharej" {
		Say("  " + BOLD + "Arming Iran '" + n + "' for autonomous blackout failover" + RST)
		SetValue(n, "path-probe-max", "6s")
		SetValue(n, "governor", "true")
		healEnable()
		_ = Restart(Unit(n))
		Ok("Iran '" + n + "' armed for autonomous failover (fast silence detection, auto-heal timer active).")
		return true
	}
	Say("  " + BOLD + "Arming Kharej '" + n + "' in fortress mode for blackout resilience" + RST)
	if isLinuxHost() {
		for _, kv := range []string{"net.ipv4.icmp_echo_ignore_all=0", "net.core.default_qdisc=fq",
			"net.ipv4.tcp_congestion_control=bbr", "net.core.rmem_max=67108864", "net.core.wmem_max=67108864"} {
			_ = exec.Command("sysctl", "-w", kv).Run()
		}
	}
	var used []string
	pick := func(proto, what string) (string, bool) {
		p, err := randOpenPort(proto, used)
		if err != nil {
			Err("No free " + strings.ToUpper(proto) + " port for the blackout " + what + " listener.")
			return "", false
		}
		used = append(used, strconv.Itoa(p))
		return strconv.Itoa(p), true
	}
	ptcp, ok1 := pick("tcp", "tcp")
	ptls, ok2 := pick("tcp", "tls")
	pwss, ok3 := pick("tcp", "wss")
	pudp, ok4 := pick("udp", "udp")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return false
	}
	dropListenLines(n)
	SetValue(n, "carrier", "icmp+tcp+tls+wss+udp")
	SetValue(n, "listen-tcp", `":`+ptcp+`"`)
	SetValue(n, "listen-tls", `":`+ptls+`"`)
	SetValue(n, "listen-wss", `":`+pwss+`"`)
	SetValue(n, "listen-udp", `":`+pudp+`"`)
	if Cfg(n, "path") == "" {
		SetValue(n, "path", randPath())
	}
	if Cfg(n, "dns-relay-upstream") == "" {
		SetValue(n, "dns-relay-upstream", "1.1.1.1:53")
	}
	fwOpen(ptcp+"/tcp", ptls+"/tcp", pwss+"/tcp", pudp+"/udp")
	_ = Restart(Unit(n))
	Ok(fmt.Sprintf("Kharej '%s' armed in fortress mode (ICMP, TCP:%s, TLS:%s, WSS:%s, UDP:%s).", n, ptcp, ptls, pwss, pudp))
	Say("  Emergency blackout token for Iran:")
	showToken(n)
	return true
}

func auditBlackoutCmd(n string) {
	if !cfgFileExists(n) {
		Err("No tunnel named '" + n + "'.")
		return
	}
	r := Role(n)
	pass, fail := 0, 0
	good := func(s string) { Ok(s); pass++ }
	bad := func(s string) { Warn(s); fail++ }
	fmt.Fprintln(Stdout)
	Title(Stdout, "Blackout readiness", n+" · "+r)

	pid := strings.TrimSpace(ShowProp(Unit(n), "MainPID"))
	if atoi(pid) > 0 && fileReadable("/proc/"+pid+"/status") {
		capEff := ""
		for _, l := range strings.Split(mustRead("/proc/"+pid+"/status"), "\n") {
			if f := strings.Fields(l); len(f) == 2 && strings.EqualFold(f[0], "CapEff:") {
				capEff = f[1]
			}
		}
		if capEff != "" {
			good("Process capabilities active (PID " + pid + ", CapEff " + capEff + ")")
		} else {
			bad("Unable to read process capabilities")
		}
	} else {
		bad("Tunnel process is not currently running")
	}

	if isLinuxHost() {
		if sysctlGet("net.ipv4.icmp_echo_ignore_all") == "0" {
			good("Sysctl: net.ipv4.icmp_echo_ignore_all == 0 (ICMP replies enabled)")
		} else {
			good("Sysctl: net.ipv4.icmp_echo_ignore_all == 1 (plain ping is off; the ICMP tunnel still receives its packets)")
		}
		if cc := sysctlGet("net.ipv4.tcp_congestion_control"); cc == "bbr" {
			good("Sysctl: congestion control is BBR")
		} else {
			Hint("Sysctl: congestion control is " + cc + " (BBR recommended for anti-policing)")
		}
	}

	if r == "Kharej" {
		for _, l := range strings.Split(p2ReadText(filepath.Join(P.Conf, n+".yml")), "\n") {
			m := reListenLn.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			car := strings.TrimPrefix(m[1], "listen-")
			if m[1] == "listen" {
				car = Cfg(n, "carrier")
			}
			_, lp := SplitHP(m[2])
			if !isDigits(lp) {
				continue
			}
			pr := rproto(car)
			if u := portUser(atoi(lp), pr); u != "" && !strings.Contains(u, "wattun") {
				bad("Port " + lp + "/" + pr + " bound by another process: " + u)
			} else {
				good("Port " + lp + "/" + pr + " available or bound by wattun")
			}
		}
	}

	if up := Cfg(n, "dns-relay-upstream"); up != "" {
		good("DNS in-band relay configured (" + up + ")")
	} else {
		Hint("DNS in-band relay not configured (default upstreams active)")
	}
	if IsActive(Unit(n)) {
		good("Service " + Unit(n) + " is active")
	} else {
		bad("Service " + Unit(n) + " is not active")
	}
	fmt.Fprintln(Stdout)
	if fail == 0 {
		Say(fmt.Sprintf("  %s%s%s ready for a blackout%s  %d checks passed", GRN, BOLD, MarkOK, RST, pass))
	} else {
		Say(fmt.Sprintf("  %s%s%s partly ready%s  %d passed, %d warnings", YEL, BOLD, MarkWarn, RST, pass, fail))
	}
	fmt.Fprintln(Stdout)
}
