package mgr

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// The Advanced page: engine knobs per tunnel, grouped Performance, Shaping & DPI, Safety,
// State & data. Every change restarts the tunnel on exit (bash adv_menu). A key is shown
// only when this server's engine knows it: an older engine stops at startup on an unknown key.

func init() {
	Register("adv_menu", func(a ...string) int { advMenu(arg(a, 0)); return 0 })
	Register("change_peer", func(a ...string) int { return b2rc(changePeer(arg(a, 0))) })
	Register("change_type", func(a ...string) int { changeType(arg(a, 0)); return 0 })
	Register("logs_menu", func(a ...string) int { LogsMenu(arg(a, 0), Stdout); return 0 })
	Register("auto_menu", func(a ...string) int { autoMenu(arg(a, 0)); return 0 })
}

const (
	engMaxSessions = 16    // maxSessions
	engMaxConns    = 64    // poolMaxConns
	engMTUMin      = 256   // MinPayload
	engMTUMax      = 1400  // MaxPayloadHi: icmp/udp/gre/ipip and any bond with one
	engMTUMaxPool  = 16384 // poolMaxMTU
)

// unsetWord: the answers that mean "back to the engine default".
func unsetWord(v string) bool { return v == "" || v == "-" || v == "0" || v == "default" }

func shapedMTU(c string, def int) int {
	switch c {
	case "dnscrypt-udp":
		return 1326
	case "ntp-direct":
		return 1336
	case "openvpn-dco", "l2tpv3":
		return 1396
	case "srtp-direct":
		return 1388
	case "fou-gre", "gue-ipip", "vxlan", "geneve", "xfrm-ipsec":
		return 1392
	case "sit", "6to4":
		return 1360
	case "etherip":
		return 1384
	}
	return def
}

// mtuMaxFor: the largest mtu the engine will not clamp for a carrier list (a bond takes its smallest leg).
func mtuMaxFor(list string) int {
	if list == "" {
		return engMTUMax
	}
	hi := engMTUMaxPool
	for _, c := range strings.Split(list, "+") {
		leg := engMTUMax
		if IsPool(CarrierLegBase(c)) {
			leg = engMTUMaxPool
		}
		hi = min(hi, shapedMTU(CarrierLegBase(c), leg))
	}
	return hi
}

func intIn(s string, lo, hi int) bool {
	v, err := strconv.Atoi(s)
	return err == nil && v >= lo && v <= hi
}

func floatOf(s string) (float64, bool) {
	if !regexp.MustCompile(`^[0-9]{1,2}(\.[0-9]+)?$`).MatchString(s) {
		return 0, false
	}
	f, _ := strconv.ParseFloat(s, 64)
	return f, true
}

func vSessions(s, car string, rev bool) bool {
	if unsetWord(s) {
		return true
	}
	if !intIn(s, 1, engMaxSessions) {
		Err(fmt.Sprintf("Enter sessions count 1-%d (or 0/default to unset).", engMaxSessions))
		return false
	}
	if atoi(s) == 1 {
		return true
	}
	if rev {
		Err("sessions > 1 does not work with reverse (the server dials one pool).")
		return false
	}
	switch car {
	case "udp", "tcp", "tls", "ws", "wss", "h2", "h2c", "grpc":
		return true
	}
	Err("sessions > 1 needs one udp/tcp/tls/ws/wss/h2/h2c/grpc carrier, not '" + car + "' (bonds, icmp/gre/ipip and the F19 shapes run one session).")
	return false
}

func vConns(s string) bool {
	if unsetWord(s) || intIn(s, 1, engMaxConns) {
		return true
	}
	Err(fmt.Sprintf("Enter conns count 1-%d (the engine caps a pool at %d; or 0/default to unset).", engMaxConns, engMaxConns))
	return false
}

func vMTU(s, car string) bool {
	hi := mtuMaxFor(car)
	if unsetWord(s) || intIn(s, engMTUMin, hi) {
		return true
	}
	Err(fmt.Sprintf("Enter MTU %d-%d for carrier '%s' (or 0/default to unset).", engMTUMin, hi, car))
	return false
}

// vUDPHop: packets per source port, 2-1000 (Wraith, 3.3.9).
func vUDPHop(s string) bool {
	if unsetWord(s) || intIn(s, 2, 1000) {
		return true
	}
	Err("Use 2 to 1000 (0 = off).")
	return false
}

func vWinMax(s string) bool {
	if unsetWord(s) || intIn(s, 4, 64) {
		return true
	}
	Err("Enter the per-stream window cap in MB (4-64), or 0/- for the engine's auto value.")
	return false
}

func vOnOff(s string) bool {
	switch s {
	case "on", "off", "true", "false", "1", "0", "default", "":
		return true
	}
	Err("Use on or off.")
	return false
}

func isOn(s string) bool { return s == "on" || s == "true" || s == "1" }

func vFecOn(s string, off float64) bool {
	if s == "" || s == "-" || s == "default" {
		return true
	}
	v, ok := floatOf(s)
	if !ok {
		Err("Enter a loss percentage above 0 and at most 50 (for example 2 or 0.5).")
		return false
	}
	if v > 0 && v <= 50 && v > off {
		return true
	}
	Err(fmt.Sprintf("fec-on-loss must be above 0, at most 50 and above fec-off-loss (%g).", off))
	return false
}

func vFecOff(s string, on float64) bool {
	if s == "" || s == "-" || s == "default" {
		return true
	}
	v, ok := floatOf(s)
	if !ok {
		Err("Enter 0 or a loss percentage (for example 0.5 or 2).")
		return false
	}
	if v >= 0 && v < on {
		return true
	}
	Err(fmt.Sprintf("fec-off-loss must be 0 or more and below fec-on-loss (%g).", on))
	return false
}

var reAbsPath = regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`)

func vStateDir(s string) bool {
	if unsetWord(s) {
		return true
	}
	switch {
	case !reAbsPath.MatchString(s):
		Err("Enter an absolute directory such as /run/wattun (no spaces), or - for the default next to the config.")
		return false
	case strings.Contains("/"+strings.Trim(s, "/")+"/", "/../"):
		Err("The state directory cannot contain '..'.")
		return false
	case len(s) > 200:
		Err("That path is too long (200 characters at most).")
		return false
	}
	if !strings.HasPrefix(s+"/", "/run/wattun/") && !strings.HasPrefix(s+"/", "/etc/wattun/") {
		Warn("The shipped systemd unit only guarantees writes under /run/wattun; add '" + s + "' to its ReadWritePaths or the engine stops at startup.")
	}
	if st, err := os.Stat(s); err == nil && !st.IsDir() {
		Err(s + " exists and is not a directory.")
		return false
	}
	return true
}

func vStateSave(s string) bool {
	if s == "" || s == "-" || s == "default" || intIn(s, 0, 2592000) {
		return true
	}
	Err("Enter the save interval in whole seconds, at most 2592000 (30 days; 0 = only on shutdown).")
	return false
}

func vShapeData(s string) bool {
	if unsetWord(s) || s == "0.0" {
		return true
	}
	if v, ok := floatOf(s); ok && v > 0 && v <= 25 {
		return true
	}
	Err("shape-data must be 0 (off) or up to 25 percent, got " + s + ".")
	return false
}

func vNoiseMode(s string) bool {
	switch s {
	case "", "off", "low", "med", "custom":
		return true
	}
	Err("Use off, low, med or custom.")
	return false
}

func vNoiseBps(s string) bool {
	if intIn(s, 64, 1000000) {
		return true
	}
	Err("Enter the filler budget in bytes/second (64..1000000).")
	return false
}

var reNoiseWin = regexp.MustCompile(`^([01]?[0-9]|2[0-3]):([0-5][0-9])-([01]?[0-9]|2[0-3]):([0-5][0-9])$`)

func vNoiseWindow(s string) bool {
	if s == "" || s == "-" || s == "default" {
		return true
	}
	m := reNoiseWin.FindStringSubmatch(s)
	if m == nil {
		Err("Enter a local-clock window such as 02:00-06:00 (HH:MM-HH:MM), or - for all day.")
		return false
	}
	if atoi(m[1])*60+atoi(m[2]) == atoi(m[3])*60+atoi(m[4]) {
		Err("The noise window cannot start and end at the same time; leave it empty for all day.")
		return false
	}
	return true
}

// ipOrCIDR: one allowlist entry; a v4-mapped v6 prefix shorter than /96 is refused like the engine does.
func ipOrCIDR(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return false
	}
	return !(p.Addr().Is4In6() && p.Bits() < 96)
}

func vAllowClients(s string) bool {
	if s == "" || s == "-" || s == "default" {
		return true
	}
	for _, e := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if !ipOrCIDR(e) {
			Err("'" + e + "' is not an IPv4/IPv6 address or CIDR prefix.")
			return false
		}
	}
	return true
}

func allowClientsDir() string {
	if P.Sandbox {
		return P.Conf
	}
	return "/etc/wattun"
}

// allowClientsCDNRisk: -allow-clients cannot be used (the source is a CDN edge).
func allowClientsCDNRisk(car, sni string) bool {
	if sni != "" && sni != "-" {
		return true
	}
	for _, c := range strings.Split(car, "+") {
		if isCDNCar(CarrierLegBase(c)) {
			return true
		}
	}
	return false
}

func vAllowClientsFile(s string) bool {
	if s == "" || s == "-" || s == "default" {
		return true
	}
	dir := allowClientsDir()
	switch {
	case !reAbsPath.MatchString(s):
		Err("Enter an absolute path to the list file (no spaces), or - for the inline list.")
	case !strings.HasPrefix(s, dir+"/"):
		Err("Put the allowlist file under " + dir + "/ (the shipped unit can only read that path); got " + s + ".")
	case !fileExists(s):
		Err(s + " does not exist (the engine reads the file at startup).")
	case !fileReadable(s):
		Err(s + " is not readable.")
	default:
		return true
	}
	return false
}

func hasHTTPCarrier(list string) bool {
	for _, c := range strings.Split(list, "+") {
		if isCDNCar(CarrierLegBase(c)) {
			return true
		}
	}
	return false
}

// advRow is one setting of the Advanced page.
type advRow struct {
	key, label, val, def, unit, group string
	edit                              func() bool // true = changed (needs the restart)
}

func advMenu(n string) {
	r := Role(n)
	changed := false
	sel := 0
	need := func(ver string) bool {
		if binVerOK(ver) {
			return true
		}
		Err("This setting needs wattun " + ver + " or newer on this server (run: " + P.Self + " update); an older engine rejects the key at startup.")
		return false
	}
	// ask asks for key's value; an unset word removes it, anything valid is written.
	ask := func(key, prompt, def string, valid func(string) bool, unset func(string) bool) bool {
		if !AskOK(prompt, def, valid) {
			return false
		}
		if unset(ReplyV) {
			UnsetValue(n, key)
		} else {
			SetValue(n, key, ReplyV)
		}
		return true
	}
	// toggle flips a boolean key (written true/false: Go's flag parser rejects "on").
	toggle := func(key, hint string) bool {
		if hint != "" {
			Hint(hint)
		}
		if Cfg(n, key) == "true" {
			UnsetValue(n, key)
			Ok(key + " off.")
		} else {
			SetValue(n, key, "true")
			Ok(key + " on.")
		}
		return true
	}
	onOffVal := func(key string) string {
		if Cfg(n, key) == "true" {
			return "on"
		}
		return ""
	}
	for {
		cr := Cfg(n, "carrier")
		rev := IsReverse(n)
		k33, k338, k339 := binVerOK("3.3.0"), binVerOK("3.3.8"), binVerOK("3.3.9")
		fecAuto := Cfg(n, "fec") == "auto"
		fecOn, _ := strconv.ParseFloat(orStr(Cfg(n, "fec-on-loss"), "2"), 64)
		fecOff, _ := strconv.ParseFloat(orStr(Cfg(n, "fec-off-loss"), "0.5"), 64)
		noise := orStr(Cfg(n, "noise"), "off")
		var rows []advRow
		add := func(on bool, row advRow) {
			if on {
				rows = append(rows, row)
			}
		}
		g := "Performance"
		add(true, advRow{"m", "Speed limit", Cfg(n, "max-mbps"), "none", "MB/s", g, func() bool {
			return ask("max-mbps", "Speed ceiling in MB/s (- or 0 = unset)", Cfg(n, "max-mbps"), vMbpsAdv, unsetWord)
		}})
		add(r == "Iran", advRow{"s", "Sessions", Cfg(n, "sessions"), "auto", "", g, func() bool {
			return ask("sessions", fmt.Sprintf("Sessions 1-%d (- or 0 = unset)", engMaxSessions), Cfg(n, "sessions"),
				func(s string) bool { return vSessions(s, cr, rev) }, unsetWord)
		}})
		add(true, advRow{"c", "Conns", Cfg(n, "conns"), "auto", "", g, func() bool {
			return ask("conns", fmt.Sprintf("Conns 1-%d (- or 0 = unset)", engMaxConns), Cfg(n, "conns"), vConns, unsetWord)
		}})
		add(true, advRow{"u", "MTU", Cfg(n, "mtu"), "auto", "", g, func() bool {
			return ask("mtu", fmt.Sprintf("MTU %d-%d for '%s' (- or 0 = unset)", engMTUMin, mtuMaxFor(cr), cr), Cfg(n, "mtu"),
				func(s string) bool { return vMTU(s, cr) }, unsetWord)
		}})
		add(k339 && isBond(cr), advRow{"z", "MTU adapt", onOffVal("mtu-adapt"), "off", "", g, func() bool {
			return toggle("mtu-adapt", "Clamps a path to 640 B for 30 s after 8 lost large packets in a row. This end only; the peer can run any version.")
		}})
		add(cr == "icmp", advRow{"i", "ICMP type", Cfg(n, "icmp-type"), "echo", "", g, func() bool {
			Hint("Must match Kharej.")
			return ask("icmp-type", "ICMP type", orStr(Cfg(n, "icmp-type"), "echo"), vIcmp, func(s string) bool { return s == "echo" })
		}})
		batchDef := "off"
		if cr == "icmp" {
			batchDef = "on"
		}
		add(cr == "icmp" || cr == "udp", advRow{"y", "Batching", Cfg(n, "batch"), batchDef, "", g, func() bool {
			if !need("3.0.0") {
				return false
			}
			return ask("batch", "Batching (on, off, default)", orStr(Cfg(n, "batch"), "default"), func(s string) bool {
				if s == "on" || s == "off" || s == "default" || s == "-" || s == "" {
					return true
				}
				Err("Use on, off or default.")
				return false
			}, func(s string) bool { return s != "on" && s != "off" })
		}})
		hopKey := "h" // the bash key; a udp+ws/h2 bond also shows Probe guard on h
		if hasHTTPCarrier(cr) {
			hopKey = "9"
		}
		add(k339 && r == "Iran" && !rev && strings.Contains("+"+cr+"+", "+udp+"), advRow{hopKey, "UDP hop", Cfg(n, "udp-hop"), "off", "pkts/port", g, func() bool {
			Hint("Sends from a new UDP source port every N-1.5N packets: passes a filter that cuts each flow after ~30 packets. 12 = field setting. Kharej needs no change.")
			return ask("udp-hop", "Packets per source port (0 = off)", Cfg(n, "udp-hop"), vUDPHop, unsetWord)
		}})
		add(binVerOK("3.0.3"), advRow{"e", "Window max", Cfg(n, "win-max"), "auto", "MB", g, func() bool {
			return ask("win-max", "Stream receive window cap in MB (4-64; 0/- = auto)", orStr(Cfg(n, "win-max"), "0"), vWinMax, unsetWord)
		}})
		add(binVerOK("3.0.0"), advRow{"r", "Loss ceiling", onOffVal("loss-ceiling"), "off", "", g, func() bool {
			return toggle("loss-ceiling", "Also cuts the rate on sudden loss spikes (the default control reacts to delay only).")
		}})

		g = "Shaping & DPI"
		add(true, advRow{"f", "FEC", Cfg(n, "fec"), "off", "", g, func() bool {
			return ask("fec", "FEC: off or auto", orStr(Cfg(n, "fec"), "off"), vFec, func(s string) bool { return s == "off" })
		}})
		add(fecAuto && k33, advRow{"o", "FEC on loss", Cfg(n, "fec-on-loss"), "2", "%", g, func() bool {
			Hint("Enables FEC parity above this loss % (0 < on <= 50).")
			return ask("fec-on-loss", fmt.Sprintf("FEC on-loss percent (above %g%%)", fecOff), Cfg(n, "fec-on-loss"),
				func(s string) bool {
					if (s == "" || s == "-" || s == "default") && !(2 > fecOff) {
						Err(fmt.Sprintf("fec-off-loss is %g %%, so default 2 %% is not above it; lower fec-off-loss first.", fecOff))
						return false
					}
					return vFecOn(s, fecOff)
				}, func(s string) bool { return s == "" || s == "-" || s == "default" })
		}})
		add(fecAuto && k33, advRow{"x", "FEC off loss", Cfg(n, "fec-off-loss"), "0.5", "%", g, func() bool {
			Hint("Stops FEC parity below this loss % (must stay below fec-on-loss).")
			return ask("fec-off-loss", fmt.Sprintf("FEC off-loss percent (below %g%%)", fecOn), Cfg(n, "fec-off-loss"),
				func(s string) bool {
					if (s == "" || s == "-" || s == "default") && !(0.5 < fecOn) {
						Err(fmt.Sprintf("fec-on-loss is %g %%, so default 0.5 %% is not below it; raise fec-on-loss first.", fecOn))
						return false
					}
					return vFecOff(s, fecOn)
				}, func(s string) bool { return s == "" || s == "-" || s == "default" })
		}})
		add(k33, advRow{"p", "Shape data", Cfg(n, "shape-data"), "off", "%", g, func() bool {
			Hint("Pads stream packets up to N% (0 = off, max 25%). Spends bandwidth.")
			return ask("shape-data", "shape-data percent (0..25)", Cfg(n, "shape-data"), vShapeData,
				func(s string) bool { return unsetWord(s) || s == "0.0" })
		}})
		add(k33, advRow{"n", "Noise", Cfg(n, "noise"), "off", "", g, func() bool {
			Hint("Idle filler per session: low ~11 MB/d, med ~88 MB/d (times the session count).")
			m := pickValue("Idle noise", n, []acOpt{{"off", ""}, {"low", "~11 MB a day"}, {"med", "~88 MB a day"}, {"custom", "set bytes per second"}},
				noise, "NI_NOISE", "", nil)
			switch m {
			case "":
				return false
			case "off":
				UnsetValue(n, "noise")
				UnsetValue(n, "noise-bps")
			case "low", "med":
				SetValue(n, "noise", m)
				UnsetValue(n, "noise-bps")
			case "custom":
				cb := Cfg(n, "noise-bps")
				if !intIn(cb, 64, 1000000) {
					cb = "1024"
				}
				if !AskOK("Noise filler bytes/second (64..1000000)", cb, vNoiseBps) {
					return false
				}
				SetValue(n, "noise-bps", ReplyV)
				SetValue(n, "noise", "custom")
			}
			return true
		}})
		add(k33 && (noise == "custom" || Cfg(n, "noise-bps") != ""), advRow{"g", "Noise B/s", Cfg(n, "noise-bps"), "custom only", "B/s", g, func() bool {
			return ask("noise-bps", "Noise filler bytes/second (64..1000000)", Cfg(n, "noise-bps"), vNoiseBps, func(string) bool { return false })
		}})
		add(k33 && (noise != "off" || Cfg(n, "noise-window") != ""), advRow{"w", "Noise window", Cfg(n, "noise-window"), "all day", "", g, func() bool {
			return ask("noise-window", "Noise window HH:MM-HH:MM (empty = all day)", Cfg(n, "noise-window"), vNoiseWindow,
				func(s string) bool { return s == "" || s == "-" || s == "default" })
		}})
		add(k338 && hasHTTPCarrier(cr), advRow{"h", "Probe guard", onOffVal("probe-guard"), "off", "", g, func() bool {
			return toggle("probe-guard", "Answers only tunnel requests that carry the key's token; a prober gets the decoy pages. Turn it on at BOTH ends (3.3.8+), or the link drops.")
		}})
		add(k338 && strings.Contains("+"+cr+"+", "+udp+") && Cfg(n, "udp-dns") == "true", advRow{"b", "DNS EDNS", onOffVal("udp-dns-edns"), "off", "", g, func() bool {
			return toggle("udp-dns-edns", "Makes udp-dns frames complete DNS (EDNS0, real TXT answers). Both ends 3.3.8+; turn it on at Kharej first.")
		}})
		if AcDialer(n) {
			st := "off"
			if acOn(n) || Cfg(n, "ech") != "" {
				st = "on"
			}
			add(true, advRow{"k", "Anti-censor", st, "", "", g, func() bool { anticensorMenu(n); return false }})
		}

		g = "Safety"
		risk := allowClientsCDNRisk(cr, Cfg(n, "sni"))
		add(k33 && r == "Kharej" && !risk, advRow{"j", "Allow clients", Cfg(n, "allow-clients"), "any source", "", g, func() bool {
			Hint("Admits only these source IPs/CIDRs (ignored in reverse mode).")
			ok := ask("allow-clients", "Allowed client addresses/CIDRs (- = any)", Cfg(n, "allow-clients"), vAllowClients,
				func(s string) bool { return s == "" || s == "-" || s == "default" })
			if ok && Cfg(n, "allow-clients") != "" && Cfg(n, "allow-clients-file") != "" {
				Warn("allow-clients-file overrides this inline list.")
			}
			return ok
		}})
		add(k33 && r == "Kharej" && !risk, advRow{"l", "Allow file", Cfg(n, "allow-clients-file"), "none", "", g, func() bool {
			Hint("One IP/CIDR per line under " + allowClientsDir() + "/; an empty file stops startup.")
			return ask("allow-clients-file", "Allowlist file (under "+allowClientsDir()+"/; - = none)", Cfg(n, "allow-clients-file"),
				vAllowClientsFile, func(s string) bool { return s == "" || s == "-" || s == "default" })
		}})
		add(r == "Iran", advRow{"a", "Bind", Cfg(n, "bind"), "0.0.0.0", "", g, func() bool {
			return ask("bind", "Bind address", orStr(Cfg(n, "bind"), "0.0.0.0"), vBind, func(s string) bool { return s == "0.0.0.0" })
		}})
		if isRevCapable(cr) {
			d := "normal " + GRY + "Iran connects to Kharej" + RST
			if rev {
				d = "reverse " + GRY + "Kharej connects to Iran" + RST
			}
			add(true, advRow{"d", "Direction", d, "", "", g, func() bool {
				// applied at once, so the direction never sits in the file without running
				if setDirection(n) {
					step("Restarting "+Unit(n), func() bool { return Restart(Unit(n)) == nil })
				}
				Pause()
				return false
			}})
		}

		g = "State & data"
		add(k33, advRow{"t", "State dir", Cfg(n, "state-dir"), "next to config", "", g, func() bool {
			Hint("Use /run/wattun (tmpfs, cleared on reboot); custom paths need unit write access.")
			if !AskOK("State directory (absolute; 0 or - = next to config)", Cfg(n, "state-dir"), vStateDir) {
				return false
			}
			if unsetWord(ReplyV) {
				UnsetValue(n, "state-dir")
			} else {
				SetValue(n, "state-dir", strings.TrimSuffix(ReplyV, "/"))
			}
			return true
		}})
		add(k33, advRow{"v", "State save", Cfg(n, "state-save"), "30", "s", g, func() bool {
			return ask("state-save", "State save interval in seconds (0 = shutdown only)", Cfg(n, "state-save"), vStateSave,
				func(s string) bool { return s == "" || s == "-" || s == "default" })
		}})

		items := make([]Item, len(rows))
		for i, rw := range rows {
			v := rw.val
			if v == "" {
				v = GRY + rw.def + RST
			} else if rw.unit != "" {
				v += " " + rw.unit
			}
			items[i] = Item{Key: rw.key, Label: rw.label, Desc: v}
		}
		ClearScreen()
		i, key := Choose(func(w io.Writer) {
			Title(w, "Advanced", n)
			hintLine(w, "Applies on exit (restarts the tunnel). File-only keys: docs/TECHNICAL.md")
			fmt.Fprintln(w)
		}, items, &sel, []string{"⏎", "change", "esc", "back and apply"}, 0)
		if i < 0 {
			if key == "esc" || key == "q" || key == "eof" {
				break
			}
			continue
		}
		fmt.Fprintln(Stdout)
		if rows[i].edit() {
			changed = true
			sleepMS(600)
		} else if ErrN() > 0 {
			ResetErrN()
			Pause()
		}
	}
	// every setting here needs a restart; an unapplied change only logs "restart needed"
	if changed {
		if r == "Kharej" && IsAutoKharej(n) {
			autoSyncHelperSettings(n, "")
			step("Restarting "+Unit(n)+" to apply", func() bool { return autoForEachUnit(n, "restart") })
		} else {
			step("Restarting "+Unit(n)+" to apply", func() bool { return Restart(Unit(n)) == nil })
		}
	}
}

// ---- the other tunnel-page flows ----

// changePeer repoints the address this side dials (or, reverse on Iran, its listen port).
func changePeer(n string) bool {
	r, cr, old := Role(n), Cfg(n, "carrier"), Cfg(n, "peer")
	oh, op := SplitHP(old)
	restart := func(tip string) bool {
		if !step("Restarting "+Unit(n), func() bool { return Restart(Unit(n)) == nil }) {
			return false
		}
		if waitLink(n, 20) {
			Ok("CONNECTED (RTT " + LinkRTT + " ms)")
		} else {
			Warn("Not connected yet.")
		}
		if tip != "" {
			Hint(tip)
		}
		return true
	}
	if IsReverse(n) {
		if r == "Kharej" { // reverse: this server dials Iran
			var v string
			if cr == "icmp" {
				if !AskOK("New Iran address (IPv4)", oh, vIPv4) {
					return false
				}
				v = ReplyV
			} else {
				if !AskOK("New Iran address (host or host:port)", old, vHost) {
					return false
				}
				h, p := SplitHP(ReplyV)
				v = JoinHP(h, orStr(p, op))
			}
			SetValue(n, "peer", v)
			tip := ""
			if cr != "icmp" {
				tip = "If the carrier port changed too, set the same listen port on Iran (tunnel page, h)."
			}
			return restart(tip)
		}
		if cr == "icmp" { // reverse on Iran: only its own port is local
			Hint("Reverse ICMP has no port to change: this server only answers ping.")
			return true
		}
		if !AskOK("New carrier listen port on this server (the same port on Kharej)", op, vPort) {
			return false
		}
		np, pr := strconv.Itoa(atoi(ReplyV)), rproto(cr)
		if np != op && listenBlocked(pr, atoi(np)) {
			Err("Port " + np + "/" + pr + " is already in use here by " + listenConflictDesc(pr, np) + ".")
			return false
		}
		SetValue(n, "listen", `":`+np+`"`)
		if op != "" {
			SetValue(n, "peer", JoinHP(oh, np))
		}
		fwOpen(np + "/" + pr)
		return restart("On Kharej set the same port as its peer target (tunnel page, h).")
	}
	if !AskOK("New Kharej address (host or host:port)", old, vHost) {
		return false
	}
	h, p := SplitHP(ReplyV)
	v := h
	if IsRawCarrier(cr) { // raw-IP carriers take a bare host; a port would break the raw socket
		if p != "" {
			Hint("Raw-IP carrier: dropped the port, the peer is a bare address.")
		}
	} else {
		if p == "" {
			if op == "" {
				Err("This carrier needs host:port (for example example.com:443).")
				return false
			}
			p = op
			Hint("No port given: keeping port " + op + ".")
		}
		if !isPortStr(p) {
			Err("The Kharej address needs a valid port, like host:443.")
			return false
		}
		v = JoinHP(h, strconv.Itoa(atoi(p)))
	}
	SetValue(n, "peer", v)
	return restart("")
}

// changeType: one place to change how the two servers connect, whatever kind of tunnel this is.
func changeType(n string) {
	c := Cfg(n, "carrier")
	fmt.Fprintln(Stdout)
	if isShapedList(c) {
		p2ShapedWarn(c)
	}
	switch {
	case Role(n) == "Iran" && fileExists(P.Conf+"/"+n+".auto"):
		if err := autoTestCmd(n); err != nil {
			Err(err.Error())
		}
	case Role(n) == "Iran":
		Say("  In use: " + c + ". Kharej fixed this type when it made the token.")
		Hint("To choose freely: on Kharej make a new tunnel, then paste the new token here (tunnel page, t).")
	case IsAutoKharej(n):
		Say("  In use: " + orStr(inUse(n), "none yet") + ". Iran chooses the type: on Iran, tunnel page, c.")
	default:
		Say("  In use: " + c + ", fixed when the tunnel was made.")
		Hint("To let Iran choose: make a new auto tunnel here, paste its token on Iran, then delete this tunnel.")
	}
}
