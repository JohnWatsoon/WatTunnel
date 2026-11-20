package mgr

// Routes whose logic already exists in Go (auto.go, matrix.go, presets.go,
// status.go, test.go) plus the small bash commands ported here: mute/unmute,
// reset_traffic, auto_watch, auto_optimize_all, mgr_lock, show_token,
// preset_cmd. Screens draw in the ui.go look.

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	Register("auto_ip", func(a ...string) int { return errRC(autoIPCmd(arg(a, 0), arg(a, 1))) })
	Register("auto_reopen", func(a ...string) int { return errRC(autoReopen(arg(a, 0))) })
	Register("auto_retest", func(a ...string) int { return errRC(autoRetest(arg(a, 0))) })
	Register("auto_test_cmd", func(a ...string) int { return errRC(autoTestCmd(arg(a, 0))) })
	Register("auto_watch", func(a ...string) int { autoWatch(arg(a, 0)); return 0 })
	Register("auto_optimize_all", func(a ...string) int { autoOptimizeAll(); return 0 })
	Register("ac_matrix_cmd", func(a ...string) int { return b2i(MatrixCmd(arg(a, 0), Stdout, true)) })
	Register("test_tunnel", func(a ...string) int { testTunnel(arg(a, 0)); return 0 })
	Register("speed_test", func(a ...string) int {
		mb := atoi(arg(a, 1))
		if mb <= 0 {
			mb = 10
		}
		SpeedTest(arg(a, 0), mb, Stdout)
		return 0
	})
	Register("show_token", func(a ...string) int { return b2i(showToken(arg(a, 0))) })
	Register("preset_cmd", func(a ...string) int { return b2i(presetCmd(arg(a, 0), arg(a, 1))) })
	Register("mute_cmd", func(a ...string) int { return b2i(carrierToggle("mute", arg(a, 0), arg(a, 1))) })
	Register("unmute_cmd", func(a ...string) int { return b2i(carrierToggle("unmute", arg(a, 0), arg(a, 1))) })
	Register("reset_traffic", func(a ...string) int { resetTraffic(arg(a, 0)); return 0 })
	Register("mgr_lock", func(a ...string) int { return b2i(mgrLock()) })
}

func errRC(err error) int {
	if err != nil {
		if s := err.Error(); s != "" {
			Err(s)
		}
		return 1
	}
	return 0
}

// autoIPCmd sets Iran's IP for the hidden reverse companion by hand.
func autoIPCmd(n, ip string) error {
	ip = strings.Trim(ip, "[]")
	if !IsAutoKharej(n) {
		return fmt.Errorf("'%s' is not an auto Kharej tunnel.", n)
	}
	if !isIPv4(ip) && !Ipv6OK(ip) {
		return fmt.Errorf("Usage: %s auto-ip %s IRAN_IP", P.Self, n)
	}
	if err := autoIP(n, ip); err != nil {
		return err
	}
	_ = Systemctl("stop", P.Prefix+"-autowatch-"+n+".service")
	ensureHealTimer()
	Ok("Reverse side for '" + n + "' is set for Iran " + ip + ". Run the test again on Iran.")
	return nil
}

// autoWatch (run by systemd-run) polls /stats for Iran's first usable client
// and writes the companion.
func autoWatch(n string) {
	cdn := ""
	if t, err := readTokFile(n); err == nil {
		cdn = t.SNI
	}
	envLogger("wattun-auto", "watching "+n+" for Iran's first connection")
	for fileExists(filepath.Join(P.Conf, n+".yml")) {
		if ip := autoDetectIranIP(n, cdn); ip != "" {
			if err := companionCreate(n, ip, false); err != nil {
				Err(err.Error())
			}
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func autoOptimizeAll() {
	for _, n := range Tunnels() {
		if Role(n) == "Iran" && fileExists(filepath.Join(P.Conf, n+".auto")) {
			envLogger("wattun-auto-optimize", "running scheduled off-peak optimization for "+n)
			os.Setenv("AUTO_OPTIMIZE", "1")
			if err := autoRetest(n); err != nil {
				Err(err.Error())
			}
		}
	}
}

// testTunnel is the doctor (bash test_tunnel) with the live probes.
func testTunnel(n string) {
	Doctor(n, &DoctorIO{Out: Stdout, SpeedTest: func(name string) { SpeedTest(name, 10, Stdout) }})
}

// showToken prints a Kharej tunnel's token in a box with what to do with it.
func showToken(n string) bool {
	if p := CompanionOf(n); p != "" {
		n = p
	}
	f := filepath.Join(P.Conf, n+".token")
	if Role(n) == "Kharej" && !fileExists(f) {
		_ = RefreshToken(n)
	}
	if !fileExists(f) {
		Err("No token stored for '" + n + "' (tokens exist only on Kharej tunnels).")
		return false
	}
	_ = RefreshToken(n)
	if IsAutoKharej(n) && autoNeedsReopen(n) {
		_ = autoReopen(n)
	}
	tok := strings.TrimSpace(mustRead(f))
	if NonInteractive || !IsTTY {
		fmt.Fprintln(Stdout, tok)
		return true
	}
	fmt.Fprintln(Stdout)
	tokenBox(tok)
	return true
}

// tokenBox shows a token: one copyable line, then what to do with it. A token
// wider than the terminal is printed bare so copying does not pick up borders.
func tokenBox(tok string) {
	lines := []string{
		BOLD + tok + RST,
		GRY + "On the Iran server: New tunnel → Paste a token." + RST,
		GRY + "It holds the tunnel key. Send it only over a private chat." + RST,
	}
	if rlen(tok)+8 > TermCols() {
		fmt.Fprintf(Stdout, "  %sToken%s\n\n%s\n\n", CYN, RST, tok)
		for _, l := range lines[1:] {
			fmt.Fprintf(Stdout, "  %s\n", l)
		}
		return
	}
	Box(Stdout, "Token", lines...)
}

var presetChoices = []struct{ name, label, desc string }{
	{"cloudflare", "Cloudflare", "www.cloudflare.com · rst · no rotation; passed a CDN whitelist"},
	{"mci", "MCI whitelist", "mci.ir · rst · 30m / 500MB, ECH ladder"},
	{"irancell", "Irancell", "irancell.ir · seq · 20m / 300MB, SNI allowlist only"},
	{"blackout", "Blackout", "mci.ir · rst · 90s / 100MB, ECH ladder"},
	{"conservative", "Low churn", "mci.ir · seq · 4h / 4GB, ECH auto, SNI allowlist only"},
	{"off", "Off", "plain tunnel, full speed"},
	{"rst-fast", "Fast", "www.cloudflare.com · rst · 30m, 4 × 4 conns"},
}

// pickPreset asks for an anti-censorship preset; "" = back.
func pickPreset(def string) string {
	if NonInteractive {
		return orStr(os.Getenv("NI_PRESET"), def)
	}
	items := make([]Item, len(presetChoices))
	sel := 0
	for i, p := range presetChoices {
		items[i] = Item{Label: p.label, Desc: p.desc}
		if p.name == def {
			sel = i
		}
	}
	ClearScreen()
	for {
		i, k := Choose(func(w io.Writer) { Title(w, "Anti-censorship preset", "what the filter sees on each connection") },
			items, &sel, []string{"⏎", "apply", "esc", "back"}, 0)
		if i >= 0 {
			return presetChoices[i].name
		}
		if k == "esc" || k == "q" || k == "eof" {
			return ""
		}
	}
}

func presetCmd(n, p string) bool {
	if !isLinuxHost() {
		Err("Anti-censorship presets are a Linux feature.")
		return false
	}
	if !cfgFileExists(n) {
		Err("No tunnel named '" + n + "'.")
		return false
	}
	if !AcDialer(n) {
		Err("'" + n + "' does not dial the carrier, so presets run on its other end (Iran normally, Kharej when reverse).")
		return false
	}
	if p == "" && !NonInteractive {
		if p = pickPreset("cloudflare"); p == "" {
			return false
		}
		ClearScreen()
		Title(Stdout, "Anti-censorship preset", n)
	}
	if p == "" {
		Err("A preset name is required (preset " + n + " mci). Available: cloudflare, rst-fast, mci, irancell, blackout, conservative")
		return false
	}
	if PresetCanonical(p) == "" {
		Err("Unknown preset '" + p + "'. Available: cloudflare, rst-fast, mci, irancell, blackout, conservative")
		return false
	}
	if !ApplyPreset(n, p) {
		return false
	}
	if stdinIsTTY() && !NonInteractive && registered("anticensor_test") {
		dispatch("anticensor_test", n)
	}
	return true
}

func isLinuxHost() bool { return fileExists("/proc/self") }

// carrierToggle mutes or unmutes one bonded path through the metrics server.
func carrierToggle(want, n, p string) bool {
	if n == "" || p == "" {
		Err("Usage: " + P.Self + " " + want + " NAME PATH (PATH = a bonded path as /stats names it, e.g. udp or udp:up).")
		return false
	}
	if !NeedTunnel(n) {
		return false
	}
	m := Cfg(n, "metrics")
	if m == "" {
		Err("Tunnel '" + n + "' has no metrics endpoint in " + n + ".yml (muting talks to the metrics server).")
		return false
	}
	ti := tinfo(n)
	idx := -1
	if isDigits(p) {
		if !ti.Auto && ti.CarCount > 0 {
			if atoi(p) >= ti.CarCount {
				Err(fmt.Sprintf("Tunnel '%s' has paths 0-%d, not '%s'.", n, ti.CarCount-1, p))
				return false
			}
			idx = atoi(p)
		}
	} else {
		for i, c := range ti.Cars {
			if c.Name == p {
				idx = i
				break
			}
		}
		if idx < 0 && !strings.Contains("+"+Cfg(n, "carrier")+"+", "+"+p+"+") {
			Err("No path '" + p + "' on tunnel '" + n + "' (paths: " + Cfg(n, "carrier") + ").")
			return false
		}
	}
	if idx >= 0 {
		switch want + ":" + ti.Cars[idx].Muted {
		case "mute:true":
			Ok("Path '" + p + "' is already muted.")
			StatusRow(Stdout, n)
			return true
		case "unmute:false":
			Ok("Path '" + p + "' is already unmuted.")
			StatusRow(Stdout, n)
			return true
		}
	}
	q := "carrier=" + p
	if isDigits(p) {
		q = "path=" + fmt.Sprint(atoi(p))
	}
	u := "http://" + m + "/carrier/toggle?" + q
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Post(u, "", nil)
	if err != nil || resp.StatusCode/100 != 2 {
		if resp != nil {
			resp.Body.Close()
		}
		Err("Tunnel '" + n + "' did not answer " + u + " (is it running? does path '" + p + "' exist?).")
		return false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	res := string(b)
	// a mute answered with muted:false is a refusal: a single carrier cannot be muted
	switch want + ":" + Jget(res, "muted") {
	case "mute:true":
		Ok("Path '" + p + "' is now muted.")
	case "mute:false":
		Err("The engine refused (muted:false): muting needs a bonded tunnel — a single carrier cannot be muted.")
		return false
	case "unmute:false":
		Ok("Path '" + p + "' is now unmuted.")
	case "unmute:true":
		Err("The engine answered muted:true to an unmute request: " + res)
		return false
	default:
		Err("Unexpected answer from " + u + ": " + res)
		return false
	}
	StatusRow(Stdout, n)
	return true
}

// stateFile is where the engine keeps a tunnel's totals or quota state:
// "<state-dir or conf>/<name>.yml.<kind>.json"; a relative state-dir resolves
// from / like the unit's working directory.
func stateFile(n, kind string) string {
	d := strings.TrimSuffix(Cfg(n, "state-dir"), "/")
	if d == "" {
		d = P.Conf
	} else if !strings.HasPrefix(d, "/") {
		d = "/" + d
	}
	return d + "/" + n + ".yml." + kind + ".json"
}

func stateFiles(n string) []string { return []string{stateFile(n, "totals"), stateFile(n, "quota")} }

func stateDirRelativeWarn(n string) {
	d := strings.TrimSuffix(Cfg(n, "state-dir"), "/")
	if d != "" && !strings.HasPrefix(d, "/") {
		Warn(fmt.Sprintf("state-dir of '%s' is relative (%s); the service resolves it from / (the manager does the same).", n, d))
		Hint("Use an absolute path (the shipped unit supports /run/wattun) so the manager and the service agree.")
	}
}

// resetTraffic zeroes a tunnel's lifetime counters (the engine keeps them
// across restarts): stop, delete the totals file, start again.
func resetTraffic(n string) {
	units := []string{n}
	if IsAutoKharej(n) {
		units = append(units, autoHelpers(n)...)
	}
	stateDirRelativeWarn(n)
	var act []string
	for _, u := range units {
		if IsActive(Unit(u)) {
			act = append(act, u)
			_ = Systemctl("stop", Unit(u))
		}
		f := stateFile(u, "totals")
		for _, x := range []string{f, f + ".host", f + ".tmp"} {
			_ = os.Remove(x)
		}
	}
	for _, u := range act {
		_ = Systemctl("start", Unit(u))
	}
	Ok("Traffic counters of '" + n + "' start from zero.")
}

// mgrLock: one manager pass at a time. The lock lives until this process exits.
func mgrLock() bool {
	_ = os.MkdirAll(P.Run, 0o755)
	if _, err := exec.LookPath("flock"); err != nil {
		return true // a stripped host: run unlocked, never refuse to work
	}
	if lockFile(filepath.Join(P.Run, "manager.lock")) {
		return true
	}
	Warn("Another wattun-manager pass is running; skipping this one.")
	return false
}
