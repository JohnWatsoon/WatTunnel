package mgr

// The home screen, the live tunnels table, Tools, Settings and the all-tunnels
// actions, in the approved design. Logic ports of the bash main_menu,
// batch_actions_menu, settings_menu, start/stop/restart_all, status_all,
// stale_tunnels, heal_enable/disable and boost_*.

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func init() {
	Register("status_all", func(args ...string) int { return b2i(statusAll()) })
	Register("start_all", func(args ...string) int { startAll(); return 0 })
	Register("stop_all", func(args ...string) int { stopAll(); return 0 })
	Register("restart_all", func(args ...string) int { restartAll(); return 0 })
	Register("batch_actions_menu", func(args ...string) int { batchMenu(); return 0 })
	Register("settings_menu", func(args ...string) int { return settingsMenu() })
	Register("live_monitor", func(args ...string) int { LiveMonitor(Stdout); return 0 })
	Register("ensure_heal_timer", func(args ...string) int { ensureHealTimer(); return 0 })
	Register("backup_cmd", func(args ...string) int { return b2i(backupCmd(arg(args, 0))) })
	Register("restore_cmd", func(args ...string) int { return b2i(restoreCmd(arg(args, 0))) })
	Register("boost_cmd", func(args ...string) int { return boostCmd(arg(args, 0)) })
}

// ---- live samples: byte-counter deltas give honest per-second rates ----

type sample struct {
	in, out float64
	at      time.Time
	down    []float64 // users' download rate history (bytes/s)
	up      []float64
}

var samples = map[string]*sample{}

// sampleTunnel reads ti's counters into the history and returns the current
// down/up rates. Down is what users receive: bytes in on Iran, bytes out on Kharej.
func sampleTunnel(n string, ti *tunnelInfo) (down, up float64) {
	s := samples[n]
	now := time.Now()
	in, out := ti.In, ti.Out
	if roleName(n) == "Kharej" {
		in, out = out, in
	}
	if s == nil {
		samples[n] = &sample{in: in, out: out, at: now}
		return 0, 0
	}
	dt := now.Sub(s.at).Seconds()
	if dt < 0.2 {
		return last(s.down), last(s.up)
	}
	if in >= s.in && out >= s.out {
		down, up = (in-s.in)/dt, (out-s.out)/dt
	}
	s.in, s.out, s.at = in, out, now
	s.down = appendCap(s.down, down, 120)
	s.up = appendCap(s.up, up, 120)
	return down, up
}

func last(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	return v[len(v)-1]
}

func appendCap(v []float64, x float64, n int) []float64 {
	v = append(v, x)
	if len(v) > n {
		v = v[len(v)-n:]
	}
	return v
}

// ---- host line: hostname · public IP · role · counts ----

var (
	hostIPOnce sync.Once
	hostIP     string
	hostIPMu   sync.Mutex
)

func cachedPublicIP() string {
	hostIPOnce.Do(func() {
		go func() {
			ip := p2PublicIP()
			hostIPMu.Lock()
			hostIP = ip
			hostIPMu.Unlock()
		}()
	})
	hostIPMu.Lock()
	defer hostIPMu.Unlock()
	return hostIP
}

// serverSide mirrors server_side(): saved role, else read from the tunnels.
func serverSide() string {
	if s := ConfGet("side", ""); s == "kharej" || s == "iran" {
		return s
	}
	k, i := false, false
	for _, n := range Tunnels() {
		if CompanionOf(n) != "" {
			continue
		}
		if Role(n) == "Kharej" {
			k = true
		} else {
			i = true
		}
	}
	switch {
	case k && !i:
		return "kharej"
	case i && !k:
		return "iran"
	}
	return ""
}

// listedTunnels: what a status list shows (hidden auto helpers never appear).
func listedTunnels() []string {
	var out []string
	for _, n := range Tunnels() {
		if !IsAutoHelper(n) {
			out = append(out, n)
		}
	}
	return out
}

func hostLine(names []string, infos map[string]*tunnelInfo) string {
	h, _ := os.Hostname()
	parts := []string{h}
	if ip := cachedPublicIP(); ip != "" {
		parts = append(parts, ip)
	}
	switch serverSide() {
	case "kharej":
		parts = append(parts, "Kharej side")
	case "iran":
		parts = append(parts, "Iran side")
	}
	up := 0
	for _, n := range names {
		if ti := infos[n]; ti != nil && (ti.State == "up" || ti.State == "degraded") {
			up++
		}
	}
	parts = append(parts, fmt.Sprintf("%d tunnels, %d up", len(names), up))
	return strings.Join(parts, " · ")
}

// ---- one tunnel as a table row ----

func stateText(n string, ti *tunnelInfo) string {
	col, dot, txt := stateCell(roleName(n), ti.State)
	if ti.State == "up" {
		if u := p1Uptime(n); u != "" {
			txt += " " + u
		}
	}
	return col + dot + " " + txt + RST
}

func carrierText(n string) string {
	c := p1CarrierLabel(n)
	if strings.Contains(c, "+") {
		c = strings.ReplaceAll(c, "+", " + ")
	}
	if IsReverse(n) {
		c += " reverse"
	}
	return c
}

func loadText(n string, ti *tunnelInfo) string {
	if ti.State == "stopped" {
		return "—"
	}
	if roleName(n) == "Kharej" {
		return fmt.Sprintf("%d", ti.Sess)
	}
	return fmt.Sprintf("%d", ti.Streams)
}

// tunnelRow formats one table row; wide adds the carrier and sparkline columns.
func tunnelRow(n string, ti *tunnelInfo, wide bool) string {
	down, up := sampleTunnel(n, ti)
	live := ti.State == "up" || ti.State == "degraded"
	rate := func(v float64) string {
		if !live {
			return GRY + "—" + RST
		}
		return Rate(v)
	}
	rtt := GRY + "—" + RST
	if live && ti.RTT > 0 {
		rtt = fmt.Sprintf("%.0f ms", ti.RTT)
	}
	row := padR(BOLD+trunc(n, 14)+RST, 15)
	if wide {
		row += padR(GRY+trunc(carrierText(n), 17)+RST, 18)
	}
	row += padR(stateText(n, ti), 15) + padL(rate(down), 11) + padL(rate(up), 11) + padL(rtt, 8) + padL(loadText(n, ti), 7)
	if wide {
		var hist []float64
		if s := samples[n]; s != nil {
			hist = s.down
		}
		row += "   " + Spark(hist, 12)
	}
	return row
}

func tableHeader(w io.Writer, wide bool) {
	h := padR("NAME", 15)
	if wide {
		h += padR("CARRIER", 18)
	}
	h += padR("STATE", 15) + padL("↓ DOWN", 11) + padL("↑ UP", 11) + padL("RTT", 8) + padL("CONNS", 7)
	if wide {
		h += "   LAST MINUTE"
	}
	fmt.Fprintf(w, "    %s%s%s\n", GRY, h, RST)
}

func wideTable() bool { return TermCols() >= 112 }

// ---- home ----

// MainMenu is the manager's home screen: wordmark, host line, a live glance at
// every tunnel, then the six choices.
func MainMenu() int {
	autoMigrateAll(true)
	sel := 0
	if len(listedTunnels()) == 0 {
		sel = 1 // nothing to manage yet: start on New tunnel
	}
	anim := UseAnim && !introDone
	introDone = true
	ClearScreen()
	for {
		names := listedTunnels()
		infos := map[string]*tunnelInfo{}
		for _, n := range names {
			infos[n] = tinfo(n)
		}
		stale := staleTunnels()
		head := func(w io.Writer) {
			homeHead(w, names, infos, stale, anim)
			anim = false
		}
		items := []Item{
			{Label: "Tunnels", Desc: fmt.Sprintf("watch traffic, restart, edit or delete (%d)", len(names))},
			{Label: "New tunnel", Desc: "set one up step by step, or paste a token"},
			{Label: "Find a carrier", Desc: "test which carriers pass on this route"},
			{Label: "Blackout kit", Desc: "emergency bond and token for a shutdown"},
			{Label: "Tools", Desc: "update, backup, speed test, kernel boost, firewall"},
			{Label: "Settings", Desc: "auto-heal, animations, update proxy, server role"},
			{Label: "Exit", Off: true},
		}
		i, k := Choose(head, items, &sel, []string{"↑↓", "move", "⏎", "open", "1-7", "jump", "q", "quit"}, 2*time.Second)
		switch k {
		case "eof":
			return 0
		case "q", "Q":
			i = 6
		case "n", "N":
			i = 1
		case "esc", "tick", "move":
			continue
		}
		switch i {
		case 0:
			tunnelsScreen()
		case 1:
			dispatch("new_tunnel")
		case 2:
			findCarrier()
		case 3:
			blackoutKit()
		case 4:
			if toolsMenu() == reloadRC {
				return reloadRC
			}
		case 5:
			if settingsMenu() == 2 {
				return 0 // uninstalled
			}
		case 6:
			CurShow()
			ClearScreen()
			return 0
		}
		ClearScreen()
	}
}

func homeHead(w io.Writer, names []string, infos map[string]*tunnelInfo, stale []string, anim bool) {
	fmt.Fprintln(w)
	if anim {
		// the reveal animates straight to the terminal once; later frames draw the still mark
		Banner(true)
	} else {
		old := Stdout
		Stdout = w
		Banner(false)
		Stdout = old
	}
	fmt.Fprintln(w)
	left := BOLD + Tagline + RST
	if Ver != "" {
		left = Badge(Ver) + "  " + left
	}
	right := GRY + hostLine(names, infos) + RST
	if pad := uiW() - rlen(left) - rlen(right); pad >= 3 {
		fmt.Fprintf(w, "  %s%s%s\n", left, rep(" ", pad), right)
	} else {
		fmt.Fprintf(w, "  %s\n  %s\n", left, right)
	}
	fmt.Fprintf(w, "  %s%s%s\n\n", GRY, rep("─", uiW()), RST)
	if len(names) == 0 {
		hint := "Start on Kharej (the server outside), then paste its token on Iran."
		switch serverSide() {
		case "iran":
			hint = "Paste the token from your Kharej server: New tunnel → Paste a token."
		case "kharej":
			hint = "Create the tunnel here, then paste its token on the Iran server."
		}
		fmt.Fprintf(w, "  %sNo tunnels yet.%s %s%s%s\n\n", BOLD, RST, GRY, hint, RST)
		return
	}
	max := 6
	for i, n := range names {
		if i == max {
			fmt.Fprintf(w, "  %s+%d more in Tunnels%s\n", GRY, len(names)-max, RST)
			break
		}
		ti := infos[n]
		col, dot, _ := stateCell(roleName(n), ti.State)
		down, up := sampleTunnel(n, ti)
		line := fmt.Sprintf("  %s%s%s %s %s", col, dot, RST, padR(BOLD+trunc(n, 12)+RST, 13), padR(GRY+trunc(carrierText(n), 16)+RST, 17))
		switch ti.State {
		case "up", "degraded":
			line += fmt.Sprintf("%s↓%s %s  %s↑%s %s  %s", CYN, RST, padL(Rate(down), 10), SAF, RST, padL(Rate(up), 10), padL(fmt.Sprintf("%.0f ms", ti.RTT), 6))
			if s := samples[n]; s != nil && TermCols() >= 96 {
				line += "   " + Spark(s.down, 10)
			}
			if ti.Why != "" {
				line += "  " + YEL + ti.Why + RST
			}
		default:
			_, _, txt := stateCell(roleName(n), ti.State)
			if ti.Why != "" {
				txt += " · " + ti.Why
			}
			line += GRY + txt + RST
		}
		fmt.Fprintln(w, line)
	}
	var rp []string
	for _, n := range names {
		if fileExists(filepath.Join(P.Conf, n+".repaste")) {
			rp = append(rp, n)
		}
	}
	if len(rp) > 0 {
		fmt.Fprintf(w, "\n  %s!%s new token on %s: open it, press t and paste the token on Iran.\n", YEL, RST, strings.Join(rp, ", "))
	}
	if len(stale) > 0 {
		fmt.Fprintf(w, "\n  %s!%s %s still runs the old binary: open it and restart to load %s.\n", YEL, RST, strings.Join(stale, ", "), orStr(Ver, "the new version"))
	}
	fmt.Fprintln(w)
}

// ---- tunnels table ----

func tunnelsScreen() {
	sel := 0
	for {
		names := listedTunnels()
		if len(names) == 0 {
			Page("Tunnels", "none yet")
			Hint("No tunnels yet. Create one with New tunnel on the home screen.")
			Pause()
			return
		}
		wide := wideTable()
		items := make([]Item, len(names))
		for i, n := range names {
			items[i] = Item{Label: tunnelRow(n, tinfo(n), wide)}
		}
		head := func(w io.Writer) {
			Title(w, "Tunnels", fmt.Sprintf("%d on this server · live, every 1 s", len(names)))
			tableHeader(w, wide)
		}
		i, k := Choose(head, items, &sel, []string{"⏎", "open", "n", "new", "r", "restart", "s", "start/stop", "d", "delete", "esc", "back"}, time.Second)
		if i >= 0 {
			tunnelPage(names[i])
			ClearScreen()
			continue
		}
		n := names[sel]
		switch strings.ToLower(k) {
		case "eof", "esc", "q", "0":
			return
		case "n":
			dispatch("new_tunnel")
		case "r":
			ClearScreen()
			Title(Stdout, "Restart "+n, "")
			if Confirm("Restart '"+n+"'? Open connections drop.", false) {
				if autoForEachUnit(n, "restart") {
					Ok("Restarted " + n + ".")
				} else {
					Err("Restart of " + n + " failed.")
				}
				sleepMS(700)
			}
		case "s":
			if IsActive(Unit(n)) {
				autoForEachUnit(n, "stop")
				Flash("Stopped " + n + ".")
			} else if !autoForEachUnit(n, "start") {
				Flash("'" + n + "' failed to start: open it and check the logs.")
			}
		case "d":
			ClearScreen()
			Title(Stdout, "Delete "+n, "")
			runFlow("delete_tunnel", n)
			Pause()
		}
		ClearScreen()
	}
}

// pickTunnel lets the user pick one tunnel (the only one is picked at once);
// filter keeps the candidates. "" = back.
func pickTunnel(title, why string, filter func(string) bool) string {
	var names []string
	for _, n := range listedTunnels() {
		if filter == nil || filter(n) {
			names = append(names, n)
		}
	}
	switch len(names) {
	case 0:
		ClearScreen()
		Title(Stdout, title, "")
		Hint("No tunnel here can use this yet.")
		Pause()
		return ""
	case 1:
		return names[0]
	}
	items := make([]Item, len(names))
	for i, n := range names {
		items[i] = Item{Label: n, Desc: carrierText(n) + " · " + roleName(n)}
	}
	sel := 0
	ClearScreen()
	for {
		i, k := Choose(func(w io.Writer) { Title(w, title, why) }, items, &sel, []string{"⏎", "choose", "esc", "back"}, 0)
		if i >= 0 {
			return names[i]
		}
		if k == "esc" || k == "q" || k == "eof" {
			return ""
		}
	}
}

// ---- Tools ----

func toolsMenu() int {
	sel := 0
	ClearScreen()
	for {
		items := []Item{
			{Label: "Update", Desc: "get the newest wattun from GitHub"},
			{Label: "Roll back", Desc: "go back to the previous binary"},
			{Label: "Speed test", Desc: "measure one tunnel, down and up"},
			{Label: "Live monitor", Desc: "every tunnel on one screen"},
			{Label: "All tunnels", Desc: "start, stop or restart everything at once"},
			{Label: "Back up configs", Desc: "save " + P.Conf + " to a .tar.gz"},
			{Label: "Restore configs", Desc: "put a backup back"},
			{Label: "Kernel boost", Desc: "BBR, fq and 64 MiB buffers"},
			{Label: "Iran firewall", Desc: "block access to this server from inside Iran"},
			{Label: "Offline bundle", Desc: "pack the installer for a server without GitHub"},
		}
		i, k := Choose(func(w io.Writer) { Title(w, "Tools", "") }, items, &sel, []string{"⏎", "open", "esc", "back"}, 0)
		if k == "esc" || k == "q" || k == "eof" || k == "0" {
			return 0
		}
		if i < 0 {
			continue
		}
		ClearScreen()
		switch i {
		case 0:
			Page("Update", "")
			if dispatch("update") == 0 {
				fmt.Fprintln(Stdout)
				Hint("The manager reloads itself to show the new version.")
				Pause()
				return reloadRC
			}
			Pause()
		case 1:
			Page("Roll back", "")
			runFlow("rollback")
			Pause()
		case 2:
			if n := pickTunnel("Speed test", "which tunnel?", func(n string) bool { return roleName(n) == "Iran" }); n != "" {
				Page("Speed test", n)
				dispatch("speed_test", n, "10")
				Pause()
			}
		case 3:
			runFlow("live_monitor")
		case 4:
			batchMenu()
		case 5:
			Page("Back up configs", "")
			backupCmd(Ask("Backup file", "wattun-backup-"+time.Now().Format("20060102")+".tar.gz"))
			Pause()
		case 6:
			Page("Restore configs", "")
			if p := Ask("Backup .tar.gz path", ""); p != "" {
				restoreCmd(p)
			}
			Pause()
		case 7:
			boostMenu()
		case 8:
			Page("Iran firewall", "")
			dispatch("iran_firewall_cmd")
			Pause()
		case 9:
			Page("Offline bundle", "")
			dispatch("bundle_cmd")
			Pause()
		}
		ClearScreen()
	}
}

// ---- all tunnels ----

func batchMenu() {
	sel := 0
	ClearScreen()
	for {
		items := []Item{
			{Label: "Start all", Desc: "start every stopped tunnel"},
			{Label: "Stop all", Desc: "stop every running tunnel"},
			{Label: "Restart all", Desc: "open connections drop"},
			{Label: "Status list", Desc: "plain list, the same as `wattun status`"},
		}
		i, k := Choose(func(w io.Writer) { Title(w, "All tunnels", "") }, items, &sel, []string{"⏎", "run", "esc", "back"}, 0)
		if k == "esc" || k == "q" || k == "eof" || k == "0" {
			return
		}
		if i < 0 {
			continue
		}
		fmt.Fprintln(Stdout)
		switch i {
		case 0:
			startAll()
		case 1:
			if Confirm("Stop all active tunnels?", false) {
				stopAll()
			}
		case 2:
			if Confirm("Restart all tunnels? Open connections drop.", false) {
				restartAll()
			}
		case 3:
			ClearScreen()
			Title(Stdout, "Status", "")
			statusAll()
		}
		Pause()
		ClearScreen()
	}
}

// step runs fn under a label and prints a ✓ or ✗ line (bash step).
func step(label string, fn func() bool) bool {
	if fn() {
		Ok(label)
		return true
	}
	Err(label)
	return false
}

func startAll() {
	c := 0
	for _, n := range Tunnels() {
		if !IsActive(Unit(n)) {
			step("Starting "+Unit(n), func() bool { return autoForEachUnit(n, "start") })
			c++
		} else if IsAutoKharej(n) {
			autoForEachUnit(n, "start")
		}
	}
	if c > 0 {
		Ok(fmt.Sprintf("Started %d tunnel(s).", c))
	} else {
		Warn("All tunnels are already active.")
	}
}

func stopAll() {
	c := 0
	for _, n := range Tunnels() {
		if IsActive(Unit(n)) {
			step("Stopping "+Unit(n), func() bool { return autoForEachUnit(n, "stop") })
			c++
		} else if IsAutoKharej(n) {
			autoForEachUnit(n, "stop")
		}
	}
	if c > 0 {
		Ok(fmt.Sprintf("Stopped %d tunnel(s).", c))
	} else {
		Warn("All tunnels are already stopped.")
	}
}

func restartAll() {
	c := 0
	for _, n := range Tunnels() {
		if IsEnabled(Unit(n)) || IsActive(Unit(n)) {
			step("Restarting "+Unit(n), func() bool { return autoForEachUnit(n, "restart") })
			c++
		}
	}
	if c == 0 {
		Warn("No tunnels to restart.")
	}
}

// statusAll is the plain, scriptable list (`wattun status`).
func statusAll() bool {
	names := listedTunnels()
	for _, n := range names {
		StatusRow(Stdout, n)
	}
	if len(names) == 0 {
		Warn("No tunnels yet. Start with Kharej: run " + P.Self + " and choose New tunnel.")
		return false
	}
	return true
}

// autoForEachUnit applies act to a tunnel and, for an auto Kharej tunnel, its
// hidden helpers (bash auto_for_each_unit). false when the parent failed.
func autoForEachUnit(parent, act string) bool {
	units := []string{parent}
	if IsAutoKharej(parent) {
		units = append(units, autoHelpers(parent)...)
	}
	for _, u := range units {
		var err error
		switch act {
		case "start":
			if !unitUp(u) {
				err = fmt.Errorf("start")
			}
		case "stop":
			_ = systemctlQ("stop", Unit(u))
		case "restart":
			err = systemctlQ("restart", Unit(u))
		case "enable", "disable":
			_ = systemctlQ(act, Unit(u))
		}
		if err != nil && u == parent {
			return false
		}
	}
	if act == "stop" && IsAutoKharej(parent) {
		w := P.Prefix + "-autowatch-" + parent + ".service"
		_ = systemctlQ("stop", w)
		_ = systemctlQ("reset-failed", w)
	}
	return true
}

// unitUp enables and starts a tunnel and waits up to 10 s for it to stay active.
func unitUp(n string) bool {
	if !ensureTemplate() {
		return false
	}
	if Systemctl("enable", "--now", Unit(n)) != nil {
		return false
	}
	for i := 0; i < 20; i++ {
		if IsActive(Unit(n)) {
			time.Sleep(time.Second)
			if IsActive(Unit(n)) {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// ensureTemplate writes the sandbox's own unit template (production uses the
// installer's wattun@.service).
func ensureTemplate() bool {
	if !P.Sandbox {
		return true
	}
	f := "/etc/systemd/system/" + P.Prefix + "@.service"
	if fileExists(f) {
		return true
	}
	body := fmt.Sprintf(`[Unit]
Description=WatTunnel %%i (sandbox %s)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=%s -config %s/%%i.yml
Restart=always
RestartSec=2
LimitNOFILE=1048576
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`, P.Prefix, P.Bin, P.Conf)
	if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
		Err(err.Error())
		return false
	}
	_ = Systemctl("daemon-reload")
	Ok("Sandbox: created " + f + " (ExecStart " + P.Bin + ", configs in " + P.Conf + ")")
	return true
}

// staleTunnels: visible tunnels whose service (or a hidden helper) still runs a
// binary that was replaced on disk.
func staleTunnels() []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range TunnelsAll() {
		if !IsActive(Unit(u)) || !isStale(u) {
			continue
		}
		p := CompanionOf(u)
		if p == "" {
			if b, err := os.ReadFile(filepath.Join(P.Conf, u+".autoext")); err == nil {
				p = strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
			}
		}
		p = orStr(p, u)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func isStale(n string) bool {
	pid := ShowProp(Unit(n), "MainPID")
	if pid == "" || pid == "0" {
		return false
	}
	exe, err := os.Readlink("/proc/" + pid + "/exe")
	return err == nil && strings.Contains(exe, "(deleted)")
}

// ---- Settings ----

func healOn() bool { return IsEnabled(P.Heal + ".timer") }

func onOff(b bool) string {
	if b {
		return GRN + "on" + RST
	}
	return GRY + "off" + RST
}

// settingsMenu returns 2 after an uninstall (the manager exits).
func settingsMenu() int {
	sel := 0
	ClearScreen()
	for {
		px := ConfGet("update-proxy", "")
		items := []Item{
			{Label: "Auto-heal", Desc: onOff(healOn()) + GRY + "   restarts down Iran tunnels, keeps auto tunnels in step"},
			{Label: "Animations", Desc: onOff(ConfGet("anim", "1") == "1") + GRY + "   spinners and the wordmark reveal"},
			{Label: "Update proxy", Desc: orStr(px, "direct") + GRY + "   mirror or proxy for updates"},
			{Label: "Server role", Desc: orStr(serverSide(), "not set") + GRY + "   Kharej (outside) or Iran (inside)"},
			{Label: "Uninstall", Desc: RED + "remove wattun, its tunnels and configs" + RST},
		}
		i, k := Choose(func(w io.Writer) { Title(w, "Settings", "") }, items, &sel, []string{"⏎", "change", "esc", "back"}, 0)
		if k == "esc" || k == "q" || k == "eof" || k == "0" {
			return 0
		}
		if i < 0 {
			continue
		}
		switch i {
		case 0:
			fmt.Fprintln(Stdout)
			if healOn() {
				healDisable()
			} else {
				healEnable()
			}
			sleepMS(800)
		case 1:
			if ConfGet("anim", "1") == "1" {
				_ = ConfSet("anim", "0")
				UseAnim = false
			} else {
				_ = ConfSet("anim", "1")
				UseAnim = IsTTY && os.Getenv("WAT_NO_ANIM") != "1"
			}
		case 2:
			fmt.Fprintln(Stdout)
			Hint("https://ghproxy.net/ · socks5h://127.0.0.1:1080 · '-' to clear")
			switch v := Ask("Update proxy / mirror URL", px); {
			case v == "-":
				_ = confUnset("update-proxy")
				Ok("Cleared update proxy.")
			case v != "" && v != px:
				_ = ConfSet("update-proxy", v)
				Ok("Saved update proxy: " + v)
			}
			sleepMS(800)
		case 3:
			askSide()
		case 4:
			ClearScreen()
			Page("Uninstall", "")
			if runFlow("uninstall_all") == 0 {
				return 2
			}
			Pause()
		}
		ClearScreen()
	}
}

// confUnset drops a key from .manager.conf.
func confUnset(key string) error {
	b, err := os.ReadFile(P.MConf)
	if err != nil {
		return err
	}
	var keep []string
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(l, key+"=") {
			keep = append(keep, l)
		}
	}
	return atomicWrite(P.MConf, []byte(strings.Join(keep, "\n")), 0o600)
}

// askSide asks and saves this server's role; "" = back.
func askSide() string {
	sel := 0
	if serverSide() == "iran" {
		sel = 1
	}
	ClearScreen()
	for {
		items := []Item{
			{Label: "Kharej", Desc: "the server outside: runs the service, makes the token"},
			{Label: "Iran", Desc: "the server inside: users connect here"},
		}
		i, k := Choose(func(w io.Writer) { Title(w, "Server role", "which server is this?") }, items, &sel, []string{"⏎", "choose", "esc", "back"}, 0)
		if i >= 0 {
			side := []string{"kharej", "iran"}[i]
			_ = ConfSet("side", side)
			return side
		}
		if k == "esc" || k == "q" || k == "eof" {
			return ""
		}
	}
}

// ---- auto-heal timer (bash heal_enable / heal_disable / ensure_heal_timer) ----

func unitDir() string { return envOr("WAT_UNIT_DIR", "/etc/systemd/system") }

// unitEnvLines are the Environment= lines a manager-run service needs.
func unitEnvLines() string {
	var b strings.Builder
	if P.Sandbox {
		fmt.Fprintf(&b, "Environment=\"WAT_PREFIX=%s\"\n", P.Prefix)
	}
	for _, k := range []string{"WAT_CONF", "WAT_BIN", "WAT_RUN", "WAT_AUTO_RUN", "WAT_GO_MGR"} {
		if v := os.Getenv(k); v != "" {
			fmt.Fprintf(&b, "Environment=\"%s=%s\"\n", k, v)
		}
	}
	return b.String()
}

func healEnable() bool {
	ud := unitDir()
	_ = os.MkdirAll(ud, 0o755)
	desc := ""
	if P.Sandbox {
		desc = " (sandbox " + P.Prefix + ")"
	}
	svc := "[Unit]\nDescription=WatTunnel auto-heal" + desc + "\n[Service]\nType=oneshot\n" + unitEnvLines() + "ExecStart=" + P.Mgr + " heal\n"
	tmr := "[Unit]\nDescription=WatTunnel auto-heal and auto-tunnel cleanup every minute\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=1min\n[Install]\nWantedBy=timers.target\n"
	if os.WriteFile(filepath.Join(ud, P.Heal+".service"), []byte(svc), 0o644) != nil ||
		os.WriteFile(filepath.Join(ud, P.Heal+".timer"), []byte(tmr), 0o644) != nil {
		Err("Could not write the auto-heal units in " + ud + ".")
		return false
	}
	if Systemctl("daemon-reload") != nil || Systemctl("enable", "--now", P.Heal+".timer") != nil {
		Err("Auto-heal timer did not start.")
		return false
	}
	Ok("Auto-heal and auto-tunnel cleanup enabled.")
	return true
}

func healDisable() {
	ud := unitDir()
	_ = Systemctl("disable", "--now", P.Heal+".timer")
	_ = os.Remove(filepath.Join(ud, P.Heal+".service"))
	_ = os.Remove(filepath.Join(ud, P.Heal+".timer"))
	Ok("Auto-heal disabled.")
}

// ensureHealTimer: an auto Kharej tunnel is maintained by heal, so its timer
// must exist even on a Kharej-only server.
func ensureHealTimer() {
	need := false
	for _, n := range Tunnels() {
		if Role(n) == "Kharej" && IsAutoKharej(n) {
			need = true
			break
		}
	}
	if !need || healOn() {
		return
	}
	old := Stdout
	Stdout = io.Discard
	ok := healEnable()
	Stdout = old
	if ok {
		envLogger("wattun-auto", "enabled the heal timer (auto-tunnel maintenance)")
	}
}

// ---- backup / restore ----

func backupCmd(dest string) bool {
	if dest == "" {
		dest = "wattun-backup-" + time.Now().Format("20060102150405") + ".tar.gz"
	}
	if a, err := filepath.Abs(dest); err == nil {
		dest = a
	}
	Say("  Backing up " + P.Conf + " to " + dest + "...")
	if out, err := exec.Command("tar", "-czf", dest, "-C", filepath.Dir(P.Conf), filepath.Base(P.Conf)).CombinedOutput(); err != nil {
		Err("Backup failed: " + strings.TrimSpace(string(out)))
		return false
	}
	_ = os.Chmod(dest, 0o600)
	size := ""
	if fi, err := os.Stat(dest); err == nil {
		size = " (" + Human(float64(fi.Size())) + ")"
	}
	Ok("Backup saved: " + dest + size)
	return true
}

func restoreCmd(src string) bool {
	if !fileExists(src) {
		Err("Backup archive '" + src + "' not found.")
		return false
	}
	Say("  Restoring " + P.Conf + " from " + src + "...")
	_ = os.MkdirAll(P.Conf, 0o700)
	if out, err := exec.Command("tar", "-xzf", src, "-C", filepath.Dir(P.Conf)).CombinedOutput(); err != nil {
		Err("Restore extraction failed: " + strings.TrimSpace(string(out)))
		return false
	}
	_ = os.Chmod(P.Conf, 0o700)
	for _, pat := range []string{"*.key", "*.yml"} {
		fs, _ := filepath.Glob(filepath.Join(P.Conf, pat))
		for _, f := range fs {
			_ = os.Chmod(f, 0o600)
		}
	}
	Ok("Restored configuration to " + P.Conf + ".")
	_ = Systemctl("daemon-reload")
	Ok("Ready. You can start or restart your tunnels now.")
	return true
}

// ---- kernel boost (bash boost_*) ----

func boostSysctl() string { return "/etc/sysctl.d/99-" + P.Prefix + "-boost.conf" }
func boostOff() string    { return filepath.Join(P.Conf, ".boost-off") }

func boostCmd(a string) int {
	switch a {
	case "--status", "-s", "status":
		boostStatus(Stdout)
	case "--undo", "-u", "undo":
		boostUndo()
	case "--yes", "-y", "apply", "":
		boostApply()
	case "auto": // installer and update: on by default, except in a container or after --undo
		if !fileExists(boostOff()) && !isContainer() {
			old := Stdout
			Stdout = io.Discard
			boostApply()
			Stdout = old
		}
	default:
		Err("Usage: " + P.Self + " boost [--status|--undo|--yes]")
		return 1
	}
	return 0
}

func boostMenu() {
	sel := 0
	ClearScreen()
	for {
		items := []Item{
			{Label: "Turn on", Desc: "BBR, fq, 64 MiB buffers (survives reboot)"},
			{Label: "Restore defaults", Desc: "remove the boost and reload the kernel defaults"},
		}
		i, k := Choose(func(w io.Writer) { Title(w, "Kernel boost", ""); boostStatus(w); fmt.Fprintln(w) }, items, &sel, []string{"⏎", "run", "esc", "back"}, 0)
		if k == "esc" || k == "q" || k == "eof" || k == "0" {
			return
		}
		if i < 0 {
			continue
		}
		fmt.Fprintln(Stdout)
		if i == 0 {
			boostApply()
		} else if Confirm("Restore default kernel sysctl values?", true) {
			boostUndo()
		}
		Pause()
		ClearScreen()
	}
}

func sysctlGet(k string) string {
	b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(k, ".", "/"))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

func boostStatus(w io.Writer) {
	fmt.Fprintf(w, "  %s\n", kv("boost", onOff(fileExists(boostSysctl()))))
	fmt.Fprintf(w, "  %s\n", kv("congestion", sysctlGet("net.ipv4.tcp_congestion_control")))
	fmt.Fprintf(w, "  %s\n", kv("qdisc", sysctlGet("net.core.default_qdisc")))
	fmt.Fprintf(w, "  %s\n", kv("rmem max", Human(parseF(sysctlGet("net.core.rmem_max")))))
	fmt.Fprintf(w, "  %s\n", kv("wmem max", Human(parseF(sysctlGet("net.core.wmem_max")))))
	if isContainer() {
		warnLine(w, "Container environment: sysctl writes may be restricted.")
	}
	if dev := defaultDev(); dev != "" {
		if out, err := exec.Command("ethtool", "-i", dev).Output(); err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				drv, ok := strings.CutPrefix(l, "driver: ")
				if !ok {
					continue
				}
				switch drv {
				case "e1000", "e1000e", "8139cp", "8139too", "rtl8139", "pcnet32", "ne2k-pci":
					warnLine(w, "Network card: "+drv+" (emulated). One CPU core handles every packet, which usually caps the server below 1 Gbit/s.")
					hintLine(w, "Ask your provider to switch this VPS to a virtio network card.")
				}
			}
		}
	}
}

const boostBody = `# WatTunnel High-Speed Transport Engine Tunables (/boost)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
`

func boostApply() {
	if isContainer() {
		Warn("Container environment detected. Sysctl writes may be restricted by the host.")
	}
	_ = os.MkdirAll(filepath.Dir(boostSysctl()), 0o755)
	if err := os.WriteFile(boostSysctl(), []byte(boostBody), 0o644); err != nil {
		Err(err.Error())
		return
	}
	_ = exec.Command("modprobe", "tcp_bbr").Run()
	if exec.Command("sysctl", "-p", boostSysctl()).Run() != nil {
		_ = exec.Command("sysctl", "--system").Run()
	}
	boostQdisc()
	_ = os.Remove(boostOff())
	Ok("Boost parameters written to " + boostSysctl() + " and applied.")
	boostStatus(Stdout)
}

func boostUndo() {
	_ = os.Remove(boostSysctl())
	_ = os.MkdirAll(P.Conf, 0o700)
	_ = os.WriteFile(boostOff(), nil, 0o600)
	_ = exec.Command("sysctl", "--system").Run()
	Ok("Removed " + boostSysctl() + " and reloaded system defaults.")
	boostStatus(Stdout)
}

// boostQdisc puts the default-route interface on fq now; default_qdisc alone
// only covers interfaces created later. Someone's own shaping is left alone.
func boostQdisc() {
	if P.Sandbox {
		return
	}
	dev := defaultDev()
	if dev == "" {
		return
	}
	out, _ := exec.Command("tc", "qdisc", "show", "dev", dev, "root").Output()
	cur := ""
	if f := strings.Fields(string(out)); len(f) > 1 {
		cur = f[1]
	}
	switch cur {
	case "mq":
		_ = exec.Command("tc", "qdisc", "replace", "dev", dev, "root", "mq").Run()
	case "pfifo_fast", "pfifo", "fq_codel":
		_ = exec.Command("tc", "qdisc", "replace", "dev", dev, "root", "fq").Run()
	}
}

func defaultDev() string {
	out, _ := exec.Command("ip", "route", "show", "default").Output()
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1]
		}
	}
	return ""
}

func isContainer() bool {
	if fileExists("/.dockerenv") || fileExists("/run/.containerenv") || fileExists("/proc/user_beancounters") {
		return true
	}
	if exec.Command("systemd-detect-virt", "--container", "-q").Run() == nil {
		return true
	}
	f, err := os.OpenFile("/proc/sys/net/ipv4/tcp_congestion_control", os.O_WRONLY, 0)
	if err != nil {
		return true
	}
	f.Close()
	return false
}
