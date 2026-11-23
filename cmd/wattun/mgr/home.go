package mgr

// The home screen, the live tunnels table, Tools, Settings and the all-tunnels
// actions, in the approved design. Logic ports of the bash main_menu,
// batch_actions_menu, settings_menu, start/stop/restart_all, status_all,
// stale_tunnels, heal_enable/disable and boost_*.

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	// The Kharej-side Scepter console, under its bash name (scepter_menu):
	// Settings' Scepter row and the CLI route through the registry like every
	// screen. If a later scepter lane registers the same name, its init (a
	// later file) overwrites this one — the richer console wins, same contract.
	Register("scepter_menu", func(args ...string) int { scepterConsole(); return 0 })
}

// ---- live samples: byte-counter deltas give honest per-second rates ----

type sample struct {
	in, out float64
	at      time.Time
	down    []float64 // users' download rate history (bytes/s)
	up      []float64
	dNum    *Tween // the head's displayed down rate settles instead of jumping
	uNum    *Tween
	dBar    *Fill // the head's meters ease toward the new level (ui_anim.go)
	uBar    *Fill
	tot     *Tween // the Kharej glance's served total counts up on entry
	state   string // the tunnel's state as of the previous head render
	flash   int    // renders left on the state-change amber flash (ui_anim.go)
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

// meterW is the home head's rate meter width; two meters plus the row's other
// columns must fit the 96-column gate the head's rich row already used.
const meterW = 8

// histMax is a meter's scale: the biggest rate the tunnel has shown lately, so
// the bar is proportional within the row the way Spark normalizes to its own
// history (a fixed cap would make any real route look empty or pegged).
func histMax(v []float64, cur float64) float64 {
	m := cur
	for _, x := range v {
		if x > m {
			m = x
		}
	}
	return m
}

// headRate steps the tweened rate for one home-head render and returns the
// settled number plus the eased GradBar meter behind it (the Fill holds the
// bar's 0..1 level, the Tween the printed rate — both step to the same target,
// so the number and its bar move together; UseAnim off snaps everything and
// the render is byte-stable across refreshes).
func headRate(num *Tween, bar *Fill, live bool, rate float64, hist []float64) (txt, meter string) {
	if !live {
		return GRY + "—" + RST, GRY + tbar(0, 1, meterW) + RST
	}
	txt = Rate(num.Step(rate))
	scale := histMax(hist, rate)
	if scale <= 0 {
		scale = 1
	}
	meter = GradBar(bar.Step(rate/scale)*scale, scale, meterW)
	return txt, meter
}

// initHeadTweens creates the head's display state. With anim on, the first
// paint counts up from zero (owner directive 2026-11-23: live values settle
// in, and the boot intro's fast ticks carry the count-up); anim off keeps the
// old snap-to-current first paint so refreshes stay byte-stable.
func initHeadTweens(s *sample, down, up float64) {
	if s.dNum != nil {
		return
	}
	if UseAnim && !NonInteractive {
		s.dNum, s.dBar = NewTween(0), NewFill(0)
		s.uNum, s.uBar = NewTween(0), NewFill(0)
		return
	}
	ds := histMax(s.down, down)
	if ds <= 0 {
		ds = 1
	}
	us := histMax(s.up, up)
	if us <= 0 {
		us = 1
	}
	s.dNum, s.dBar = NewTween(down), NewFill(down/ds)
	s.uNum, s.uBar = NewTween(up), NewFill(up/us)
}

// stateFlash tracks a tunnel's state between head renders: a change arms a
// 3-render amber flash on the state cell (odd renders amber, even ones the new
// colour), so a tunnel going up or down catches the eye. Zero-cost when
// nothing changed, and entirely skipped with anim off — refreshes stay
// byte-stable.
func stateFlash(s *sample, ti *tunnelInfo) bool {
	if !UseAnim || NonInteractive {
		return false
	}
	if s.state != "" && s.state != ti.State {
		s.flash = 3
	}
	s.state = ti.State
	if s.flash > 0 {
		amber := s.flash%2 == 1
		s.flash--
		return amber
	}
	return false
}

// servedTotal steps the Kharej glance's served figure: it counts up from zero
// on the tunnel's first live render (anim on) and snaps to the counter
// otherwise, so the anim-off render is byte-identical to the old static text.
func servedTotal(s *sample, ti *tunnelInfo) float64 {
	if s.tot == nil {
		if UseAnim && !NonInteractive {
			s.tot = NewTween(0)
		} else {
			s.tot = NewTween(ti.Out)
		}
	}
	return s.tot.Step(ti.Out)
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
	case k && i:
		return "mixed" // both roles on one host (owner feedback 2026-11-23: say so, never guess)
	}
	return ""
}

// roleBadge is the home head's role line: which side this host is, in its
// side colour. Text colour only — the GradBand stays the head's one bright
// moment (U1), so the badge never gets Badge()'s background.
func roleBadge() string {
	switch serverSide() {
	case "iran":
		return CYN + "IRAN — the cockpit" + RST
	case "kharej":
		return SAF + "KHAREJ — the server" + RST
	case "mixed":
		return YEL + "Kharej + Iran — this host does both" + RST
	}
	return GRY + "role not set" + RST
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
	case "mixed":
		parts = append(parts, "both sides")
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

// mainMenuItems builds the home menu's rows; n is the live tunnel count for
// the Tunnels row. The menu is role-aware (owner feedback 2026-11-23: the two
// dashboards must not be identical): on Kharej the Scepter slot is the local
// pairing console — the fleet cockpit is Iran's tool and never appears there;
// on Iran it is the cockpit. An unset role shows Iran's row with a hint to set
// the role, so the first pair stays reachable.
func mainMenuItems(n int) []Item {
	scepter := Item{Label: "Scepter", Desc: "the paired Kharej cockpit: remote tunnels and state"}
	switch serverSide() {
	case "kharej":
		scepter = Item{Label: "Scepter console", Desc: "LOCAL: this server's pairing: rotate, revoke, audit"}
	case "":
		scepter.Desc = "the paired Kharej cockpit — set this server's role in Settings to focus this menu"
	}
	return []Item{
		{Label: "Tunnels", Desc: fmt.Sprintf("watch traffic, restart, edit or delete (%d)", n)},
		{Label: "New tunnel", Desc: "set one up step by step, or paste a token"},
		scepter,
		{Label: "Find a carrier", Desc: "test which carriers pass on this route"},
		{Label: "Blackout kit", Desc: "emergency bond and token for a shutdown"},
		{Label: "Tools", Desc: "update, monitor, backup, firewall, kernel boost"},
		{Label: "Settings", Desc: "auto-heal, animations, boost, update proxy, role"},
		{Label: "Exit", Off: true},
	}
}

// scepterRoute is the Scepter slot's dispatch target per role: Kharej (and an
// unset role, whose console gate sorts itself out) gets the local pairing
// console; Iran gets the fleet cockpit.
func scepterRoute() string {
	if serverSide() == "iran" {
		return "scepter_fleet"
	}
	return "scepter_menu"
}

// MainMenu is the manager's home screen: wordmark, host line, a live glance at
// every tunnel, then the choices.
func MainMenu() int {
	autoMigrateAll(true)
	sel := 0
	names0 := listedTunnels()
	if len(names0) == 0 {
		sel = 1 // nothing to manage yet: start on New tunnel
	}
	// The boot intro cascades the whole composition in once per run; introDone
	// gates re-entry for every later full page (banner.go) and this cascade.
	intro := UseAnim && !introDone && IsTTY && !NonInteractive
	introDone = true
	ClearScreen()
	if intro {
		infos0 := map[string]*tunnelInfo{}
		for _, n := range names0 {
			infos0[n] = tinfo(n)
		}
		introCascade(names0, infos0)
		introUntil = animNow().Add(introTail)
	}
	for {
		names := listedTunnels()
		infos := map[string]*tunnelInfo{}
		for _, n := range names {
			infos[n] = tinfo(n)
		}
		stale := staleTunnels()
		head := func(w io.Writer) {
			homeHead(w, names, infos, stale, false)
		}
		items := mainMenuItems(len(names))
		tick := 2 * time.Second
		if animNow().Before(introUntil) {
			tick = 250 * time.Millisecond // intro tail: the entry count-up needs sub-second frames, then the cadence returns to normal
		}
		i, k := Choose(head, items, &sel, []string{"↑↓", "move", "⏎", "open", "1-8", "jump", "q", "quit"}, tick)
		switch k {
		case "eof":
			return 0
		case "q", "Q":
			i = 7
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
			// The Scepter slot is role-aware: the fleet cockpit entry
			// (ScepterFleetEntry, lane U3) on Iran, registered under
			// "scepter_fleet" by scepter_cockpit.go; the local pairing console
			// ("scepter_menu") on Kharej or an unset role.
			dispatch(scepterRoute())
		case 3:
			findCarrier()
		case 4:
			blackoutKit()
		case 5:
			if toolsMenu() == reloadRC {
				return reloadRC
			}
		case 6:
			if settingsMenu() == 2 {
				return 0 // uninstalled
			}
		case 7:
			CurShow()
			ClearScreen()
			return 0
		}
		ClearScreen()
	}
}

func homeHead(w io.Writer, names []string, infos map[string]*tunnelInfo, stale []string, anim bool) {
	_ = anim // retired 2026-11-23: the boot intro (introCascade) owns the one animated entry
	fmt.Fprintln(w)
	old := Stdout
	Stdout = w
	Banner(false)
	Stdout = old
	fmt.Fprintln(w)
	for _, l := range homeBadgeLine(names, infos) {
		fmt.Fprintln(w, l)
	}
	// The header band is the screen's one bright moment (ui_grad.go); colour
	// off keeps the old grey rule byte-for-byte (GradLine's tier-0 contract).
	GradBand(w, uiW())
	gap(w, SecGap)
	if len(names) == 0 {
		hint := "Start on Kharej (the server outside), then paste its token on Iran."
		switch serverSide() {
		case "iran":
			hint = "Paste the token from your Kharej server: New tunnel → Paste a token."
		case "kharej":
			hint = "Create the tunnel here, then paste its token on the Iran server."
		}
		fmt.Fprintf(w, "  %sNo tunnels yet.%s %s%s%s\n", BOLD, RST, GRY, hint, RST)
		fmt.Fprintf(w, "  %sStart with New tunnel in the menu below.%s\n", GRY, RST)
		gap(w, SecGap)
		return
	}
	for _, l := range homeGlanceLines(names, infos, -1) {
		fmt.Fprintln(w, l)
	}
	gap(w, SecGap)
	pairLines(w)
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

// homeBadgeLine is the head's badge row: the role badge leads it (owner
// feedback 2026-11-23: "which side am I on" must be unmissable at a glance),
// the tagline follows it, the host line sits right-aligned. One or two lines
// depending on width; the boot intro re-renders it per frame.
func homeBadgeLine(names []string, infos map[string]*tunnelInfo) []string {
	left := roleBadge() + "  " + BOLD + Tagline + RST
	if Ver != "" {
		left = Badge(Ver) + "  " + left
	}
	right := GRY + hostLine(names, infos) + RST
	if pad := uiW() - rlen(left) - rlen(right); pad >= 3 {
		return []string{fmt.Sprintf("  %s%s%s", left, rep(" ", pad), right)}
	}
	return []string{"  " + left, "  " + right}
}

// homeRowLine is one tunnel's glance row (the head's live list). The state
// cell carries the state-change flash; the Kharej glance counts its served
// total up on entry; the wide Iran glance keeps the tweened rate meters (U1).
func homeRowLine(n string, ti *tunnelInfo) string {
	col, dot, _ := stateCell(roleName(n), ti.State)
	down, up := sampleTunnel(n, ti)
	s := samples[n]
	if stateFlash(s, ti) {
		col = YEL
	}
	line := fmt.Sprintf("  %s%s%s %s %s", col, dot, RST, padR(BOLD+trunc(n, 12)+RST, 13), padR(GRY+trunc(carrierText(n), 16)+RST, 17))
	switch ti.State {
	case "up", "degraded":
		if serverSide() == "kharej" {
			// The server-side glance: clients served, the ports this tunnel
			// answers on, total served — the rate meters and RTT are the
			// client's view (owner feedback 2026-11-23: role-aware head).
			line += fmt.Sprintf("%d clients · ports %s · served %s", ti.Sess, portsSummary(n, 24), Human(servedTotal(s, ti)))
		} else if TermCols() >= 96 {
			// Wide: the rates get tweened meters (U1's GradBar+Fill). The
			// spark gives way below 96; from 112 it returns next to them.
			if s != nil {
				initHeadTweens(s, down, up)
				dt, dm := headRate(s.dNum, s.dBar, true, down, s.down)
				ut, um := headRate(s.uNum, s.uBar, true, up, s.up)
				line += fmt.Sprintf("%s↓%s %s %s  %s↑%s %s %s  %s", CYN, RST, padL(dt, 10), dm, SAF, RST, padL(ut, 10), um, padL(fmt.Sprintf("%.0f ms", ti.RTT), 6))
				if TermCols() >= 112 {
					line += "  " + Spark(s.down, 10)
				}
			}
		} else {
			line += fmt.Sprintf("%s↓%s %s  %s↑%s %s  %s", CYN, RST, padL(Rate(down), 10), SAF, RST, padL(Rate(up), 10), padL(fmt.Sprintf("%.0f ms", ti.RTT), 6))
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
	return line
}

// glanceMax is how many rows the head's glance list shows before the "+N more"
// line (bash main_menu parity).
const glanceMax = 6

// glanceHeight is the glance region's constant line count: the boot intro
// holds blank lines for rows that have not risen yet, so its cursor-return
// repaint stays aligned frame after frame.
func glanceHeight(n int) int {
	h := n
	if h > glanceMax {
		h = glanceMax + 1 // the "+N more" line rides the cascade too
	}
	return h
}

// homeGlanceLines renders the head's glance rows, at most vis of them (-1 =
// all): the boot intro passes a growing vis so the rows rise one beat apart.
func homeGlanceLines(names []string, infos map[string]*tunnelInfo, vis int) []string {
	var out []string
	for i, n := range names {
		if vis >= 0 && len(out) >= vis {
			break
		}
		if i == glanceMax {
			out = append(out, fmt.Sprintf("  %s+%d more in Tunnels%s", GRY, len(names)-glanceMax, RST))
			break
		}
		out = append(out, homeRowLine(n, infos[n]))
	}
	return out
}

// ---- boot intro: the head cascades in after the wordmark reveal ----

// Owner directive 2026-11-23: purposeful motion everywhere, so the first home
// entry plays one composition cascade — badge, one row per beat, then the
// gradient band sweeps left to right and lands on its static self — all under
// 1.2 s, skippable with any key, never again in the run (introDone gates it).
const (
	introBadgeMS = 90 * time.Millisecond  // the badge appears one beat after the mark
	introRowMS   = 75 * time.Millisecond  // each glance row rises one beat later
	introSweepMS = 480 * time.Millisecond // the band's left-to-right sweep
	introFrameMS = 60 * time.Millisecond  // the cascade's repaint cadence
	introTail    = time.Second            // fast-tick window after the cascade (count-up)
)

// introUntil holds the animNow instant until which MainMenu keeps Choose on a
// fast tick so the entry count-up has sub-second frames (the zero value is
// always in the past: no fast ticks without an intro).
var introUntil time.Time

// introTotal is when the cascade settles for a tunnel count: badge + one beat
// per glance line (rows and the "+N more" line) + the sweep. At most 7 glance
// lines, so the ceiling is 90+8·75+480 ≈ 1.17 s.
func introTotal(n int) time.Duration {
	return introBadgeMS + time.Duration(glanceHeight(n)+1)*introRowMS + introSweepMS
}

// introRowVis is how many glance lines have risen at elapsed e.
func introRowVis(e time.Duration, h int) int {
	if e < introBadgeMS {
		return 0
	}
	v := int((e - introBadgeMS) / introRowMS)
	if v > h {
		v = h
	}
	return v
}

// introSweepPhase is the band's sweep phase at elapsed e (0 before the last
// row has risen, 1 = settled on the static GradBand).
func introSweepPhase(e time.Duration, h int) float64 {
	start := introBadgeMS + time.Duration(h+1)*introRowMS
	if e <= start {
		return 0
	}
	return clamp01(float64(e-start) / float64(introSweepMS))
}

// introBlockLines is one boot-cascade frame of the head below the wordmark:
// the badge line, the band and the glance rows each appear on their beat and
// hold blank lines until then, so the block's height never changes. e is the
// elapsed time the frame shows — tests step e through the animNow seam.
func introBlockLines(names []string, infos map[string]*tunnelInfo, e time.Duration) []string {
	badge := homeBadgeLine(names, infos)
	if e < introBadgeMS {
		badge = make([]string, len(badge))
	}
	h := glanceHeight(len(names))
	lines := append([]string{""}, badge...)
	lines = append(lines, "  "+GradSweep(uiW(), introSweepPhase(e, h)), "")
	drawn := homeGlanceLines(names, infos, introRowVis(e, h))
	for i := 0; i < h; i++ {
		if i < len(drawn) {
			lines = append(lines, drawn[i])
		} else {
			lines = append(lines, "")
		}
	}
	return lines
}

// introCascade plays the boot intro straight to the terminal on the banner
// reveal's own mechanism: the wordmark reveal first, then each frame repainting
// the head block via one cursor-return, frames advancing on the animNow clock.
// A pressed key skips to the settled frame instantly (the key is spent on the
// skip); no goroutine is involved — this runs inside the render, like
// Banner(true).
func introCascade(names []string, infos map[string]*tunnelInfo) {
	CurHide()
	defer CurShow()
	Banner(true)
	start := animNow()
	total := introTotal(len(names))
	skip := false
	for {
		e := animNow().Sub(start)
		if skip {
			e = total
		}
		lines := introBlockLines(names, infos, e)
		for _, l := range lines {
			fmt.Fprintf(Stdout, "%s%s\n", l, EL)
		}
		if e >= total {
			return
		}
		if _, ok, _ := keyByteTimeout(0); ok {
			skip = true
		} else {
			time.Sleep(introFrameMS)
		}
		fmt.Fprintf(Stdout, "\r\x1b[%dA", len(lines))
	}
}

// gap writes n blank rows — the spacing rhythm is whole blank rows only
// (ui_panel.go RowH/SecGap/PanelGap), so sections read at one cadence.
func gap(w io.Writer, n int) {
	for i := 0; i < n; i++ {
		fmt.Fprintln(w)
	}
}

// ---- Scepter pair line: the last fleet state, honestly absent when unpaired ----

// The head redraws every tick and must never dial (the fleet screen's own
// rule: fetched on entry and on refresh, never per tick). So the head renders
// the LAST fetched state document and one short-lived goroutine refreshes the
// cache at most every pairRefreshEvery — a stalled Kharej costs one pending
// dial in the background, never the render loop.
const pairRefreshEvery = 10 * time.Second

// pairBreathMS is the pair dot's breath flip interval (ui_anim.go Breath).
const pairBreathMS = 600 * time.Millisecond

var (
	pairMu     sync.Mutex
	pairDocs   = map[string]*scepterDoc{} // last good state per paired tunnel
	pairFail   = map[string]string{}      // last fetch error per paired tunnel, "" never stored
	pairFlying bool                       // one refresh pass in flight
	pairAt     time.Time                  // last finished pass
	homeSpin   Spinner                    // the head's one spinner (waiting state)
)

// pairKick starts one background refresh pass when the cache is stale.
func pairKick() {
	pairs := pairedTunnels()
	if len(pairs) == 0 {
		return
	}
	pairMu.Lock()
	stale := time.Since(pairAt) >= pairRefreshEvery
	if stale && !pairFlying {
		pairFlying = true
	} else {
		stale = false
	}
	pairMu.Unlock()
	if !stale {
		return
	}
	go func() {
		for _, n := range pairs {
			doc, err := scepterFetchDocOr(n)
			pairMu.Lock()
			if err != nil {
				pairFail[n] = err.Error()
			} else {
				pairDocs[n] = &doc
				delete(pairFail, n)
			}
			pairMu.Unlock()
		}
		pairMu.Lock()
		pairFlying = false
		pairAt = time.Now()
		pairMu.Unlock()
	}()
}

// pruneTunnelCaches drops a gone tunnel's entries from the home-side caches —
// the rate history, the pair's last state document and its last fetch error —
// so delete/rename leaves no ghost rows and a recreated tunnel of the same
// name starts with an empty graph (round 3). UI-goroutine only, like samples.
func pruneTunnelCaches(n string) {
	pairMu.Lock()
	delete(pairDocs, n)
	delete(pairFail, n)
	pairMu.Unlock()
	delete(samples, n)
}

// scepterFetchDocOr fetches one pair's state document, dial failure and RPC
// failure collapsed into one error each (the row must say why, not which layer).
func scepterFetchDocOr(n string) (scepterDoc, error) {
	cl, err := scepterDial(n)
	if err != nil {
		return scepterDoc{}, err
	}
	return scepterFetchDoc(cl)
}

// pairLines renders the pair status under the head: one line per paired
// tunnel's Kharej (seq, remote tunnels, uptime — the state document), the
// waiting spinner while the first fetch runs, the dial error honestly, and
// the plain not-paired line otherwise. Kharej hosts skip the block: their
// pairing plane is the console in Settings (IsPaired is Iran-only).
func pairLines(w io.Writer) {
	if serverSide() == "kharej" {
		return
	}
	pairKick()
	pairs := pairedTunnels()
	if len(pairs) == 0 {
		fmt.Fprintf(w, "  %s◌%s %sScepter%s  %snot paired — open a tunnel and attach the Kharej pairing line%s\n",
			GRY, RST, BOLD, RST, GRY, RST)
		return
	}
	pairMu.Lock()
	defer pairMu.Unlock()
	for _, n := range pairs {
		doc, fail := pairDocs[n], pairFail[n]
		switch {
		case fail != "":
			fmt.Fprintf(w, "  %s!%s %sScepter %s%s  %sunreachable: %s%s\n", YEL, RST, BOLD, trunc(n, 16), RST, YEL, fail, RST)
		case doc != nil:
			// The status dot breathes (◆↔◇) only while a refresh is in flight
			// — a live "working" tell; a settled pair holds the solid diamond.
			dot := "◆"
			if pairFlying && !Breath(pairBreathMS) {
				dot = "◇"
			}
			fmt.Fprintf(w, "  %s%s%s %sScepter %s%s  %sseq %d · %d remote tunnel(s) · up %s%s\n",
				GRN, dot, RST, BOLD, trunc(n, 16), RST, GRY, doc.StateSeq, len(doc.Tunnels), scepterUp(doc.UptimeS), RST)
		default:
			fmt.Fprintf(w, "  %s%s%s %sScepter %s%s  %schecking the pair…%s\n",
				GRY, homeSpin.Frame(), RST, BOLD, trunc(n, 16), RST, GRY, RST)
		}
	}
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

// toolAction is one Tools row: what it shows and the code it runs (rc is the
// exit code the Tools menu propagates — reloadRC after a self-update).
type toolAction struct {
	label, desc string
	run         func() int
}

// toolGroup runs one regrouped Tools submenu (the old flat ten-row list became
// Update / Monitor / Maintenance / Host security — unrelated concerns do not
// share one list). Every action keeps its original Page/Pause behavior.
func toolGroup(title string, actions []toolAction) int {
	sel := 0
	ClearScreen()
	for {
		items := make([]Item, len(actions))
		for i, a := range actions {
			items[i] = Item{Label: a.label, Desc: a.desc}
		}
		i, k := Choose(func(w io.Writer) { Title(w, title, "") }, items, &sel, []string{"⏎", "open", "esc", "back"}, 0)
		if k == "esc" || k == "q" || k == "eof" || k == "0" || i < 0 {
			return 0
		}
		ClearScreen()
		if rc := actions[i].run(); rc == reloadRC {
			return rc
		}
		ClearScreen()
	}
}

func toolsMenu() int {
	sel := 0
	ClearScreen()
	for {
		items := []Item{
			{Label: "Update", Desc: "get the newest wattun · roll back"},
			{Label: "Monitor", Desc: "speed test · live monitor · all tunnels"},
			{Label: "Maintenance", Desc: "back up · restore · offline bundle"},
			{Label: "Host security", Desc: "Iran firewall · kernel boost"},
		}
		i, k := Choose(func(w io.Writer) { Title(w, "Tools", "grouped by what they touch") }, items, &sel, []string{"⏎", "open", "esc", "back"}, 0)
		if k == "esc" || k == "q" || k == "eof" || k == "0" {
			return 0
		}
		if i < 0 {
			continue
		}
		var rc int
		switch i {
		case 0:
			rc = toolGroup("Tools · Update", []toolAction{
				{"Update", "get the newest wattun from GitHub", func() int {
					Page("Update", "")
					if dispatch("update") == 0 {
						fmt.Fprintln(Stdout)
						Hint("The manager reloads itself to show the new version.")
						Pause()
						return reloadRC
					}
					Pause()
					return 0
				}},
				{"Roll back", "go back to the previous binary", func() int {
					Page("Roll back", "")
					runFlow("rollback")
					Pause()
					return 0
				}},
			})
		case 1:
			toolGroup("Tools · Monitor", []toolAction{
				{"Speed test", "measure one tunnel, down and up", func() int {
					if n := pickTunnel("Speed test", "which tunnel?", func(n string) bool { return roleName(n) == "Iran" }); n != "" {
						Page("Speed test", n)
						dispatch("speed_test", n, "10")
						Pause()
					}
					return 0
				}},
				{"Live monitor", "every tunnel on one screen", func() int {
					runFlow("live_monitor")
					return 0
				}},
				{"All tunnels", "start, stop or restart everything at once", func() int {
					batchMenu()
					return 0
				}},
			})
		case 2:
			toolGroup("Tools · Maintenance", []toolAction{
				{"Back up configs", "save " + P.Conf + " to a .tar.gz", func() int {
					Page("Back up configs", "")
					backupCmd(Ask("Backup file", "wattun-backup-"+time.Now().Format("20060102")+".tar.gz"))
					Pause()
					return 0
				}},
				{"Restore configs", "put a backup back", func() int {
					Page("Restore configs", "")
					if p := Ask("Backup .tar.gz path", ""); p != "" {
						restoreCmd(p)
					}
					Pause()
					return 0
				}},
				{"Offline bundle", "pack the installer for a server without GitHub", func() int {
					Page("Offline bundle", "")
					dispatch("bundle_cmd")
					Pause()
					return 0
				}},
			})
		case 3:
			toolGroup("Tools · Host security", []toolAction{
				{"Iran firewall", "block access to this server from inside Iran", func() int {
					Page("Iran firewall", "")
					dispatch("iran_firewall_cmd")
					Pause()
					return 0
				}},
				{"Kernel boost", "BBR, fq and 64 MiB buffers", func() int {
					boostMenu()
					return 0
				}},
			})
		}
		if rc == reloadRC {
			return reloadRC
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

// settingsItems builds the Settings rows. The Scepter console row shows when
// this host can own the pairing store — Kharej, an unsaved role, or a store
// that already exists (bash settings_menu's gate: kharej || ” || pairing_active;
// an unsaved side must still reach the first pair, an explicit Iran hides it —
// Iran pairs from the Go cockpit). The Kernel boost row is bash parity: the
// settings_menu carries it, the old Go port had dropped it.
func settingsItems() []Item {
	px := ConfGet("update-proxy", "")
	items := []Item{
		{Label: "Auto-heal", Desc: onOff(healOn()) + GRY + "   restarts down Iran tunnels, keeps auto tunnels in step"},
		{Label: "Animations", Desc: onOff(ConfGet("anim", "1") == "1") + GRY + "   spinners and the wordmark reveal"},
		{Label: "Kernel boost", Desc: onOff(fileExists(boostSysctl())) + GRY + "   BBR, fq, 64 MiB buffers"},
		{Label: "Update proxy", Desc: orStr(px, "direct") + GRY + "   mirror or proxy for updates"},
		{Label: "Server role", Desc: orStr(serverSide(), "not set") + GRY + "   Kharej (outside) or Iran (inside)"},
	}
	if serverSide() != "iran" || fileExists(pairStorePath()) {
		desc := GRY + "off" + RST + GRY + "   Kharej's pairing console: pair, rotate, revoke, audit" + RST
		if c, st := pairLoad(); st == 0 {
			desc = GRN + "paired" + RST + GRY + "   (" + capTier(c.line.Caps) + ") pair, rotate, revoke, audit" + RST
		}
		items = append(items, Item{Label: "Scepter", Desc: desc})
	}
	items = append(items, Item{Label: "Uninstall", Desc: RED + "remove wattun, its tunnels and configs" + RST})
	return items
}

// settingsMenu returns 2 after an uninstall (the manager exits). Rows are
// matched by label: the Scepter row is conditional, so indexes would drift.
func settingsMenu() int {
	sel := 0
	ClearScreen()
	for {
		px := ConfGet("update-proxy", "")
		items := settingsItems()
		i, k := Choose(func(w io.Writer) { Title(w, "Settings", "") }, items, &sel, []string{"⏎", "change", "esc", "back"}, 0)
		if k == "esc" || k == "q" || k == "eof" || k == "0" {
			return 0
		}
		if i < 0 {
			continue
		}
		switch items[i].Label {
		case "Auto-heal":
			fmt.Fprintln(Stdout)
			if healOn() {
				healDisable()
			} else {
				healEnable()
			}
			sleepMS(800)
		case "Animations":
			if ConfGet("anim", "1") == "1" {
				_ = ConfSet("anim", "0")
				UseAnim = false
			} else {
				_ = ConfSet("anim", "1")
				UseAnim = IsTTY && os.Getenv("WAT_NO_ANIM") != "1"
			}
		case "Kernel boost":
			boostMenu()
		case "Update proxy":
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
		case "Server role":
			askSide()
		case "Scepter":
			ClearScreen()
			scepterConsole()
		case "Uninstall":
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

// ---- Scepter console (bash scepter_menu, Kharej's local pairing panel) ----

// The store is $CONF/.pairing (PAIR_STORE): line 1 is the credential in the
// engine's watp1: format, the manager's own bookkeeping rides as '# ' comment
// lines after it (bash pairing_store_write). The engine writes a bare line and
// skips comments on read (cmd/wattun/pairing.go readPairingFile), so both
// shapes parse here; the console only ever rewrites the whole file, never one
// line, so the engine's copy of the credential is replaced byte-complete.

func pairStorePath() string { return filepath.Join(P.Conf, ".pairing") }
func pairAuditPath() string { return filepath.Join(P.Conf, ".pairing.audit") }

// pairCred is the store's parsed content: the credential plus the manager's
// bookkeeping (bash pairing_load's P_* variables).
type pairCred struct {
	line          PairingLine
	created       int64  // epoch seconds the pairing was first created; a rotation keeps it
	oldKey        string // the pre-rotation key, kept for reference during the window
	oldKeyExpires int64  // epoch seconds the rotation window ends, 0 = no rotation pending
}

// pairLoad parses the store: 0 = parsed, 1 = exists but unreadable, 2 = no
// store (bash pairing_load's rc contract), 3 = a revoke tombstone (Handoff 4 R3). Deliberately stricter than the bash
// on the credential line: ReadPairingLine refuses a version the manager does
// not know, and an unparsable store must not be rewritten — it may be a newer
// engine's format holding the only copy of the credential (F1-B, 2026-11-22).
func pairLoad() (*pairCred, int) {
	b, err := os.ReadFile(pairStorePath())
	if err != nil {
		return nil, 2
	}
	var c pairCred
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "#") {
			if k, v, ok := strings.Cut(strings.TrimPrefix(l, "#"), "="); ok {
				switch strings.TrimSpace(k) {
				case "created":
					c.created = int64(atoi(strings.TrimSpace(v)))
				case "oldkey":
					c.oldKey = strings.TrimSpace(v)
				case "oldkey_expires":
					c.oldKeyExpires = int64(atoi(strings.TrimSpace(v)))
				}
			}
			continue
		}
		if c.line.Version != "" {
			continue // a later credential line never wins: the engine reads the first
		}
		if strings.HasPrefix(l, "revoked") {
			return nil, 3
		}
		p, perr := ReadPairingLine(l)
		if perr != nil {
			return nil, 1
		}
		c.line = p
	}
	if c.line.Version == "" {
		return nil, 1
	}
	return &c, 0
}

// pairStoreWrite writes the whole store atomically at 0600, engine format
// first: the engine's parser reads exactly line 1 (bash pairing_store_write).
func pairStoreWrite(p PairingLine, oldKey string, oldKeyExpires int64) error {
	created := time.Now().Unix()
	if c, st := pairLoad(); st == 0 && c.created > 0 {
		created = c.created // a rotation keeps the original creation time
	}
	var b strings.Builder
	b.WriteString(MakePairingLine(p.Version, p.UUID, p.Key, p.Caps))
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "# created=%d\n", created)
	if oldKey != "" {
		fmt.Fprintf(&b, "# oldkey=%s\n# oldkey_expires=%d\n", oldKey, oldKeyExpires)
	}
	return atomicWrite(pairStorePath(), []byte(b.String()), 0o600)
}

// pairAudit appends one line, never rewriting (F5, 2026-11-22: the engine
// appends with open-append-close per entry — a tmp+rename rewrite drops
// entries written to the renamed-away inode in the read-rename window). A
// failed append is an error: an unaudited pairing change must not look like
// success.
func pairAudit(event, detail string) bool {
	_ = os.MkdirAll(P.Conf, 0o700)
	f, err := os.OpenFile(pairAuditPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		Err("Could not append to " + pairAuditPath() + " — the audit line was NOT recorded.")
		return false
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s %s\n", time.Now().UTC().Format("2006-01-02T15:04:05Z"), event, detail)
	return true
}

// pairAuditTail prints the last n audit lines raw (bash pairing_audit_tail).
func pairAuditTail(n int) {
	b, err := os.ReadFile(pairAuditPath())
	if err != nil {
		Hint("No pairing audit entries yet.")
		return
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, l := range lines {
		Say(l)
	}
}

// pairStatus renders the store's state as KV rows (bash pairing_status).
func pairStatus() []string {
	c, st := pairLoad()
	switch st {
	case 2:
		return []string{KV(11, "pairing", GRY+"waiting"+RST+GRY+" (the first Iran that connects with a pairing token pairs itself)"+RST)}
	case 3:
		return []string{KV(11, "pairing", RED+"revoked"+RST+GRY+" (no Iran can manage this server — allow a new Iran to pair)"+RST)}
	case 1:
		return []string{KV(11, "pairing", YEL+"unreadable"+RST+GRY+" ("+pairStorePath()+" is not a format this manager reads)"+RST)}
	}
	state := GRN + "on" + RST
	if b, _ := os.ReadFile(pairStorePath()); strings.Contains(string(b), "\n# claimed") {
		state = GRN + "paired with an Iran" + RST
	}
	rows := []string{
		KV(11, "pairing", state),
		KV(11, "uuid", c.line.UUID),
		KV(11, "caps", capTier(c.line.Caps)),
	}
	if c.created > 0 {
		rows = append(rows, KV(11, "created", time.Unix(c.created, 0).UTC().Format("2006-01-02 15:04 UTC")))
	}
	if c.oldKey != "" && c.oldKeyExpires > 0 {
		// "the old key is accepted" was a lie (round-2, 2026-11-22): the engine
		// takes only the current credential — the old line sits in the store as
		// reference for the rotation window.
		if left := c.oldKeyExpires - time.Now().Unix(); left > 0 {
			rows = append(rows, KV(11, "rotation", YEL+"attach the new line on Iran now — window "+strconv.FormatInt(left, 10)+"s"+RST))
		} else {
			rows = append(rows, KV(11, "rotation", GRY+"old key expired"+RST))
		}
	}
	return rows
}

// newPairUUID mints a lowercase 8-4-4-4-12 hex UUID from 16 random bytes (bash
// new_pair_uuid's fold — crypto/rand, no kernel file needed).
func newPairUUID() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return "" // the caller refuses an empty UUID, same as the bash's empty fallback
	}
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// newPairKey is the D5 credential: exactly 32 random bytes (bash
// new_pair_key's head -c 32 /dev/urandom); MakePairingLine renders the base64.
func newPairKey() []byte {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return nil
	}
	return b
}

// pairCapsOK is the capability tier validator (bash v_pair_caps / PAIR_CAPS).
func pairCapsOK(s string) bool {
	_, ok := capName[s]
	return ok
}

// pairKharejOnly refuses the write actions on an explicit Iran side (bash
// scepter_kharej_only, F1-C): on Iran the same path holds the CLIENT credential
// written by wattun -pair-to; rewriting it here would desync the pair.
func pairKharejOnly() bool {
	if serverSide() == "iran" {
		Err("This is the Kharej-side action; Iran's pairing is managed by the Go cockpit (wattun -pair-to).")
		return false
	}
	return true
}

// pairReadable refuses to touch a store this manager cannot parse (bash
// pairing_check_readable, F1-B): it may be a newer engine's format holding the
// only copy of the credential, and pair/rotate/revoke would destroy it.
func pairReadable() bool {
	if _, st := pairLoad(); st != 1 {
		return true
	}
	Err(pairStorePath() + " exists but this manager cannot read it; nothing was changed.")
	Hint("Pair or rotate with the engine (wattun -pair) or delete the file by hand, then try again.")
	return false
}

// scepterConsole is the Scepter console (bash scepter_menu). On Iran it
// degrades to read-only: status and audit only, pair/rotate/revoke are the
// Kharej console's to run. The panels are quiet chrome (ui_panel.go); the
// status rows are the screen's one KV list.
func scepterConsole() {
	if serverSide() == "iran" {
		ClearScreen()
		sel := 0
		for {
			head := func(w io.Writer) {
				Title(w, "Pairing", "Iran · read-only")
				Panel(w, "Pairing", pairStatus()...)
				gap(w, SecGap)
				Hint("This Iran pairs itself with Kharej the first time a tunnel made from a pairing token connects.")
				gap(w, SecGap)
			}
			i, k := Choose(head, []Item{{Key: "a", Label: "Audit tail", Desc: "the last entries of .pairing.audit"}},
				&sel, []string{"⏎", "open", "esc", "back"}, 0)
			if k == "esc" || k == "q" || k == "eof" || k == "0" {
				return
			}
			if i < 0 {
				continue
			}
			gap(Stdout, SecGap)
			pairAuditTail(20)
			Pause()
			ClearScreen()
		}
	}
	sel := 0
	ClearScreen()
	for {
		_, st := pairLoad()
		head := func(w io.Writer) {
			Title(w, "Pairing", "which Iran manages this server")
			Panel(w, "Pairing", pairStatus()...)
			gap(w, SecGap)
		}
		items := []Item{
			{Key: "o", Label: "Allow a new Iran", Desc: "end the current pairing; the next Iran that connects takes over", Off: st == 2},
			{Key: "x", Label: "Revoke", Desc: "no Iran manages this server; tunnels keep running", Off: st == 3},
			{Key: "r", Label: "Rotate", Desc: "new key; give the new line to Iran", Off: st != 0},
			{Key: "p", Label: "Pair by hand", Desc: "generate or adopt a watp1: line"},
			{Key: "a", Label: "Audit log", Desc: "the last pairing changes"},
		}
		i, k := Choose(head, items, &sel, []string{"⏎", "run", "esc", "back"}, 0)
		if k == "esc" || k == "q" || k == "eof" || k == "0" {
			return
		}
		if i < 0 {
			continue
		}
		ClearScreen()
		switch i {
		case 0:
			scepterReopen()
		case 1:
			scepterRevoke()
		case 2:
			scepterRotate()
		case 3:
			scepterPair()
		case 4:
			gap(Stdout, SecGap)
			pairAuditTail(20)
		}
		Pause()
		ClearScreen()
	}
}

// scepterPair generates (or adopts a pasted) watp1: line, stores the pairing
// and prints the line for Iran (bash scepter_pair).
func scepterPair() {
	if !pairKharejOnly() || !pairReadable() {
		return
	}
	if c, st := pairLoad(); st == 0 {
		if !Confirm(fmt.Sprintf("A pairing already exists (%s). Replace it? Iran must be given the new line.", c.line.UUID), false) {
			return
		}
	}
	var p PairingLine
	if line := Ask("Paste a watp1: line (Enter = generate a fresh pairing here)", ""); strings.TrimSpace(line) != "" {
		var err error
		p, err = ReadPairingLine(strings.TrimSpace(line))
		if err != nil {
			Err(err.Error())
			return
		}
	} else {
		tier := capTier(CapFull)
		if !AskOK("Capability tier ("+tier+")", tier, pairCapsOK) {
			return
		}
		tier = ReplyV
		p = PairingLine{Version: ScepterVersion, UUID: newPairUUID(), Key: newPairKey(),
			Caps: tierBits(capName[tier])}
		if p.UUID == "" || p.Key == nil {
			Err("No randomness available for a fresh pairing.")
			return
		}
	}
	if pairStoreWrite(p, "", 0) != nil {
		Err("Could not write " + pairStorePath() + ".")
		return
	}
	stored := fmt.Sprintf("Pairing stored (%s, caps %s).", p.UUID, capTier(p.Caps))
	if pairAudit("pair_created", p.UUID+" caps="+capTier(p.Caps)) {
		Ok(stored)
	} else {
		// the store change is live either way — an unaudited change must not
		// look like plain success (the revoke path aborts instead, round 3)
		Warn(stored + " The audit line was NOT recorded.")
	}
	fmt.Fprintln(Stdout)
	fmt.Fprintf(Stdout, "  %s%s%s\n\n", BOLD+YEL, MakePairingLine(p.Version, p.UUID, p.Key, p.Caps), RST)
	Hint("Give this watp1: line to Iran (pairs the cockpit; wattun 3.5.0 on both ends).")
}

// scepterRotate mints a new key under the same UUID, keeping the original
// creation time and the old line for the window's reference (bash
// scepter_rotate; the menu always used the default 24 h window).
func scepterRotate() {
	if !pairKharejOnly() {
		return
	}
	c, st := pairLoad()
	if st == 2 {
		Err("No pairing to rotate (pair first).")
		return
	}
	if st == 1 {
		pairReadable() // its error text is the honest why
		return
	}
	nk := newPairKey()
	if nk == nil {
		Err("No randomness available for a rotation.")
		return
	}
	p := c.line
	p.Key = nk
	const win = 86400 // bash scepter_menu's default rotation window (24 h)
	if pairStoreWrite(p, base64.StdEncoding.EncodeToString(c.line.Key), time.Now().Unix()+win) != nil {
		Err("Could not write " + pairStorePath() + ".")
		return
	}
	rotated := "Pairing key rotated; the engine switches to the new key within its poll interval."
	if pairAudit("pair_rotated", p.UUID+" window="+strconv.Itoa(win)+"s") {
		Ok(rotated)
	} else {
		Warn(rotated + " The audit line was NOT recorded.") // the key swap is live either way
	}
	fmt.Fprintln(Stdout)
	fmt.Fprintf(Stdout, "  %s%s%s\n\n", BOLD+YEL, MakePairingLine(p.Version, p.UUID, p.Key, p.Caps), RST)
	Hint("Attach this new watp1: line on Iran NOW (rotation takes effect at the next store poll).")
}

// scepterRevoke unpairs: drop the credential locally; tunnels keep running
// (bash scepter_revoke, plan D3).
func scepterRevoke() {
	if !pairKharejOnly() {
		return
	}
	c, st := pairLoad()
	switch st {
	case 3:
		Err("The pairing is already revoked (allow a new Iran to pair again).")
		return
	case 1:
		pairReadable()
		return
	}
	id := "token" // no store: the token bootstrap is the pairing, the tombstone revokes it too
	if c != nil {
		id = c.line.UUID
	}
	if !Confirm("Revoke the pairing? No Iran can manage this server until you allow a new one; tunnels keep running.", false) {
		return
	}
	if !pairAudit("pair_revoked", id) {
		return
	}
	// Handoff 4 R3: a tombstone, not a delete — a deleted store lets a token-paired unit re-derive the
	// pairing at its next start
	tomb := fmt.Sprintf("revoked %s %s\n", id, time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	if err := atomicWrite(pairStorePath(), []byte(tomb), 0o600); err != nil {
		Err("Writing " + pairStorePath() + " failed: " + err.Error())
		return
	}
	Ok("Pairing revoked. The audit log is kept in " + pairAuditPath() + ".")
}

// scepterReopen deletes the store (Handoff 4 R2): the next Iran that connects with a pairing token pairs
// itself. The running units fall back to the token bootstrap within their poll interval.
func scepterReopen() {
	if !pairKharejOnly() {
		return
	}
	c, st := pairLoad()
	if st == 2 {
		Hint("Nothing to do: no Iran is paired yet; the next one to connect pairs itself.")
		return
	}
	if st == 1 && !pairReadable() {
		return
	}
	if !Confirm("Allow a new Iran to pair? The current pairing ends; the next Iran that connects with a pairing token takes over.", false) {
		return
	}
	id := "revoked"
	if c != nil {
		id = c.line.UUID
	}
	if !pairAudit("pair_reopened", id) {
		return
	}
	_ = os.Remove(pairStorePath())
	Ok("Pairing open: the next Iran that connects with this server's pairing token pairs itself.")
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
	Panel(w, "Kernel boost",
		KV(11, "boost", onOff(fileExists(boostSysctl()))),
		KV(11, "congestion", sysctlGet("net.ipv4.tcp_congestion_control")),
		KV(11, "qdisc", sysctlGet("net.core.default_qdisc")),
		KV(11, "rmem max", Human(parseF(sysctlGet("net.core.rmem_max")))),
		KV(11, "wmem max", Human(parseF(sysctlGet("net.core.wmem_max")))))
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
