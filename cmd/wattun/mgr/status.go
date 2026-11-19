// Port of the wattun-manager live status surface: the dashboard (page_full/dash_*),
// the single-tunnel status (tunnel_card/tunnel_header/status_row), the logs viewer
// (logs_menu), the doctor (test_tunnel/icmp_path_report/local_icmp_check) and the
// live monitor (live_monitor/mon_frame/spark). Screen-for-screen and text-for-text
// with the bash; function names referenced in comments are the bash originals.

package mgr

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// =====================================================================================
//  P1 adapters — the ported logic below only ever calls these, so tests (and any
// future P1 change) swap a body here instead of touching the port. The default
// bodies are the real P1 calls: term.KeyRead/Ask/Confirm/ClearScreen/IsTTY,
// theme.TermCols/UIInitWidth/palette, conf.Cfg/Tunnels/CompanionOf/IsAutoKharej/
// YmlMaps, stats.FetchStatsRaw, sysd.Systemctl/IsActive/UptimeOf, mgr.Register.
// =====================================================================================

var errP1 = fmt.Errorf("mgr/p3: key read failed")

var (
	p1ReadKey = func() (string, error) {
		k, _, ok := KeyRead(0)
		if !ok {
			return "", errP1
		}
		return k, nil
	}
	p1ReadLine = func(prompt, def string) string { return Ask(prompt, def) }
	p1Confirm  = func(prompt string, defYes bool) bool { return Confirm(prompt, defYes) }
	p1Clear    = func() { ClearScreen() }
	p1TermCols = func() int { return TermCols() }
	p1IsTTY    = func() bool { return IsTTY }
	p1Cfg      = func(name, key string) string { return Cfg(name, key) }
	p1Tunnels  = func() []string { return Tunnels() }
	p1Stats    = func(name string) (map[string]any, error) {
		blob, err := FetchStatsRaw(Cfg(name, "metrics"))
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(strings.NewReader(blob))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			return nil, err
		}
		return m, nil
	}
	p1Register = func(key, title string, fn func(string)) { Register(key, func(args ...string) int { fn(""); return 0 }) }

	p1Systemctl = func(action, unit string) error { return Systemctl(action, unit) }
	p1IsActive  = func(unit string) bool { return IsActive(unit) }
	p1Journal   = func(name string, args ...string) (string, error) { // journalctl text (doctor filters it)
		a := append([]string{"-u", Unit(name)}, args...)
		out, err := exec.Command("journalctl", a...).Output()
		return string(out), err
	}
	p1Uptime = func(name string) string { return UptimeOf(name) }

	// auto/companion namespace (conf.go / token.go side of P1)
	p1IsAutoKharej = func(name string) bool { return IsAutoKharej(name) }
	p1CompanionOf  = func(name string) string { return CompanionOf(name) }
	p1AutoHelpers  = func(name string) []string { return nil } // TODO(P2): auto_helpers (token plan, $parent-r/$parent-e-*)
	p1YmlMaps      = func(name string) []string { return YmlMaps(name) }
	p1CarrierLabel = func(name string) string { // carrier_label(): auto / auto-r / carrier
		if p1IsAutoKharej(name) {
			return "auto"
		}
		if p1CompanionOf(name) != "" {
			return "auto-r"
		}
		return p1Cfg(name, "carrier")
	}
)

// uiW: the bash ui_init_width() content width (theme keeps UI_W in step with the tty).
func uiW() int {
	UIInitWidth()
	return UI_W
}

// =====================================================================================
//  Small formatting helpers (ports of rep/vlen/human/ms/tbar/kv/hr/key_label/...)
// =====================================================================================

func rep(s string, n int) string { return strings.Repeat(s, n) }

// StripANSI/Vlen/Human/Ms/SpecL..SpecYaml/YmlMaps/IsPool/IsPoolList/IsReverse are P1's
// (conf.go/stats.go/theme.go) — the shared ports live there, not here.

// tbar(): proportional throughput bar, plain form (the color wrapper is tbarC).
func tbar(val, max float64, w int) string {
	if max <= 0 {
		max = 1
	}
	f := int(val*float64(w)/max + 0.5)
	if f < 0 {
		f = 0
	}
	if f > w {
		f = w
	}
	return rep("▰", f) + rep("▱", w-f)
}

// rlen: character (rune) length with ANSI stripped — the bash ${#s} on a stripped
// row; box rows carry multi-byte glyphs (▰▱●★) so byte counting overflows.
func rlen(s string) int { return len([]rune(StripANSI(s))) }

func tbarC(val, max float64, w int) string {
	if UseColor {
		return CYN + strings.Repeat("▰", strings.Count(tbar(val, max, w), "▰")) + GRY + strings.Repeat("▱", strings.Count(tbar(val, max, w), "▱")) + RST
	}
	return tbar(val, max, w)
}

// jget/jget_flat on the map form of /stats: a missing key returns ""; numbers are
// rendered like the raw JSON token the bash greps out.
func get(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func getFlat(m map[string]any, key, legacy string) string {
	if v := get(m, key); v != "" {
		return v
	}
	return get(m, legacy)
}

func getF(m map[string]any, key string) float64 {
	f, _ := strconv.ParseFloat(get(m, key), 64)
	return f
}

func getI(m map[string]any, key string) int { return int(getF(m, key)) }

func okLine(w io.Writer, args ...any) {
	fmt.Fprintf(w, "  %s✔%s %s\n", GRN, RST, strings.Trim(fmt.Sprint(args...), " "))
}
func errLine(w io.Writer, args ...any) {
	fmt.Fprintf(w, "  %s✘%s %s\n", RED, RST, strings.Trim(fmt.Sprint(args...), " "))
}
func warnLine(w io.Writer, s string) { fmt.Fprintf(w, "  %s!%s %s\n", YEL, RST, s) }
func hintLine(w io.Writer, s string) { fmt.Fprintf(w, "  %s%s%s\n", GRY, s, RST) }
func hr(w io.Writer)                 { fmt.Fprintf(w, "  %s%s%s\n", GRY, rep("─", uiW()), RST) }
func keyLabel(k any) string          { return CYN + "[" + fmt.Sprint(k) + "]" + RST }
func kv(label, value string) string  { return fmt.Sprintf("%s%-11s%s %s", GRY, label, RST, value) }

func secHdr(w io.Writer, title string, meta ...string) {
	m := ""
	if len(meta) > 0 && meta[0] != "" {
		m = " · " + meta[0]
	}
	rem := uiW() - (3 + len(title) + Vlen(m) + 1)
	if rem < 2 {
		rem = 2
	}
	fmt.Fprintf(w, "\n  %s── %s%s%s%s %s%s%s\n", GRY, RST+BOLD, title, RST, m, GRY, rep("─", rem)+RST, "")
}

func menuLine(w io.Writer, pairs ...string) { // pairs of key,label wrapped at width
	i := 0
	for _, p := range pairs {
		if i+Vlen(p)+4 > uiW() && i > 0 {
			fmt.Fprintln(w)
			i = 0
		}
		fmt.Fprintf(w, "%s ", keyLabel(p[:1])+fmt.Sprintf(" %s", p[1:]))
		i += Vlen(p) + 4
	}
	fmt.Fprintln(w)
}

// ---- box (tunnel card framing) ----

const boxW = 58

func boxTop(w io.Writer, title string) {
	if title == "" {
		fmt.Fprintf(w, "  %s╭%s╮%s\n", GRY, rep("─", boxW), RST)
		return
	}
	rem := boxW - rlen(title) - 3
	if rem < 1 {
		rem = 1
	}
	fmt.Fprintf(w, "  %s╭─ %s%s%s %s╮%s\n", GRY, RST, title, GRY, rep("─", rem), RST)
}

func boxMid(w io.Writer) { fmt.Fprintf(w, "  %s├%s┤%s\n", GRY, rep("─", boxW), RST) }

func boxRow(w io.Writer, t string) {
	if rlen(t) > boxW-2 { // a row never pushes the right border out: cut it (runes, not bytes)
		r := []rune(StripANSI(t))
		if len(r) > boxW-3 {
			r = r[:boxW-3]
		}
		t = string(r) + "…"
	}
	fmt.Fprintf(w, "  %s│%s %s%s%s│%s\n", GRY, RST, t, rep(" ", boxW-2-rlen(t)), GRY, RST)
}

func row2col(w io.Writer, left, right string) {
	if boxW < 58 {
		boxRow(w, left)
		if StripANSI(right) != "" {
			boxRow(w, right)
		}
		return
	}
	wLeft := (boxW - 4) / 2
	pad := wLeft - rlen(left)
	if pad < 0 {
		pad = 0
	}
	boxRow(w, left+rep(" ", pad)+"  "+right)
}

func boxBot(w io.Writer) { fmt.Fprintf(w, "  %s╰%s╯%s\n", GRY, rep("─", boxW), RST) }

// =====================================================================================
//  parse_carriers / tinfo / state_cell / ports_summary
// =====================================================================================

type carInfo struct {
	Name, Alive, RTT, Loss, Share, Muted string
}

func parseCarriers(m map[string]any) []carInfo {
	raw, _ := m["carriers"].([]any)
	var out []carInfo
	for _, it := range raw {
		c, _ := it.(map[string]any)
		if c == nil {
			continue
		}
		getc := func(k, def string) string {
			if v := get(c, k); v != "" {
				return v
			}
			return def
		}
		out = append(out, carInfo{
			Name: getc("name", "unknown"), Alive: getc("alive", "false"),
			RTT: getc("srtt_ms", "0"), Loss: getc("loss", "0"),
			Share: getc("share", "0"), Muted: getc("muted", "false"),
		})
	}
	return out
}

// tinfo(): state: up | degraded | down | standby | unknown | stopped.
// TODO(P1): the auto-Kharej aggregation branch sums parent + hidden helpers
// (auto_helpers units, stats_flat): port it once conf exposes the token plan.
type tunnelInfo struct {
	State, Why, Raw    string
	stats              map[string]any
	RTT, MinRTT, Loss  float64
	Streams, Sess      int
	DgramFlows         int
	In, Out, Rate      float64
	CarCount           int
	CarAlive, CarMuted int
	Live, LivePick     string
	Auto               bool
	Cars               []carInfo
}

func statsOf(name string) (map[string]any, error) { return p1Stats(name) }

func tinfo(name string) *tunnelInfo {
	ti := &tunnelInfo{State: "stopped", Live: p1Cfg(name, "carrier")}
	par := p1CompanionOf(name)
	if par != "" { // hidden reverse companion of an auto tunnel
		ti.Auto = true
		if !p1IsActive("wattun@" + name) {
			return ti
		}
		m, err := statsOf(name)
		if err != nil {
			ti.State, ti.Why = "unknown", "stats did not answer, status not known"
			return ti
		}
		ti.stats = m
		if get(m, "alive") == "true" {
			ti.State = "up"
		} else if pm, err := statsOf(par); err == nil && get(pm, "alive") == "true" {
			ti.State, ti.Why = "standby", "not in use, Iran is connected through "+par
		} else {
			ti.State = "down"
		}
		fillTI(ti, ti.stats)
		return ti
	}
	// TODO(P1): is_auto_kharej branch (sum over parent + -r + -e-* helpers) — same
	// aggregation the bash does; until tokens are readable it degrades to the plain path.
	on := p1IsActive("wattun@" + name)
	var other string
	if p := p1CompanionOf(name + "-r"); p == name {
		other = name + "-r"
	}
	var om map[string]any
	miss := false
	if other != "" && p1IsActive("wattun@"+other) {
		var err error
		if om, err = statsOf(other); err != nil {
			miss = true
		}
	}
	switch {
	case on:
		m, err := statsOf(name)
		if err != nil {
			ti.State, ti.Why = "unknown", "stats did not answer, status not known"
			return ti
		}
		ti.stats = m
	case par == "" && om != nil:
		ti.stats = om
	case par == "" && miss:
		ti.State, ti.Why = "unknown", other+" stats did not answer, status not known"
		return ti
	default:
		return ti
	}
	if on && get(ti.stats, "alive") == "true" {
		ti.State = "up"
	} else if miss {
		ti.State, ti.Why = "unknown", other+" stats did not answer, status not known"
	} else if om == nil || get(om, "alive") != "true" {
		ti.State = "down"
	} else if par != "" {
		ti.State, ti.Why = "standby", "not in use, Iran is connected through "+par
	} else {
		ti.State, ti.Why = "up", "Iran is connected through "+other
	}
	fillTI(ti, ti.stats)
	return ti
}

// fillTI(): the common field picks of tinfo's tail (rtt/streams/sessions/totals/carriers).
func fillTI(ti *tunnelInfo, m map[string]any) {
	if m == nil {
		m = map[string]any{}
	}
	ti.RTT = getF(m, "rtt_ms")
	if ti.RTT == 0 {
		ti.RTT = getF(m, "srtt_ms")
	}
	ti.MinRTT = getF(m, "min_rtt_ms")
	ti.Loss = getF(m, "loss_pct")
	ti.Streams = getIFlat(m, "streams_total", "streams")
	ti.Sess = getI(m, "sessions")
	ti.DgramFlows = getI(m, "dgram_flows")
	ti.In = getF(m, "bytes_in_total")
	ti.Out = getF(m, "bytes_out_total")
	if get(m, "bytes_in_total") == "" { // before 2.4.19: since the last restart
		ti.In = getF(m, "bytes_in")
		ti.Out = getF(m, "bytes_out")
	}
	ti.Rate = getF(m, "rate_bps")
	if ti.RTT < 0.5 { // a server between samples reports srtt 0
		ti.RTT = ti.MinRTT
	}
	ti.Cars = parseCarriers(m)
	ti.CarCount = len(ti.Cars)
	if ti.CarCount > 0 {
		live := ""
		for _, c := range ti.Cars {
			if c.Alive == "true" {
				live += livePart(live) + c.Name
			}
		}
		ti.Live = live
	}
	if ti.State == "up" && ti.CarCount > 0 && !ti.Auto {
		unmutedLive, unmutedTotal := 0, 0
		for _, c := range ti.Cars {
			if c.Muted == "true" {
				ti.CarMuted++
			} else {
				unmutedTotal++
				if c.Alive == "true" {
					unmutedLive++
				}
			}
		}
		ti.CarAlive = unmutedLive
		if unmutedTotal > 1 && unmutedLive < unmutedTotal {
			ti.State = "degraded"
			ti.Why = fmt.Sprintf("%d of %d carriers down", unmutedTotal-unmutedLive, unmutedTotal)
		}
	}
}

func getIFlat(m map[string]any, k, legacy string) int { return int(getFFlat(m, k, legacy)) }

func getFFlat(m map[string]any, k, legacy string) float64 {
	if v := getF(m, k); v != 0 {
		return v
	}
	return getF(m, legacy)
}

func livePart(live string) string {
	if live == "" {
		return ""
	}
	return "+"
}

// state_cell(): role-tinted state text.
func stateCell(role, state string) (col, dot, txt string) {
	switch state {
	case "up":
		return GRN, "●", "up"
	case "degraded":
		return YEL, "◐", "partial"
	case "standby":
		return GRY, "◌", "standby"
	case "unknown":
		return YEL, "◐", "unknown"
	case "down":
		if role == "Kharej" {
			return RED, "○", "waiting"
		}
		return RED, "○", "down"
	default:
		return GRY, "◌", "stopped"
	}
}

// ports_summary(): "443 · 8443→443 · 53/udp" (+N when clipped).
func portsSummary(name string, max int) string {
	role := roleName(name)
	out, cnt, total := "", 0, 0
	for _, it := range p1YmlMaps(name) {
		if it == "" {
			continue
		}
		total++
		piece := SpecHuman(it)
		if role == "Kharej" {
			piece = SpecT(it)
			if SpecP(it) == "udp" {
				piece += "/udp"
			}
		}
		if len(out)+len(piece)+5 > max {
			continue
		}
		if out != "" {
			out += " · "
		}
		out += piece
		cnt++
	}
	if total == 0 {
		if role == "Kharej" {
			return "any port"
		}
		return "no ports yet"
	}
	if cnt < total {
		out += fmt.Sprintf(" +%d", total-cnt)
	}
	return out
}

// lastColon: tail of a host:port pair after the last colon (splitHostPort's twin).
func lastColon(s string) string {
	if i := strings.LastIndex(s, ":"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// roleName mirrors role(): Kharej for a server config, Iran otherwise.
func roleName(name string) string {
	if p1Cfg(name, "mode") == "server" {
		return "Kharej"
	}
	return "Iran"
}

// has_dgram(): every carrier in the list is non-pool -> loss_pct is wire loss.
func hasDgram(carriers string) bool {
	for _, c := range strings.Split(carriers, "+") {
		if IsPool(c) {
			return false
		}
	}
	return true
}

// =====================================================================================
//  Dashboard (dash_table / dash_row / dash_actions) — the page_full main screen
// =====================================================================================

var dashN []string

func renderSubpageHeader(w io.Writer, title, subtitle string) {
	fmt.Fprintf(w, "\n  %sWatTunnel ·%s %s%s%s", GRY, RST, BOLD, title, RST)
	if subtitle != "" {
		fmt.Fprintf(w, "  %s%s%s", GRY, subtitle, RST)
	}
	fmt.Fprintln(w)
}

func pageHeader(w io.Writer, title, subtitle string) {
	p1Clear()
	fmt.Fprintln(w)
	renderSubpageHeader(w, title, subtitle)
	hr(w)
	fmt.Fprintln(w)
}

func dashRow(w io.Writer, i int, n string) {
	cols := p1TermCols()
	r := roleName(n)
	cr := p1CarrierLabel(n)
	par := p1CompanionOf(n)
	ti := tinfo(n)
	col, dot, txt := stateCell(r, ti.State)
	if p1IsAutoKharej(n) && ti.LivePick != "" {
		cr = ti.LivePick
	} else if p1IsAutoKharej(n) {
		cr = "auto"
	}
	load, rtt := "", "-"
	if ti.State != "stopped" {
		if r == "Kharej" {
			load = fmt.Sprintf("%dc", ti.Sess)
		} else {
			load = fmt.Sprintf("%ds", ti.Streams)
		}
		if ti.State == "up" || ti.State == "degraded" {
			rtt = fmt.Sprintf("%.0f ms", ti.RTT)
		}
	}
	tr := ""
	if ti.State != "stopped" {
		tr = "↓" + Human(ti.In) + " ↑" + Human(ti.Out)
	}
	pl := portsSummary(n, 38)
	if par != "" {
		pl = "reverse of " + par
	}
	if ti.State != "stopped" && IsPoolList(p1Cfg(n, "carrier")) &&
		p1Cfg(n, "fake-sni") == "" && p1Cfg(n, "pool-rotate") == "" && p1Cfg(n, "pool-rotate-bytes") == "" &&
		roleName(n) == "Iran" && !IsReverse(n) { // ac_dialer: the dialing side carries the kit
		pl += "  " + YEL + "[anti-censor off]" + RST
	}
	idxPad := ""
	if i < 10 {
		idxPad = " "
	}
	if cols < 74 {
		carDisplay := cr
		if strings.Contains(cr, "+") {
			carDisplay = fmt.Sprintf("bond[%d]", len(strings.Split(cr, "+")))
		} else if len(carDisplay) > 8 {
			carDisplay = carDisplay[:8]
		}
		fmt.Fprintf(w, "  %s%s %-11s %-6s %s%s %-8s%s %5s  %s\n",
			keyLabel(i), idxPad, trunc(n, 11), r, col, dot, txt, RST, rtt, carDisplay)
		if tr+pl != "" {
			t := pl
			if tr != "" {
				t = tr + " · " + pl
			}
			fmt.Fprintf(w, "       %s%s%s\n", GRY, t, RST)
		}
	} else {
		carDisplay := cr
		if len(carDisplay) > 12 {
			carDisplay = carDisplay[:12]
		}
		tail := ""
		if tr != "" {
			tail = tr + " · " + load
		}
		fmt.Fprintf(w, "  %s%s %-14s %-6s %-12s %s%s %-8s%s %6s  %s\n",
			keyLabel(i), idxPad, trunc(n, 14), r, carDisplay, col, dot, txt, RST, rtt, tail)
		if pl != "" {
			fmt.Fprintf(w, "       %s%s%s\n", GRY, pl, RST)
		}
	}
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func dashTable(w io.Writer) {
	cols := p1TermCols()
	dashN = append([]string(nil), p1Tunnels()...)
	if len(dashN) == 0 {
		fmt.Fprintf(w, "  No tunnels configured. Press %s to create one", keyLabel("n"))
		switch p1Cfg(".manager", "side") { // TODO(P1): conf server_side
		case "kharej":
			fmt.Fprint(w, " (Kharej).\n")
		case "iran":
			fmt.Fprint(w, " (paste token from Kharej).\n")
		default:
			fmt.Fprint(w, " (Kharej first, then Iran).\n")
		}
		return
	}
	if cols < 74 {
		fmt.Fprintf(w, "  %s%-4s %-11s %-6s %-10s %5s  %s%s\n", GRY, "#", "NAME", "ROLE", "STATE", "RTT", "CARRIER", RST)
	} else {
		fmt.Fprintf(w, "  %s%-4s %-14s %-6s %-12s %-10s %6s  %s%s\n", GRY, "#", "NAME", "ROLE", "CARRIER", "STATE", "RTT", "TRAFFIC", RST)
	}
	for i, n := range dashN {
		dashRow(w, i+1, n)
	}
}

func dashActions(w io.Writer) {
	cnt := len(dashN)
	fmt.Fprintln(w)
	hr(w)
	if cnt > 0 {
		open := "1"
		if cnt > 1 {
			open = fmt.Sprintf("1-%d", cnt)
		}
		menuLine(w, open, "open", "n", "new", "a", "batch", "m", "monitor", "s", "settings", "u", "update", "q", "quit")
	} else {
		menuLine(w, "n", "new", "s", "settings", "u", "update", "q", "quit")
	}
}

// RunDashboard: the main_menu loop — re-render on every key, the bash refresh cadence.
func RunDashboard(out io.Writer) {
	for {
		pageHeader(out, "Tunnels", fmt.Sprintf("%d total", len(p1Tunnels())))
		dashTable(out)
		dashActions(out)
		k, err := p1ReadKey()
		if err != nil {
			return
		}
		switch {
		case k >= "1" && k <= "9":
			num, _ := strconv.Atoi(k)
			if num >= 1 && num <= len(dashN) {
				_ = num // TODO(P2): tunnel_page(dashN[num-1]) — the tunnel deck is P2's
			}
		case k == "m" || k == "M":
			if len(dashN) > 0 {
				LiveMonitor(out)
			}
		case k == "q" || k == "Q", k == "esc":
			return
		}
	}
}

// =====================================================================================
//  status_all / status_row / tunnel_card / tunnel_header — the single-tunnel status
// =====================================================================================

func StatusAll(w io.Writer) {
	any := false
	for _, n := range p1Tunnels() {
		any = true
		StatusRow(w, n)
	}
	if !any {
		warnLine(w, "No tunnels yet. Start with Kharej: run wattun-manager and press n.")
	}
}

func StatusRow(w io.Writer, n string) {
	r := roleName(n)
	cr := p1CarrierLabel(n)
	ti := tinfo(n)
	col, dot, txt := stateCell(r, ti.State)
	load := ""
	if ti.State != "stopped" {
		if r == "Kharej" {
			load = fmt.Sprintf("clients %d", ti.Sess)
		} else {
			load = fmt.Sprintf("streams %d", ti.Streams)
		}
	}
	rtt := "-"
	if ti.State == "up" {
		rtt = fmt.Sprintf("%.0fms", ti.RTT)
	}
	fmt.Fprintf(w, "  %-12s %-6s %-5s %s%s %-12s%s %-6s %-11s %s\n",
		trunc(n, 12), r, cr, col, dot, strings.ToUpper(txt), RST, rtt, load, portsSummary(n, 17))
}

// TunnelHeader: one line, "WatTunnel · name  role   ● up · carrier · ↓rate/s".
func TunnelHeader(w io.Writer, n, r string) {
	p1Clear()
	fmt.Fprintln(w)
	ti := tinfo(n)
	col, dot, txt := stateCell(r, ti.State)
	left := fmt.Sprintf("%sWatTunnel ·%s %s%s%s  %s%s%s", GRY, RST, BOLD, n, RST, GRY, r, RST)
	right := fmt.Sprintf("%s%s %s%s %s· %s%s", col, dot, txt, RST, GRY, p1CarrierLabel(n), RST)
	if ti.State == "up" || ti.State == "degraded" {
		if ti.Rate > 0 {
			right += fmt.Sprintf(" %s·%s ↓%s/s", GRY, RST, Human(ti.Rate))
		} else {
			right += fmt.Sprintf(" %s· idle%s", GRY, RST)
		}
	}
	pad := uiW() - rlen(left) - rlen(right)
	if pad < 2 {
		pad = 2
	}
	fmt.Fprintf(w, "  %s%s%s%s\n", left, rep(" ", pad), right, "")
	hr(w)
	fmt.Fprintln(w)
}

// TunnelCard: the box the status screen shows — every field from /stats the bash prints.
func TunnelCard(w io.Writer, n string) {
	r := roleName(n)
	cr := p1Cfg(n, "carrier")
	peer := p1Cfg(n, "peer")
	lis := p1Cfg(n, "listen")
	par := p1CompanionOf(n)
	ti := tinfo(n)
	col, _, _ := stateCell(r, ti.State)
	srvAct := "inactive"
	if p1IsActive("wattun@" + n) {
		srvAct = "active"
	}
	srvUp := p1Uptime(n)
	routingTxt := kv("ports", portsSummary(n, 26))
	if r == "Kharej" {
		routingTxt = kv("allows", portsSummary(n, 26))
	}
	title := ""
	if par != "" {
		title = "reverse side of " + par
	}
	boxTop(w, title)
	boot := "boot off"
	if srvAct == "active" {
		boot = "boot on"
	}
	if ti.Why != "" {
		boxRow(w, col+ti.Why+RST)
	}
	if srvAct == "active" && srvUp != "" {
		boxRow(w, fmt.Sprintf("%sactive %s · %s%s", GRY, srvUp, boot, RST))
	} else {
		boxRow(w, fmt.Sprintf("%s%s · %s%s", GRY, srvAct, boot, RST))
	}
	carTxt := kv("carrier", cr)
	if par != "" && ti.State == "up" && ti.Live != "" {
		carTxt = kv("carrier", ti.Live)
	} else if par != "" {
		carTxt = kv("carrier", fmt.Sprintf("auto %s(%d ready)%s", GRY, len(strings.Split(cr, "+")), RST))
	}
	row2col(w, carTxt, routingTxt)
	// sub-role detail row
	switch {
	case par != "":
		boxRow(w, kv("reverse", "to Iran "+p1Cfg(n, "peer-icmp")))
	case cr == "icmp" && IsReverse(n):
		if r == "Iran" {
			boxRow(w, kv("reverse", "pinged by "+dash(peer)))
		} else {
			boxRow(w, kv("reverse", "pings "+dash(peer)))
		}
	case (cr == "udp" || IsPool(cr)) && IsReverse(n):
		if r == "Iran" {
			boxRow(w, kv("reverse", "listen "+dash(lis)))
		} else {
			boxRow(w, kv("reverse", "dials "+dash(peer)))
		}
	case r == "Iran":
		boxRow(w, kv("Kharej", dash(peer)))
	case lis != "":
		boxRow(w, kv("listen", lis))
	}
	if ti.State != "stopped" {
		boxMid(w)
		uf := ti.DgramFlows
		if ti.State == "up" || ti.State == "degraded" {
			rt, mr := fmt.Sprintf("%.0f", ti.RTT), fmt.Sprintf("%.0f", ti.MinRTT)
			rtTxt := rt + " ms"
			if rt != mr {
				rtTxt = fmt.Sprintf("%s ms %smin %s%s", rt, GRY, mr, RST)
			}
			lossRight := ""
			if hasDgram(ti.Live) {
				lossRight = kv("loss", fmt.Sprintf("%.1f %%", ti.Loss))
				if uf > 0 {
					// bash puts loss+udp-flows on the left/right of one row only for dgram
					// carriers; a second kv would overflow — keep the bash's single kv.
					lossRight = kv("udp flows", fmt.Sprintf("%d", uf))
				}
			}
			if lossRight == "" && uf > 0 {
				lossRight = kv("udp flows", fmt.Sprintf("%d", uf))
			}
			row2col(w, kv("rtt", rtTxt), kv("streams", fmt.Sprintf("%d", ti.Streams)))
			row2col(w, kv("total", fmt.Sprintf("↓%s  ↑%s", Human(ti.In), Human(ti.Out))), kv("sessions", fmt.Sprintf("%d", ti.Sess)))
			if hasDgram(ti.Live) {
				row2col(w, kv("loss", fmt.Sprintf("%.1f %%", ti.Loss)), lossRight)
			} else if lossRight != "" {
				boxRow(w, lossRight)
			}
		} else if ti.In > 0 {
			boxRow(w, kv("total", fmt.Sprintf("↓%s  ↑%s", Human(ti.In), Human(ti.Out))))
		}
		// one row per carrier of a bond (only when the live set is a bond)
		multi := strings.Contains(ti.Live, "+")
		if ti.CarCount > 1 && (!ti.Auto || multi) {
			boxMid(w)
			for _, c := range ti.Cars {
				var ccol, cdot, ctxt, det string
				switch {
				case c.Muted == "true":
					ccol, cdot, ctxt = GRY, "◌", "muted"
				case c.Alive == "true":
					ccol, cdot, ctxt = GRN, "●", "up"
					det = fmt.Sprintf("%.0f ms · %.0f%% traffic", parseF(c.RTT), parseF(c.Share)*100)
					if hasDgram(c.Name) {
						det += fmt.Sprintf(" · loss %.1f%%", parseF(c.Loss)*100)
					}
				default:
					if ti.Auto {
						continue
					}
					ccol, cdot, ctxt = RED, "○", "down"
				}
				boxRow(w, fmt.Sprintf("%s%s %-5s%s %-6s %s%s%s", ccol, cdot, ctxt, RST, c.Name, GRY, det, RST))
			}
		}
	}
	boxBot(w)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func parseF(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

// =====================================================================================
//  logs_menu: journalctl views, incl. -f streaming via os/exec
// =====================================================================================

func LogsMenu(name string, out io.Writer) {
	menuLine(out, "1", "last 100", "2", "follow live", "3", "errors only", "4", "since boot", "0", "back")
	fmt.Fprintf(out, "  %s▸%s %s[1]%s ", CYN, RST, GRY, RST)
	key, err := p1ReadKey()
	fmt.Fprintln(out)
	fmt.Fprintln(out)
	if err != nil {
		return
	}
	unit := "wattun@" + name
	switch key {
	case "1", "enter":
		s, _ := p1Journal(name, "-n", "100", "--no-pager", "-o", "short-iso")
		fmt.Fprint(out, s)
	case "2": // follow live: stream until Ctrl+C
		c := exec.Command("journalctl", "-u", unit, "-f", "-o", "short-iso")
		c.Stdout = out
		c.Stderr = out
		_ = c.Run()
	case "3":
		s, _ := p1Journal(name, "-n", "2000", "--no-pager", "-o", "short-iso")
		var hits []string
		for _, l := range strings.Split(s, "\n") {
			if matchAny(l, "error", "fail", "denied", "refused", "lost", "restart") {
				hits = append(hits, l)
			}
		}
		if len(hits) > 50 {
			hits = hits[len(hits)-50:]
		}
		fmt.Fprintln(out, strings.Join(hits, "\n"))
	case "4":
		s, _ := p1Journal(name, "-b", "--no-pager", "-o", "short-iso")
		lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
		if len(lines) > 200 {
			lines = lines[len(lines)-200:]
		}
		fmt.Fprintln(out, strings.Join(lines, "\n"))
	}
}

func matchAny(s string, words ...string) bool {
	ls := strings.ToLower(s)
	for _, w := range words {
		if strings.Contains(ls, w) {
			return true
		}
	}
	return false
}

// =====================================================================================
//  Doctor: test_tunnel + icmp_path_report + local_icmp_check (verbatim verdicts)
// =====================================================================================

// Doctor is the bash test_tunnel(). IO hooks are injectable for tests.
type DoctorIO struct {
	Out       io.Writer
	PingHost  func(host string) bool              // ping -c N -W 2
	TCPProbe  func(host string, port string) bool // /dev/tcp probe
	PortBusy  func(port, proto string) bool       // port_busy
	SysctlEq1 func(key string) bool               // sysctl -n key = 1
	FwICMP    func() []string                     // iptables/nft ICMP drop/reject rules
	Journal   func(name string, args ...string) string
	SpeedTest func(name string) // the Iran-only tail of the doctor
}

func (d *DoctorIO) ping(host string) bool {
	if d.PingHost != nil {
		return d.PingHost(host)
	}
	return exec.Command("ping", "-c", "3", "-W", "2", "-q", host).Run() == nil
}

func (d *DoctorIO) tcp(host, port string) bool {
	if d.TCPProbe != nil {
		return d.TCPProbe(host, port)
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 4*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (d *DoctorIO) journal(name string, args ...string) string {
	if d.Journal != nil {
		return d.Journal(name, args...)
	}
	s, _ := p1Journal(name, args...)
	return s
}

func Doctor(name string, io_ *DoctorIO) {
	n := name
	d := io_
	w := d.Out
	cr := p1Cfg(n, "carrier")
	peer := p1Cfg(n, "peer")
	r := roleName(n)
	pageHeader(w, "Doctor", fmt.Sprintf("%s (%s · %s)", n, r, cr))
	secHdr(w, "Checks")
	if p1IsActive("wattun@" + n) {
		okLine(w, fmt.Sprintf("Service     running (wattun@%s)", n))
	} else {
		errLine(w, "Service     stopped")
		fmt.Fprint(w, d.journal(n, "-n", "10", "--no-pager", "-o", "cat"))
		return
	}
	host, port := splitHostPort(peer)
	if r == "Iran" {
		switch {
		case cr == "icmp" && IsReverse(n):
			hintLine(w, " · Reverse ICMP: Kharej pings this server — run Doctor on Kharej")
		case cr == "icmp":
			if d.ping(host) {
				okLine(w, "Ping        "+host+" reachable")
			} else {
				errLine(w, "Ping        "+host+" unreachable (ICMP blocked or dropped)")
			}
		case IsReverse(n) && (cr == "udp" || IsPool(cr)):
			lport := lastColon(p1Cfg(n, "listen"))
			proto := "tcp"
			if cr == "udp" {
				proto = "udp"
			}
			busy := false
			if d.PortBusy != nil {
				busy = d.PortBusy(lport, proto)
			}
			if lport != "" && busy {
				okLine(w, fmt.Sprintf("Listen      :%s/%s open", lport, proto))
			} else {
				errLine(w, fmt.Sprintf("Listen      :%s/%s not listening", dash(lport), proto))
			}
		case IsPool(cr) && port != "":
			if d.tcp(host, port) {
				okLine(w, "TCP         "+host+":"+port+" open")
			} else {
				errLine(w, "TCP         "+host+":"+port+" closed or filtered")
			}
		}
	}
	if strings.Contains(cr, "+") { // bond legs, one probe line each
		for i, cp := range strings.Split(cr, "+") {
			cpeer := p1Cfg(n, "peer-"+cp)
			if cpeer == "" {
				cpeer = peer
			}
			chost, cport := splitHostPort(cpeer)
			fmt.Fprintf(w, "    %s%d%s %-6s ", GRY, i+1, RST, cp)
			if r == "Iran" {
				switch {
				case cp == "icmp":
					if d.ping(chost) {
						fmt.Fprintf(w, "%s✔ ping ok%s\n", GRN, RST)
					} else {
						fmt.Fprintf(w, "%s✘ ping fails%s\n", RED, RST)
					}
				case IsPool(cp) && cport != "":
					if d.tcp(chost, cport) {
						fmt.Fprintf(w, "%s✔ tcp %s:%s open%s\n", GRN, chost, cport, RST)
					} else {
						fmt.Fprintf(w, "%s✘ tcp %s:%s closed/filtered%s\n", RED, chost, cport, RST)
					}
				default:
					fmt.Fprintf(w, "%sconfigured%s\n", GRY, RST)
				}
			} else {
				fmt.Fprintf(w, "%sactive%s\n", GRY, RST)
			}
		}
	}
	stats, _ := statsOf(n)
	alive := stats != nil && get(stats, "alive") == "true"
	if alive {
		rtt := getFFlat(stats, "rtt_ms", "srtt_ms")
		okLine(w, fmt.Sprintf("Link        CONNECTED · RTT %s ms", Ms(rtt)))
		if cars := parseCarriers(stats); len(cars) > 0 {
			secHdr(w, "Live paths")
			for _, c := range cars {
				ccol, cdot, ctxt := RED, "○", "down"
				if c.Alive == "true" {
					ccol, cdot, ctxt = GRN, "●", "up"
				}
				if c.Muted == "true" {
					ccol, cdot, ctxt = GRY, "◌", "muted"
				}
				pct := parseF(c.Share) * 100
				fmt.Fprintf(w, "  %s%s %-6s%s %-8s %4.0f ms  loss %4.1f%%  share %3.0f%%  %s\n",
					ccol, cdot, ctxt, RST, c.Name, parseF(c.RTT), parseF(c.Loss)*100, pct, tbarC(pct, 100, 10))
			}
		}
	} else {
		if r == "Kharej" {
			errLine(w, "Link        no Iran client connected")
		} else {
			errLine(w, "Link        DISCONNECTED")
		}
		hintLine(w, " · Key/carrier mismatch -> re-paste Kharej token")
		hintLine(w, " · Peer down or port blocked -> check Kharej status & firewall")
		hintLine(w, " · Route filtered -> run auto-test or blackout")
		if r == "Iran" && IsPool(cr) && !IsReverse(n) && host != "" && port != "" && d.tcp(host, port) {
			fmt.Fprintln(w)
			warnLine(w, "TCP open but handshake fails (likely SNI allowlist)")
			hintLine(w, " · Fix: wattun-manager blackout "+n+" mci.ir  (or tunnel page -> z)")
		}
	}
	if r == "Iran" && cr == "icmp" && !alive {
		if IsReverse(n) {
			secHdr(w, "Local ICMP")
			if hits := localICMPCheck(d, true, p1Cfg(n, "icmp-type")); len(hits) > 0 {
				warnLine(w, "iptables has ICMP rules that drop or reject:")
				for _, l := range hits {
					fmt.Fprintf(w, "        %s%s%s\n", GRY, l, RST)
				}
				hintLine(w, " · Fix rule above so Kharej pings reach this host")
			} else {
				okLine(w, "Local firewall allows ICMP")
			}
		} else {
			icmpPathReport(n, host, d)
		}
	}
	if r == "Kharej" && !alive {
		log := d.journal(n, "--since", "-6 hours", "--no-pager", "-o", "cat")
		seen := strings.Count(log, "new client session")
		idle := strings.Count(log, "idle, closing")
		fmt.Fprintln(w)
		if seen > 0 {
			warnLine(w, fmt.Sprintf("Iran connected %d time(s) in 6h, went idle %d time(s) (return path blocked?)", seen, idle))
		} else {
			warnLine(w, "No Iran connection in the last 6h")
			if cr == "udp" || IsPool(cr) || cr == "icmp" {
				if IsReverse(n) {
					hintLine(w, fmt.Sprintf(" · Verify Iran listens on :%s/%s and firewall allows it", lastColon(peer), rproto(cr)))
				} else {
					hintLine(w, " · Verify key, carrier, and open port/ICMP in cloud firewall")
				}
			} else {
				hintLine(w, " · Verify key, carrier, and open port/ICMP in cloud firewall")
			}
		}
	}
	// per-port checks
	for _, it := range p1YmlMaps(n) {
		if it == "" {
			continue
		}
		if r == "Iran" {
			p := SpecL(it)
			busy := false
			if d.PortBusy != nil {
				busy = d.PortBusy(p, SpecP(it))
			}
			if busy {
				okLine(w, fmt.Sprintf("Port :%s/%s  listening", p, SpecP(it)))
			} else {
				warnLine(w, fmt.Sprintf("Port :%s/%s  not listening", p, SpecP(it)))
			}
		} else {
			p := SpecT(it)
			if SpecP(it) == "udp" {
				continue
			}
			if d.tcp("127.0.0.1", p) {
				okLine(w, "Target 127.0.0.1:"+p+"  answers")
			} else {
				warnLine(w, "Target 127.0.0.1:"+p+"  not answering")
			}
		}
	}
	if r == "Iran" && alive {
		if d.SpeedTest != nil {
			d.SpeedTest(n)
		} else {
			SpeedTestDefault(n, w)
		}
	} else if r == "Kharej" {
		hintLine(w, " · Speed test runs on Iran (press [v] there)")
	}
	e := tailErrors(d.journal(n, "-n", "200", "--no-pager", "-o", "cat"), 5)
	if e != "" {
		secHdr(w, "Recent log errors")
		for _, l := range strings.Split(e, "\n") {
			fmt.Fprintf(w, "  %s%s%s\n", GRY, l, RST)
		}
	}
}

func rproto(carrier string) string {
	if carrier == "udp" {
		return "udp"
	}
	return "tcp"
}

func splitHostPort(peer string) (host, port string) {
	i := strings.LastIndex(peer, ":")
	if i < 0 {
		return peer, ""
	}
	return peer[:i], peer[i+1:]
}

func tailErrors(log string, n int) string {
	var hits []string
	for _, l := range strings.Split(log, "\n") {
		if matchAny(l, "error", "fail", "denied", "refused", "restart needed") {
			hits = append(hits, l)
		}
	}
	if len(hits) > n {
		hits = hits[len(hits)-n:]
	}
	return strings.Join(hits, "\n")
}

// local_icmp_check(): prints the kernel-ignore hint and returns the offending firewall rules.
func localICMPCheck(d *DoctorIO, reverseIran bool, icmpType string) []string {
	if !reverseIran && d.SysctlEq1 != nil && d.SysctlEq1("net.ipv4.icmp_echo_ignore_all") {
		hintLine(d.Out, "This server ignores plain ping (icmp_echo_ignore_all=1). The tunnel still works; only ping-based checks go unanswered.")
	}
	if d.FwICMP != nil {
		return d.FwICMP()
	}
	out, err := exec.Command("iptables", "-S").Output()
	if err != nil {
		return nil
	}
	var hits []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(l), "icmp") && matchAny(l, "-j DROP", "-j REJECT") {
			hits = append(hits, l)
		}
	}
	return hits
}

// icmp_path_report(): size sweep + diagnosis, verbatim verdicts.
func icmpPathReport(n, host string, d *DoctorIO) {
	w := d.Out
	secHdr(w, "ICMP path", host)
	okSizes, badSizes := "", ""
	maxOK := 0
	for _, sz := range []int{56, 200, 400, 640} {
		loss := 100
		if d.PingHost != nil { // fixture path: a probe answers or not
			if d.PingHost(fmt.Sprintf("%s/%d", host, sz)) {
				loss = 0
			}
		} else if exec.Command("ping", "-c", "4", "-i", "0.3", "-W", "2", "-q", "-M", "do", "-s",
			strconv.Itoa(sz), host).Run() == nil {
			loss = 0
		}
		if loss <= 25 {
			okSizes += fmt.Sprintf(" %d", sz)
			maxOK = sz
			okLine(w, fmt.Sprintf("%d B   loss %d%%", sz, loss))
		} else {
			badSizes += fmt.Sprintf(" %d", sz)
			errLine(w, fmt.Sprintf("%d B   no answer (%d%% loss)", sz, loss))
		}
	}
	s, _ := statsOf(n)
	pin, pout := 0, 0
	if s != nil {
		pin, pout = getI(s, "pkts_in"), getI(s, "pkts_out")
	}
	if hits := localICMPCheck(d, false, p1Cfg(n, "icmp-type")); len(hits) > 0 {
		warnLine(w, "iptables has ICMP rules that drop or reject:")
		for _, l := range hits {
			fmt.Fprintf(w, "        %s%s%s\n", GRY, l, RST)
		}
	}
	secHdr(w, "Diagnosis")
	switch {
	case okSizes == "":
		errLine(w, "Kharej drops ping at every size")
		hintLine(w, " · Allow ICMP in Kharej's cloud firewall (or wait if route blocks ICMP)")
		hintLine(w, " · One-way block? Test from Kharej; switch both sides to reverse ICMP (Adv -> d)")
	case badSizes != "" && maxOK < 256:
		errLine(w, fmt.Sprintf("Max ICMP size ~%d B (below tunnel 256 B minimum)", maxOK))
		hintLine(w, " · Switch both sides to another carrier (udp, tcp, wss)")
	case badSizes != "" && maxOK < 640:
		errLine(w, fmt.Sprintf("Path drops ICMP > ~%d B", maxOK))
		hintLine(w, fmt.Sprintf(" · Set  mtu: %d  in /etc/wattun/<name>.yml on both sides and restart", maxOK))
	case pout > 0 && pin == 0:
		errLine(w, "Ping passes, tunnel packets get no reply")
		hintLine(w, " · Re-paste Kharej token (key/icmp-type check) or try icmp-type: timestamp")
		hintLine(w, " · Otherwise switch carrier (udp, tcp, wss)")
	case pin > 0:
		warnLine(w, "Ping passes; tunnel went silent recently (auto-heal retries)")
	default:
		okLine(w, "ICMP path is open — verify key and carrier match on both ends")
	}
}

// =====================================================================================
//  live_monitor / mon_frame / spark / hist_push (2 s refresh, any key exits)
// =====================================================================================

var hist = map[string][]int{}

func histPush(name string, v float64) {
	hist[name] = append(hist[name], int(v))
	if len(hist[name]) > 16 {
		hist[name] = hist[name][1:]
	}
}

// spark(): "····▁▂▃▅▇" of the last values, cyan bars on grey pad when colored.
func spark(vals []int, w int) string {
	chars := []string{"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"}
	if len(vals) > w {
		vals = vals[len(vals)-w:]
	}
	max := 0
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	res := ""
	for _, v := range vals {
		if max == 0 {
			res += chars[0]
		} else {
			res += chars[v*7/max]
		}
	}
	pad := w - len(vals)
	if pad < 0 {
		pad = 0
	}
	if UseColor {
		return GRY + rep("·", pad) + CYN + res + RST
	}
	return rep("·", pad) + res
}

func monFrame(w io.Writer, at time.Time) {
	cols := p1TermCols()
	spw := 16
	if cols < 78 {
		spw = 10
	}
	left := fmt.Sprintf("%sWatTunnel ·%s %sLive monitor%s", GRY, RST, BOLD, RST)
	right := fmt.Sprintf("%s%s · 2 s · any key%s", GRY, at.Format("15:04:05"), RST)
	pad := uiW() - rlen(left) - rlen(right)
	if pad < 2 {
		pad = 2
	}
	fmt.Fprintf(w, "\n  %s%s%s\n", left, rep(" ", pad), right)
	fmt.Fprintf(w, "  %s%s%s\n\n", GRY, rep("─", uiW()), RST)
	if cols < 68 {
		fmt.Fprintf(w, "  %s%-12s %-10s %6s  %s%s\n", GRY, "NAME", "STATE", "RTT", "RATE", RST)
	} else {
		fmt.Fprintf(w, "  %s%-13s %-10s %6s  %-10s %-"+strconv.Itoa(spw)+"s  %s%s\n", GRY, "NAME", "STATE", "RTT", "RATE", "HISTORY", "LOAD", RST)
	}
	for _, n := range p1Tunnels() {
		r := roleName(n)
		ti := tinfo(n)
		col, dot, txt := stateCell(r, ti.State)
		histPush(n, ti.Rate)
		sp := spark(hist[n], spw)
		rttStr := "-"
		if ti.State == "up" || ti.State == "degraded" {
			rttStr = fmt.Sprintf("%.0f ms", ti.RTT)
		}
		rate := "-"
		if ti.State != "stopped" {
			rate = Human(ti.Rate) + "/s"
		}
		loadStr := "-"
		if ti.State != "stopped" {
			if r == "Kharej" {
				loadStr = fmt.Sprintf("%dc", ti.Sess)
			} else {
				loadStr = fmt.Sprintf("%ds", ti.Streams)
			}
		}
		if cols < 68 {
			fmt.Fprintf(w, "  %-12s %s%s %-8s%s %6s  %s\n", trunc(n, 12), col, dot, txt, RST, rttStr, rate)
		} else {
			fmt.Fprintf(w, "  %-13s %s%s %-8s%s %6s  %-10s %s  %s\n", trunc(n, 13), col, dot, txt, RST, rttStr, rate, sp, loadStr)
		}
	}
	fmt.Fprintln(w)
}

// LiveMonitor: full-screen 2 s redraw loop; any key ends it.
func LiveMonitor(out io.Writer) {
	if !p1IsTTY() {
		monFrame(out, time.Now())
		return
	}
	p1Clear()
	for {
		p1Clear()
		monFrame(out, time.Now())
		if k, err := p1ReadKey(); err == nil && k != "" {
			return
		}
		time.Sleep(2 * time.Second) // the bash's read -t 2 cadence
	}
}

// registerScreens wires this surface into the P1 screen registry.
// TODO(P1): call from the registry bootstrap once the tag is dropped.
func registerStatusScreens() {
	p1Register("status", "Status", func(name string) {
		TunnelStatus(name, os.Stdout)
	})
	p1Register("logs", "Logs", func(name string) { LogsMenu(name, os.Stdout) })
	p1Register("doctor", "Diagnose", func(name string) { Doctor(name, &DoctorIO{Out: os.Stdout}) })
	p1Register("monitor", "Live monitor", func(string) { LiveMonitor(os.Stdout) })
}

// TunnelStatus renders the full single-tunnel status page (header + card).
func TunnelStatus(name string, out io.Writer) {
	TunnelHeader(out, name, roleName(name))
	TunnelCard(out, name)
}
