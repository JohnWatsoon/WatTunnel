package ui

// The detail page: the live monitor for one tunnel. A big autoscaling throughput sparkline fed by the 1 s
// polls, one row per bond carrier (alive dot, muted flag, share bar, srtt, sent/acked), and the unit's
// action keys — mute a carrier, stop/restart/start the unit, open the journal tail — each with a spinner
// while in flight and an inline ok/bad flash that fades after ~2 s.

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/JohnWatsoon/WatTunnel/cmd/wattun/ui/comp"
)

// detail row widths (runes).
const (
	detNameW = 10
	detBarW  = 8
)

// detState is the detail page's local state: which tunnel, which carrier, the sparkline, the journal tail
// and the action in flight.
type detState struct {
	name      string     // tunnel name ("" = none selected yet)
	carr      int        // selected carrier index
	spark     comp.Spark // throughput window, one sample per poll
	peak      float64    // peak MB/s seen since the page opened
	logs      bool       // journal tail open
	logsLines []string   // last journal lines, newest last
	logsErr   error      // journalctl failure, shown inline
	busy      string     // action in flight, e.g. "restarting wattun@main" ("" = idle)
}

// feed takes one poll's stats into the sparkline window and the peak tracker.
func (d *detState) feed(st Stats) {
	mbs := st.RateBps / 1e6
	d.spark.Add(mbs)
	if mbs > d.peak {
		d.peak = mbs
	}
}

// doMute toggles the selected carrier's mute. Needs a carrier cursor and a metrics address; anything else
// is an inline bad flash, never a crash.
func (a *app) doMute() tea.Cmd {
	t := a.byName(a.det.name)
	if t == nil {
		return nil
	}
	cs := a.carriers()
	if len(cs) == 0 {
		a.setFlash("no bond carriers to mute — this tunnel runs a single carrier", true)
		return nil
	}
	a.clampCarr()
	c := cs[a.det.carr]
	addr := metricsFor(*t, a.defaultMetrics)
	if addr == "" {
		a.setFlash(errNoMetrics.Error(), true)
		return nil
	}
	a.det.busy = "toggling " + c.Name
	name, tun := c.Name, t.Name
	return func() tea.Msg {
		muted, err := ToggleMute(addr, name)
		if err != nil {
			return actionDoneMsg{kind: "mute", bad: true, tunnel: tun, carrier: name,
				text: fmt.Sprintf("mute %s: %v", name, err)}
		}
		verb := "muted"
		if !muted {
			verb = "unmuted"
		}
		return actionDoneMsg{kind: "mute", tunnel: tun, carrier: name, muted: &muted,
			text: name + " " + verb}
	}
}

// doSystemctl runs one unit action (stop/restart/start) with a spinner; the flash reports the verdict.
func (a *app) doSystemctl(action string) []tea.Cmd {
	t := a.byName(a.det.name)
	if t == nil {
		return nil
	}
	a.det.busy = action + "ing " + unitOf(*t)
	unit := unitOf(*t)
	return []tea.Cmd{func() tea.Msg {
		if err := Systemctl(action, unit); err != nil {
			return actionDoneMsg{kind: action, bad: true, text: err.Error()}
		}
		return actionDoneMsg{kind: action, text: fmt.Sprintf("%s %s: ok", action, unit)}
	}}
}

// toggleLogs opens or closes the journal tail; opening fires the first fetch.
func (a *app) toggleLogs() tea.Cmd {
	if a.det.logs {
		a.det.logs = false
		return nil
	}
	a.det.logs = true
	a.det.logsLines, a.det.logsErr = nil, nil
	if t := a.byName(a.det.name); t != nil {
		a.det.busy = "reading " + unitOf(*t)
	}
	return a.logsCmd()
}

// logsCmd tails the unit's journal: the last 30 lines, no pager, timestamps stripped. On a host without
// systemd (a Windows dev box) the exec fails and the error lands inline; nothing blocks the UI.
func (a *app) logsCmd() tea.Cmd {
	name := a.det.name
	t := a.byName(name)
	if t == nil {
		return nil
	}
	unit := unitOf(*t)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "journalctl", "-u", unit, "-n", "30", "--no-pager", "-o", "cat").
			CombinedOutput()
		if err != nil {
			return logsMsg{name: name, err: fmt.Errorf("journalctl %s: %v: %s", unit, err, strings.TrimSpace(string(out)))}
		}
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		if len(lines) > 30 {
			lines = lines[len(lines)-30:]
		}
		return logsMsg{name: name, lines: lines}
	}
}

// View renders the detail page for det.name; every section fades in staggered.
func (a *app) viewDetail() string {
	t := a.byName(a.det.name)
	if t == nil {
		return pageFrame(a, comp.Dim.Render("tunnel gone from the config dir — press q"))
	}
	var secs []string

	// section 0: header + live state line
	secs = append(secs, a.detHeader(*t))

	// section 1: THROUGHPUT — the focused card: autoscaling sparkline + now/peak
	var spark strings.Builder
	spark.WriteString(comp.Accent.Render(a.det.spark.View()) + "\n")
	spark.WriteString(comp.Dim.Render("now ") + rateStr(a.detRate(), a.detHaveData()) +
		comp.Dim.Render(" · peak ") + rateStr(a.det.peak, a.det.peak > 0))
	secs = append(secs, comp.Label("throughput")+"\n"+comp.Card(true).Render(spark.String()))

	// section 2: CARRIERS — one row per bond leg, or the single-carrier note
	secs = append(secs, comp.Label("carriers")+"\n"+a.carrierRows())

	// section 3: LOGS — only while open
	if a.det.logs {
		secs = append(secs, comp.Label("logs")+"\n"+a.logsBody())
	}

	// section 4: status line (busy spinner or fading flash) + hints
	var foot strings.Builder
	if st := a.statusLine(); st != "" {
		foot.WriteString(st + "\n")
	}
	foot.WriteString(comp.KeyHint(
		[2]string{"↑/↓", "carrier"},
		[2]string{"m", "mute"},
		[2]string{"t", "test"},
		[2]string{"s", "stop"},
		[2]string{"r", "restart"},
		[2]string{"S", "start"},
		[2]string{"l", "logs"},
		[2]string{"q", "back"},
	))
	secs = append(secs, foot.String())

	return a.joinSections(secs)
}

// detHeader is the tunnel's title line and its live state line (dot, glided rate, srtt, streams).
func (a *app) detHeader(t Tunnel) string {
	info := strings.ToUpper(t.Mode) + " · " + t.Carrier + " · " + unitOf(t)
	if len(t.Ports) > 0 {
		info += " · ports " + trunc(strings.Join(t.Ports, ", "), 44)
	}
	head := comp.Title(t.Name) + "  " + comp.Dim.Render(info) + "\n"

	s := a.states[t.Name]
	var line string
	switch {
	case s == nil || !s.have:
		line = comp.Dim.Render("waiting for first sample…")
	case s.err != nil:
		line = comp.Bad.Render("stats unreachable: " + s.err.Error())
	default:
		up := "down"
		if s.st.Alive {
			up = "up"
		}
		line = comp.Dot(s.st.Alive) + " " + comp.Text.Render(up) +
			comp.Dim.Render(" · ") + rateStr(s.rateMBs, true) +
			comp.Dim.Render(fmt.Sprintf(" · srtt %.0f ms · %d streams", s.st.SRTT.Seconds()*1000, s.st.Streams))
	}
	return head + line
}

// detRate is the detail tunnel's glided rate (0 before data).
func (a *app) detRate() float64 {
	if s := a.states[a.det.name]; s != nil && s.have && s.err == nil {
		return s.rateMBs
	}
	return 0
}

func (a *app) detHaveData() bool {
	s := a.states[a.det.name]
	return s != nil && s.have && s.err == nil
}

// carrierRows renders one row per bond leg, or the dim single-carrier note when /stats reports no carriers.
func (a *app) carrierRows() string {
	cs := a.carriers()
	if len(cs) == 0 {
		if s := a.states[a.det.name]; s != nil && s.err != nil {
			return comp.Dim.Render("carriers unknown — " + s.err.Error())
		}
		return comp.Dim.Render("single-carrier tunnel — no bond paths to mute or watch")
	}
	a.clampCarr()
	var rows []string
	for i, c := range cs {
		cursor := "  "
		if i == a.det.carr {
			cursor = comp.Accent.Render("▸ ")
		}
		name := comp.Text.Render(pad(trunc(c.Name, detNameW), detNameW))
		dot := comp.Dot(c.Alive)
		muted := ""
		if c.Muted {
			muted = " " + comp.Warn.Render("muted")
		}
		share := comp.Bar(c.Share*100, detBarW) + comp.Dim.Render(fmt.Sprintf(" %2.0f%%", c.Share*100))
		srtt := comp.Dim.Render(fmt.Sprintf("srtt %5.1f ms", c.SRTTms))
		traffic := comp.Dim.Render("sent " + fmtBytes(c.Sent) + " ack " + fmtBytes(c.Acked))
		rows = append(rows, cursor+name+" "+dot+muted+"  "+share+"  "+srtt+"  "+traffic)
	}
	return strings.Join(rows, "\n")
}

// logsBody renders the journal tail dim, newest last; a failure renders as one inline bad line.
func (a *app) logsBody() string {
	if a.det.logsErr != nil {
		return comp.Bad.Render(trunc(a.det.logsErr.Error(), a.width))
	}
	if len(a.det.logsLines) == 0 {
		return comp.Dim.Render(a.spin.View() + " reading journal…")
	}
	var b strings.Builder
	for _, ln := range a.det.logsLines {
		b.WriteString(comp.Dim.Render(trunc(ln, max(a.width-2, 8))) + "\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// statusLine is the busy spinner while an action runs, else the flash fading out after ~2 s.
func (a *app) statusLine() string {
	if a.det.busy != "" {
		return comp.Dim.Render(a.spin.View() + " " + a.det.busy + "…")
	}
	if a.flash.text == "" {
		return ""
	}
	if a.flash.age >= flashHold { // past the bright hold: fade out through dim
		return comp.Dim.Render(trunc(a.flash.text, a.width))
	}
	if a.flash.bad {
		return comp.Bad.Render(trunc(a.flash.text, a.width))
	}
	return comp.Ok.Render(trunc(a.flash.text, a.width))
}

// doSpeedtest runs one 10 MB download speed test against the tunnel's metrics endpoint. The real handler is
// synchronous (it answers after the whole transfer), so the spinner stays up for the duration.
func (a *app) doSpeedtest() tea.Cmd {
	t := a.byName(a.det.name)
	if t == nil {
		return nil
	}
	addr := metricsFor(*t, a.defaultMetrics)
	if addr == "" {
		a.setFlash(errNoMetrics.Error(), true)
		return nil
	}
	a.det.busy = "running 10 MB speed test"
	return func() tea.Msg {
		res, err := PostSpeedtest(addr, 10)
		if err != nil {
			return actionDoneMsg{kind: "speedtest", bad: true, tunnel: t.Name,
				text: fmt.Sprintf("speed test: %v", err)}
		}
		if !res.OK {
			return actionDoneMsg{kind: "speedtest", bad: true, tunnel: t.Name,
				text: fmt.Sprintf("speed test failed: %s", res.Error)}
		}
		return actionDoneMsg{kind: "speedtest", tunnel: t.Name,
			text: fmt.Sprintf("down %.1f Mbit/s (%.1f MB/s, %.1f s, %d streams)",
				res.Mbit, res.MBps, res.Seconds, res.Streams)}
	}
}
