package ui

// The dashboard page: one live line per tunnel config in the config dir (harness.ReadTunnels, refreshed
// every few polls so new or removed tunnels appear without a restart) under a single summary line, with the
// tunnel list as the page's focused card. Each row shows the mode badge, the carrier list, a live rate bar
// fed by the 1 s polls and a systemd dot; the cursor moves with the arrows and enter opens the detail page.

import (
	"fmt"
	"strings"

	"github.com/JohnWatsoon/WatTunnel/cmd/wattun/ui/comp"
)

// dashboard column widths (runes). Tight enough for the minW notice threshold of 72 columns.
const (
	dashNameW = 14
	dashModeW = 6
	dashCarrW = 14
	dashBarW  = 9
	dashRateW = 10
)

// View renders the dashboard: header + glided summary, the tunnels card, the key hints; the three sections
// fade in staggered on a page switch.
func (a *app) viewDashboard() string {
	var secs []string

	// section 0: title + single live summary line
	var head strings.Builder
	head.WriteString(comp.Title("wattun") + "  " + comp.Dim.Render("tunnels from "+confDir()) + "\n")
	head.WriteString(a.summaryLine())
	secs = append(secs, head.String())

	// section 1: the tunnel list, the page's one focused card
	secs = append(secs, comp.Label("tunnels")+"\n"+comp.Card(true).Render(a.dashRows()))

	// section 2: key hints
	secs = append(secs, comp.KeyHint(
		[2]string{"↑/↓", "select"},
		[2]string{"enter", "detail"},
		[2]string{"1", "dashboard"},
		[2]string{"q", "quit"},
	))

	return a.joinSections(secs)
}

// joinSections renders the sections with the stagger fade-in, one blank line between them.
func (a *app) joinSections(secs []string) string {
	var out []string
	for i, s := range secs {
		f := fade(sectionAlpha(a.frames, float64(i)), s)
		if f != "" {
			out = append(out, f)
		}
	}
	return pageFrame(a, strings.Join(out, "\n\n"))
}

// summaryLine is the one live line under the title: tunnel count, aggregate glided rate, worst SRTT among
// the alive tunnels, spinner while a fetch is in flight.
func (a *app) summaryLine() string {
	if a.tunnelsErr != nil {
		return comp.Bad.Render("cannot list tunnels: " + a.tunnelsErr.Error())
	}
	var agg float64
	worst, worstSet := 0.0, false
	for _, s := range a.states {
		if !s.have || s.err != nil {
			continue
		}
		agg += s.rateMBs
		if s.st.Alive {
			if ms := s.st.SRTT.Seconds() * 1000; !worstSet || ms > worst {
				worst, worstSet = ms, true
			}
		}
	}
	line := fmt.Sprintf("%d tunnel%s · ", len(a.tunnels), plural(len(a.tunnels))) +
		rateStr(agg, a.anyData()) + comp.Dim.Render(" · worst srtt ") + srttMsStr(worst, worstSet)
	if a.pending > 0 {
		line += "  " + comp.Dim.Render(a.spin.View())
	}
	return line
}

// anyData reports whether at least one tunnel has delivered a successful poll (drives the summary "—").
func (a *app) anyData() bool {
	for _, s := range a.states {
		if s.have && s.err == nil {
			return true
		}
	}
	return false
}

// dashRows is the card body: either a placeholder (loading / broken config dir / no tunnels) or one row per
// tunnel, cursor on the selected one.
func (a *app) dashRows() string {
	switch {
	case a.loading:
		return comp.Dim.Render(a.spin.View() + " reading " + confDir() + "…")
	case a.tunnelsErr != nil:
		return comp.Bad.Render("cannot read "+confDir()+": "+a.tunnelsErr.Error()) + "\n" +
			comp.Dim.Render("point WAT_CONF_DIR at the directory holding the tunnel *.yml files")
	case len(a.tunnels) == 0:
		return comp.Dim.Render("no tunnels in "+confDir()+" yet") + "\n" +
			comp.Dim.Render("create one with the manager; it appears here within a few seconds")
	}

	nameW := 0 // widest tunnel name, clamped so a huge name cannot eat the row
	for _, t := range a.tunnels {
		if w := len([]rune(t.Name)); w > nameW {
			nameW = w
		}
	}
	nameW = clampInt(nameW, 8, dashNameW)

	var rows []string
	for i, t := range a.tunnels {
		cursor := "  "
		if i == a.dash.sel {
			cursor = comp.Accent.Render("▸ ")
		}
		name := comp.Text.Render(pad(trunc(t.Name, nameW), nameW))
		mode := comp.Dim.Render(pad(strings.ToUpper(t.Mode), dashModeW))
		carr := comp.Dim.Render(pad(trunc(t.Carrier, dashCarrW), dashCarrW))
		live := a.liveCell(t)
		dot := comp.Dot(a.states[t.Name] != nil && a.states[t.Name].active)
		rows = append(rows, cursor+name+" "+mode+" "+carr+" "+live+" "+dot)
	}
	return strings.Join(rows, "\n")
}

// liveCell is the right half of a row: rate bar + glided MB/s, or the dim/bad placeholder for a tunnel
// whose stats are not in yet or unreachable.
func (a *app) liveCell(t Tunnel) string {
	s := a.states[t.Name]
	switch {
	case s == nil || !s.have:
		return comp.Dim.Render(strings.Repeat(" ", dashBarW) + " " + pad("…", dashRateW))
	case s.err != nil:
		// the full error text belongs on the detail page; here the row stays quiet and fixed-width
		return comp.Dim.Render(pad("no stats", dashBarW+dashRateW+1))
	}
	bar := comp.Bar(a.ratePct(s), dashBarW)
	rate := comp.Text.Render(pad(fmt.Sprintf("%.1f MB/s", s.rateMBs), dashRateW))
	return bar + " " + rate
}

// ratePct is the fill fraction behind a row's bar: utilization against the pacer's ceiling when /stats
// reports one (the bar's ok/warn/bad thresholds then mean real headroom), otherwise a comparative share of
// the busiest tunnel so the bars still rank tunnels against each other.
func (a *app) ratePct(s *tunState) float64 {
	if s.st.CeilingBps > 0 {
		return s.st.RateBps / s.st.CeilingBps * 100
	}
	top := 0.0
	for _, o := range a.states {
		if o.have && o.err == nil && o.st.RateBps > top {
			top = o.st.RateBps
		}
	}
	if top <= 0 {
		return 0
	}
	// a comparative share is not a utilization: cap the fill just under comp.Bar's warn threshold (70 %)
	// so the busiest tunnel's bar stays ok-colored and the MB/s number carries the alarm
	return s.st.RateBps / top * 69
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
