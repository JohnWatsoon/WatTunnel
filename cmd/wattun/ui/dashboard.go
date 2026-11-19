package ui

// The dashboard page: the identity banner + a live summary line, then the tunnels table — columns
// #, NAME, ROLE, CARRIER, STATE, RTT, TRAFFIC — one row per tunnel config in the config dir
// (harness.ReadTunnels, refreshed every few polls so new or removed tunnels appear live). The
// cursor moves with the arrows and enter opens the detail page. Sections fade in staggered.

import (
	"fmt"
	"strings"

	"github.com/JohnWatsoon/WatTunnel/cmd/wattun/ui/comp"
)

// dashboard column widths (runes). Tight enough for the minW notice threshold of 72 columns.
const (
	dashNumW   = 3
	dashNameW  = 12
	dashRoleW  = 8
	dashCarrW  = 16
	dashStateW = 12
	dashRttW   = 8
)

// View renders the dashboard: the identity banner + live summary, the tunnels table, the footer
// keybar; the sections fade in staggered on a page switch.
func (a *app) viewDashboard() string {
	var secs []string

	// section 0: the identity banner (kite + WATTUN mark, meta right) + the live summary line
	secs = append(secs, a.header()+"\n"+a.summaryLine())

	// section 1: the tunnels table
	secs = append(secs, comp.SectionLabel("Tunnels", fmt.Sprintf("%d total", len(a.tunnels)), a.width)+"\n"+a.dashTable())

	// section 2: the footer keybar
	secs = append(secs, comp.KeyBar(
		[2]string{"↑/↓", "select"},
		[2]string{"enter", "open"},
		[2]string{"1", "dashboard"},
		[2]string{"q", "quit"},
	))

	return a.joinSections(secs)
}

// header is the identity block: the kite + WATTUN banner with the meta block right-aligned
// (engine version from the freshest successful poll), used by every page.
func (a *app) header() string {
	var meta []string
	if v := a.knownVersion(); v != "" {
		meta = append(meta, "WatTunnel · "+v)
	}
	meta = append(meta, "github.com/JohnWatsoon", "t.me/WatxDev")
	return comp.Banner(meta, a.width)
}

// knownVersion is the engine version from the freshest successful poll ("" before the first one).
func (a *app) knownVersion() string {
	for _, s := range a.states {
		if s.have && s.err == nil && s.st.Version != "" {
			return s.st.Version
		}
	}
	return ""
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

// summaryLine is the one live line under the banner: tunnel count, aggregate glided rate, worst SRTT among
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

// dashTable is the section body: either a placeholder (loading / broken config dir / no tunnels) or the
// tunnels table — columns #, NAME, ROLE, CARRIER, STATE, RTT, TRAFFIC, cursor on the selected row.
func (a *app) dashTable() string {
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

	head := "  " + comp.Dim.Render(
		pad("#", dashNumW)+" "+pad("NAME", dashNameW)+" "+pad("ROLE", dashRoleW)+" "+
			pad("CARRIER", dashCarrW)+" "+pad("STATE", dashStateW)+" "+pad("RTT", dashRttW)+" TRAFFIC")
	rows := []string{head}
	for i, t := range a.tunnels {
		cursor := "  "
		if i == a.dash.sel {
			cursor = comp.Accent.Render("▸ ")
		}
		num := comp.Dim.Render(pad(fmt.Sprintf("%d", i+1), dashNumW))
		name := comp.Text.Render(pad(trunc(t.Name, dashNameW), dashNameW))
		role := comp.Dim.Render(pad(t.Role(), dashRoleW))
		carr := comp.Dim.Render(pad(trunc(t.Carrier, dashCarrW), dashCarrW))
		state := a.stateCell(t)
		rtt := a.rttCell(t)
		traffic := a.trafficCell(t)
		rows = append(rows, cursor+num+" "+name+" "+role+" "+carr+" "+state+" "+rtt+" "+traffic)
	}
	return strings.Join(rows, "\n")
}

// stateCell is the STATE column: systemd + stats alive state, colored like the old UI (waiting is warn).
func (a *app) stateCell(t Tunnel) string {
	s := a.states[t.Name]
	switch {
	case s == nil || !s.have:
		return comp.Dim.Render(pad("…", dashStateW))
	case s.err != nil:
		return comp.Warn.Render(pad("no stats", dashStateW))
	case !s.active:
		return comp.Bad.Render(pad("down", dashStateW))
	case s.st.Alive:
		return comp.Ok.Render(pad("● up", dashStateW))
	default:
		return comp.Warn.Render(pad("○ waiting", dashStateW))
	}
}

// rttCell is the RTT column: the session's srtt in ms, or a dash while nothing is connected.
func (a *app) rttCell(t Tunnel) string {
	s := a.states[t.Name]
	if s == nil || !s.have || s.err != nil || !s.st.Alive {
		return comp.Dim.Render(pad("–", dashRttW))
	}
	return comp.Text.Render(pad(fmt.Sprintf("%.0f ms", s.st.SRTT.Seconds()*1000), dashRttW))
}

// trafficCell is the TRAFFIC column: session totals up + down (the same numbers the old UI showed).
func (a *app) trafficCell(t Tunnel) string {
	s := a.states[t.Name]
	if s == nil || !s.have || s.err != nil {
		return comp.Dim.Render("↑0 B ↓0 B")
	}
	return comp.Text.Render("↑" + comp.FormatBytes(s.st.BytesOut) + " ↓" + comp.FormatBytes(s.st.BytesIn))
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
