package ui

// The app shell of the wattun TUI: the root bubbletea model routing between the dashboard (pageDashboard)
// and one tunnel's detail monitor (pageDetail), owning the data both pages render from — the tunnel list and
// the latest /stats per tunnel — plus the motion machinery.
//
// Motion model (the "alive" feel, all driven by one 100 ms animation clock):
//   - counters glide: every frame each tunnel's displayed rate moves glidePerFrame of the way toward its real
//     rate, so the numbers ease to their new value between the 1 s polls instead of jumping;
//   - sections fade in staggered on a page switch: sectionAlpha ramps 0→1 over fadeTicks (150 ms), each next
//     section starting staggerTicks (50 ms) later; alpha 0 renders nothing, below 1 renders dim, 1 normal;
//   - the comp.Spin braille spinner runs on its own 80 ms cycle whenever something is in flight (stats fetch,
//     systemctl action, journal tail) and inline flash messages hold ~1 s bright then fade ~1 s dim.
//
// Everything that can block (HTTP, systemd, journalctl) runs in tea.Cmd goroutines; the Update/View paths
// never wait on the network, so the UI cannot freeze. Errors surface inline (flash or dim text), never as a
// crash: a missing stats endpoint, a stopped tunnel or a missing journalctl all degrade to dim text.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/JohnWatsoon/WatTunnel/cmd/wattun/ui/comp"
)

// Motion and poll timing. The animation clock is 100 ms (10 fps); the stats poll is 1 s per tunnel.
const (
	frameEvery    = 100 * time.Millisecond
	pollEvery     = time.Second
	glidePerFrame = 0.30 // fraction of the remaining gap one animation frame closes (10 fps ⇒ smooth glide)
	fadeTicks     = 1.5  // one section's fade-in lasts 150 ms of animation ticks
	staggerTicks  = 0.5  // 50 ms between section reveals on a page switch
	flashHold     = 10.0 // frames a flash stays bright (~1 s)
	flashFade     = 10.0 // frames of dim fade-out (~1 s): gone after ~2 s
	activeEvery   = 5    // refresh the systemd dots and the tunnel list every N polls (5 s)
	sparkWidth    = 48   // detail sparkline samples (comp.Spark fixes its width at construction)
	minW          = 72   // below this the app shows the too-small notice
	minH          = 18
)

// errNoMetrics marks a tunnel whose config has no metrics: address — its row shows dim text instead of a bar.
var errNoMetrics = errors.New("no metrics address (set metrics: in the tunnel config)")

// tunState is the cached live view of one tunnel: the latest /stats, its fetch error, the systemd state, and
// the displayed (glided) rate the UI animates between polls.
type tunState struct {
	st        Stats
	have      bool    // at least one successful poll arrived
	err       error   // last fetch error (nil when the last poll succeeded)
	active    bool    // systemd reports the unit active
	rateMBs   float64 // displayed rate, glided toward st.RateBps each animation frame
	glideInit bool    // the first sample snaps instead of gliding up from 0
}

// app is the root model; dashState and detState live in dashboard.go / detail.go.
type app struct {
	width, height int
	page          page
	frames        float64 // animation ticks since the page switch (drives the stagger fade-in)
	pollN         int     // polls since start (drives the periodic active/tunnel refresh)

	dash dashState
	det  detState

	tunnels    []Tunnel
	tunnelsErr error
	loading    bool                 // the initial ReadTunnels is in flight
	states     map[string]*tunState // per tunnel name, latest known live state

	pending int       // stats fetch batches in flight
	spin    comp.Spin // shared braille spinner; its cycle self-schedules through Update
	flash   flashMsg  // inline ok/bad message, fades after ~2 s

	defaultMetrics string // -metrics fallback for tunnels whose config has no metrics: address
}

// dashState is the dashboard's local state: the selection cursor.
type dashState struct {
	sel int
}

// flashMsg is one inline message; age counts animation frames since it was shown.
type flashMsg struct {
	text string
	bad  bool
	age  float64
}

// ---- messages ----

type frameMsg struct{ t time.Time }    // animation clock tick
type pollTickMsg struct{ t time.Time } // stats poll clock tick
type tunnelsMsg struct {
	ts  []Tunnel
	err error
}
type statsMsg struct {
	name string
	st   Stats
	err  error
}
type pollMsg struct {
	stats   []statsMsg
	actives map[string]bool // tunnel name → systemd active, refreshed every activeEvery polls
}
type actionDoneMsg struct {
	kind    string // "mute" | "stop" | "restart" | "start"
	text    string
	bad     bool
	tunnel  string
	carrier string
	muted   *bool // mute only: the carrier's mute state after the toggle
}
type logsMsg struct {
	name  string
	lines []string
	err   error
}

// ---- lifecycle ----

// newApp builds the root model. No I/O here: everything blocking starts from Init's commands.
func newApp(defaultMetrics string) *app {
	return &app{
		defaultMetrics: defaultMetrics,
		states:         map[string]*tunState{},
		spin:           comp.NewSpin(),
		det:            detState{spark: comp.NewSpark(sparkWidth)},
	}
}

// Init boots the clocks and the first load: tunnel list, both tick chains, and the spinner cycle.
func (a *app) Init() tea.Cmd {
	return tea.Batch(a.spin.Tick, loadTunnels(), frameClock(), pollClock())
}

// View routes to the current page; before the first resize the screen stays blank (no flash of a wrong
// frame), a too-small terminal gets the notice instead of a broken layout.
func (a *app) View() string {
	if a.width == 0 {
		return ""
	}
	if a.width < minW || a.height < minH {
		return tooSmall(a.width, a.height)
	}
	if a.page == pageDetail {
		return a.viewDetail()
	}
	return a.viewDashboard()
}

// loadTunnels reads the config dir (harness.ReadTunnels, /etc/wattun or WAT_CONF_DIR) off the UI thread.
func loadTunnels() tea.Cmd {
	return func() tea.Msg {
		ts, err := ReadTunnels()
		return tunnelsMsg{ts: ts, err: err}
	}
}

func frameClock() tea.Cmd {
	return tea.Tick(frameEvery, func(t time.Time) tea.Msg { return frameMsg{t: t} })
}

func pollClock() tea.Cmd {
	return tea.Tick(pollEvery, func(t time.Time) tea.Msg { return pollTickMsg{t: t} })
}

// fetchNow fires one stats batch immediately (used on page entry and after a successful action).
func (a *app) fetchNow() tea.Cmd {
	if len(a.tunnels) == 0 {
		return nil
	}
	return fetchAll(a.tunnels, a.defaultMetrics, false)
}

// fetchAll polls every tunnel's /stats in parallel (and, every activeEvery-th call, re-checks systemd and
// re-reads the config dir so new or removed tunnels appear live). Returns one combined message.
func fetchAll(ts []Tunnel, defaultMetrics string, withRefresh bool) tea.Cmd {
	return func() tea.Msg {
		out := make([]statsMsg, 0, len(ts))
		actives := map[string]bool{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, t := range ts {
			wg.Add(1)
			go func(t Tunnel) {
				defer wg.Done()
				addr := metricsFor(t, defaultMetrics)
				var st Stats
				var err error
				if addr == "" {
					err = errNoMetrics
				} else {
					st, err = FetchStats(addr)
				}
				mu.Lock()
				out = append(out, statsMsg{name: t.Name, st: st, err: err})
				mu.Unlock()
			}(t)
			if withRefresh {
				wg.Add(1)
				go func(t Tunnel) {
					defer wg.Done()
					mu.Lock()
					actives[t.Name] = IsActive(unitOf(t))
					mu.Unlock()
				}(t)
			}
		}
		wg.Wait()
		return pollMsg{stats: out, actives: actives}
	}
}

// ---- update ----

// Update is the root router: keys go through routeKey, everything else lands where it belongs.
func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var spinCmd tea.Cmd
	a.spin, spinCmd = a.spin.Update(msg) // the spinner cycle keeps itself alive through its own cmd
	if spinCmd != nil {
		cmds = append(cmds, spinCmd)
	}

	switch m := msg.(type) {
	case tea.KeyMsg:
		cmds = append(cmds, a.handleKey(m)...)

	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height

	case frameMsg:
		a.frames++
		a.ageFlash()
		a.glideRates()
		cmds = append(cmds, frameClock())

	case pollTickMsg:
		a.pollN++
		cmds = append(cmds, pollClock())
		if !a.loading && len(a.tunnels) > 0 {
			cmds = append(cmds, fetchAll(a.tunnels, a.defaultMetrics, a.pollN%activeEvery == 0))
		}
		if a.pollN%activeEvery == 0 { // the tunnel list itself refreshes: new/removed configs appear live
			cmds = append(cmds, loadTunnels())
		}
		if a.page == pageDetail && a.det.logs {
			cmds = append(cmds, a.logsCmd()) // the journal tail keeps scrolling while open
		}

	case tunnelsMsg:
		a.loading = false
		prev := a.states
		a.tunnels, a.tunnelsErr = m.ts, m.err
		a.states = make(map[string]*tunState, len(a.tunnels))
		for _, t := range a.tunnels { // keep the glide state of tunnels that survived the reload
			if s, ok := prev[t.Name]; ok {
				a.states[t.Name] = s
			} else {
				a.states[t.Name] = &tunState{active: t.Active}
			}
		}
		a.clampSel()
		if a.page == pageDetail && a.det.name != "" && a.byName(a.det.name) == nil {
			a.setPage(pageDashboard) // the watched tunnel's config vanished
		}
		if len(a.tunnels) > 0 {
			cmds = append(cmds, fetchAll(a.tunnels, a.defaultMetrics, true))
		}

	case pollMsg:
		if a.pending > 0 {
			a.pending--
		}
		for _, r := range m.stats {
			s := a.states[r.name]
			if s == nil {
				continue
			}
			s.st, s.err, s.have = r.st, r.err, r.err == nil
		}
		for name, act := range m.actives {
			if s := a.states[name]; s != nil {
				s.active = act
			}
		}
		if a.page == pageDetail {
			if s := a.states[a.det.name]; s != nil && s.have {
				a.det.feed(s.st) // sparkline sample + peak, once per poll
			}
		}

	case actionDoneMsg:
		a.det.busy = ""
		a.setFlash(m.text, m.bad)
		if m.kind == "mute" && m.muted != nil {
			a.applyMute(m.tunnel, m.carrier, *m.muted) // instant feedback; the next poll confirms
		}
		if !m.bad && m.kind != "mute" {
			cmds = append(cmds, a.fetchNow()) // a start/stop/restart changed the unit: refresh the dots soon
		}

	case logsMsg:
		if a.det.name == m.name {
			a.det.logsErr = m.err
			if m.err == nil {
				a.det.logsLines = m.lines
			}
		}
	}

	return a, tea.Batch(cmds...)
}

// handleKey applies one routed key press; it may return follow-up commands (action goroutines).
func (a *app) handleKey(msg tea.KeyMsg) []tea.Cmd {
	switch routeKey(a.page, msg) {
	case actQuit:
		return []tea.Cmd{tea.Quit}

	case actHome:
		a.setPage(pageDashboard)

	case actBack:
		a.setPage(pageDashboard)

	case actOpen:
		if a.page == pageDashboard && len(a.tunnels) > 0 {
			a.openDetail(clampInt(a.dash.sel, 0, len(a.tunnels)-1))
		}

	case actUp:
		if a.page == pageDashboard {
			a.dash.sel--
			a.clampSel()
		} else {
			a.det.carr--
			a.clampCarr()
		}

	case actDown:
		if a.page == pageDashboard {
			a.dash.sel++
			a.clampSel()
		} else {
			a.det.carr++
			a.clampCarr()
		}

	case actMute:
		if cmd := a.doMute(); cmd != nil {
			return []tea.Cmd{cmd}
		}

	case actStop:
		return a.doSystemctl("stop")

	case actRestart:
		return a.doSystemctl("restart")

	case actStart:
		return a.doSystemctl("start")

	case actLogs:
		if cmd := a.toggleLogs(); cmd != nil {
			return []tea.Cmd{cmd}
		}

	case actSpeed:
		if cmd := a.doSpeedtest(); cmd != nil {
			return []tea.Cmd{cmd}
		}
	}
	return nil
}

// setPage switches pages and restarts the stagger fade-in.
func (a *app) setPage(p page) {
	if a.page == p {
		return
	}
	a.page = p
	a.frames = 0
}

// openDetail enters the detail page for the tunnel at dashboard index i, with a fresh sparkline window
// seeded by whatever the last poll already knows.
func (a *app) openDetail(i int) {
	t := a.tunnels[i]
	a.dash.sel = i
	a.det = detState{name: t.Name, spark: comp.NewSpark(sparkWidth)}
	if s := a.states[t.Name]; s != nil && s.have {
		a.det.feed(s.st)
	}
	a.setPage(pageDetail)
}

// glideRates moves every tunnel's displayed rate toward its real rate, one frame at a time. The first
// sample snaps so a freshly loaded tunnel does not animate up from zero.
func (a *app) glideRates() {
	for _, s := range a.states {
		if !s.have || s.err != nil {
			continue
		}
		real := s.st.RateBps / 1e6
		if !s.glideInit {
			s.rateMBs, s.glideInit = real, true
			continue
		}
		s.rateMBs = glide(s.rateMBs, real, glidePerFrame)
	}
}

// ageFlash advances the flash lifetime and clears it once the fade window is over.
func (a *app) ageFlash() {
	if a.flash.text == "" {
		return
	}
	a.flash.age++
	if a.flash.age > flashHold+flashFade {
		a.flash = flashMsg{}
	}
}

// setFlash shows an inline result message (ok unless bad), replacing any current one.
func (a *app) setFlash(text string, bad bool) {
	a.flash = flashMsg{text: text, bad: bad}
}

// applyMute writes a successful toggle straight into the cached carrier row so the row flips without
// waiting for the next poll (which then confirms from /stats).
func (a *app) applyMute(tunnel, carrier string, muted bool) {
	s := a.states[tunnel]
	if s == nil {
		return
	}
	for i := range s.st.Carriers {
		if s.st.Carriers[i].Name == carrier {
			s.st.Carriers[i].Muted = muted
		}
	}
}

// ---- lookups and helpers shared by the pages ----

func (a *app) byName(name string) *Tunnel {
	for i := range a.tunnels {
		if a.tunnels[i].Name == name {
			return &a.tunnels[i]
		}
	}
	return nil
}

func (a *app) clampSel() {
	a.dash.sel = clampInt(a.dash.sel, 0, max(len(a.tunnels)-1, 0))
}

// clampCarr keeps the carrier cursor inside the current carrier list (0 when there is none).
func (a *app) clampCarr() {
	a.det.carr = clampInt(a.det.carr, 0, max(len(a.carriers())-1, 0))
}

// carriers returns the selected detail tunnel's live carrier rows (nil before the first poll).
func (a *app) carriers() []CarrierInfo {
	if s := a.states[a.det.name]; s != nil && s.have {
		return s.st.Carriers
	}
	return nil
}

// metricsFor picks the address to poll: the tunnel's own metrics: address, falling back to -metrics.
func metricsFor(t Tunnel, def string) string {
	if t.Metrics != "" {
		return t.Metrics
	}
	return def
}

// unitOf is the systemd unit of a tunnel config: the installer's templated wattun@.service instance
// (harness.ReadTunnels checks the same name). No .service suffix: systemctl accepts the bare instance.
func unitOf(t Tunnel) string {
	return "wattun@" + t.Name
}

// confDir mirrors harness's config dir choice (WAT_CONF_DIR, else the installer default) for display text.
func confDir() string {
	if d := os.Getenv("WAT_CONF_DIR"); d != "" {
		return d
	}
	return "/etc/wattun"
}

// sectionAlpha is the reveal alpha 0..1 of section i after f animation frames on the current page:
// a 150 ms fade, sections staggered 50 ms apart, clamped to [0,1].
func sectionAlpha(f, i float64) float64 {
	a := (f - i*staggerTicks) / fadeTicks
	return clampFloat(a, 0, 1)
}

// glide moves cur a fraction k of the way toward target: the easing behind the ticking counters.
// k <= 0 holds, k >= 1 snaps; monotone, never overshoots.
func glide(cur, target, k float64) float64 {
	if k <= 0 {
		return cur
	}
	if k >= 1 {
		return target
	}
	return cur + (target-cur)*k
}

// fade wraps a rendered section for the stagger fade-in: hidden at alpha 0, dim below 1, normal at 1.
func fade(alpha float64, content string) string {
	if alpha <= 0 {
		return ""
	}
	if alpha < 1 {
		return comp.Dim.Render(content)
	}
	return content
}

// ---- small format helpers (shared by both pages) ----

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// trunc cuts s to at most w runes, marking a cut with an ellipsis.
func trunc(s string, w int) string {
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w <= 1 {
		return ""
	}
	return string(r[:w-1]) + "…"
}

// pad right-pads s with spaces to exactly w runes wide.
func pad(s string, w int) string {
	r := []rune(s)
	if len(r) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(r))
}

// fmtBytes renders a byte count for the carrier rows (sent/acked).
func fmtBytes(b uint64) string {
	const kb, mb, gb = 1e3, 1e6, 1e9 // decimal units, matching the project's MB/s convention
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/gb)
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/mb)
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/kb)
	}
	return fmt.Sprintf("%d B", b)
}

// rateStr renders a glided MB/s figure; ok=false renders a quiet placeholder instead of 0.0.
func rateStr(mbs float64, ok bool) string {
	if !ok {
		return comp.Dim.Render("—")
	}
	return comp.Text.Render(fmt.Sprintf("%.1f MB/s", mbs))
}

// srttMsStr renders a round millisecond figure for the summary line.
func srttMsStr(ms float64, ok bool) string {
	if !ok {
		return comp.Dim.Render("—")
	}
	return comp.Text.Render(fmt.Sprintf("%.0f ms", ms))
}

// pageFrame clamps a page view to the terminal so nothing wraps mid-frame on a resize.
func pageFrame(a *app, content string) string {
	return lipgloss.NewStyle().MaxWidth(a.width).Render(content)
}

// tooSmall is the terminal-too-small notice (never crashes on a shrunk window).
func tooSmall(w, h int) string {
	body := comp.Dim.Render(fmt.Sprintf("terminal too small — wattun needs %dx%d, got %dx%d", minW, minH, w, h))
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, body)
}
