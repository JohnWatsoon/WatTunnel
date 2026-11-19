package ui

// Tests for the app shell: the keymap (routeKey), the page router (key press → state transition), the
// interpolation/animation math, the flash lifetime, and static frame renders of both pages fed with fake
// stats (they double as the living screenshots: run with -v to print them).

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// key builds a runes KeyMsg like a real terminal would deliver.
func key(s string) tea.KeyMsg {
	switch s {
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestRouteKeyPageMap(t *testing.T) {
	tests := []struct {
		page page
		k    string
		want action
	}{
		{pageDashboard, "q", actQuit},
		{pageDashboard, "ctrl+c", actQuit},
		{pageDashboard, "1", actHome},
		{pageDashboard, "2", actOpen},
		{pageDashboard, "enter", actOpen},
		{pageDashboard, "up", actUp},
		{pageDashboard, "k", actUp},
		{pageDashboard, "down", actDown},
		{pageDashboard, "j", actDown},
		{pageDashboard, "m", actNone}, // detail-only keys mean nothing on the dashboard
		{pageDashboard, "s", actNone},
		{pageDashboard, "S", actNone},
		{pageDashboard, "r", actNone},
		{pageDashboard, "l", actNone},
		{pageDetail, "q", actBack},
		{pageDetail, "esc", actBack},
		{pageDetail, "1", actHome},
		{pageDetail, "m", actMute},
		{pageDetail, "s", actStop},
		{pageDetail, "r", actRestart},
		{pageDetail, "S", actStart},
		{pageDetail, "l", actLogs},
		{pageDetail, "up", actUp},
		{pageDetail, "down", actDown},
		{pageDetail, "enter", actNone},
		{pageDetail, "x", actNone},
	}
	for _, tc := range tests {
		if got := routeKey(tc.page, key(tc.k)); got != tc.want {
			t.Errorf("routeKey(page %d, %q) = %d, want %d", tc.page, tc.k, got, tc.want)
		}
	}
}

// testApp is a fully-loaded fake: three tunnels (live bond, live single carrier, stopped/broken) and no
// I/O anywhere, so the router tests stay synchronous.
func testApp() *app {
	a := newApp("127.0.0.1:19700")
	a.width, a.height = 92, 26
	a.tunnels = []Tunnel{
		{Name: "main", Mode: "client", Carrier: "icmp+udp+tcp", Metrics: "127.0.0.1:19701",
			Ports: []string{"20030", "53/udp"}, Active: true},
		{Name: "kharej-2", Mode: "server", Carrier: "udp", Metrics: "127.0.0.1:19702",
			Ports: []string{"20031"}, Active: true},
		{Name: "backup", Mode: "client", Carrier: "tcp", Metrics: "127.0.0.1:19703", Active: false},
	}
	a.states = map[string]*tunState{
		"main": {have: true, active: true, glideInit: true, rateMBs: 4.2,
			st: Stats{Alive: true, RateBps: 4.2e6, SRTT: 41 * time.Millisecond, MinRTT: 30 * time.Millisecond,
				Streams: 3, Sessions: 1, CeilingBps: 16e6,
				Carriers: []CarrierInfo{
					{Name: "icmp", Alive: true, Share: 0.62, SRTTms: 41, Sent: 12_300_000, Acked: 12_100_000},
					{Name: "udp", Alive: true, Share: 0.38, SRTTms: 55.4, Sent: 7_800_000, Acked: 7_650_000},
					{Name: "tcp", Alive: false, Muted: true, Share: 0, Sent: 120_000, Acked: 118_000},
				}}},
		"kharej-2": {have: true, active: true, glideInit: true, rateMBs: 8.1,
			st: Stats{Alive: true, RateBps: 8.1e6, SRTT: 63 * time.Millisecond, Streams: 1}},
		"backup": {have: true, active: false, err: errors.New("dial 127.0.0.1:19703: connection refused")},
	}
	a.frames = 10 // fade-in complete: the static frames show the settled page
	return a
}

func TestRouterTransitions(t *testing.T) {
	t.Run("enter opens the selected tunnel's detail", func(t *testing.T) {
		a := testApp()
		a.dash.sel = 1
		a.handleKey(key("enter"))
		if a.page != pageDetail {
			t.Fatalf("page = %d, want pageDetail", a.page)
		}
		if a.det.name != "kharej-2" {
			t.Fatalf("detail tunnel = %q, want kharej-2", a.det.name)
		}
		if a.dash.sel != 1 {
			t.Fatalf("sel moved to %d, want 1", a.dash.sel)
		}
		if a.frames != 0 {
			t.Fatalf("page switch must restart the fade, frames = %v", a.frames)
		}
	})

	t.Run("2 opens detail and q steps back", func(t *testing.T) {
		a := testApp()
		a.handleKey(key("2"))
		if a.page != pageDetail || a.det.name != "main" {
			t.Fatalf("2 did not open the first tunnel (page %d, name %q)", a.page, a.det.name)
		}
		a.handleKey(key("q"))
		if a.page != pageDashboard {
			t.Fatalf("q on detail must step back to the dashboard, page = %d", a.page)
		}
	})

	t.Run("q on detail returns to the dashboard", func(t *testing.T) {
		a := testApp()
		a.handleKey(key("enter"))
		a.handleKey(key("q"))
		if a.page != pageDashboard {
			t.Fatalf("q on detail: page = %d, want pageDashboard", a.page)
		}
	})

	t.Run("1 returns home from anywhere and q quits on the dashboard", func(t *testing.T) {
		a := testApp()
		a.handleKey(key("enter"))
		cmds := a.handleKey(key("1"))
		if a.page != pageDashboard {
			t.Fatalf("1 from detail: page = %d, want pageDashboard", a.page)
		}
		if cmds != nil {
			t.Fatalf("1 must not quit, got %d cmds", len(cmds))
		}
		cmds = a.handleKey(key("q"))
		if len(cmds) != 1 || cmds[0] == nil {
			t.Fatalf("q on the dashboard must return a quit cmd, got %v", cmds)
		}
	})

	t.Run("dashboard cursor clamps and detail carrier cursor clamps", func(t *testing.T) {
		a := testApp()
		a.handleKey(key("up"))
		if a.dash.sel != 0 {
			t.Fatalf("sel = %d, want clamped 0", a.dash.sel)
		}
		a.handleKey(key("down"))
		a.handleKey(key("down"))
		a.handleKey(key("down"))
		if a.dash.sel != 2 {
			t.Fatalf("sel = %d, want clamped 2", a.dash.sel)
		}
		a.dash.sel = 0 // open the bonded tunnel: it is the one with carriers to scroll
		a.handleKey(key("enter"))
		for i := 0; i < 6; i++ {
			a.handleKey(key("down"))
		}
		if a.det.carr != 2 {
			t.Fatalf("carrier cursor = %d, want clamped 2 (3 carriers)", a.det.carr)
		}
		a.handleKey(key("up"))
		a.handleKey(key("up"))
		a.handleKey(key("up"))
		if a.det.carr != 0 {
			t.Fatalf("carrier cursor = %d, want clamped 0", a.det.carr)
		}
	})

	t.Run("watching a vanished tunnel bounces home", func(t *testing.T) {
		a := testApp()
		a.handleKey(key("enter"))
		a.Update(tunnelsMsg{ts: []Tunnel{{Name: "other", Mode: "client"}}})
		if a.page != pageDashboard {
			t.Fatalf("detail of a removed tunnel: page = %d, want pageDashboard", a.page)
		}
	})
}

func TestGlideInterpolation(t *testing.T) {
	if got := glide(0, 10, 0.5); got != 5 {
		t.Fatalf("glide(0,10,0.5) = %v, want 5", got)
	}
	if got := glide(3, 10, 0); got != 3 {
		t.Fatalf("glide with k=0 must hold, got %v", got)
	}
	if got := glide(3, 10, 1); got != 10 {
		t.Fatalf("glide with k=1 must snap, got %v", got)
	}
	// monotone approach, never overshoots, converges
	cur, dist := 0.0, 10.0
	for i := 0; i < 200; i++ {
		cur = glide(cur, 10, 0.3)
		d := 10 - cur
		if d < 0 {
			t.Fatalf("glide overshot: cur = %v", cur)
		}
		if d > dist+1e-12 {
			t.Fatalf("glide moved away from the target: cur = %v after %d frames", cur, i)
		}
		dist = d
	}
	if dist > 1e-6 {
		t.Fatalf("glide did not converge, residual %v", dist)
	}
}

func TestSectionAlphaStagger(t *testing.T) {
	if got := sectionAlpha(0, 0); got != 0 {
		t.Fatalf("section 0 at frame 0 = %v, want 0", got)
	}
	if got := sectionAlpha(1.5, 0); got != 1 {
		t.Fatalf("section 0 after fadeTicks = %v, want 1", got)
	}
	if got := sectionAlpha(1.5, 1); got < 0.6 || got >= 1 {
		t.Fatalf("section 1 at 150 ms must be mid-fade (it started 50 ms in), got %v", got)
	}
	if got := sectionAlpha(1.0, 2); got != 0 {
		t.Fatalf("section 2 must still be hidden at 100 ms (it starts at 100 ms), got %v", got)
	}
	if got := sectionAlpha(10, 3); got != 1 {
		t.Fatalf("late frames must clamp to 1, got %v", got)
	}
	if got := sectionAlpha(-5, 0); got != 0 {
		t.Fatalf("negative frames must clamp to 0, got %v", got)
	}
}

func TestFlashFadesAfterTwoSeconds(t *testing.T) {
	a := testApp()
	a.setFlash("restart ok", false)
	if got := a.statusLine(); got == "" || !strings.Contains(got, "restart ok") {
		t.Fatalf("fresh flash not rendered: %q", got)
	}
	for i := 0; i < int(flashHold); i++ { // ~1 s bright
		a.ageFlash()
	}
	bright := a.statusLine()
	for i := 0; i < int(flashFade); i++ { // ~1 s fading through dim
		a.ageFlash()
	}
	if got := a.statusLine(); got == "" || !strings.Contains(got, "restart ok") {
		t.Fatalf("flash must still be visible while fading, got %q", got)
	}
	a.ageFlash()
	if got := a.statusLine(); got != "" {
		t.Fatalf("flash must be gone after hold+fade (was %q), got %q", bright, got)
	}
	if a.flash.text != "" {
		t.Fatalf("flash state must be cleared, got %+v", a.flash)
	}
}

func TestPollUpdatesStatesAndFeedsSpark(t *testing.T) {
	a := testApp()
	a.handleKey(key("enter")) // detail of "main"
	before := a.states["main"].rateMBs
	st := Stats{Alive: true, RateBps: 9e6, SRTT: 50 * time.Millisecond, Streams: 2,
		Carriers: []CarrierInfo{{Name: "icmp", Alive: true, Share: 1}}}
	a.Update(pollMsg{stats: []statsMsg{{name: "main", st: st}}})
	s := a.states["main"]
	if s.st.RateBps != 9e6 || s.err != nil {
		t.Fatalf("poll did not land in the state cache: %+v", s)
	}
	if len(s.st.Carriers) != 1 {
		t.Fatalf("carriers not updated: %+v", s.st.Carriers)
	}
	if a.det.peak < 9 {
		t.Fatalf("spark peak = %v, want at least 9 MB/s", a.det.peak)
	}
	// the glide state is untouched by the poll itself; the next animation frame closes 30% of the gap
	a.glideRates()
	if a.states["main"].rateMBs <= before || a.states["main"].rateMBs >= 9 {
		t.Fatalf("glided rate %v must sit between %v and 9", a.states["main"].rateMBs, before)
	}
}

func TestMuteErrorPathsFlashInline(t *testing.T) {
	a := testApp()
	a.handleKey(key("enter")) // main: has carriers, but mute runs in a goroutine — only check the cmd exists
	if cmd := a.doMute(); cmd == nil {
		t.Fatalf("mute on a bonded tunnel must fire a cmd")
	}
	if a.det.busy == "" {
		t.Fatalf("mute must show a busy spinner")
	}
	a.det.busy = ""
	a.det.name = "backup" // stats unreachable: still has cached carriers? no — backup has none
	if cmd := a.doMute(); cmd != nil {
		t.Fatalf("mute on a carrierless tunnel must not fire a cmd")
	}
	if a.flash.text == "" || !a.flash.bad {
		t.Fatalf("carrierless mute must flash bad inline, got %+v", a.flash)
	}
}

// ---- static frames: the screenshots-as-text for the review (go test -run TestRender -v) ----

func TestRenderDashboardFrame(t *testing.T) {
	a := testApp()
	fmt.Println("\n=== DASHBOARD (live) ===")
	fmt.Println(a.viewDashboard())
	if !strings.Contains(a.viewDashboard(), "main") {
		t.Fatal("dashboard frame missing tunnel rows")
	}
}

func TestRenderDetailFrame(t *testing.T) {
	a := testApp()
	a.handleKey(key("enter"))
	a.frames = 10
	for i := 0; i < 12; i++ { // give the sparkline a window
		a.det.feed(Stats{RateBps: float64(2_000_000 + i*400_000)})
	}
	out := a.viewDetail()
	fmt.Println("\n=== DETAIL (live) ===")
	fmt.Println(out)
	if !strings.Contains(strings.ToLower(out), "throughput") || !strings.Contains(out, "icmp") {
		t.Fatal("detail frame missing sparkline or carriers")
	}
}

func TestRenderEmptyAndDegradedFrames(t *testing.T) {
	a := testApp()
	a.loading = false
	a.tunnels, a.tunnelsErr, a.states = nil, nil, map[string]*tunState{}
	fmt.Println("\n=== DASHBOARD (no tunnels) ===")
	fmt.Println(a.viewDashboard())

	b := testApp()
	b.loading = true
	fmt.Println("\n=== DASHBOARD (loading) ===")
	fmt.Println(b.viewDashboard())

	c := testApp()
	c.width, c.height = 60, 12
	fmt.Println("\n=== TOO SMALL ===")
	fmt.Println(c.View())
}
