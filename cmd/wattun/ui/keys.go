package ui

// The keymap of the wattun TUI: every key press routes through routeKey to a page-independent action, so the
// keymap is one pure function tests can pin. Global keys (1, 2/enter, q, ctrl+c) work on both pages; the
// detail-only action keys (m/s/r/S/l) route to actNone on the dashboard, where they mean nothing.

import (
	tea "github.com/charmbracelet/bubbletea"
)

// page is the top-level screen the app router shows.
type page int

const (
	pageDashboard page = iota // all tunnels, live
	pageDetail                // one tunnel: sparkline, carriers, actions, logs
)

// action is what one key press means after page routing.
type action int

const (
	actNone    action = iota
	actQuit           // ctrl+c anywhere; q on the dashboard
	actHome           // 1: back to the dashboard from anywhere
	actBack           // q on the detail page: step back to the dashboard
	actOpen           // enter / 2 on the dashboard: open the selected tunnel's detail
	actUp             // up / k: move the cursor up (dashboard: tunnel, detail: carrier)
	actDown           // down / j: move the cursor down
	actMute           // m on detail: toggle mute of the selected bond carrier
	actStop           // s on detail: systemctl stop the tunnel's unit
	actRestart        // r on detail: systemctl restart
	actStart          // S (capital) on detail: systemctl start
	actLogs           // l on detail: open/close the journal tail
	actSpeed          // t on detail: run a 10 MB speed test against the tunnel's metrics
)

// routeKey maps a key press on page p to its action. Pure: tests pin the whole keymap here.
func routeKey(p page, msg tea.KeyMsg) action {
	switch msg.String() {
	case "ctrl+c":
		return actQuit
	case "up", "k":
		return actUp
	case "down", "j":
		return actDown
	case "1":
		return actHome
	}
	switch p {
	case pageDashboard:
		switch msg.String() {
		case "enter", "2":
			return actOpen
		case "q":
			return actQuit
		}
	case pageDetail:
		switch msg.String() {
		case "q", "esc":
			return actBack
		case "m":
			return actMute
		case "s":
			return actStop
		case "r":
			return actRestart
		case "S":
			return actStart
		case "l":
			return actLogs
		case "t":
			return actSpeed
		}
	}
	return actNone
}
