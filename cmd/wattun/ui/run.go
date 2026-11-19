package ui

// The entrypoint of the wattun TUI.

import (
	tea "github.com/charmbracelet/bubbletea"
)

// Run boots the TUI on the alternate screen and blocks until the user quits. defaultMetrics is the
// fallback metrics address (the -metrics flag) for tunnels whose config has no metrics: address; each
// tunnel's own address wins when set. The manager handoff never reaches here: runManager skips every
// argv that starts with '-', and -ui is a flag, so the TUI always runs inside wattun itself.
func Run(defaultMetrics string) error {
	p := tea.NewProgram(newApp(defaultMetrics), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
