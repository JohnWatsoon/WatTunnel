package comp

// Braille spinner sub-model, bubbles-style: Init starts the cycle, every TickMsg advances one frame and
// schedules the next 80 ms out. Embed New() in a parent model and route its messages through Update.

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// spinInterval is the frame duration of Spin.
const spinInterval = 80 * time.Millisecond

// spinFrames is the classic ten-frame braille cycle.
var spinFrames = [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spin is the spinner sub-model; the zero value works, New is the constructor.
type Spin struct{ frame int }

// TickMsg advances the spinner one frame and carries the tick time for schedulers that want it.
type TickMsg struct{ Time time.Time }

// NewSpin returns a fresh spinner. (The contract's per-type New() names cannot both exist in one Go package,
// so the constructors carry the type name: NewSpin, NewSpark.)
func NewSpin() Spin { return Spin{} }

// Tick is the tea.Msg that starts and keeps the spinner running (the initial Init cmd and every scheduled
// next tick produce it).
func (s Spin) Tick() tea.Msg { return TickMsg{Time: time.Now()} }

// Init starts the spin cycle.
func (s Spin) Init() tea.Cmd { return s.Tick }

// Update advances one frame per TickMsg and schedules the next tick 80 ms out; other messages pass through.
func (s Spin) Update(msg tea.Msg) (Spin, tea.Cmd) {
	if _, ok := msg.(TickMsg); ok {
		s.frame++
		return s, tea.Tick(spinInterval, func(t time.Time) tea.Msg { return TickMsg{Time: t} })
	}
	return s, nil
}

// View renders the current frame.
func (s Spin) View() string { return spinFrames[s.frame%len(spinFrames)] }
