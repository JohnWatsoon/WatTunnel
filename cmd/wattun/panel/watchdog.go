package panel

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// watchdog records outages from the 1 s live samples (features §3.9b): a tunnel that should run (its unit is
// enabled or active) but is not up starts an outage; it ends when the tunnel is up again. Closed outages are
// appended to outages.jsonl and kept 90 days; the open ones live in memory (a panel restart closes nothing:
// the next sample reopens it at the restart time). shortcut: the cause is not recorded yet; phase 3 adds it
// from the unit's exit status and the heal log.
type watchdog struct {
	mu    sync.Mutex
	file  string
	open  map[string]int64 // tunnel -> outage start (unix)
	past  []outage
	since map[string]int64 // first time this panel saw the tunnel: before that there is no data
}

type outage struct {
	Tunnel string `json:"tunnel"`
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
}

const keepOutages = 90 * 24 * 3600

func newWatchdog(file string) *watchdog {
	w := &watchdog{file: file, open: map[string]int64{}, since: map[string]int64{}}
	if f, err := os.Open(file); err == nil {
		cut := time.Now().Unix() - keepOutages
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var o outage
			if json.Unmarshal(sc.Bytes(), &o) == nil && o.End >= cut {
				w.past = append(w.past, o)
			}
		}
		f.Close()
	}
	return w
}

func (w *watchdog) observe(name string, want, up bool, now time.Time) {
	t := now.Unix()
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.since[name]; !ok {
		w.since[name] = t
	}
	start, isOpen := w.open[name]
	switch {
	case want && !up && !isOpen:
		w.open[name] = t
	case isOpen && (up || !want):
		delete(w.open, name)
		o := outage{Tunnel: name, Start: start, End: t}
		w.past = append(w.past, o)
		if f, err := os.OpenFile(w.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			b, _ := json.Marshal(o)
			f.Write(append(b, '\n'))
			f.Close()
		}
	}
}

// wdTunnel is one row of the overview's watchdog card: 24 hourly cells (0 = no data, 1 = up, 2 = some downtime,
// 3 = down most of the hour), uptime over the window, and the outage numbers.
type wdTunnel struct {
	Name     string  `json:"name"`
	Hours    []int   `json:"hours"`
	UptimePc float64 `json:"uptime_pct"`
	Outages  int     `json:"outages"`
	Longest  int64   `json:"longest_s"`
	Ongoing  int64   `json:"ongoing_since,omitempty"`
}

func (w *watchdog) summary(names []string, now time.Time) []wdTunnel {
	w.mu.Lock()
	defer w.mu.Unlock()
	end := now.Unix()
	from := end - 24*3600
	out := []wdTunnel{}
	for _, n := range names {
		row := wdTunnel{Name: n, Hours: make([]int, 24)}
		var spans []outage
		for _, o := range w.past {
			if o.Tunnel == n && o.End > from {
				spans = append(spans, o)
			}
		}
		if s, ok := w.open[n]; ok {
			spans = append(spans, outage{Tunnel: n, Start: s, End: end})
			row.Ongoing = s
		}
		seen := w.since[n]
		for _, o := range w.past { // data older than this process counts as seen
			if o.Tunnel == n && o.Start < seen {
				seen = o.Start
			}
		}
		var down, observed int64
		for h := 0; h < 24; h++ {
			hs, he := from+int64(h)*3600, from+int64(h+1)*3600
			if seen == 0 || he <= seen {
				continue
			}
			obsStart := max(hs, seen)
			var d int64
			for _, o := range spans {
				d += max(0, min(he, o.End)-max(obsStart, o.Start))
			}
			span := he - obsStart
			observed += span
			down += d
			switch {
			case d == 0:
				row.Hours[h] = 1
			case d*2 < span:
				row.Hours[h] = 2
			default:
				row.Hours[h] = 3
			}
		}
		for _, o := range spans {
			row.Outages++
			row.Longest = max(row.Longest, o.End-o.Start)
		}
		row.UptimePc = 100
		if observed > 0 {
			row.UptimePc = float64(observed-down) * 100 / float64(observed)
		}
		out = append(out, row)
	}
	return out
}
