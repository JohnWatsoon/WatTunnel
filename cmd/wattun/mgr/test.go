// Port of the bash speed_test(): drives the tunnel's own /speedtest endpoint on the
// local metrics address (Iran only) and prints the two result lines with bars.
// The bash uses curl; here net/http. URL and params are pinned by test against the
// handler contract in cmd/wattun/speedtest.go (?dir=down|up&mb=N[&streams=N]).

package mgr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// speedtestURL: exactly what the bash curls: http://$m/speedtest?dir=$d&mb=$mb
// (the matrix adds &streams=N; the handler reads dir/mb/streams only).
func speedtestURL(metricsAddr, dir string, mb int) string {
	return fmt.Sprintf("http://%s/speedtest?dir=%s&mb=%d", metricsAddr, dir, mb)
}

func speedtestURLStreams(metricsAddr, dir string, mb, streams int) string {
	return fmt.Sprintf("http://%s/speedtest?dir=%s&mb=%d&streams=%d", metricsAddr, dir, mb, streams)
}

// stAnim: the speed test animates only on the real interactive screen — UseAnim
// already implies a tty, and w must be Stdout so a buffer-backed caller (tests,
// the doctor's captured output) keeps the static, byte-stable rendering.
// speedRow is one direction's measurement (down first, then up).
type speedRow struct {
	dir       string
	ok        bool
	mbs, mbit float64
	secs      float64
	err       string
}

func stAnim(w io.Writer) bool { return UseAnim && w == Stdout }

// stExpected: the pacing floor for the live progress bar. The engine answers
// one JSON blob when the transfer ends, so per-interval samples do not exist;
// elapsed time and the requested size are the only real signals (an honest
// elapsed/expected bar, never an invented byte counter). Planning floor is
// 1 MB/s: mb MB takes at least mb seconds, capped so a slow link does not pin
// the bar at zero for minutes.
func stExpected(mb int) float64 {
	e := float64(mb)
	if e < 3 {
		e = 3
	}
	return e
}

// stLive runs fn while a live panel advances: spinner frame, the direction and
// size, the real elapsed seconds and a gradient bar paced by elapsed/expected.
// Anim off (or a non-Stdout writer) calls straight through and prints nothing,
// so the static path is byte-identical. Same shape as spin()/scepterCall: one
// worker goroutine, 100 ms ticks, cursor restored on exit.
func stLive(w io.Writer, dir string, mb int, fn func() (*speedtestResult, error)) (*speedtestResult, error) {
	if !stAnim(w) {
		return fn()
	}
	type ans struct {
		r   *speedtestResult
		err error
	}
	done := make(chan ans, 1)
	go func() {
		r, err := fn()
		done <- ans{r, err}
	}()
	sp := &Spinner{}
	fill := NewFill(0)
	exp := stExpected(mb)
	start := animNow()
	CurHide()
	defer CurShow()
	for i := 0; ; i++ {
		select {
		case a := <-done:
			fmt.Fprint(Stdout, "\r\x1b[K")
			return a.r, a.err
		case <-time.After(100 * time.Millisecond):
			el := animNow().Sub(start).Seconds()
			bar := GradBar(fill.Step(el/exp), 1, 14)
			fmt.Fprintf(Stdout, "\r\x1b[K  %s%s%s %-9s %2d MB  %s%5.1f s%s  %s",
				CYN, sp.Frame(), RST, label(dir), mb, GRY, el, RST, bar)
		}
	}
}

// stLandLine renders one landing row: the arrow and label, the rate, and the
// side-by-side GradBar meter (val against the better of the two directions, so
// down and up share one scale). v is the value currently presented — the tween
// feeds it during the count-up, the final frame passes the exact measurement.
func stLandLine(r speedRow, v, maxv float64) string {
	arr, col := "↓", CYN
	if r.dir == "up" {
		arr, col = "↑", SAF
	}
	if ColorTier > 0 {
		arr = col + arr + RST
	}
	if !r.ok {
		return fmt.Sprintf("  %s %s%-9s%s %sfailed%s  %s", arr, RED, label(r.dir), RST, RED, RST, r.err)
	}
	return fmt.Sprintf("  %s %s%-9s%s %s%6.1f MB/s%s  %s", arr, BOLD, label(r.dir), RST, BOLD, v, RST, GradBar(v, maxv, 12))
}

// stLand: on completion the two results land with a count-up tween of each
// rate and one side-by-side down/up GradBar — this screen's ramp moment. The
// tween only presents the final numbers over ~0.8 s; every figure is the real
// measurement and the last frame is exact. Anim-only (guarded by stAnim).
func stLand(w io.Writer, rows []speedRow) {
	maxv := 0.0
	for _, r := range rows {
		if r.ok && r.mbs > maxv {
			maxv = r.mbs
		}
	}
	if maxv <= 0 {
		return
	}
	var dn, up *Tween = NewTween(0), NewTween(0)
	for i := 0; i < 10; i++ {
		if i > 0 {
			fmt.Fprint(w, "\x1b[2A")
		}
		for _, r := range rows {
			v := 0.0
			if r.dir == "down" {
				v = dn.Step(r.mbs)
			} else {
				v = up.Step(r.mbs)
			}
			fmt.Fprintf(w, "\r\x1b[K%s\n", stLandLine(r, v, maxv))
		}
		sleepMS(80)
	}
	fmt.Fprint(w, "\x1b[2A")
	for _, r := range rows {
		fmt.Fprintf(w, "\r\x1b[K%s\n", stLandLine(r, r.mbs, maxv))
	}
}

// speedtestResult is the engine's JSON answer (cmd/wattun/speedtest.go Result).
type speedtestResult struct {
	OK       bool    `json:"ok"`
	Dir      string  `json:"dir"`
	MB       float64 `json:"mb"`
	Seconds  float64 `json:"seconds"`
	MBPerS   float64 `json:"mb_per_s"`
	MbitPerS float64 `json:"mbit_per_s"`
	Streams  int     `json:"streams"`
	Error    string  `json:"error"`
}

// httpClient is swappable in tests.
var httpClient = &http.Client{Timeout: 200 * time.Second}

func fetchSpeedtest(metricsAddr, dir string, mb int) (*speedtestResult, error) {
	resp, err := httpClient.Get(speedtestURL(metricsAddr, dir, mb))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var r speedtestResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// SpeedTestDefault is the doctor's tail call: 10 MB each way (the bash default).
func SpeedTestDefault(name string, w io.Writer) { SpeedTest(name, 10, w) }

// SpeedTest: port of speed_test(). name [mb=10].
func SpeedTest(name string, mb int, w io.Writer) {
	if roleName(name) == "Kharej" {
		errLine(w, "Speed test runs on Iran only (press [m] here for live monitor)")
		return
	}
	m := p1Cfg(name, "metrics")
	if m == "" {
		warnLine(w, "Speed test needs metrics: in "+name+".yml")
		return
	}
	secHdr(w, "Speed test", fmt.Sprintf("%d MB", mb))
	var rows []speedRow
	peak := 200.0
	for _, d := range []string{"down", "up"} {
		r, err := stLive(w, d, mb, func() (*speedtestResult, error) { return fetchSpeedtest(m, d, mb) })
		if err != nil || r == nil {
			s, _ := statsOf(name)
			if s == nil {
				errLine(w, label(d)+": tunnel '"+name+"' is not running")
			} else {
				v := get(s, "version")
				warnLine(w, fmt.Sprintf("Speed test unavailable (wattun %s did not answer on http://%s/speedtest)", dashVer(v), m))
			}
			return
		}
		if r.OK {
			rows = append(rows, speedRow{dir: d, ok: true, mbs: r.MBPerS, mbit: r.MbitPerS, secs: r.Seconds})
			if r.MBPerS > peak {
				peak = r.MBPerS
			}
		} else {
			e := r.Error
			if e == "" {
				e = "unknown error"
			}
			rows = append(rows, speedRow{dir: d, err: e})
		}
	}
	cols := p1TermCols()
	for _, r := range rows {
		lbl := label(r.dir)
		if r.ok {
			if cols >= 74 {
				fmt.Fprintf(w, "  %s✓%s %-9s %s%6.1f MB/s%s  %5.0f Mbps  %5.2f s  %s\n",
					GRN, RST, lbl, BOLD, r.mbs, RST, r.mbit, r.secs, tbarC(r.mbs, peak, 10))
			} else {
				fmt.Fprintf(w, "  %s✓%s %-9s %s%6.1f MB/s%s  %5.0f Mbps  %5.2f s\n",
					GRN, RST, lbl, BOLD, r.mbs, RST, r.mbit, r.secs)
			}
		} else {
			fmt.Fprintf(w, "  %s✗%s %-9s %sfailed%s  %s\n", RED, RST, lbl, RED, RST, r.err)
			if containsStr(r.err, "1.8.1") {
				warnLine(w, "Kharej runs older wattun — run: wattun-manager update")
			}
		}
	}
	stLand(w, rows)
}

func label(dir string) string {
	if dir == "down" {
		return "Download"
	}
	return "Upload  " // the bash pads Upload to align with Download
}

func dashVer(v string) string {
	if v == "" {
		return "old"
	}
	return v
}

func containsStr(s, sub string) bool { return strings.Contains(s, sub) }
