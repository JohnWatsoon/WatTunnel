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
	type row struct {
		dir       string
		ok        bool
		mbs, mbit float64
		secs      float64
		err       string
	}
	var rows []row
	peak := 200.0
	for _, d := range []string{"down", "up"} {
		r, err := fetchSpeedtest(m, d, mb)
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
			rows = append(rows, row{dir: d, ok: true, mbs: r.MBPerS, mbit: r.MbitPerS, secs: r.Seconds})
			if r.MBPerS > peak {
				peak = r.MBPerS
			}
		} else {
			e := r.Error
			if e == "" {
				e = "unknown error"
			}
			rows = append(rows, row{dir: d, err: e})
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
