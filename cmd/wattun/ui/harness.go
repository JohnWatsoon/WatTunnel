package ui

// The data harness of the wattun TUI: everything the app needs that does not render — reading /stats, tunnel
// config files and systemd state, and the POST endpoints (carrier mute toggle, built-in speed test). All HTTP
// goes straight to the loopback metrics address with 2 s timeouts and no proxies, except the speed test: its
// handler answers only after the whole transfer (3-min cap), so it gets a longer client timeout.
//
// Everything here is lenient by design — the metrics server is a live process whose JSON may gain, lose or
// rename fields between versions, and a config file is read-only data — so no path ever panics; errors are
// returned, unknown fields ignored, missing fields left at their zero value.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	harnessTimeout = 2 * time.Second // FetchStats, ToggleMute
	// harnessSpeedTimeout covers the whole transfer: the /speedtest handler is synchronous and the server's own
	// cap is 3 min (cmd/wattun/speedtest.go speedTestLimit), so 2 s would abort every real test.
	harnessSpeedTimeout = 200 * time.Second
	harnessBodyCap      = 4 << 20       // /stats can carry a big ports/clients table; keep the read bounded
	harnessConfDir      = "/etc/wattun" // config dir when WAT_CONF_DIR is unset (the installer's default)
)

// Stats is the slice of /stats the TUI shows. SRTT/MinRTT are durations converted from srtt_ms/min_rtt_ms.
type Stats struct {
	Version    string
	Alive      bool
	Sessions   int
	Streams    int
	PktsOut    uint64
	PktsIn     uint64
	BytesOut   uint64
	BytesIn    uint64
	Retrans    uint64
	RateBps    float64
	SRTT       time.Duration
	MinRTT     time.Duration
	CeilingBps float64
	Carriers   []CarrierInfo
}

// CarrierInfo is one carrier of a bond, from /stats "carriers" (absent on single-carrier tunnels).
type CarrierInfo struct {
	Name   string
	Alive  bool
	Muted  bool
	Share  float64
	SRTTms float64
	Sent   uint64
	Acked  uint64
	Lost   uint64
}

// SpeedResult mirrors the /speedtest answer (cmd/wattun/speedtest.go speedResult).
type SpeedResult struct {
	Dir      string  `json:"dir"`
	Bytes    uint64  `json:"bytes"`
	Seconds  float64 `json:"seconds"`
	MBps     float64 `json:"mb_per_s"`
	Mbit     float64 `json:"mbit_per_s"`
	OK       bool    `json:"ok"`
	Error    string  `json:"error,omitempty"`
	Sessions int     `json:"sessions"` // sessions the test ran on in parallel
	Streams  int     `json:"streams"`  // streams per session
}

// Tunnel is one tunnel config file (one wattun process) in the config dir.
type Tunnel struct {
	Name    string   // file base name, the wattun@ unit instance
	Mode    string   // mode: client|server
	Carrier string   // carrier: icmp, icmp+udp, tcp, ...
	Listen  string   // listen: address
	Peer    string   // peer: address
	Metrics string   // metrics: address ("" if unset)
	Ports   []string // ports: list items as written ("N", "N:M", "N/udp", "N:M/udp")
	Active  bool     // systemd reports the wattun@Name unit active
}

// Role is the operator-facing side name: server configs are the Kharej box, client configs Iran.
func (t Tunnel) Role() string {
	if t.Mode == "server" {
		return "Kharej"
	}
	return "Iran"
}

// FetchStats GETs /stats and copies the known fields out of it. The decode is lenient: unknown fields are
// ignored and a field that is missing or of an unexpected type stays at its zero value without an error —
// only transport failures and unparseable JSON are errors.
func FetchStats(metricsAddr string) (Stats, error) {
	var out Stats
	body, err := harnessGet(metricsAddr, "/stats")
	if err != nil {
		return out, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return out, fmt.Errorf("stats: not JSON: %w", err)
	}
	out.Version = harnessStr(m, "version")
	out.Alive = harnessBool(m, "alive")
	out.Sessions = int(harnessUint(m, "sessions"))
	out.Streams = int(harnessUint(m, "streams"))
	out.PktsOut = harnessUint(m, "pkts_out")
	out.PktsIn = harnessUint(m, "pkts_in")
	out.BytesOut = harnessUint(m, "bytes_out")
	out.BytesIn = harnessUint(m, "bytes_in")
	out.Retrans = harnessUint(m, "retrans")
	out.RateBps = harnessFloat(m, "rate_bps")
	out.CeilingBps = harnessFloat(m, "ceiling_bps")
	out.SRTT = time.Duration(harnessFloat(m, "srtt_ms") * float64(time.Millisecond))
	out.MinRTT = time.Duration(harnessFloat(m, "min_rtt_ms") * float64(time.Millisecond))
	out.Carriers = harnessCarriers(m["carriers"])
	return out, nil
}

// ToggleMute POSTs /carrier/toggle?carrier=NAME and returns the carrier's mute state after the toggle.
func ToggleMute(metricsAddr, carrier string) (bool, error) {
	u := harnessURL(metricsAddr, "/carrier/toggle?carrier="+url.QueryEscape(carrier))
	resp, err := harnessClient(harnessTimeout).Post(u, "application/json", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("carrier/toggle: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var d struct {
		Path    int    `json:"path"`
		Carrier string `json:"carrier"`
		Muted   bool   `json:"muted"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return false, fmt.Errorf("carrier/toggle: not JSON: %w", err)
	}
	return d.Muted, nil
}

// PostSpeedtest runs the built-in speed test, downloading mb megabytes (the handler's default is 10 when
// mb < 1). The handler is synchronous — the answer arrives after the whole transfer — so this call blocks
// for the duration of the test.
func PostSpeedtest(metricsAddr string, mb int) (SpeedResult, error) {
	return harnessSpeedtest(metricsAddr, "down", mb, 0)
}

// PostSpeedtestFull is PostSpeedtest with the handler's other knobs: dir "down" or "up" and the number of
// streams per session (the handler clamps 1..32 and defaults to 16 for anything else; 0 sends no streams
// parameter and takes that default).
func PostSpeedtestFull(metricsAddr, dir string, mb, streams int) (SpeedResult, error) {
	return harnessSpeedtest(metricsAddr, dir, mb, streams)
}

// ReadTunnels lists the tunnel config files of the config dir: every *.yml except the *-r.yml and *-e-*
// helper files, parsed with the config subset (mode/carrier/listen/peer/metrics + the ports: list), sorted
// by name (os.ReadDir order). Active is systemd's verdict on the wattun@Name unit.
func ReadTunnels() ([]Tunnel, error) {
	dir := os.Getenv("WAT_CONF_DIR")
	if dir == "" {
		dir = harnessConfDir
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Tunnel
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, "-r.yml") || strings.Contains(name, "-e-") {
			continue // helper files, not tunnels
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		t := harnessParseTunnel(string(b))
		t.Name = strings.TrimSuffix(name, ".yml")
		t.Active = IsActive("wattun@" + t.Name)
		out = append(out, t)
	}
	return out, nil
}

// Systemctl runs `systemctl ACTION UNIT` for the actions that change tunnel state (start, stop, restart).
// Without systemd (e.g. a Windows dev box) the exec fails and the error is returned cleanly.
func Systemctl(action, unit string) error {
	switch action {
	case "start", "stop", "restart":
	default:
		return fmt.Errorf("unsupported systemctl action %q (want start, stop or restart)", action)
	}
	out, err := exec.Command("systemctl", action, unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %w: %s", action, unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// IsActive reports whether `systemctl is-active UNIT` says "active". Anything else — inactive, unknown,
// failed, no systemd, a Windows box — is false.
func IsActive(unit string) bool {
	out, err := exec.Command("systemctl", "is-active", unit).Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// ---- HTTP plumbing ----

// harnessClient builds the loopback client: the given timeout, no proxies.
func harnessClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}}
}

// harnessURL joins the metrics address (bare "host:port" or a full URL) and an endpoint path.
func harnessURL(addr, path string) string {
	addr = strings.TrimSuffix(addr, "/")
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}
	return addr + path
}

// harnessGet GETs one endpoint of the metrics address (2 s timeout) and returns its body, bounded by
// harnessBodyCap. Non-200 is an error carrying the status and body snippet.
func harnessGet(addr, path string) ([]byte, error) {
	resp, err := harnessClient(harnessTimeout).Get(harnessURL(addr, path))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, harnessBodyCap))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// harnessSpeedtest POSTs the speed test request and decodes the one-shot result.
func harnessSpeedtest(addr, dir string, mb, streams int) (SpeedResult, error) {
	var res SpeedResult
	if mb < 1 {
		mb = 10 // the handler's default
	}
	q := url.Values{}
	if dir != "" {
		q.Set("dir", dir)
	}
	q.Set("mb", strconv.Itoa(mb))
	if streams > 0 {
		q.Set("streams", strconv.Itoa(streams))
	}
	resp, err := harnessClient(harnessSpeedTimeout).Post(harnessURL(addr, "/speedtest?"+q.Encode()), "application/json", nil)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return res, err
	}
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("speedtest: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return res, fmt.Errorf("speedtest: not JSON: %w", err)
	}
	return res, nil
}

// ---- lenient JSON field extraction ----

func harnessUint(m map[string]json.RawMessage, key string) uint64 {
	var v uint64
	if json.Unmarshal(m[key], &v) == nil {
		return v
	}
	return 0
}

func harnessFloat(m map[string]json.RawMessage, key string) float64 {
	var v float64
	if json.Unmarshal(m[key], &v) == nil {
		return v
	}
	return 0
}

func harnessStr(m map[string]json.RawMessage, key string) string {
	var v string
	if json.Unmarshal(m[key], &v) == nil {
		return v
	}
	return ""
}

func harnessBool(m map[string]json.RawMessage, key string) bool {
	var v bool
	if json.Unmarshal(m[key], &v) == nil {
		return v
	}
	return false
}

// harnessCarriers decodes the "carriers" array; a missing, malformed or empty entry leaves the result nil.
func harnessCarriers(raw json.RawMessage) []CarrierInfo {
	if len(raw) == 0 {
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	var out []CarrierInfo
	for _, it := range list {
		var cs struct {
			Name   string  `json:"name"`
			Alive  bool    `json:"alive"`
			Muted  bool    `json:"muted"`
			Share  float64 `json:"share"`
			SRTTms float64 `json:"srtt_ms"`
			Sent   uint64  `json:"sent"`
			Acked  uint64  `json:"acked"`
			Lost   uint64  `json:"lost"`
		}
		if json.Unmarshal(it, &cs) != nil {
			continue
		}
		out = append(out, CarrierInfo(cs))
	}
	return out
}

// ---- config-file subset parsing ----

// harnessParseTunnel reads the fields the TUI needs out of one config file. It parses exactly the subset the
// engine parses (cmd/wattun/config.go parseConfig): `key: value` lines, `#` comments outside quotes, values
// optionally quoted, and the `ports:` list of `- item` lines. Unknown keys and stray lines are ignored — this
// is a reader, not a validator.
func harnessParseTunnel(txt string) (t Tunnel) {
	inPorts := false
	for _, line := range strings.Split(txt, "\n") {
		s := strings.TrimSpace(harnessStripComment(strings.TrimRight(line, "\r")))
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "- ") || s == "-" {
			if inPorts {
				t.Ports = append(t.Ports, harnessUnquote(strings.TrimSpace(strings.TrimPrefix(s, "-"))))
			}
			continue
		}
		inPorts = false
		k, v, ok := strings.Cut(s, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), harnessUnquote(strings.TrimSpace(v))
		switch k {
		case "mode":
			t.Mode = v
		case "carrier":
			t.Carrier = v
		case "listen":
			t.Listen = v
		case "peer":
			t.Peer = v
		case "metrics":
			t.Metrics = v
		case "ports":
			inPorts = true
		}
	}
	return t
}

// harnessStripComment removes a trailing `# ...` that is outside quotes and starts a line or follows
// whitespace (the engine's rule, config.go stripComment).
func harnessStripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

// harnessUnquote strips matching "double" or 'single' quotes around a value (config.go unquote).
func harnessUnquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}
