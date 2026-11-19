package mgr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// statsClient mirrors `curl -fs --noproxy '*' --max-time 2`: never proxied,
// 2 s budget, body errors surface as failures.
var statsClient = &http.Client{
	Timeout:   2 * time.Second,
	Transport: &http.Transport{Proxy: nil},
}

// FetchStatsRaw GETs http://addr/stats and returns the body verbatim ("" +
// error on any failure). Addr is the config's metrics: host:port.
func FetchStatsRaw(addr string) (string, error) {
	res, err := statsClient.Get("http://" + addr + "/stats")
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /stats: HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// FetchStatsFlat mirrors stats_flat(): /stats?flat=1 first (one key=value line
// per top-level value, 3.3.6); an older binary answers it with the JSON, and an
// empty answer falls back to one plain /stats — jget reads both forms.
func FetchStatsFlat(addr string) (string, error) {
	res, err := statsClient.Get("http://" + addr + "/stats?flat=1")
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /stats?flat=1: HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if len(body) > 0 {
		return string(body), nil
	}
	return FetchStatsRaw(addr)
}

// FetchPorts GETs /ports (the per-port counters page); "" on any failure —
// screens treat it like the bash $(curl ... || true).
func FetchPorts(addr string) string {
	res, err := statsClient.Get("http://" + addr + "/ports")
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return ""
	}
	return string(body)
}

// StatsRaw fetches /stats for a tunnel by name via its metrics: key, the way
// stats() does (empty metrics key = no metrics server = "" with no error noise).
func StatsRaw(name string) string {
	m := Cfg(name, "metrics")
	if m == "" {
		return ""
	}
	v, err := FetchStatsRaw(m)
	if err != nil {
		return ""
	}
	return v
}

// Jget mirrors jget(): a top-level value of a JSON object, or of stats_flat's
// key=value lines. Which keys and which fallbacks matter to the screens; this
// accessor keeps their picks exactly as the bash greps them.
func Jget(text, key string) string {
	if strings.HasPrefix(text, "{") {
		m := parseTopLevel(text)
		if v, ok := m[key]; ok {
			return strings.Trim(v, `"`)
		}
		return ""
	}
	for _, line := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	return ""
}

// JgetFlat mirrors jget_flat(): the flat aggregate first, the legacy key as a
// fallback for older binaries.
func JgetFlat(text, flatKey, legacyKey string) string {
	if v := Jget(text, flatKey); v != "" {
		return v
	}
	return Jget(text, legacyKey)
}

// parseTopLevel decodes a flat JSON object with json.Number so the > 2^53 byte
// counters stay exact, and tolerates trailing garbage the way grep did not —
// a value it cannot decode is simply absent.
func parseTopLevel(text string) map[string]string {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil
	}
	out := make(map[string]string, len(obj))
	for k, v := range obj {
		switch x := v.(type) {
		case json.Number:
			out[k] = x.String()
		case string:
			out[k] = x
		case bool:
			if x {
				out[k] = "true"
			} else {
				out[k] = "false"
			}
		default:
			// arrays/objects (carriers, cc, ports): skipped, the screens that
			// need them parse the raw text or the typed Stats below
		}
	}
	return out
}

// Carrier is one leg of a bond as /stats reports it.
type Carrier struct {
	Name   string
	Alive  bool
	Muted  bool
	SRTTms float64
	Share  float64
	Sent   int64
	Acked  int64
	Lost   int64
}

// Stats is the typed /stats view the screens build their rows from: the exact
// keys tinfo reads, with the same legacy fallbacks applied.
type Stats struct {
	Version string
	Alive   bool

	RTTms   float64 // rtt_ms, falling back to srtt_ms
	MinRTT  float64 // min_rtt_ms
	LossPct float64 // loss_pct
	RateBps float64 // rate_bps

	Streams       int64  // streams_total, falling back to streams
	Sessions      int64  // sessions
	DgramFlows    int64  // dgram_flows
	BytesIn       string // bytes_in_total, falling back to bytes_in (pre-2.4.19); exact digits — the counters exceed 2^53 and int64 would clamp
	BytesOut      string // bytes_out_total, falling back to bytes_out
	PktsIn        int64
	PktsOut       int64
	Retrans       int64
	LastRxAgeMs   float64
	Inflight      int64
	ConnsActive   int64
	SessionsUp    int64
	CeilingBps    float64
	FecState      string
	FilterProfile string

	Carriers []Carrier
}

// ParseStats decodes a /stats body (JSON) into the typed view. The raw text
// stays available via Jget on the original blob.
func ParseStats(blob string) (*Stats, error) {
	dec := json.NewDecoder(strings.NewReader(blob))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	st := &Stats{}
	num := func(k string) float64 {
		if v, ok := raw[k].(json.Number); ok {
			f, _ := v.Float64()
			return f
		}
		return 0
	}
	int64Of := func(k string) int64 {
		if v, ok := raw[k].(json.Number); ok {
			n, _ := v.Int64()
			return n
		}
		return 0
	}
	str := func(k string) string {
		if v, ok := raw[k].(string); ok {
			return v
		}
		return ""
	}
	st.Version = str("version")
	st.Alive, _ = raw["alive"].(bool)
	st.RTTms = num("rtt_ms")
	if st.RTTms == 0 {
		st.RTTms = num("srtt_ms")
	}
	st.MinRTT = num("min_rtt_ms")
	st.LossPct = num("loss_pct")
	st.RateBps = num("rate_bps")
	st.CeilingBps = num("ceiling_bps")
	st.LastRxAgeMs = num("last_rx_age_ms")
	st.Inflight = int64Of("inflight")
	st.ConnsActive = int64Of("conns_active")
	st.SessionsUp = int64Of("sessions_up")
	st.FecState = str("fec_state")
	st.FilterProfile = str("filter_profile")
	st.Streams = int64Of("streams_total")
	if st.Streams == 0 {
		st.Streams = int64Of("streams")
	}
	st.Sessions = int64Of("sessions")
	st.DgramFlows = int64Of("dgram_flows")
	numStr := func(k string) string {
		if v, ok := raw[k].(json.Number); ok {
			return v.String()
		}
		return ""
	}
	st.BytesIn = numStr("bytes_in_total")
	if st.BytesIn == "" {
		st.BytesIn = numStr("bytes_in")
	}
	st.BytesOut = numStr("bytes_out_total")
	if st.BytesOut == "" {
		st.BytesOut = numStr("bytes_out")
	}
	st.PktsIn = int64Of("pkts_in")
	st.PktsOut = int64Of("pkts_out")
	st.Retrans = int64Of("retrans")
	if arr, ok := raw["carriers"].([]any); ok {
		for _, e := range arr {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			c := Carrier{Name: ""}
			if n, ok := m["name"].(string); ok {
				c.Name = n
			}
			c.Alive, _ = m["alive"].(bool)
			c.Muted, _ = m["muted"].(bool)
			if v, ok := m["srtt_ms"].(json.Number); ok {
				c.SRTTms, _ = v.Float64()
			}
			if v, ok := m["share"].(json.Number); ok {
				c.Share, _ = v.Float64()
			}
			// a numeric field that is present but malformed marks the entry bad:
			// it is skipped, the good ones kept (the ui harness pins this too)
			bad := false
			geti := func(dst *int64, k string) {
				v, present := m[k]
				if !present {
					return
				}
				n, ok := v.(json.Number)
				if !ok {
					bad = true
					return
				}
				*dst, _ = n.Int64()
			}
			geti(&c.Sent, "sent")
			geti(&c.Acked, "acked")
			geti(&c.Lost, "lost")
			if bad || (c.Name == "" && c.Sent == 0 && c.Acked == 0 && c.Lost == 0) {
				continue
			}
			st.Carriers = append(st.Carriers, c)
		}
	}
	return st, nil
}

// FetchStats fetches and parses /stats in one step.
func FetchStats(addr string) (*Stats, error) {
	blob, err := FetchStatsRaw(addr)
	if err != nil {
		return nil, err
	}
	return ParseStats(blob)
}

// Human mirrors human(): "1.2 GB" byte formatting.
func Human(b float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for b >= 1024 && i < 4 {
		b /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", b, units[i])
}

// Ms mirrors ms(): one decimal, "0.0" for empty.
func Ms(v float64) string { return fmt.Sprintf("%.1f", v) }
