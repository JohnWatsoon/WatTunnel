package main

// Per-port traffic counters, rate limits and quotas.
//
// Every public port (client: the port users connect to; server: the target port) has a portStat of atomics that the
// copy loops update; one 1 s ticker derives rates and peaks, enforces quotas and (every -state-save seconds, default
// 30) persists quota usage and the lifetime totals. Limits come from the config's `limits:` list and are hot-reloaded.
// With no limit set the only per-chunk cost is a few atomic adds and two atomic loads.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type limitSpec struct {
	Port        int
	Rate, Quota int64 // bytes/s per direction, bytes up+down; 0 = unlimited
}

// parseSize parses "5MB", "1.5GB", "300k", "1000" (decimal units: 1 MB = 1e6 bytes).
func parseSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	t = strings.TrimSuffix(t, "B")
	mul := 1.0
	if n := len(t); n > 0 {
		switch t[n-1] {
		case 'K':
			mul = 1e3
		case 'M':
			mul = 1e6
		case 'G':
			mul = 1e9
		case 'T':
			mul = 1e12
		}
		if mul != 1 {
			t = t[:n-1]
		}
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return int64(f * mul), nil
}

func parseLimitItem(s string) (limitSpec, error) {
	f := strings.Fields(s)
	var ls limitSpec
	if len(f) == 0 {
		return ls, fmt.Errorf("limit needs a port")
	}
	p, err := strconv.Atoi(f[0])
	if err != nil || p < 1 || p > 65535 {
		return ls, fmt.Errorf("bad limit port %q", f[0])
	}
	ls.Port = p
	for _, kvs := range f[1:] {
		k, v, ok := strings.Cut(kvs, "=")
		if !ok {
			return ls, fmt.Errorf("want rate=SIZE or quota=SIZE, got %q", kvs)
		}
		n, err := parseSize(v)
		if err != nil {
			return ls, err
		}
		switch k {
		case "rate":
			ls.Rate = n
		case "quota":
			ls.Quota = n
		default:
			return ls, fmt.Errorf("unknown limit key %q", k)
		}
	}
	return ls, nil
}

func limitsKey(c *fileConfig) string { return fmt.Sprintf("%v", c.Limits) }

// bucket is a token bucket; wait sleeps (debt model), allow drops instead (datagrams).
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(rate int64) *bucket {
	b := float64(rate) / 10
	if b < 32<<10 {
		b = 32 << 10
	}
	return &bucket{rate: float64(rate), burst: b, tokens: b, last: time.Now()}
}

func (b *bucket) refill() {
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
}

func (b *bucket) wait(n int) {
	b.mu.Lock()
	b.refill()
	b.tokens -= float64(n)
	var d time.Duration
	if b.tokens < 0 {
		d = time.Duration(-b.tokens / b.rate * float64(time.Second))
	}
	b.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
}

func (b *bucket) allow(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	if b.tokens <= 0 {
		return false
	}
	b.tokens -= float64(n)
	return true
}

type portStat struct {
	port                                                  int
	bytesUp, bytesDown, connsTotal, connsActive, udpFlows atomic.Int64
	dgUp, dgDown, errs, refused                           atomic.Int64
	rateUp, rateDown, peakUp, peakDown                    atomic.Int64
	lastUp, lastDown                                      int64 // ticker goroutine only
	baseUp, baseDown, baseConns                           int64 // totals from before the last restart (set once at creation)
	qused, quota, rateLim                                 atomic.Int64
	bUp, bDown                                            atomic.Pointer[bucket]

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func (p *portStat) exceeded() bool {
	q := p.quota.Load()
	return q > 0 && p.qused.Load() >= q
}

func (p *portStat) add(up bool, n int) {
	if up {
		p.bytesUp.Add(int64(n))
	} else {
		p.bytesDown.Add(int64(n))
	}
	// qused counts only traffic served under an active quota: bytes from an unlimited period
	// must not be charged when a quota later appears by hot-reload (audit 2026-10-22).
	if q := p.quota.Load(); q > 0 && p.qused.Add(int64(n)) >= q {
		p.kill()
	}
}

// track registers an accepted connection; false = quota used up, caller closes it.
func (p *portStat) track(c net.Conn) bool {
	if p.exceeded() {
		p.refused.Add(1)
		return false
	}
	p.mu.Lock()
	if p.conns == nil {
		p.conns = map[net.Conn]struct{}{}
	}
	p.conns[c] = struct{}{}
	p.mu.Unlock()
	p.connsTotal.Add(1)
	p.connsActive.Add(1)
	return true
}

func (p *portStat) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
	p.connsActive.Add(-1)
}

// kill closes every tracked connection (quota exceeded).
func (p *portStat) kill() {
	p.mu.Lock()
	cs := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		cs = append(cs, c)
	}
	p.mu.Unlock()
	for _, c := range cs {
		c.Close()
	}
}

// dgramOK gates one datagram: false when the quota is used up or the port's rate is exceeded (dropped).
func (p *portStat) dgramOK(up bool, n int) bool {
	b := p.bDown.Load()
	if up {
		b = p.bUp.Load()
	}
	if p.exceeded() || b != nil && !b.allow(n) {
		p.refused.Add(1)
		return false
	}
	return true
}

func (p *portStat) dgram(up bool, n int) {
	if up {
		p.dgUp.Add(1)
	} else {
		p.dgDown.Add(1)
	}
	p.add(up, n)
}

// copy pipes src to dst counting (and, if limited, pacing) every chunk. up = client->server payload.
// copy starts with a small buffer and doubles it (up to copyBufMax) only while reads fill it: most forwarded
// connections are idle or carry small requests, and two 32 KB buffers per connection were ~40 MB of a 200 MB heap at
// ~1300 connections (field 2026-10-12, 2.4.7 heap profiles on both ends).
const (
	copyBufMin = 4 << 10
	copyBufMax = 32 << 10
)

func (p *portStat) copy(dst io.Writer, src io.Reader, up bool) (int64, error) {
	buf := make([]byte, copyBufMin)
	var total int64
	for {
		n, err := src.Read(buf)
		if n == len(buf) && len(buf) < copyBufMax {
			nb := make([]byte, 2*len(buf))
			copy(nb, buf[:n])
			buf = nb
		}
		if n > 0 {
			b := p.bDown.Load()
			if up {
				b = p.bUp.Load()
			}
			if b != nil {
				b.wait(n)
			}
			w, werr := dst.Write(buf[:n])
			p.add(up, w)
			total += int64(w)
			if werr != nil {
				return total, werr
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func (p *portStat) setLimit(ls limitSpec) {
	p.quota.Store(ls.Quota)
	p.rateLim.Store(ls.Rate)
	if ls.Rate > 0 {
		if b := p.bUp.Load(); b == nil || int64(b.rate) != ls.Rate {
			p.bUp.Store(newBucket(ls.Rate))
			p.bDown.Store(newBucket(ls.Rate))
		}
	} else {
		p.bUp.Store(nil)
		p.bDown.Store(nil)
	}
	if p.exceeded() {
		p.kill()
	}
}

type registry struct {
	mu     sync.Mutex
	stats  map[string]*portStat // "c:20001" / "s:20001"
	limits map[int]limitSpec
	loaded map[int]int64 // quota usage read from the state file
	path   string        // quota state file ("" = no persistence)

	// Lifetime totals (2.5.0): bytes and connections per port and the session's wire bytes, kept across restarts in
	// totPath. /ports and /stats report base + what this process counted.
	totPath  string
	tot      map[string][3]int64 // "c:20001" -> up, down, conns; "session" -> in, out, 0
	sess     func() (in, out uint64)
	sessBase [2]int64

	saveMu sync.Mutex // one disk writer at a time: the .tmp + rename pair must not interleave between callers
}

var portReg = newRegistry()

func newRegistry() *registry {
	return &registry{stats: map[string]*portStat{}, limits: map[int]limitSpec{}, loaded: map[int]int64{}}
}

func (r *registry) get(side string, port int) *portStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.getLocked(side+":"+strconv.Itoa(port), port)
}

func (r *registry) getLocked(k string, port int) *portStat {
	p := r.stats[k]
	if p == nil {
		p = &portStat{port: port}
		p.qused.Store(r.loaded[port])
		if t, ok := r.tot[k]; ok {
			p.baseUp, p.baseDown, p.baseConns = t[0], t[1], t[2]
		}
		if ls, ok := r.limits[port]; ok {
			p.setLimit(ls)
		}
		r.stats[k] = p
	}
	return p
}

// applyLimits replaces the limit set; ports no longer listed become unlimited.
func (r *registry) applyLimits(ls []limitSpec) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limits = map[int]limitSpec{}
	for _, l := range ls {
		r.limits[l.Port] = l
	}
	for _, p := range r.stats {
		p.setLimit(r.limits[p.port])
	}
}

func (r *registry) loadQuota(path string) {
	r.path = path
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var m map[string]int64
	if json.Unmarshal(b, &m) != nil {
		log.Printf("quota state %s: unreadable, starting from zero", path)
		return
	}
	r.mu.Lock()
	for k, v := range m {
		if p, err := strconv.Atoi(k); err == nil {
			r.loaded[p] = v
		}
	}
	r.mu.Unlock()
}

// hostID identifies this machine; a totals file written elsewhere belongs to another server's traffic, and showing
// it here (a config copied to a new VPS) reads as a broken counter. Empty = unknown, the check is skipped.
var hostID = func() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return ""
}()

// loadTotals reads the lifetime totals; sess reports this process's session bytes for the "session" entry.
func (r *registry) loadTotals(path string, sess func() (in, out uint64)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.totPath, r.sess, r.tot = path, sess, map[string][3]int64{}
	if hostID != "" {
		idPath := path + ".host"
		if b, err := os.ReadFile(idPath); err == nil && strings.TrimSpace(string(b)) != hostID {
			log.Printf("traffic totals %s: written on another machine, starting from zero", path)
			_ = os.Remove(path)
		}
		_ = os.WriteFile(idPath, []byte(hostID+"\n"), 0o600)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if json.Unmarshal(b, &r.tot) != nil {
		log.Printf("traffic totals %s: unreadable, starting from zero", path)
		r.tot = map[string][3]int64{}
		return
	}
	t := r.tot["session"]
	r.sessBase = [2]int64{t[0], t[1]}
}

// sessionTotals is the session's wire bytes in and out since the totals file was started.
func (r *registry) sessionTotals(in, out uint64) (int64, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessBase[0] + int64(in), r.sessBase[1] + int64(out)
}

// saveTotals writes the lifetime totals atomically (tmp file + rename; saveMu held via save).
func (r *registry) saveTotals() {
	r.mu.Lock()
	if r.totPath == "" {
		r.mu.Unlock()
		return
	}
	m := make(map[string][3]int64, len(r.tot)+len(r.stats))
	for k, v := range r.tot {
		m[k] = v
	}
	for k, p := range r.stats {
		m[k] = [3]int64{p.baseUp + p.bytesUp.Load(), p.baseDown + p.bytesDown.Load(), p.baseConns + p.connsTotal.Load()}
	}
	path, sess, base := r.totPath, r.sess, r.sessBase
	r.mu.Unlock()
	if sess != nil {
		in, out := sess()
		m["session"] = [3]int64{base[0] + int64(in), base[1] + int64(out), 0}
	}
	b, _ := json.Marshal(m)
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		if err := os.Rename(tmp, path); err != nil {
			log.Printf("traffic totals: %v", err)
		}
	}
}

// save writes quota usage and the lifetime totals atomically (tmp file + rename). One writer at a time:
// the periodic ticker, the shutdown save and /quota/reset can overlap, and two writers on the same .tmp
// file interleave and publish a corrupt state (audit 2026-10-21).
func (r *registry) save() {
	r.saveMu.Lock()
	defer r.saveMu.Unlock()
	r.saveTotals()
	if r.path == "" {
		return
	}
	r.mu.Lock()
	m := map[string]int64{}
	for p, v := range r.loaded {
		m[strconv.Itoa(p)] = v
	}
	for _, p := range r.stats {
		if p.quota.Load() > 0 {
			m[strconv.Itoa(p.port)] = p.qused.Load()
		}
	}
	r.mu.Unlock()
	b, _ := json.Marshal(m)
	tmp := r.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		if err := os.Rename(tmp, r.path); err != nil {
			log.Printf("quota state: %v", err)
		}
	}
}

// resetQuota zeroes the used bytes of port on every side; false if the port is unknown.
func (r *registry) resetQuota(port int) bool {
	r.mu.Lock()
	_, found := r.loaded[port]
	delete(r.loaded, port)
	for _, p := range r.stats {
		if p.port == port {
			p.qused.Store(0)
			found = true
		}
	}
	r.mu.Unlock()
	r.save()
	return found
}

// run is the 1 s ticker: rates, peaks, quota enforcement, and a state save every saveEvery (0 = only on shutdown,
// from -state-save / F8).
func (r *registry) run(saveEvery time.Duration) {
	n := 0
	for range time.Tick(time.Second) {
		r.tick()
		n++
		if saveEvery > 0 && time.Duration(n)*time.Second%saveEvery == 0 {
			r.save()
		}
	}
}

func (r *registry) tick() {
	r.mu.Lock()
	ps := make([]*portStat, 0, len(r.stats))
	for _, p := range r.stats {
		ps = append(ps, p)
	}
	r.mu.Unlock()
	for _, p := range ps {
		u, d := p.bytesUp.Load(), p.bytesDown.Load()
		p.rateUp.Store(u - p.lastUp)
		p.rateDown.Store(d - p.lastDown)
		p.lastUp, p.lastDown = u, d
		if v := p.rateUp.Load(); v > p.peakUp.Load() {
			p.peakUp.Store(v)
		}
		if v := p.rateDown.Load(); v > p.peakDown.Load() {
			p.peakDown.Store(v)
		}
		if p.exceeded() {
			p.kill()
		}
	}
}

// snapshot is the /ports map for one side ("c" or "s").
func (r *registry) snapshot(side string) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]any{}
	for k, p := range r.stats {
		if !strings.HasPrefix(k, side+":") {
			continue
		}
		out[strconv.Itoa(p.port)] = map[string]any{
			"bytes_up": p.bytesUp.Load(), "bytes_down": p.bytesDown.Load(),
			"bytes_up_total": p.baseUp + p.bytesUp.Load(), "bytes_down_total": p.baseDown + p.bytesDown.Load(),
			"conns_total": p.connsTotal.Load(), "conns_all_time": p.baseConns + p.connsTotal.Load(),
			"conns_active":     p.connsActive.Load(),
			"udp_flows_active": p.udpFlows.Load(), "dgram_up": p.dgUp.Load(), "dgram_down": p.dgDown.Load(),
			"errors": p.errs.Load(), "refused": p.refused.Load(),
			"rate_bps_up": p.rateUp.Load(), "rate_bps_down": p.rateDown.Load(),
			"peak_bps_up": p.peakUp.Load(), "peak_bps_down": p.peakDown.Load(),
			"rate_limit_bps": p.rateLim.Load(), "quota_limit": p.quota.Load(),
			"quota_used": p.qused.Load(), "quota_exceeded": p.exceeded(),
		}
	}
	return out
}

// quotaResetHandler: POST /quota/reset?port=N, loopback callers only.
func quotaResetHandler(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		http.Error(w, "loopback only", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, err := strconv.Atoi(r.URL.Query().Get("port"))
	if err != nil {
		http.Error(w, "bad port", http.StatusBadRequest)
		return
	}
	if !portReg.resetQuota(p) {
		http.Error(w, "unknown port", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "{\"port\":%d,\"reset\":true}\n", p)
}
