package panel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webEmbed embed.FS

var webFS fs.FS = webEmbed

// SetDevWebDir serves web/ from DIR on disk instead of the binary (the local dev harness edits it live).
func SetDevWebDir(dir string) { webFS = os.DirFS(dir) }

const csp = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; " +
	"font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// cliName is the console command the page names in its help text (sent only after sign-in).
var cliName = "wattun"

// product and repo name the software in the sidebar; like cliName they are sent only after sign-in, so the login
// page does not say what this server runs
const product, productRepo = "WatTunnel", "https://github.com/JohnWatsoon/WatTunnel"

// Server is one running panel.
type Server struct {
	cfgMu   sync.Mutex
	cfg     *Config
	be      Backend
	g       *guard
	base    string // "/<secret>/"
	dataDir string

	liveMu sync.Mutex
	live   map[string]*liveRow
	last   map[string]Counters
	lastAt time.Time
	khMu   sync.Mutex
	kh     []Kharej
	wd     *watchdog

	pendingMu   sync.Mutex
	pendingTOTP string // secret shown on the enrolment screen, not active until a code confirms it

	hub *hub

	jobs   *jobs
	certs  *certStore
	tr     *traffic
	al     *alerts
	hostMu sync.Mutex
	host   Host
	hostAt time.Time
	tick   int
	ver    versionCache
	geo    geoCache
}

type liveRow struct {
	Name    string  `json:"name"`
	Alive   bool    `json:"alive"`
	Down    float64 `json:"down"`
	Up      float64 `json:"up"`
	RTT     float64 `json:"rtt"`
	Loss    float64 `json:"loss"`
	Streams int64   `json:"streams"`
	Conns   int64   `json:"conns"`
	Metrics bool    `json:"metrics"`
}

// New builds a server over cfg and be; dataDir holds the watchdog record.
func New(cfg *Config, be Backend, dataDir string) *Server {
	s := &Server{cfg: cfg, be: be, g: newGuard(), base: "/" + cfg.Path + "/", dataDir: dataDir,
		live: map[string]*liveRow{}, last: map[string]Counters{}, hub: newHub()}
	s.wd = newWatchdog(filepath.Join(dataDir, "outages.jsonl"))
	s.jobs, s.certs, s.tr, s.al = newJobs(""), &certStore{}, newTraffic(dataDir), newAlerts(dataDir)
	s.geoLoad()
	if dataDir != "" {
		s.g.loadSessions(filepath.Join(dataDir, "sessions"))
		s.jobs = newJobs(filepath.Join(dataDir, "jobs"))
	}
	return s
}

// Run loads FILE, makes the certificate if needed and serves until the process ends.
func Run(file string, be Backend) error {
	cfg, err := LoadConfig(file)
	if err != nil {
		return err
	}
	dataDir := envOr("WAT_PANEL_DATA", "/var/lib/wattun/panel")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	if err := EnsureCert(cfg.CertFile, cfg.KeyFile, localIPs()); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	s := New(cfg, be, dataDir)
	if err := s.certs.load(cfg.CertFile, cfg.KeyFile); err != nil {
		if cfg.CertKind == "self" {
			return fmt.Errorf("certificate: %w", err)
		}
		log.Printf("panel: certificate %s does not load (%v); back to the self-signed one", cfg.CertFile, err)
		if err := useSelfSigned(cfg); err != nil {
			return fmt.Errorf("certificate: %w", err)
		}
		if err := s.certs.load(cfg.CertFile, cfg.KeyFile); err != nil {
			return fmt.Errorf("certificate: %w", err)
		}
		cfg.Save()
	}
	s.StartPollers()
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           s,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.certs.get},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(discard{}, "", 0), // TLS handshake noise from scanners
	}
	log.Printf("panel: listening on :%d (TLS)", cfg.Port)
	return srv.ListenAndServeTLS("", "")
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// localIPs is every global unicast address of this host (the certificate's SANs).
func localIPs() []net.IP {
	var out []net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.IsGlobalUnicast() {
			out = append(out, n.IP)
		}
	}
	return out
}

func (s *Server) conf() *Config {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return s.cfg
}

// StartPollers starts the 1 s live sampler and the 15 s Kharej poller (they run until the process ends).
func (s *Server) StartPollers() {
	ctx := context.Background()
	go s.pollLive(ctx)
	go s.pollKharej(ctx)
	go s.pollGeo(ctx)
	if s.dataDir != "" {
		go s.schedule(ctx)
	}
}

// ServeHTTP: the secret prefix or the nginx 404, nothing in between.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	cfg := s.conf()
	base := "/" + cfg.Path + "/"
	if !allowed(cfg.Allow, ip) {
		notFound(w, r)
		return
	}
	if r.URL.Path == strings.TrimSuffix(base, "/") && !s.g.banned(ip) {
		http.Redirect(w, r, base, http.StatusFound)
		return
	}
	if !strings.HasPrefix(r.URL.Path, base) || s.g.banned(ip) {
		notFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	rest := strings.TrimPrefix(r.URL.Path, base)
	if strings.HasPrefix(rest, "api/") {
		s.api(w, r, strings.TrimPrefix(rest, "api/"), ip)
		return
	}
	s.static(w, r, rest)
}

func (s *Server) static(w http.ResponseWriter, r *http.Request, rest string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		notFound(w, r)
		return
	}
	if rest == "" {
		rest = "index.html"
	}
	rest = path.Clean(rest)
	b, err := fs.ReadFile(webFS, "web/"+rest)
	if err != nil || strings.Contains(rest, "..") {
		notFound(w, r)
		return
	}
	if rest == "index.html" {
		b = []byte(strings.ReplaceAll(string(b), "{{TITLE}}", htmlEscape(s.conf().Title)))
	}
	// the files are ~180 KB of text that every visit fetched again over a slow link: answer a repeat visit with
	// 304 (ETag, revalidated each time so an update is never served stale) and the first one gzipped
	tag := `"` + etagOf(b) + `"`
	w.Header().Set("Cache-Control", "private, no-cache")
	w.Header().Set("ETag", tag)
	w.Header().Set("Vary", "Accept-Encoding")
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	switch path.Ext(rest) {
	case ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case ".woff2":
		w.Header().Set("Content-Type", "font/woff2")
	}
	if path.Ext(rest) != ".woff2" && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gzipped(tag, b))
		return
	}
	w.Write(b)
}

var (
	gzMu    sync.Mutex
	gzCache = map[string][]byte{} // by ETag: the files are embedded, so the set is small and fixed per binary
)

func etagOf(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:8]) }

func gzipped(tag string, b []byte) []byte {
	gzMu.Lock()
	defer gzMu.Unlock()
	if z, ok := gzCache[tag]; ok {
		return z
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.Write(b)
	zw.Close()
	if len(gzCache) > 64 { // a dev web dir or a changing title: never grow without bound
		clear(gzCache)
	}
	gzCache[tag] = buf.Bytes()
	return gzCache[tag]
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 64<<10)
	return json.NewDecoder(r.Body).Decode(v)
}

// api routes. Unauthenticated: login, 2fa. Everything else needs a session; every non-GET also needs the
// X-Requested-With header (a cross-site form cannot set it).
func (s *Server) api(w http.ResponseWriter, r *http.Request, route, ip string) {
	if r.Method != http.MethodGet && r.Header.Get("X-Requested-With") != "panel" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing request header"})
		return
	}
	switch route {
	case "login":
		s.apiLogin(w, r, ip)
		return
	case "2fa":
		s.api2FA(w, r, ip)
		return
	}
	sess := s.g.session(r)
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sign in"})
		return
	}
	s.dispatch(w, r, route, ip, sess)
}

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request, ip string) {
	var in struct{ User, Pass string }
	if r.Method != http.MethodPost || readJSON(r, &in) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	c := s.conf()
	if !checkPassword(c, in.User, in.Pass) {
		s.g.fail(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Wrong username or password."})
		return
	}
	if c.TOTP != "" {
		writeJSON(w, http.StatusOK, map[string]any{"need2fa": true, "ticket": s.g.newTicket(ip)})
		return
	}
	s.g.clear(ip)
	setCookie(w, s.cookiePath(), s.g.newSession(c.User, r), 0)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) api2FA(w http.ResponseWriter, r *http.Request, ip string) {
	var in struct{ Ticket, Code string }
	if r.Method != http.MethodPost || readJSON(r, &in) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if !s.g.takeTicket(in.Ticket, ip) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "Sign in again.", "restart": true})
		return
	}
	s.cfgMu.Lock()
	c := s.cfg
	ok := false
	if step, good := VerifyTOTP(c.TOTP, in.Code, time.Now(), c.TOTPLast); good {
		c.TOTPLast, ok = step, true
	} else if useRecovery(c, in.Code) {
		ok = true
	}
	var saveErr error
	if ok {
		saveErr = c.Save()
	}
	s.cfgMu.Unlock()
	if !ok {
		s.g.fail(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "Wrong code.", "restart": true,
			"server_time": time.Now().UTC().Format("15:04:05 UTC")})
		return
	}
	if saveErr != nil {
		log.Printf("panel: saving the 2FA replay guard: %v", saveErr)
	}
	s.g.clear(ip)
	setCookie(w, s.cookiePath(), s.g.newSession(c.User, r), 0)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) api2FASetup(w http.ResponseWriter) {
	sec := NewTOTPSecret()
	s.pendingMu.Lock()
	s.pendingTOTP = sec
	s.pendingMu.Unlock()
	c := s.conf()
	uri := TOTPURI(c.Title, c.User, sec)
	q, err := EncodeQR(uri)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": groupBy4(sec), "svg": q.SVG(), "uri": uri})
}

func groupBy4(s string) string {
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:min(i+4, len(s))])
	}
	return strings.Join(parts, " ")
}

func (s *Server) api2FAEnable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if readJSON(r, &in) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	s.pendingMu.Lock()
	sec := s.pendingTOTP
	s.pendingMu.Unlock()
	step, ok := VerifyTOTP(sec, in.Code, time.Now(), 0)
	if sec == "" || !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "That code does not match. Check the phone's time and try the next code."})
		return
	}
	plain, hashed := NewRecoveryCodes()
	s.cfgMu.Lock()
	s.cfg.TOTP, s.cfg.TOTPLast, s.cfg.Recovery = sec, step, hashed
	err := s.cfg.Save()
	s.cfgMu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save: " + err.Error()})
		return
	}
	s.pendingMu.Lock()
	s.pendingTOTP = ""
	s.pendingMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recovery": plain})
}

func (s *Server) api2FADisable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Pass, Code string }
	if readJSON(r, &in) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	c := s.cfg
	_, codeOK := VerifyTOTP(c.TOTP, in.Code, time.Now(), c.TOTPLast)
	if !checkPassword(c, c.User, in.Pass) || !codeOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Password or code is wrong."})
		return
	}
	c.TOTP, c.TOTPLast, c.Recovery = "", 0, nil
	if err := c.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiPassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Old, New string }
	if readJSON(r, &in) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if len(in.New) < 12 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Use at least 12 characters."})
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if !checkPassword(s.cfg, s.cfg.User, in.Old) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "The current password is wrong."})
		return
	}
	h, err := HashPassword(in.New)
	if err == nil {
		s.cfg.PassHash = h
		err = s.cfg.Save()
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiOverview(w http.ResponseWriter) {
	s.khMu.Lock()
	kh := s.kh
	s.khMu.Unlock()
	if kh == nil {
		kh = []Kharej{}
	}
	tun := s.be.Tunnels()
	if tun == nil {
		tun = []Tunnel{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host": s.be.Host(), "tunnels": tun, "kharej": kh, "twofa": s.conf().TOTP != "",
		"watchdog": s.wd.summary(tunnelNames(tun), time.Now()), "alerts": s.al.list(), "latest": s.latestVersion(), "geo": s.geoAll(),
	})
}

func tunnelNames(t []Tunnel) []string {
	out := make([]string, len(t))
	for i, x := range t {
		out[i] = x.Name
	}
	return out
}

func (s *Server) known(name string) bool {
	for _, t := range s.be.Tunnels() {
		if t.Name == name {
			return true
		}
	}
	return false
}

func (s *Server) apiHistory(c *call) {
	if !s.known(c.arg[0]) {
		c.fail(http.StatusNotFound, "no such tunnel")
		return
	}
	b := s.be.History(c.arg[0])
	if b == nil {
		b = []byte("[]")
	}
	c.w.Header().Set("Content-Type", "application/json")
	c.w.Write(b)
}

func (s *Server) apiLogs(c *call) {
	if !s.known(c.arg[0]) {
		c.fail(http.StatusNotFound, "no such tunnel")
		return
	}
	n, _ := strconv.Atoi(c.r.URL.Query().Get("n"))
	if n <= 0 || n > 2000 {
		n = 200
	}
	lines := s.be.Logs(c.arg[0], n)
	if lines == nil {
		lines = []string{}
	}
	c.ok(map[string]any{"lines": lines})
}

// ---- live data ----

// pollLive samples every tunnel's /stats once a second while a page is open, turns byte totals into rates (down
// = what users receive: bytes in on Iran, bytes out on Kharej — the dashboard's rule, mgr/home.go sampleTunnel)
// and pushes one SSE frame to every open page. With no page open it samples every 5 s: enough for the watchdog
// and the traffic totals, which work on deltas.
func (s *Server) pollLive(ctx context.Context) {
	for {
		s.sample(time.Now())
		every := time.Second
		if s.hub.count() == 0 {
			every = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		case <-s.hub.joined:
		}
	}
}

func (s *Server) sample(now time.Time) {
	tun := s.be.Tunnels()
	rows := make([]*liveRow, 0, len(tun))
	s.liveMu.Lock()
	dt := now.Sub(s.lastAt).Seconds()
	seen := map[string]bool{}
	for _, t := range tun {
		seen[t.Name] = true
		row := &liveRow{Name: t.Name}
		c, ok := s.be.Stats(t.Name)
		row.Metrics = ok
		if ok {
			row.Alive, row.RTT, row.Loss, row.Streams, row.Conns = c.Alive, c.RTTms, c.LossPct, c.Streams, c.Conns
			in, out := c.BytesIn, c.BytesOut
			if t.Role == "Kharej" {
				in, out = out, in
			}
			if p, had := s.last[t.Name]; had && dt > 0.2 {
				pin, pout := p.BytesIn, p.BytesOut
				if t.Role == "Kharej" {
					pin, pout = pout, pin
				}
				if in >= pin && out >= pout {
					row.Down, row.Up = (in-pin)/dt, (out-pout)/dt
					s.tr.add(t.Name, in-pin, out-pout, now)
				}
			}
			s.last[t.Name] = c
		}
		up := t.Active && (!ok || c.Alive)
		s.wd.observe(t.Name, t.Enabled || t.Active, up, now)
		rows = append(rows, row)
	}
	for n := range s.last {
		if !seen[n] {
			delete(s.last, n)
		}
	}
	s.lastAt = now
	s.live = map[string]*liveRow{}
	for _, r := range rows {
		s.live[r.Name] = r
	}
	live := s.live
	s.liveMu.Unlock()
	if s.tick++; s.tick%5 == 0 {
		s.checkAlerts(tun, live, now)
	}
	b, _ := json.Marshal(map[string]any{"t": now.Unix(), "tunnels": rows})
	s.hub.publish(b)
}

func (s *Server) pollKharej(ctx context.Context) {
	for {
		kh := s.be.Kharej()
		s.khMu.Lock()
		s.kh = kh
		s.khMu.Unlock()
		every := 15 * time.Second
		if s.hub.count() == 0 {
			every = time.Minute // nobody looks: keep it fresh enough for the first page load
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// apiLive is the SSE stream: one "data:" frame per second.
func (s *Server) apiLive(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	ch := s.hub.sub()
	defer s.hub.unsub(ch)
	bw := bufio.NewWriter(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-ch:
			bw.WriteString("data: ")
			bw.Write(b)
			bw.WriteString("\n\n")
			if bw.Flush() != nil {
				return
			}
			fl.Flush()
		}
	}
}

type hub struct {
	mu     sync.Mutex
	subs   map[chan []byte]bool
	joined chan struct{} // a page opened: the sampler leaves its idle pace at once
}

func newHub() *hub { return &hub{subs: map[chan []byte]bool{}, joined: make(chan struct{}, 1)} }

func (h *hub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

func (h *hub) sub() chan []byte {
	ch := make(chan []byte, 4)
	h.mu.Lock()
	h.subs[ch] = true
	h.mu.Unlock()
	select {
	case h.joined <- struct{}{}:
	default:
	}
	return ch
}

func (h *hub) unsub(ch chan []byte) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *hub) publish(b []byte) {
	h.mu.Lock()
	for ch := range h.subs {
		select {
		case ch <- b:
		default: // a slow page skips a frame instead of stalling the sampler
		}
	}
	h.mu.Unlock()
}

// cookiePath is the secret prefix the session cookie is scoped to.
func (s *Server) cookiePath() string { return "/" + s.conf().Path + "/" }
