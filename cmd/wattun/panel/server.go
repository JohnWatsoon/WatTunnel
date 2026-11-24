package panel

import (
	"bufio"
	"context"
	"crypto/tls"
	"embed"
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
var webFS embed.FS

const csp = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; " +
	"font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// cliName is the console command the page names in its help text (sent only after sign-in).
var cliName = "wattun"

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
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	s := New(cfg, be, dataDir)
	s.StartPollers()
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           s,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
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
}

// ServeHTTP: the secret prefix or the nginx 404, nothing in between.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if r.URL.Path == strings.TrimSuffix(s.base, "/") && !s.g.banned(ip) {
		http.Redirect(w, r, s.base, http.StatusFound)
		return
	}
	if !strings.HasPrefix(r.URL.Path, s.base) || s.g.banned(ip) {
		notFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	rest := strings.TrimPrefix(r.URL.Path, s.base)
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
	w.Write(b)
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
	switch {
	case route == "logout" && r.Method == http.MethodPost:
		s.g.drop(r)
		setCookie(w, s.base, "", -1)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case route == "logout-all" && r.Method == http.MethodPost:
		s.g.dropAll()
		setCookie(w, s.base, "", -1)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case route == "me":
		c := s.conf()
		writeJSON(w, http.StatusOK, map[string]any{"user": c.User, "twofa": c.TOTP != "", "recovery_left": len(c.Recovery), "title": c.Title, "cli": cliName})
	case route == "overview":
		s.apiOverview(w)
	case route == "live":
		s.apiLive(w, r)
	case strings.HasPrefix(route, "tunnels/"):
		s.apiTunnel(w, r, strings.TrimPrefix(route, "tunnels/"))
	case route == "settings/2fa/setup" && r.Method == http.MethodPost:
		s.api2FASetup(w)
	case route == "settings/2fa/enable" && r.Method == http.MethodPost:
		s.api2FAEnable(w, r)
	case route == "settings/2fa/disable" && r.Method == http.MethodPost:
		s.api2FADisable(w, r)
	case route == "settings/password" && r.Method == http.MethodPost:
		s.apiPassword(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such call"})
	}
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
	setCookie(w, s.base, s.g.newSession(c.User), 0)
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
	setCookie(w, s.base, s.g.newSession(c.User), 0)
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
		"watchdog": s.wd.summary(tunnelNames(tun), time.Now()),
	})
}

func tunnelNames(t []Tunnel) []string {
	out := make([]string, len(t))
	for i, x := range t {
		out[i] = x.Name
	}
	return out
}

func (s *Server) apiTunnel(w http.ResponseWriter, r *http.Request, rest string) {
	name, what, _ := strings.Cut(rest, "/")
	known := false
	for _, t := range s.be.Tunnels() {
		if t.Name == name {
			known = true
		}
	}
	if !known {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such tunnel"})
		return
	}
	switch what {
	case "history":
		b := s.be.History(name)
		if b == nil {
			b = []byte("[]")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	case "logs":
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 || n > 2000 {
			n = 200
		}
		lines := s.be.Logs(name, n)
		if lines == nil {
			lines = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"lines": lines})
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such call"})
	}
}

// ---- live data ----

// pollLive samples every tunnel's /stats once a second, turns byte totals into rates (down = what users
// receive: bytes in on Iran, bytes out on Kharej — the dashboard's rule, mgr/home.go sampleTunnel) and pushes one
// SSE frame to every open page.
func (s *Server) pollLive(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		s.sample(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
	s.liveMu.Unlock()
	b, _ := json.Marshal(map[string]any{"t": now.Unix(), "tunnels": rows})
	s.hub.publish(b)
}

func (s *Server) pollKharej(ctx context.Context) {
	for {
		kh := s.be.Kharej()
		s.khMu.Lock()
		s.kh = kh
		s.khMu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
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
	mu   sync.Mutex
	subs map[chan []byte]bool
}

func newHub() *hub { return &hub{subs: map[chan []byte]bool{}} }

func (h *hub) sub() chan []byte {
	ch := make(chan []byte, 4)
	h.mu.Lock()
	h.subs[ch] = true
	h.mu.Unlock()
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
