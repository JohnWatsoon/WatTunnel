package panel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	maxFails     = 5
	banFor       = 15 * time.Minute
	idleTimeout  = 12 * time.Hour
	absTimeout   = 7 * 24 * time.Hour
	ticketTTL    = 5 * time.Minute
	cookieName   = "sid" // generic on purpose: no product name in any pre-login byte
	recoveryLen  = 10
	recoveryKeep = 10
)

// RandToken returns n random bytes, URL-safe base64.
func RandToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashPassword is bcrypt at the default cost.
func HashPassword(p string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return string(h), err
}

// NewRecoveryCodes returns plain codes (shown once) and their bcrypt hashes (stored).
func NewRecoveryCodes() (plain, hashed []string) {
	const alpha = "abcdefghjkmnpqrstuvwxyz23456789" // no 0/o/1/l/i
	for i := 0; i < recoveryKeep; i++ {
		b := make([]byte, recoveryLen)
		rand.Read(b)
		for j := range b {
			b[j] = alpha[int(b[j])%len(alpha)]
		}
		h, _ := bcrypt.GenerateFromPassword(b, bcrypt.DefaultCost)
		plain, hashed = append(plain, string(b[:5])+"-"+string(b[5:])), append(hashed, string(h))
	}
	return
}

type session struct {
	User    string    `json:"u"`
	IP      string    `json:"ip"`
	Agent   string    `json:"ua"`
	Created time.Time `json:"c"`
	Seen    time.Time `json:"s"`
}

type ticket struct {
	exp time.Time
	ip  string
}

type ban struct {
	fails int
	until time.Time
}

// guard holds the auth state. Sessions are also kept in FILE (hashed keys only, 0600), so a panel restart (a
// self-update) does not sign anyone out; tickets and bans stay in memory.
type guard struct {
	mu       sync.Mutex
	sessions map[string]*session // key: sha256 of the cookie value
	tickets  map[string]*ticket  // password ok, waiting for the 2FA code
	bans     map[string]*ban
	fails    []time.Time // every failed sign-in, newest last (the "someone is hammering" alert)
	now      func() time.Time
	file     string
	saved    time.Time // last write of file; "seen" updates are flushed at most once a minute
}

func newGuard() *guard {
	return &guard{sessions: map[string]*session{}, tickets: map[string]*ticket{}, bans: map[string]*ban{}, now: time.Now}
}

// loadSessions reads FILE (missing = none) and keeps writing it from now on.
func (g *guard) loadSessions(file string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.file = file
	b, err := os.ReadFile(file)
	if err != nil {
		return
	}
	var m map[string]*session
	if json.Unmarshal(b, &m) != nil {
		return
	}
	now := g.now()
	for k, s := range m {
		kb, err := hex.DecodeString(k)
		if err != nil || s == nil || now.Sub(s.Seen) > idleTimeout || now.Sub(s.Created) > absTimeout {
			continue
		}
		g.sessions[string(kb)] = s
	}
}

// saveLocked writes the sessions; mu held.
func (g *guard) saveLocked() {
	if g.file == "" {
		return
	}
	g.saved = g.now()
	m := make(map[string]*session, len(g.sessions))
	for k, s := range g.sessions {
		m[hex.EncodeToString([]byte(k))] = s
	}
	b, _ := json.Marshal(m)
	tmp := g.file + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, g.file)
	}
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (g *guard) banned(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.bans[ip]
	return b != nil && g.now().Before(b.until)
}

func (g *guard) fail(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.bans[ip]
	if b == nil || (!b.until.IsZero() && g.now().After(b.until)) {
		b = &ban{}
		g.bans[ip] = b
	}
	b.fails++
	g.fails = append(g.fails, g.now())
	if len(g.fails) > 200 {
		g.fails = g.fails[len(g.fails)-200:]
	}
	if b.fails >= maxFails {
		b.until = g.now().Add(banFor)
	}
}

func (g *guard) clear(ip string) {
	g.mu.Lock()
	delete(g.bans, ip)
	g.mu.Unlock()
}

func hashKey(v string) string { s := sha256.Sum256([]byte(v)); return string(s[:]) }

func (g *guard) newSession(user string, r *http.Request) string {
	tok := RandToken(32)
	g.mu.Lock()
	now := g.now()
	ua := r.UserAgent()
	if len(ua) > 160 {
		ua = ua[:160]
	}
	g.sessions[hashKey(tok)] = &session{User: user, IP: clientIP(r), Agent: ua, Created: now, Seen: now}
	g.saveLocked()
	g.mu.Unlock()
	return tok
}

func (g *guard) session(r *http.Request) *session {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	k := hashKey(c.Value)
	s := g.sessions[k]
	if s == nil {
		return nil
	}
	now := g.now()
	if now.Sub(s.Seen) > idleTimeout || now.Sub(s.Created) > absTimeout {
		delete(g.sessions, k)
		g.saveLocked()
		return nil
	}
	s.Seen = now
	if now.Sub(g.saved) > time.Minute {
		g.saveLocked()
	}
	return s
}

func (g *guard) drop(r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		g.mu.Lock()
		delete(g.sessions, hashKey(c.Value))
		g.saveLocked()
		g.mu.Unlock()
	}
}

func (g *guard) dropAll() {
	g.mu.Lock()
	g.sessions = map[string]*session{}
	g.saveLocked()
	g.mu.Unlock()
}

// sessionID is a short public handle of a session (the first 6 bytes of its key hash, hex): enough to tell
// sessions apart in Settings, useless as a cookie.
func sessionID(k string) string { return hex.EncodeToString([]byte(k)[:6]) }

type sessionView struct {
	ID      string    `json:"id"`
	IP      string    `json:"ip"`
	Agent   string    `json:"agent"`
	Created time.Time `json:"created"`
	Seen    time.Time `json:"seen"`
	Current bool      `json:"current"`
}

func (g *guard) list(r *http.Request) []sessionView {
	cur := ""
	if c, err := r.Cookie(cookieName); err == nil {
		cur = hashKey(c.Value)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	out := []sessionView{}
	for k, s := range g.sessions {
		out = append(out, sessionView{ID: sessionID(k), IP: s.IP, Agent: s.Agent, Created: s.Created, Seen: s.Seen, Current: k == cur})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seen.After(out[j].Seen) })
	return out
}

func (g *guard) dropID(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k := range g.sessions {
		if sessionID(k) == id {
			delete(g.sessions, k)
			g.saveLocked()
			return true
		}
	}
	return false
}

func (g *guard) newTicket(ip string) string {
	t := RandToken(24)
	g.mu.Lock()
	g.tickets[hashKey(t)] = &ticket{exp: g.now().Add(ticketTTL), ip: ip}
	g.mu.Unlock()
	return t
}

func (g *guard) takeTicket(t, ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := hashKey(t)
	tk := g.tickets[k]
	if tk == nil || tk.ip != ip || g.now().After(tk.exp) {
		return false
	}
	delete(g.tickets, k)
	return true
}

// checkPassword compares in constant time against the user name and bcrypt; a wrong user still pays one bcrypt so
// timing does not tell which part was wrong.
func checkPassword(c *Config, user, pass string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(c.User)) == 1
	err := bcrypt.CompareHashAndPassword([]byte(c.PassHash), []byte(pass))
	return userOK && err == nil
}

// useRecovery consumes a matching recovery code; it reports whether one matched.
func useRecovery(c *Config, code string) bool {
	code = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(code) != recoveryLen {
		return false
	}
	for i, h := range c.Recovery {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(code)) == nil {
			c.Recovery = append(c.Recovery[:i:i], c.Recovery[i+1:]...)
			return true
		}
	}
	return false
}

func setCookie(w http.ResponseWriter, path, val string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: val, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func (g *guard) recentFails(now time.Time, d time.Duration) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, t := range g.fails {
		if now.Sub(t) <= d {
			n++
		}
	}
	return n
}
