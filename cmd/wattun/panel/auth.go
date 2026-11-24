package panel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
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
	user          string
	created, seen time.Time
}

type ticket struct {
	exp time.Time
	ip  string
}

type ban struct {
	fails int
	until time.Time
}

// guard holds the in-memory auth state. shortcut: sessions live in memory, so a panel restart (an update) signs
// everyone out; move them to /var/lib/wattun/panel/sessions when phase 2 adds self-update jobs.
type guard struct {
	mu       sync.Mutex
	sessions map[string]*session // key: sha256 of the cookie value
	tickets  map[string]*ticket  // password ok, waiting for the 2FA code
	bans     map[string]*ban
	now      func() time.Time
}

func newGuard() *guard {
	return &guard{sessions: map[string]*session{}, tickets: map[string]*ticket{}, bans: map[string]*ban{}, now: time.Now}
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

func (g *guard) newSession(user string) string {
	tok := RandToken(32)
	g.mu.Lock()
	now := g.now()
	g.sessions[hashKey(tok)] = &session{user: user, created: now, seen: now}
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
	if now.Sub(s.seen) > idleTimeout || now.Sub(s.created) > absTimeout {
		delete(g.sessions, k)
		return nil
	}
	s.seen = now
	return s
}

func (g *guard) drop(r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		g.mu.Lock()
		delete(g.sessions, hashKey(c.Value))
		g.mu.Unlock()
	}
}

func (g *guard) dropAll() {
	g.mu.Lock()
	g.sessions = map[string]*session{}
	g.mu.Unlock()
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
