package panel

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type fakeBE struct{}

func (fakeBE) Host() Host { return Host{Name: "box", Version: "x"} }
func (fakeBE) Tunnels() []Tunnel {
	return []Tunnel{{Name: "t1", Role: "Iran", Active: true, Enabled: true, Ports: []string{"443"}}}
}
func (fakeBE) Stats(string) (Counters, bool) { return Counters{Alive: true, BytesIn: 1000}, true }
func (fakeBE) History(string) []byte         { return []byte(`[]`) }
func (fakeBE) Logs(string, int) []string     { return []string{"a"} }
func (fakeBE) Kharej() []Kharej              { return nil }

const testPath = "s3cretpathXYZabc"

func newTestServer(t *testing.T, totp string) (*Server, *Config) {
	t.Helper()
	dir := t.TempDir()
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	c := &Config{Port: 1234, Path: testPath, Title: "box", User: "owner", PassHash: h, TOTP: totp}
	if err := c.SaveAs(filepath.Join(dir, "panel.conf")); err != nil {
		t.Fatal(err)
	}
	c, err = LoadConfig(filepath.Join(dir, "panel.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return New(c, fakeBE{}, dir), c
}

func do(s *Server, method, path, body string, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.9:5555"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

var xr = map[string]string{"X-Requested-With": "panel"}

func TestTOTPRFC6238(t *testing.T) {
	sec := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		got, _ := totpAt(sec, ts/30)
		if got != want {
			t.Errorf("t=%d: got %s want %s", ts, got, want)
		}
	}
	now := time.Unix(1234567890, 0)
	step, ok := VerifyTOTP(sec, "005924", now, 0)
	if !ok {
		t.Fatal("current code refused")
	}
	if _, ok := VerifyTOTP(sec, "005924", now, step); ok {
		t.Fatal("replayed code accepted")
	}
	prev, _ := totpAt(sec, now.Unix()/30-1)
	if _, ok := VerifyTOTP(sec, prev, now, 0); !ok {
		t.Fatal("-1 step refused")
	}
	old, _ := totpAt(sec, now.Unix()/30-2)
	if _, ok := VerifyTOTP(sec, old, now, 0); ok {
		t.Fatal("-2 steps accepted")
	}
}

func TestOutsideSecretIsNginx404(t *testing.T) {
	s, _ := newTestServer(t, "")
	var ref []byte
	for _, m := range []string{"GET", "POST", "PUT"} {
		for _, p := range []string{"/", "/favicon.ico", "/login", "/robots.txt", "/" + testPath + "x/", "/api/me"} {
			w := do(s, m, p, "", nil)
			if w.Code != 404 || w.Header().Get("Server") != "nginx/1.18.0 (Ubuntu)" || w.Body.String() != nginx404 {
				t.Fatalf("%s %s: %d %q", m, p, w.Code, w.Header())
			}
			if len(w.Header()) != 3 {
				t.Fatalf("%s %s: extra headers %v", m, p, w.Header())
			}
			if ref == nil {
				ref = w.Body.Bytes()
			}
		}
	}
	if w := do(s, "HEAD", "/", "", nil); w.Code != 404 || w.Body.Len() != 0 {
		t.Fatal("HEAD")
	}
}

func TestNoFingerprintBeforeLogin(t *testing.T) {
	s, _ := newTestServer(t, "")
	re := regexp.MustCompile(`(?i)wat ?tun`)
	for _, p := range []string{"/", "/" + testPath + "/", "/" + testPath + "/app.js", "/" + testPath + "/app.css", "/" + testPath + "/api/me"} {
		w := do(s, "GET", p, "", nil)
		hdr, _ := json.Marshal(w.Header())
		if re.Match(w.Body.Bytes()) || re.Match(hdr) {
			t.Errorf("%s names the product", p)
		}
		if strings.HasPrefix(p, "/"+testPath) && w.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("%s: no CSP", p)
		}
	}
}

func TestEmbeddedAssetsAreSelfContained(t *testing.T) {
	ext := regexp.MustCompile(`https?://`)
	inline := regexp.MustCompile(`<script>|<script [^>]*>[^<]|\sstyle="|<style`)
	fs.WalkDir(webFS, "web", func(p string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		b, _ := fs.ReadFile(webFS, p)
		for _, m := range ext.FindAllIndex(b, -1) {
			// the only URL allowed is the SVG namespace in strings the page builds
			if !bytes.HasPrefix(b[m[0]:], []byte("http://www.w3.org/2000/svg")) {
				t.Errorf("%s: external URL at %d: %q", p, m[0], b[m[0]:min(len(b), m[0]+60)])
			}
		}
		if strings.HasSuffix(p, ".html") && inline.Match(b) {
			t.Errorf("%s: inline script or style breaks the CSP", p)
		}
		return nil
	})
}

func TestLoginBanAndSession(t *testing.T) {
	s, _ := newTestServer(t, "")
	api := "/" + testPath + "/api/"
	if w := do(s, "POST", api+"login", `{"user":"owner","pass":"x"}`, nil); w.Code != 403 {
		t.Fatalf("no X-Requested-With: %d", w.Code)
	}
	if w := do(s, "GET", api+"overview", "", nil); w.Code != 401 {
		t.Fatalf("overview without session: %d", w.Code)
	}
	w := do(s, "POST", api+"login", `{"user":"owner","pass":"correct horse battery"}`, xr)
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	ck := w.Result().Cookies()
	if len(ck) != 1 || !ck[0].HttpOnly || !ck[0].Secure || ck[0].SameSite != http.SameSiteStrictMode || ck[0].Path != "/"+testPath+"/" {
		t.Fatalf("cookie %+v", ck)
	}
	if w := do(s, "GET", api+"overview", "", nil, ck[0]); w.Code != 200 {
		t.Fatalf("overview: %d", w.Code)
	}
	if w := do(s, "POST", api+"logout", "", nil, ck[0]); w.Code != 403 {
		t.Fatalf("state change without header: %d", w.Code)
	}
	for i := 0; i < maxFails; i++ {
		do(s, "POST", api+"login", `{"user":"owner","pass":"wrong"}`, xr)
	}
	w = do(s, "POST", api+"login", `{"user":"owner","pass":"correct horse battery"}`, xr)
	if w.Code != 404 || w.Body.String() != nginx404 {
		t.Fatalf("banned address got %d", w.Code)
	}
	s.g.now = func() time.Time { return time.Now().Add(banFor + time.Minute) }
	if w := do(s, "POST", api+"login", `{"user":"owner","pass":"correct horse battery"}`, xr); w.Code != 200 {
		t.Fatalf("after the ban: %d", w.Code)
	}
}

func TestLoginWith2FAAndRecovery(t *testing.T) {
	sec := NewTOTPSecret()
	s, c := newTestServer(t, sec)
	plain, hashed := NewRecoveryCodes()
	c.Recovery = hashed
	api := "/" + testPath + "/api/"
	step1 := func() string {
		w := do(s, "POST", api+"login", `{"user":"owner","pass":"correct horse battery"}`, xr)
		var r struct {
			Need2FA bool `json:"need2fa"`
			Ticket  string
		}
		json.Unmarshal(w.Body.Bytes(), &r)
		if !r.Need2FA || r.Ticket == "" || len(w.Result().Cookies()) != 0 {
			t.Fatalf("password alone must not sign in: %s", w.Body)
		}
		return r.Ticket
	}
	code, _ := totpAt(sec, time.Now().Unix()/30)
	tk := step1()
	if w := do(s, "POST", api+"2fa", `{"ticket":"`+tk+`","code":"`+code+`"}`, xr); w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("2fa: %d %s", w.Code, w.Body)
	}
	if w := do(s, "POST", api+"2fa", `{"ticket":"`+tk+`","code":"`+code+`"}`, xr); w.Code != 401 {
		t.Fatal("ticket reused")
	}
	if w := do(s, "POST", api+"2fa", `{"ticket":"`+step1()+`","code":"`+code+`"}`, xr); w.Code != 401 {
		t.Fatal("code replayed")
	}
	if w := do(s, "POST", api+"2fa", `{"ticket":"`+step1()+`","code":"`+plain[0]+`"}`, xr); w.Code != 200 {
		t.Fatalf("recovery code: %d", w.Code)
	}
	if w := do(s, "POST", api+"2fa", `{"ticket":"`+step1()+`","code":"`+plain[0]+`"}`, xr); w.Code != 401 {
		t.Fatal("recovery code worked twice")
	}
	saved, err := LoadConfig(c.file)
	if err != nil || len(saved.Recovery) != recoveryKeep-1 || saved.TOTPLast == 0 {
		t.Fatalf("not persisted: %v %d %d", err, len(saved.Recovery), saved.TOTPLast)
	}
}

func TestQRShape(t *testing.T) {
	for n, want := range map[int]int{2: 21, 50: 33, 130: 49, 300: 69, 400: 77} {
		q, err := EncodeQR(strings.Repeat("a", n))
		if err != nil || len(q) != want {
			t.Fatalf("%d bytes: size %d err %v", n, len(q), err)
		}
		// finder pattern corners and the always-dark module
		if !q[0][0] || !q[0][6] || q[1][1] || !q[3][3] || !q[want-8][8] {
			t.Fatalf("%d bytes: finder/dark module wrong", n)
		}
	}
	if _, err := EncodeQR(strings.Repeat("a", 500)); err == nil {
		t.Fatal("too long accepted")
	}
}

func TestWatchdog(t *testing.T) {
	w := newWatchdog(filepath.Join(t.TempDir(), "o.jsonl"))
	t0 := time.Unix(1_700_000_000, 0)
	w.observe("a", true, true, t0.Add(-3*time.Hour))
	w.observe("a", true, false, t0.Add(-2*time.Hour))
	w.observe("a", true, true, t0.Add(-2*time.Hour+30*time.Minute))
	w.observe("a", false, false, t0.Add(-time.Hour)) // stopped by hand: not an outage
	w.observe("a", true, false, t0.Add(-10*time.Minute))
	s := w.summary([]string{"a"}, t0)[0]
	if s.Outages != 2 || s.Longest != 1800 || s.Ongoing == 0 {
		t.Fatalf("%+v", s)
	}
	if s.Hours[20] != 0 || s.Hours[21] != 1 || s.Hours[22] != 3 || s.Hours[23] != 2 {
		t.Fatalf("hours %v", s.Hours)
	}
	b, _ := io.ReadAll(must(t, w.file))
	if strings.Count(string(b), "\n") != 1 {
		t.Fatalf("closed outages on disk: %q", b)
	}
}

func must(t *testing.T, f string) io.Reader {
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}
