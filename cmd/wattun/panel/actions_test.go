package panel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const api = "/" + testPath + "/api/"

func signIn(t *testing.T, s *Server, code string) *http.Cookie {
	t.Helper()
	w := do(s, "POST", api+"login", `{"user":"owner","pass":"correct horse battery"}`, xr)
	if w.Code != 200 {
		t.Fatalf("login %d %s", w.Code, w.Body)
	}
	var j struct {
		Need2FA bool `json:"need2fa"`
		Ticket  string
	}
	json.Unmarshal(w.Body.Bytes(), &j)
	if j.Need2FA {
		w = do(s, "POST", api+"2fa", fmt.Sprintf(`{"ticket":%q,"code":%q}`, j.Ticket, code), xr)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatalf("no cookie: %d %s", w.Code, w.Body)
	return nil
}

// Every route is reachable only through the table; full routes refuse without 2FA, and a wrong code counts as a
// failed sign-in (features §9: a full-cap action without a fresh password + 2FA is refused even with a session).
func TestFullTierNeedsFreshPasswordAndCode(t *testing.T) {
	s, _ := newTestServer(t, "")
	ck := signIn(t, s, "")
	if w := do(s, "POST", api+"tunnels/t1/token", `{}`, xr, ck); w.Code != 403 || !strings.Contains(w.Body.String(), "need2fa") {
		t.Fatalf("no 2FA: %d %s", w.Code, w.Body)
	}
	sec := NewTOTPSecret()
	s2, _ := newTestServer(t, sec)
	ck = signIn(t, s2, codeAt(sec, time.Now()))
	if w := do(s2, "POST", api+"tunnels/t1/token", `{"password":"correct horse battery","code":"000000"}`, xr, ck); w.Code != 403 || !strings.Contains(w.Body.String(), "reauth") {
		t.Fatalf("wrong code: %d %s", w.Code, w.Body)
	}
	if n := s2.g.recentFails(time.Now(), time.Minute); n != 1 {
		t.Fatalf("a failed re-auth must count toward the ban, got %d", n)
	}
	body := fmt.Sprintf(`{"password":"correct horse battery","code":%q}`, codeAt(sec, time.Now().Add(30*time.Second)))
	if w := do(s2, "POST", api+"tunnels/t1/token", body, xr, ck); w.Code != 200 || !strings.Contains(w.Body.String(), "wat1:abc") {
		t.Fatalf("good re-auth: %d %s", w.Code, w.Body)
	}
	// the same code again is a replay
	if w := do(s2, "POST", api+"tunnels/t1/token", body, xr, ck); w.Code != 403 {
		t.Fatalf("replayed code: %d", w.Code)
	}
}

func codeAt(sec string, at time.Time) string { c, _ := totpAt(sec, at.Unix()/30); return c }

func TestRouteTable(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range routes {
		k := r.method + " " + r.pattern
		if seen[k] || r.h == nil {
			t.Fatalf("duplicate or empty route %s", k)
		}
		seen[k] = true
		if r.method != "GET" && r.method != "POST" && r.method != "PUT" {
			t.Fatalf("method %s", k)
		}
		if r.tier == tierFull && r.method == "GET" {
			t.Fatalf("%s: a full route needs a body for the password and code", k)
		}
	}
	for _, must := range []string{"POST tunnels/*/delete", "POST kharej/*/update", "POST kharej/*/backup", "POST restore", "POST update"} {
		found := false
		for _, r := range routes {
			if r.method+" "+r.pattern == must && r.tier == tierFull {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s must be full tier", must)
		}
	}
}

func TestLastLinkGuard(t *testing.T) {
	fakePaired, fakeCalls = true, nil
	fakeKharej = []Kharej{{Host: "1.2.3.4", Via: []string{"t1"}, Online: true}}
	defer func() { fakePaired, fakeKharej = false, nil }()
	s, _ := newTestServer(t, "")
	s.kh = fakeKharej
	ck := signIn(t, s, "")
	w := do(s, "POST", api+"tunnels/t1/stop", `{}`, xr, ck)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "last link") || len(fakeCalls) != 0 {
		t.Fatalf("stop without the name: %d %s %v", w.Code, w.Body, fakeCalls)
	}
	if w := do(s, "POST", api+"bulk", `{"action":"stop"}`, xr, ck); w.Code != 409 {
		t.Fatalf("bulk stop: %d", w.Code)
	}
	if w := do(s, "POST", api+"tunnels/t1/stop", `{"confirm":"t1"}`, xr, ck); w.Code != 200 || fakeCalls[0] != "stop t1" {
		t.Fatalf("stop with the name: %d %v", w.Code, fakeCalls)
	}
	if w := do(s, "POST", api+"tunnels/t1/restart", `{}`, xr, ck); w.Code != 200 {
		t.Fatalf("restart is not guarded: %d", w.Code)
	}
}

// A job started before a panel restart shows its end state after it (features §9).
func TestJobSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	j := newJobs(dir)
	id, err := j.do("x", "test", "u", func(say func(string, ...any)) error { say("TUNNEL=a1"); return nil })
	if err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if v, _ := j.get(id); v.State != "running" {
			break
		}
	}
	v, ok := newJobs(dir).get(id) // a fresh panel process
	if !ok || v.State != "done" || v.Result["TUNNEL"] != "a1" {
		t.Fatalf("%+v", v)
	}
	if _, ok := j.get("../../etc/passwd"); ok {
		t.Fatal("job id path trick")
	}
}

func TestSessionsSurviveRestart(t *testing.T) {
	s, c := newTestServer(t, "")
	ck := signIn(t, s, "")
	s2 := New(c, fakeBE{}, s.dataDir)
	if w := do(s2, "GET", api+"me", "", nil, ck); w.Code != 200 {
		t.Fatalf("after restart: %d", w.Code)
	}
	b, _ := os.ReadFile(filepath.Join(s.dataDir, "sessions"))
	if strings.Contains(string(b), ck.Value) {
		t.Fatal("the session file holds a raw cookie")
	}
}

func TestAllowlist(t *testing.T) {
	s, c := newTestServer(t, "")
	c.Allow = []string{"198.51.100.0/24"}
	if w := do(s, "GET", "/"+testPath+"/", "", nil); w.Code != 404 {
		t.Fatalf("outside the list: %d", w.Code)
	}
	c.Allow = []string{"203.0.113.0/24"}
	if w := do(s, "GET", "/"+testPath+"/", "", nil); w.Code != 200 {
		t.Fatalf("inside the list: %d", w.Code)
	}
}

func tgz(t *testing.T, names ...string) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	tw := tar.NewWriter(zw)
	for _, n := range names {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
		tw.Write([]byte("x"))
	}
	tw.Close()
	zw.Close()
	return b.Bytes()
}

func TestRestoreArchiveChecks(t *testing.T) {
	if _, top, err := tarList(tgz(t, "wattun/a.yml", "wattun/a.key")); err != nil || top != "wattun" {
		t.Fatalf("good archive: %v %q", err, top)
	}
	for _, bad := range [][]string{{"../x"}, {"/etc/x"}, {"wattun/a", "systemd/b"}, {"wattun/../../x"}} {
		if _, _, err := tarList(tgz(t, bad...)); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
}

func TestTrafficRollup(t *testing.T) {
	tr := newTraffic(t.TempDir())
	h := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	tr.add("a", 100, 10, h.Add(time.Minute))
	tr.add("a", 50, 5, h.Add(2*time.Minute))
	tr.add("a", 7, 1, h.Add(time.Hour+time.Second)) // closes 10:00
	rows := tr.rows(0)
	var d float64
	for _, r := range rows {
		d += r.D
	}
	if len(rows) != 2 || d != 157 {
		t.Fatalf("%+v", rows)
	}
}

// The private CA may only vouch for this server's IPs (plan D5 tier 4).
func TestPrivateCANameConstraint(t *testing.T) {
	dir := t.TempDir()
	c := &Config{Title: "box", file: filepath.Join(dir, "panel.conf")}
	ip := net.ParseIP("203.0.113.7")
	if err := usePrivateCA(c, []net.IP{ip}); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	cab, _ := os.ReadFile(caFile(c))
	pool.AppendCertsFromPEM(cab)
	lb, _ := os.ReadFile(c.CertFile)
	blk, _ := pem.Decode(lb)
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("own leaf: %v", err)
	}
	// a leaf for another address, signed by the same CA, must not verify
	cb, _ := pem.Decode(cab)
	ca, _ := x509.ParseCertificate(cb.Bytes)
	kb, _ := os.ReadFile(filepath.Join(dir, ".panel-ca.key"))
	kblk, _ := pem.Decode(kb)
	caKey, _ := x509.ParseECPrivateKey(kblk.Bytes)
	k, _, _ := newKey()
	tpl := &x509.Certificate{SerialNumber: serial(), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("8.8.8.8")}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, caKey)
	other, _ := x509.ParseCertificate(der)
	if _, err := other.Verify(x509.VerifyOptions{Roots: pool}); err == nil {
		t.Fatal("the CA vouched for another address")
	}
	if strings.Contains(strings.ToLower(ca.Subject.CommonName), "wattun") {
		t.Fatal("product name in the CA")
	}
}

func TestOwnerCertRejectsMismatch(t *testing.T) {
	dir := t.TempDir()
	c := &Config{Title: "box", file: filepath.Join(dir, "panel.conf")}
	if err := useOwnerCert(c, []byte("junk"), []byte("junk")); err == nil {
		t.Fatal("junk accepted")
	}
	if c.CertKind == "owner" {
		t.Fatal("config changed on failure")
	}
}

func TestSpeedMBTakesStringOrNumber(t *testing.T) {
	for body, want := range map[string]int{`{"mb":"100"}`: 100, `{"mb":250}`: 250, `{"mb":"x"}`: 10, `{}`: 10, `{"mb":9000}`: 10} {
		if got := speedMB([]byte(body)); got != want {
			t.Errorf("%s: got %d, want %d", body, got, want)
		}
	}
}
