package panel

// The rest of the plan: per-port usage and quota reset, pairing rotate/forget, delete on Kharej too, the panel
// port change, passphrase-encrypted backups, the restore preview, and the quota / update / speed-drop alerts.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// ---- per-port usage ----

func (s *Server) apiTunnelPorts(c *call) {
	if _, ok := s.tunnel(c.arg[0]); !ok {
		c.fail(http.StatusNotFound, "no such tunnel")
		return
	}
	p := s.be.Ports(c.arg[0])
	if p == nil {
		p = []PortUse{}
	}
	c.ok(map[string]any{"ports": p})
}

func (s *Server) apiQuotaReset(c *call) {
	var in struct{ Port int }
	if c.json(&in) != nil || in.Port <= 0 || in.Port > 65535 {
		c.fail(http.StatusBadRequest, "port is needed")
		return
	}
	err := s.be.QuotaReset(c.arg[0], in.Port)
	s.audit(c, "quota reset", c.arg[0]+":"+strconv.Itoa(in.Port), errText(err))
	if err != nil {
		c.fail(http.StatusBadGateway, err.Error())
		return
	}
	c.ok(map[string]bool{"ok": true})
}

// ---- pairing ----

// apiPairForget turns a local tunnel's pairing channel off. It is the last link when no other paired tunnel runs
// to that Kharej, so the same typed-name guard applies.
func (s *Server) apiPairForget(c *call) {
	var in struct{ Confirm string }
	c.json(&in)
	name := c.arg[0]
	t, ok := s.tunnel(name)
	if !ok || !t.Paired {
		c.fail(http.StatusBadRequest, "That tunnel is not paired.")
		return
	}
	if !s.guardLast(c, name, in.Confirm) {
		return
	}
	err := s.be.PairForget(name)
	s.audit(c, "pairing forget", name, errText(err))
	if err != nil {
		c.fail(http.StatusInternalServerError, err.Error())
		return
	}
	s.refreshKharej()
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) apiPairRotate(c *call) {
	var via []string
	for _, k := range s.kharejSnap() {
		if k.Host == c.arg[0] {
			via = k.Via
		}
	}
	if len(via) == 0 {
		c.fail(http.StatusNotFound, "no such Kharej server")
		return
	}
	if _, ok := s.via(c, c.arg[0]); !ok {
		return
	}
	err := s.be.PairRotate(via)
	s.audit(c, "pairing rotate", c.arg[0], errText(err))
	if err != nil {
		c.fail(http.StatusBadGateway, err.Error())
		return
	}
	s.refreshKharej()
	c.ok(map[string]any{"ok": true, "tunnels": via})
}

// apiKharejDelete deletes one tunnel on Kharej (tunnel.delete with the name typed back, as the cockpit does).
func (s *Server) apiKharejDelete(c *call) {
	var in struct{ Name, Confirm string }
	if c.json(&in) != nil || !nameRe.MatchString(in.Name) {
		c.fail(http.StatusBadRequest, "name is needed")
		return
	}
	if in.Confirm != in.Name {
		c.fail(http.StatusBadRequest, "Type the tunnel's name to delete it on Kharej.")
		return
	}
	if err := s.kharejDelete(c, c.arg[0], in.Name); err == nil {
		c.ok(map[string]bool{"ok": true})
	}
}

func (s *Server) kharejDelete(c *call, host, name string) error {
	if _, ok := s.kharejDo(c, "kharej delete", host+"/"+name, "tunnel.delete", map[string]any{"name": name, "confirm": name}); !ok {
		return errors.New("refused")
	}
	s.audit(c, "kharej delete", host+"/"+name, "ok")
	s.refreshKharej()
	return nil
}

// kharejWith is the one Kharej that has a tunnel called NAME ("" = none, or more than one): the Kharej half of a
// tunnel here that is not paired, which the panel made with the same name on both sides.
func (s *Server) kharejWith(name string) string {
	host := ""
	for _, k := range s.kharejSnap() {
		for _, t := range k.Tunnels {
			if t.Name == name {
				if host != "" && host != k.Host {
					return ""
				}
				host = k.Host
			}
		}
	}
	return host
}

// hostOf is the Kharej host a local tunnel is paired with ("" = none).
func (s *Server) hostOf(name string) string {
	for _, k := range s.kharejSnap() {
		for _, v := range k.Via {
			if v == name {
				return k.Host
			}
		}
	}
	return ""
}

// ---- panel port ----

// commonPorts are never offered or accepted: the panel stays off every port a scanner or another panel expects.
var commonPorts = map[int]bool{2052: true, 2053: true, 2082: true, 2083: true, 2086: true, 2087: true, 2095: true,
	2096: true, 8080: true, 8443: true, 8880: true, 10000: true, 54321: true}

func portFree(p int) bool {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func randomPort() int {
	for i := 0; i < 200; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(40000))
		if p := 20000 + int(n.Int64()); !commonPorts[p] && portFree(p) {
			return p
		}
	}
	return 0
}

func (s *Server) apiRandomPort(c *call) { c.ok(map[string]int{"port": randomPort()}) }

// checkPort refuses a port the panel must not use; P is the panel's own current port (always fine).
func checkPort(p, cur int) error {
	switch {
	case p == cur:
		return nil
	case p < 10000 || p > 65535 || commonPorts[p]:
		return errors.New("Pick a port from 10000 to 65535 that no other panel or service uses (the random one is safest).")
	case !portFree(p):
		return fmt.Errorf("Port %d is in use on this server.", p)
	}
	return nil
}

// movePanel is called after a port change answered: firewall for the new port, then the restart; the old port
// closes once the new process listens.
func (s *Server) movePanel(old, new int) {
	go func() {
		s.be.PanelFirewall(new, 0)
		time.Sleep(1500 * time.Millisecond)
		s.be.RestartSelf()
		time.Sleep(3 * time.Second)
		s.be.PanelFirewall(0, old)
	}()
}

// ---- encrypted backups ----

var bkMagic = []byte("WATBK1\x00")

// sealBackup encrypts RAW under a passphrase: scrypt(N=32768) key, XChaCha20-Poly1305.
func sealBackup(raw []byte, pass string) ([]byte, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	key, err := scrypt.Key([]byte(pass), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	rand.Read(nonce)
	out := append(append(append([]byte{}, bkMagic...), salt...), nonce...)
	return a.Seal(out, nonce, raw, bkMagic), nil
}

var errNeedPass = errors.New("This backup is encrypted: give its passphrase.")

// openBackup decrypts a sealed backup, or returns RAW as it is when it is not sealed.
func openBackup(raw []byte, pass string) ([]byte, error) {
	if !bytes.HasPrefix(raw, bkMagic) {
		return raw, nil
	}
	if pass == "" {
		return nil, errNeedPass
	}
	b := raw[len(bkMagic):]
	if len(b) < 16+24+16 {
		return nil, errors.New("the encrypted backup is cut short")
	}
	key, err := scrypt.Key([]byte(pass), b[:16], 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	a, _ := chacha20poly1305.NewX(key)
	out, err := a.Open(nil, b[16:40], b[40:], bkMagic)
	if err != nil {
		return nil, errors.New("Wrong passphrase, or the file is damaged.")
	}
	return out, nil
}

// sendBackup answers a download, sealed when the request carries a passphrase (at least 10 characters).
func sendBackup(c *call, name, ctype string, raw []byte) {
	var in struct{ Passphrase string }
	c.json(&in)
	if in.Passphrase != "" {
		if len(in.Passphrase) < 10 {
			c.fail(http.StatusBadRequest, "The passphrase needs at least 10 characters.")
			return
		}
		b, err := sealBackup(raw, in.Passphrase)
		if err != nil {
			c.fail(http.StatusInternalServerError, err.Error())
			return
		}
		attach(c.w, name+".wbk", "application/octet-stream", b)
		return
	}
	attach(c.w, name, ctype, raw)
}

// ---- restore preview ----

type fileDiff struct {
	File   string     `json:"file"`
	Status string     `json:"status"` // new | changed | same | secret (a key or token: content not shown)
	Diff   []diffLine `json:"diff,omitempty"`
}

type diffLine struct {
	Op   string `json:"op"` // " " "+" "-"
	Text string `json:"text"`
}

func tarRead(raw []byte) (map[string][]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	total := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return nil, err
		}
		if total += len(b); total > 32<<20 {
			return nil, errors.New("too big")
		}
		out[path.Clean(h.Name)] = b
	}
}

// secretFile: keys, tokens, pairing credentials and the panel's own secrets never leave as text.
func secretFile(n string) bool {
	b := path.Base(n)
	for _, suf := range []string{".key", ".token", ".pairing", ".crt", ".pem", "panel.conf"} {
		if strings.HasSuffix(b, suf) {
			return true
		}
	}
	return strings.Contains(b, "pairing") || strings.Contains(b, "secret")
}

// maskLine hides a config value that looks like a credential (key:, psk:, password: ...).
func maskLine(l string) string {
	k, _, ok := strings.Cut(l, ":")
	lk := strings.ToLower(strings.TrimSpace(k))
	if ok && (strings.Contains(lk, "key") || strings.Contains(lk, "psk") || strings.Contains(lk, "pass") || strings.Contains(lk, "secret") || lk == "pairing") {
		return k + ": ••••"
	}
	return l
}

// lineDiff is a plain LCS diff (config files are small).
func lineDiff(a, b []string) []diffLine {
	n, m := len(a), len(b)
	if n*m > 4_000_000 {
		return []diffLine{{Op: " ", Text: "(too large to compare)"}}
	}
	t := make([][]int, n+1)
	for i := range t {
		t[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				t[i][j] = t[i+1][j+1] + 1
			} else {
				t[i][j] = max(t[i+1][j], t[i][j+1])
			}
		}
	}
	var out []diffLine
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			out = append(out, diffLine{" ", a[i]})
			i, j = i+1, j+1
		case j < m && (i == n || t[i][j+1] >= t[i+1][j]):
			out = append(out, diffLine{"+", b[j]})
			j++
		default:
			out = append(out, diffLine{"-", a[i]})
			i++
		}
	}
	return out
}

func splitLines(b []byte) []string {
	s := strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	if s == "" {
		return nil
	}
	l := strings.Split(s, "\n")
	for i := range l {
		l[i] = maskLine(l[i])
	}
	return l
}

// preview compares an archive with the config directory it would be written over.
func preview(files map[string][]byte, dir string) ([]fileDiff, []string) {
	var out []fileDiff
	inArchive := map[string]bool{}
	for n, b := range files {
		_, rel, _ := strings.Cut(n, "/")
		if rel == "" {
			continue
		}
		inArchive[rel] = true
		cur, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		d := fileDiff{File: rel}
		switch {
		case err != nil:
			d.Status = "new"
		case bytes.Equal(cur, b):
			d.Status = "same"
		default:
			d.Status = "changed"
		}
		if secretFile(rel) {
			if d.Status == "changed" {
				d.Status = "secret"
			}
		} else if d.Status != "same" {
			d.Diff = lineDiff(splitLines(cur), splitLines(b))
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	var kept []string
	m, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	for _, f := range m {
		if !inArchive[filepath.Base(f)] {
			kept = append(kept, filepath.Base(f))
		}
	}
	return out, kept
}

// backupInput decodes an uploaded backup: base64, then the passphrase when it is sealed, then the archive checks.
func (s *Server) backupInput(c *call) ([]byte, []string, bool) {
	var in struct{ Data, Passphrase string }
	if c.json(&in) != nil {
		c.fail(http.StatusBadRequest, "bad request")
		return nil, nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(in.Data)
	if err != nil || len(raw) == 0 {
		c.fail(http.StatusBadRequest, "The file did not arrive whole.")
		return nil, nil, false
	}
	if raw, err = openBackup(raw, in.Passphrase); err != nil {
		c.fail(http.StatusBadRequest, err.Error())
		return nil, nil, false
	}
	files, top, err := tarList(raw)
	if err == nil && top != filepath.Base(confDir(s.conf())) {
		err = fmt.Errorf("it holds %q, this server keeps its settings in %q", top, filepath.Base(confDir(s.conf())))
	}
	if err != nil {
		c.fail(http.StatusBadRequest, "That is not a backup of this kind: "+err.Error())
		return nil, nil, false
	}
	return raw, files, true
}

func (s *Server) apiRestorePreview(c *call) {
	raw, _, ok := s.backupInput(c)
	if !ok {
		return
	}
	files, err := tarRead(raw)
	if err != nil {
		c.fail(http.StatusBadRequest, err.Error())
		return
	}
	diff, kept := preview(files, s.cfgDirOfTunnels())
	c.ok(map[string]any{"files": diff, "kept": nonNil(kept)})
}

// cfgDirOfTunnels is where the tunnel configs live: the panel's own conf sits in the same directory.
func (s *Server) cfgDirOfTunnels() string { return confDir(s.conf()) }

// ---- quota, update and speed-drop alerts ----

type versionCache struct {
	mu     sync.Mutex
	latest string
	at     time.Time
}

func (s *Server) latestVersion() string {
	s.ver.mu.Lock()
	defer s.ver.mu.Unlock()
	return s.ver.latest
}

// noteLatest keeps v as the newest known release when it is newer than the one known: a Kharej that already
// updated itself marks this server behind even when GitHub is slow or unreachable from here.
func (s *Server) noteLatest(v string) {
	s.ver.mu.Lock()
	defer s.ver.mu.Unlock()
	if v != "" && (s.ver.latest == "" || newer(v, s.ver.latest)) {
		s.ver.latest = v
	}
}

// refreshLatest asks GitHub now (restarting the 6-hour timer) and takes any newer version a Kharej runs.
func (s *Server) refreshLatest(now time.Time) string {
	s.ver.mu.Lock()
	s.ver.at = now
	s.ver.mu.Unlock()
	s.noteLatest(s.be.LatestVersion())
	for _, k := range s.kharejSnap() {
		s.noteLatest(k.Version)
	}
	return s.latestVersion()
}

// newer reports a > b for dotted versions ("3.6.10" > "3.6.9").
func newer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// slowChecks runs once a minute from the scheduler: quota use per port, and (every 6 h) the release check.
func (s *Server) slowChecks(now time.Time) {
	seen := map[string]bool{}
	for _, t := range s.be.Tunnels() {
		if !t.Active {
			continue
		}
		for _, p := range s.be.Ports(t.Name) {
			if p.QuotaLimit <= 0 {
				continue
			}
			k := "quota:" + t.Name + ":" + p.Port
			seen[k] = true
			pct := p.QuotaUsed * 100 / p.QuotaLimit
			text := fmt.Sprintf("Port %s of %s used %.0f%% of its quota", p.Port, t.Name, pct)
			if p.Exceeded {
				text = fmt.Sprintf("Port %s of %s is over its quota and refuses users", p.Port, t.Name)
			}
			s.al.set(k, "quota", text, p.Exceeded || pct >= 90, 0, now)
		}
	}
	s.al.keep("quota:", seen, now)

	s.ver.mu.Lock()
	due := now.Sub(s.ver.at) >= 6*time.Hour
	s.ver.mu.Unlock()
	if due {
		s.refreshLatest(now)
	}
	for _, k := range s.kharejSnap() {
		s.noteLatest(k.Version)
	}
	latest := s.latestVersion()
	here := s.hostCached(now).Version
	s.al.set("update", "update", "Version "+latest+" is out (this server runs "+here+")", latest != "" && newer(latest, here), 0, now)
	kseen := map[string]bool{}
	for _, k := range s.kharejSnap() {
		key := "update:" + k.Host
		kseen[key] = true
		s.al.set(key, "update", "Version "+latest+" is out ("+k.Host+" runs "+k.Version+")", latest != "" && k.Version != "" && newer(latest, k.Version), 0, now)
	}
	s.al.keep("update:", kseen, now)
}

// speedCheck raises "speed:NAME" when a scheduled test runs at under half the median of the 5 before it.
func (s *Server) speedCheck(name string, down float64, now time.Time) {
	var prev []float64
	readJSONL(filepath.Join(s.dataDir, "speedtests.jsonl"), func(b []byte) {
		var r speedRun
		if json.Unmarshal(b, &r) == nil && r.Name == name && r.Auto && r.Down > 0 {
			prev = append(prev, r.Down)
		}
	})
	if len(prev) > 0 {
		prev = prev[:len(prev)-1] // the run just written
	}
	if len(prev) > 5 {
		prev = prev[len(prev)-5:]
	}
	if len(prev) < 3 {
		return
	}
	sort.Float64s(prev)
	med := prev[len(prev)/2]
	s.al.set("speed:"+name, "speed", fmt.Sprintf("%s ran at %.1f MB/s, under half its usual %.1f MB/s", name, down, med), down < med/2, 0, now)
}
