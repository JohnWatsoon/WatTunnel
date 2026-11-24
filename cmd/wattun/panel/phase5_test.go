package panel

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupSealRoundTrip(t *testing.T) {
	raw := tgz(t, "wattun/a.yml")
	sealed, err := sealBackup(raw, "correct horse battery")
	if err != nil || bytes.Contains(sealed, raw[10:]) {
		t.Fatalf("seal: %v", err)
	}
	if _, err := openBackup(sealed, ""); err != errNeedPass {
		t.Fatalf("no passphrase: %v", err)
	}
	if _, err := openBackup(sealed, "wrong passphrase!"); err == nil {
		t.Fatal("wrong passphrase opened it")
	}
	if got, err := openBackup(sealed, "correct horse battery"); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("open: %v", err)
	}
	if got, _ := openBackup(raw, ""); !bytes.Equal(got, raw) {
		t.Fatal("a plain backup must pass through")
	}
}

func TestRestorePreviewMasksSecrets(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yml"), []byte("mode: client\npeer: 1.2.3.4:443\nkey: OLDSECRET\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "a.key"), []byte("old"), 0o600)
	os.WriteFile(filepath.Join(dir, "b.yml"), []byte("mode: client\n"), 0o600)
	files := map[string][]byte{
		"wattun/a.yml": []byte("mode: client\npeer: 5.6.7.8:443\nkey: NEWSECRET\n"),
		"wattun/a.key": []byte("new"),
		"wattun/c.yml": []byte("mode: server\n"),
	}
	diff, kept := preview(files, dir)
	got := map[string]fileDiff{}
	for _, d := range diff {
		got[d.File] = d
	}
	if got["a.yml"].Status != "changed" || got["a.key"].Status != "secret" || got["c.yml"].Status != "new" || len(got["a.key"].Diff) != 0 {
		t.Fatalf("%+v", diff)
	}
	all := fmt.Sprint(got["a.yml"].Diff)
	if strings.Contains(all, "SECRET") || !strings.Contains(all, "5.6.7.8") {
		t.Fatalf("diff: %s", all)
	}
	if len(kept) != 1 || kept[0] != "b.yml" {
		t.Fatalf("kept %v", kept)
	}
}

func TestEncryptedRestoreNeedsPassphrase(t *testing.T) {
	s, _ := newTestServer(t, "")
	ck := signIn(t, s, "")
	top := filepath.Base(s.dataDir) // newTestServer keeps panel.conf in dataDir
	sealed, _ := sealBackup(tgz(t, top+"/a.yml"), "correct horse battery")
	b64 := base64.StdEncoding.EncodeToString(sealed)
	if w := do(s, "POST", api+"restore/preview", `{"data":"`+b64+`"}`, xr, ck); w.Code != 400 || !strings.Contains(w.Body.String(), "passphrase") {
		t.Fatalf("no passphrase: %d %s", w.Code, w.Body)
	}
	if w := do(s, "POST", api+"restore/preview", `{"data":"`+b64+`","passphrase":"correct horse battery"}`, xr, ck); w.Code != 200 || !strings.Contains(w.Body.String(), `"a.yml"`) {
		t.Fatalf("with passphrase: %d %s", w.Code, w.Body)
	}
}

func TestPanelPortRules(t *testing.T) {
	if checkPort(8443, 30000) == nil || checkPort(443, 30000) == nil || checkPort(70000, 30000) == nil {
		t.Fatal("a common or invalid port passed")
	}
	if checkPort(30000, 30000) != nil {
		t.Fatal("the current port must always pass")
	}
	if p := randomPort(); p < 20000 || p >= 60000 || commonPorts[p] {
		t.Fatalf("random port %d", p)
	}
}

func TestNewerVersion(t *testing.T) {
	for _, c := range [][3]string{{"3.6.10", "3.6.9", "y"}, {"3.6.0", "3.6.0", ""}, {"3.5.9", "3.6.0", ""}, {"4.0", "3.9.9", "y"}} {
		if newer(c[0], c[1]) != (c[2] == "y") {
			t.Fatalf("%v", c)
		}
	}
}

func TestDeleteAlsoOnKharej(t *testing.T) {
	fakePaired, fakeCalls = true, nil
	fakeKharej = []Kharej{{Host: "1.2.3.4", Via: []string{"t1"}, Online: true}}
	defer func() { fakePaired, fakeKharej = false, nil }()
	sec := NewTOTPSecret()
	s, _ := newTestServer(t, sec)
	s.kh = fakeKharej
	ck := signIn(t, s, codeAt(sec, time.Now()))
	body := fmt.Sprintf(`{"password":"correct horse battery","code":%q,"confirm":"t1","kharej":"t1"}`, codeAt(sec, time.Now().Add(30*time.Second)))
	if w := do(s, "POST", api+"tunnels/t1/delete", body, xr, ck); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(fakeCalls) == 0 || fakeCalls[0] != "kharej tunnel.delete" {
		t.Fatalf("Kharej delete must run first: %v", fakeCalls)
	}
}

func TestKharejTunnelAction(t *testing.T) {
	fakePaired, fakeCalls = true, nil
	fakeKharej = []Kharej{{Host: "1.2.3.4", Via: []string{"t1"}, Online: true}}
	defer func() { fakePaired, fakeKharej = false, nil }()
	s, _ := newTestServer(t, "")
	s.kh = fakeKharej
	ck := signIn(t, s, "")
	if w := do(s, "POST", api+"kharej/1.2.3.4/tunnel", `{"name":"k1","action":"restart"}`, xr, ck); w.Code != 200 || len(fakeCalls) != 1 {
		t.Fatalf("%d %s %v", w.Code, w.Body, fakeCalls)
	}
}

func TestGeoRefreshCachesAndSkips(t *testing.T) {
	s, c := newTestServer(t, "")
	s.kh = []Kharej{{Host: "198.51.100.7"}, {Host: "10.0.0.5"}}
	now := time.Now()
	s.geoRefresh(now)
	g := s.geoAll()
	if g["203.0.113.9"].CC != "IR" || len(g) != 1 {
		t.Fatalf("geo = %v", g)
	}
	if s.geo.tried["198.51.100.7"].IsZero() || !s.geo.tried["10.0.0.5"].IsZero() {
		t.Fatal("a failed lookup is remembered, a private address is never asked")
	}
	s2 := New(c, fakeBE{}, s.dataDir) // the answer survives a restart
	if s2.geoAll()["203.0.113.9"].City != "Tehran" {
		t.Fatal("geo.json not reloaded")
	}
}

// The carrier switch and bond endpoints: labels and modes are checked before any manager command runs.
func TestUseAndBondValidation(t *testing.T) {
	s, _ := newTestServer(t, "")
	ck := signIn(t, s, "")
	for _, c := range []struct {
		path, body string
		want       int
	}{
		{"tunnels/t1/use", `{"labels":["tcp :443"]}`, 200},
		{"tunnels/t1/use", `{"labels":["tcp :443","udp :51820"]}`, 200},
		{"tunnels/t1/use", `{"labels":[]}`, 400},
		{"tunnels/t1/use", `{"labels":["tcp;rm -rf /"]}`, 400},
		{"tunnels/nope/use", `{"labels":["tcp :443"]}`, 400},
		{"tunnels/t1/bond-mode", `{"mode":"balanced"}`, 400}, // t1 has one carrier
		{"tunnels/t1/bond-mode", `{"mode":"fastest"}`, 400},
		{"tunnels/t1/mute", `{"path":"udp","mute":true}`, 200},
		{"tunnels/t1/mute", `{"path":"udp\nx","mute":true}`, 400},
		{"tunnels/t1/retest", `{"pick":"bond","test":"fast"}`, 200},
		{"tunnels/t1/retest", `{"pick":"all"}`, 400},
	} {
		if w := do(s, "POST", api+c.path, c.body, xr, ck); w.Code != c.want {
			t.Errorf("%s %s: %d %s", c.path, c.body, w.Code, w.Body)
		}
	}
	if w := do(s, "GET", api+"tunnels/t1/paths", "", xr, ck); w.Code != 200 || !strings.Contains(w.Body.String(), `"muted":true`) {
		t.Fatalf("paths: %d %s", w.Code, w.Body)
	}
}
