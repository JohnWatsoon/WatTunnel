package mgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeReadTokenRoundTrip(t *testing.T) {
	InitColor(false, 8)
	cases := []struct {
		name string
		tok  Token
	}{
		{"seven fields", Token{Carrier: "icmp", Peer: "198.51.100.7:4443", Key: "k0", Path: "/wat", SNI: "", Icmp: "echo", Ports: "443,53/udp"}},
		{"reverse flag", Token{Carrier: "icmp", Peer: "198.51.100.7", Key: "k1", Ports: "", Rev: "1"}},
		{"auto plan", Token{Carrier: "auto", Peer: "198.51.100.9:4443", Key: "k2", Ports: "443", Auto: "d=udp:4443,tcp:4443;r=tcp:24431"}},
		{"bond", Token{Carrier: "udp+tcp", Peer: "198.51.100.7:4443,198.51.100.7:8443", Key: "k3", Ports: "443"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := MakeToken(c.tok.Carrier, c.tok.Peer, c.tok.Key, c.tok.Path, c.tok.SNI, c.tok.Icmp, c.tok.Ports, c.tok.Rev, c.tok.Auto)
			if !strings.HasPrefix(s, "wat1:") {
				t.Fatalf("token %q lacks the wat1: prefix", s)
			}
			got, err := ReadToken(s)
			if err != nil {
				t.Fatalf("ReadToken: %v", err)
			}
			if got.Carrier != c.tok.Carrier || got.Peer != c.tok.Peer || got.Key != c.tok.Key ||
				got.Path != c.tok.Path || got.SNI != c.tok.SNI || got.Icmp != c.tok.Icmp ||
				got.Ports != c.tok.Ports || got.Rev != c.tok.Rev || got.Auto != c.tok.Auto {
				t.Errorf("round trip lost fields: got %+v want %+v", got, c.tok)
			}
		})
	}
}

func TestReadTokenPaddingTolerant(t *testing.T) {
	// a bash-made token carries base64 padding; an unpadded one must read too
	padded := MakeToken("udp", "h:1", "k", "", "", "", "", "", "")
	if _, err := ReadToken(padded); err != nil {
		t.Fatalf("padded token: %v", err)
	}
	unpadded := strings.TrimSuffix(padded, "=")
	if _, err := ReadToken(unpadded); err != nil {
		t.Errorf("unpadded token: %v", err)
	}
	if _, err := ReadToken("not-a-token"); err == nil {
		t.Error("no error on a foreign token")
	}
	if _, err := ReadToken("wat1:!!!"); err == nil {
		t.Error("no error on bad base64")
	}
}

func TestTokenBondLegs(t *testing.T) {
	InitColor(false, 8)
	// a bond token: 2 carriers, 2 endpoints
	tok, err := ReadToken(MakeToken("udp+tcp", "h1:4443,h1:8443", "k", "", "", "", "", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := tok.TokenBondLegs(); err != nil {
		t.Fatalf("TokenBondLegs: %v", err)
	}
	if len(tok.LegC) != 2 || len(tok.LegP) != 2 ||
		tok.LegC[0] != "udp" || tok.LegC[1] != "tcp" ||
		tok.LegP[0] != "h1:4443" || tok.LegP[1] != "h1:8443" {
		t.Errorf("legs wrong: %v / %v", tok.LegC, tok.LegP)
	}
	if tok.Peer != "h1:4443" {
		t.Errorf("Peer should become the first leg, got %q", tok.Peer)
	}
	// a single-carrier token keeps the plain form
	tok2, _ := ReadToken(MakeToken("udp", "h1:4443", "k", "", "", "", "", "", ""))
	if err := tok2.TokenBondLegs(); err != nil || tok2.LegC != nil {
		t.Errorf("single-carrier token must not split: err=%v legs=%v", err, tok2.LegC)
	}
	// mismatched counts are refused with the bash's message (both sides carry
	// separators before the check applies)
	tok3, _ := ReadToken(MakeToken("udp+tcp", "a,b,c", "k", "", "", "", "", "", ""))
	err = tok3.TokenBondLegs()
	if err == nil || !strings.Contains(err.Error(), "3 endpoints for 2 carriers") {
		t.Errorf("count mismatch: err=%v", err)
	}
}

func TestBondPeerField(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	oldConf := P.Conf
	P.Conf = dir
	defer func() { P.Conf = oldConf }()
	write := "carrier: icmp+udp\nlisten: 0.0.0.0:4443\nlisten-udp: 0.0.0.0:5555\n"
	if err := os.WriteFile(filepath.Join(dir, "fort.yml"), []byte(write), 0o600); err != nil {
		t.Fatal(err)
	}
	// icmp is a raw carrier: bare address, no port; udp keeps its own listen port;
	// the bond carries no tcp leg, so nothing else is emitted
	got := BondPeerField("fort", "203.0.113.9")
	want := "203.0.113.9,203.0.113.9:5555"
	if got != want {
		t.Errorf("BondPeerField = %q, want %q", got, want)
	}
	// a leg without its own listen-<carrier>: key takes the global listen port
	if err := os.WriteFile(filepath.Join(dir, "fort2.yml"), []byte("carrier: udp+tcp\nlisten: 0.0.0.0:4443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := BondPeerField("fort2", "h"); got != "h:4443,h:4443" {
		t.Errorf("fallback port wrong: %q", got)
	}
}

func TestRefreshToken(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	oldConf := P.Conf
	P.Conf = dir
	defer func() { P.Conf = oldConf }()

	// a bonded Kharej config whose token predates the arming: carrier list,
	// per-leg endpoints, path and allowed ports must all be carried over
	conf := "mode: server\ncarrier: udp+tcp\nlisten: 0.0.0.0:4443\nlisten-udp: 0.0.0.0:4443\nlisten-tcp: 0.0.0.0:8443\npath: /fresh\nports:\n  - 443\n  - 53/udp\n"
	if err := os.WriteFile(filepath.Join(dir, "b.yml"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	old := MakeToken("udp", "198.51.100.7:4443", "secret", "/old", "old.example", "echo", "443", "", "")
	if err := os.WriteFile(filepath.Join(dir, "b.token"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RefreshToken("b"); err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "b.token"))
	tok, err := ReadToken(string(raw))
	if err != nil {
		t.Fatalf("refreshed token unreadable: %v", err)
	}
	if tok.Carrier != "udp+tcp" {
		t.Errorf("carrier = %q, want udp+tcp", tok.Carrier)
	}
	if tok.Peer != "198.51.100.7:4443,198.51.100.7:8443" {
		t.Errorf("peer = %q, want per-leg endpoints", tok.Peer)
	}
	if tok.Path != "/fresh" {
		t.Errorf("path not carried: %q", tok.Path)
	}
	// the config's (empty) sni/icmp-type win over the old token's values
	if tok.SNI != "" || tok.Icmp != "" {
		t.Errorf("sni/icmp must follow the config: %q %q", tok.SNI, tok.Icmp)
	}
	if tok.Ports != "443,53/udp" {
		t.Errorf("ports = %q, want 443,53/udp", tok.Ports)
	}
	// an unchanged token must not be rewritten
	st1, _ := os.Stat(filepath.Join(dir, "b.token"))
	if err := RefreshToken("b"); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(filepath.Join(dir, "b.token"))
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Error("a matching token was rewritten")
	}
	// reverse companion of an auto Kharej tunnel gets the same ports written
	ac := "mode: server\ncarrier: udp\nlisten: 0.0.0.0:4443\nports:\n  - 8443\n"
	if err := os.WriteFile(filepath.Join(dir, "auto.yml"), []byte(ac), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "auto.token"),
		[]byte(MakeToken("auto", "198.51.100.7:4443", "k", "", "", "", "", "", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "auto-r.yml"), []byte("mode: server\ncarrier: udp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RefreshToken("auto"); err != nil {
		t.Fatalf("RefreshToken(auto): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "auto-r.yml")); err != nil {
		t.Fatal(err)
	}
	rbody, _ := os.ReadFile(filepath.Join(dir, "auto-r.yml"))
	if !strings.Contains(string(rbody), "- 8443") {
		t.Errorf("auto-r ports block missing: %q", string(rbody))
	}
}
