package panel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// The hand-built TLS-ALPN-01 certificate carries the same acmeIdentifier as the acme package's own, and an IP
// check names the IP as an IP.
func TestALPNChallengeCert(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cl := &acme.Client{Key: k}
	ka, err := cl.HTTP01ChallengeResponse("tok")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := cl.TLSALPN01ChallengeCert("tok", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	ext := func(der []byte) []byte {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range c.Extensions {
			if e.Id.String() == "1.3.6.1.5.5.7.1.31" && e.Critical {
				return e.Value
			}
		}
		t.Fatal("no critical acmeIdentifier extension")
		return nil
	}
	mine, err := alpnChallengeCert(ka, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ext(mine.Certificate[0]), ext(ref.Certificate[0])) {
		t.Fatal("acmeIdentifier differs from the acme package's")
	}
	ipc, err := alpnChallengeCert(ka, "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(ipc.Certificate[0])
	if len(c.IPAddresses) != 1 || c.IPAddresses[0].String() != "203.0.113.7" || len(c.DNSNames) != 0 {
		t.Fatalf("IP check names %v / %v", c.IPAddresses, c.DNSNames)
	}
}

// Live loss is retransmits over packets sent in the last 30 s; too few packets read 0, a restart starts over, and
// an engine without totals keeps its one-interval figure.
func TestWindowLoss(t *testing.T) {
	s := &Server{lossW: map[string][]lossMark{}}
	t0 := time.Unix(1000, 0)
	if got := s.windowLoss("a", Counters{LossPct: 3}, t0); got != 3 {
		t.Fatalf("old engine: %v", got)
	}
	s.windowLoss("a", Counters{PktsOut: 1000, Retrans: 10}, t0)
	if got := s.windowLoss("a", Counters{PktsOut: 1100, Retrans: 11}, t0.Add(10*time.Second)); got != 0 {
		t.Fatalf("100 packets read %v, want 0", got)
	}
	if got := s.windowLoss("a", Counters{PktsOut: 2000, Retrans: 30}, t0.Add(20*time.Second)); got != 2 {
		t.Fatalf("20 of 1000: %v, want 2", got)
	}
	// 40 s later the first mark has left the window: 1100 -> 3100 sent, 11 -> 51 resent
	if got := s.windowLoss("a", Counters{PktsOut: 3100, Retrans: 51}, t0.Add(41*time.Second)); got != 2 {
		t.Fatalf("window slid: %v, want 2", got)
	}
	if got := s.windowLoss("a", Counters{PktsOut: 50, Retrans: 5}, t0.Add(45*time.Second)); got != 0 {
		t.Fatalf("after a restart: %v, want 0", got)
	}
}
