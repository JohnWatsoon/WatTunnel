package mgr

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestSumsVerify(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	sums := []byte("abc123  install.sh\n")
	h := sha256.Sum256(sums)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	if !sumsVerify(sums, sig, pub) {
		t.Error("good signature rejected")
	}
	if sumsVerify([]byte("abc124  install.sh\n"), sig, pub) {
		t.Error("tampered sums accepted")
	}
	if sumsVerify(sums, sig, "") {
		t.Error("a throwaway key's signature must not pass the pinned key")
	}
	if !sumsHas(sums, "install.sh", "abc123") || sumsHas(sums, "install.sh", "abc12") || sumsHas(sums, "wattun", "abc123") {
		t.Error("sumsHas must match the exact line")
	}
}

func TestApplyUpdateProxy(t *testing.T) {
	for _, c := range []struct{ in, prefix, proxy string }{
		{"https://ghproxy.net/", "https://ghproxy.net/", ""},
		{"socks5h://127.0.0.1:1080", "", "socks5h://127.0.0.1:1080"},
		{"http://10.0.0.1:3128", "", "http://10.0.0.1:3128"},
		{"http://mirror.example/gh", "http://mirror.example/gh/", ""},
		{"127.0.0.1:8080", "", "http://127.0.0.1:8080"},
		{"https://user:pw@proxy.example:443", "", "https://user:pw@proxy.example:443"},
		{"", "", ""},
	} {
		applyUpdateProxy(c.in)
		if uURLPrefix != c.prefix || uProxy != c.proxy {
			t.Errorf("%q: prefix=%q proxy=%q, want %q %q", c.in, uURLPrefix, uProxy, c.prefix, c.proxy)
		}
	}
}
