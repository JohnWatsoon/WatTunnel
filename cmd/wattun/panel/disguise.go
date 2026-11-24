package panel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Everything outside the secret path answers nginx 1.18's stock 404, byte for byte, for every method — also
// while an address is banned — so a scanner sees a default web server and nothing else (plan D1, features §2).
const nginx404 = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx/1.18.0 (Ubuntu)</center>\r\n</body>\r\n</html>\r\n"

func notFound(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	for k := range h {
		delete(h, k)
	}
	h.Set("Server", "nginx/1.18.0 (Ubuntu)")
	h.Set("Content-Type", "text/html")
	h.Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusNotFound)
	if r.Method != http.MethodHead {
		w.Write([]byte(nginx404))
	}
}

// EnsureCert makes the self-signed certificate (TLS tier 1, plan D5) when certFile/keyFile do not exist: ECDSA
// P-256, 10 years, subject = the first IP, SAN = every given IP. No network, no product name.
func EnsureCert(certFile, keyFile string, ips []net.IP) error {
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	cn := "localhost"
	if len(ips) > 0 {
		cn = ips[0].String()
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// CertFingerprint is the SHA-256 of the certificate as browsers show it (AA:BB:...), so the owner can check the
// warning page against the console the first time.
func CertFingerprint(certFile string) string {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return ""
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ""
	}
	sum := sha256.Sum256(blk.Bytes)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}
