package wat

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20"
)

// Raw tcp pool, hello v2 (3.0.0). Until 3.0.0 a pool connection opened with the pool id in clear (8 bytes, equal on
// every connection of a pool) and then framed each packet with a 2-byte length. A filter that lets only known protocols
// through (Iran's whitelist passes DNS, HTTP and HTTPS and drops the rest, Bock et al., FOCI 2020, and a 2025
// measurement of the same filter) saw neither. Now the first bytes of every connection are one TLS ClientHello record
// (the 517-byte Chrome-shaped hello of the fake-SNI layer, SNI = the tunnel's mimic name), and the authentication rides in
// its random and session-id fields, 64 bytes that look random anyway:
//
//	salt(16) | pool id XOR HMAC(root, "id"|salt)(8) | HMAC(root, "tag"|salt|that)(16) | random(24)
//
// root is HMAC(PSK, label), so only a holder of the key can build or check one. The 2-byte frame lengths that follow are
// XORed with a ChaCha20 keystream per direction (keys from the PSK and the salt), so the stream carries no plain length
// either. Both ends must run 3.0.0; the listener tells the two hellos apart by the first five bytes (an old pool id
// matches the TLS record header with probability 2^-40), and a dialer that hears nothing from a listener falls back to
// the 8-byte id (mimicWatch), so an older peer on either side still works after a few seconds.

const (
	mimicHelloLen = 517
	mimicDefault  = "www.cloudflare.com"
)

var (
	mimicFallback = 6 * time.Second  // dial succeeded but the peer said nothing in this mode for this long: try the other hello
	mimicLater    = 30 * time.Second // same, once the peer has been heard in this mode
	errMimic      = errors.New("wat: bad tcp hello")
)

func hmacSum(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// mimicCiphers derives the two length masks of one connection: dialer to listener (d2l) and back (l2d).
func mimicCiphers(root, salt []byte) (d2l, l2d *chacha20.Cipher, err error) {
	sr := hmacSum(root, []byte("stream"), salt)
	var zero [12]byte
	if d2l, err = chacha20.NewUnauthenticatedCipher(hmacSum(sr, []byte("d2l")), zero[:]); err != nil {
		return nil, nil, err
	}
	l2d, err = chacha20.NewUnauthenticatedCipher(hmacSum(sr, []byte("l2d")), zero[:])
	return d2l, l2d, err
}

// buildMimicHello returns the hello for pool id plus the dialer's masks (tx = what it sends, rx = what it reads).
func buildMimicHello(psk []byte, sni string, id [8]byte) (hello []byte, tx, rx *chacha20.Cipher, err error) {
	if sni == "" {
		sni = mimicDefault
	}
	if len(sni) > 200 {
		return nil, nil, nil, errMimic
	}
	root := hmacSum(psk, []byte("wattun tcp hello v2"))
	var a [64]byte
	if _, err = rand.Read(a[:]); err != nil {
		return nil, nil, nil, err
	}
	salt := a[:16]
	enc := hmacSum(root, []byte("id"), salt)[:8]
	for i := range id {
		enc[i] ^= id[i]
	}
	copy(a[16:24], enc)
	copy(a[24:40], hmacSum(root, []byte("tag"), salt, enc)[:16])
	if hello = mimicBrowserHello(sni, a[:32], a[32:]); hello == nil { // utls refused: the fixed hello of the fake-SNI layer
		mimicHelloFallbackLog.Do(func() {
			log.Printf("wat: tcp-mimic: browser hello unavailable for sni %q, using the fixed hello (one JA3 on every tunnel)", sni)
		})
		hello = FakeClientHello(sni)
		if len(hello) != mimicHelloLen {
			return nil, nil, nil, errMimic
		}
		copy(hello[11:43], a[:32]) // ClientHello.random
		copy(hello[44:76], a[32:]) // legacy_session_id (its length byte, hello[43], is 32)
	}
	tx, rx, err = mimicCiphers(root, salt)
	return hello, tx, rx, err
}

// isMimicPrefix reports whether b (at least 5 bytes) starts like the hello: a TLS handshake record of 512 bytes.
func isMimicPrefix(b []byte) bool {
	return len(b) >= 5 && b[0] == 0x16 && b[1] == 0x03 && b[2] == 0x01 && b[3] == 0x02 && b[4] == 0x00
}

// parseMimicHello checks a received hello and returns the pool id and the listener's masks (tx = what it sends, rx =
// what it reads).
func parseMimicHello(psk, hello []byte) (id [8]byte, tx, rx *chacha20.Cipher, ok bool) {
	if len(hello) != mimicHelloLen || !isMimicPrefix(hello) {
		return id, nil, nil, false
	}
	root := hmacSum(psk, []byte("wattun tcp hello v2"))
	var a [64]byte
	copy(a[:32], hello[11:43]) // random, then the session id: the byte between them is its length
	copy(a[32:], hello[44:76])
	salt, enc, tag := a[:16], a[16:24], a[24:40]
	if !hmac.Equal(tag, hmacSum(root, []byte("tag"), salt, enc)[:16]) {
		return id, nil, nil, false
	}
	m := hmacSum(root, []byte("id"), salt)
	for i := range id {
		id[i] = enc[i] ^ m[i]
	}
	d2l, l2d, err := mimicCiphers(root, salt)
	if err != nil {
		return id, nil, nil, false
	}
	return id, l2d, d2l, true
}

// mimicBrowserHello builds the hello from a real browser profile (utls Chrome 106, the last Chrome hello of exactly 517
// bytes, extension order shuffled per connection like Chrome does), with rnd in ClientHello.random and sid in the
// session id. The fixed hello of FakeClientHello has one JA3 on every tunnel and a cipher list no browser sends. nil
// means "use that one": utls failed, or the SNI is so long the hello is not 517 bytes any more (3.0.1).
func mimicBrowserHello(sni string, rnd, sid []byte) []byte {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_106_Shuffle)
	if err != nil {
		return nil
	}
	c1, c2 := net.Pipe() // nothing is read or written: only the hello is built
	defer c1.Close()
	defer c2.Close()
	uc := utls.UClient(c1, &utls.Config{ServerName: sni}, utls.HelloCustom)
	if uc.ApplyPreset(&spec) != nil || uc.BuildHandshakeState() != nil || uc.SetClientRandom(rnd) != nil {
		return nil
	}
	uc.HandshakeState.Hello.SessionId = append([]byte(nil), sid...)
	if uc.MarshalClientHello() != nil {
		return nil
	}
	raw := uc.HandshakeState.Hello.Raw
	if len(raw)+5 != mimicHelloLen || len(sid) != 32 {
		return nil
	}
	hello := append([]byte{0x16, 0x03, 0x01, 0x02, 0x00}, raw...)
	if !isMimicPrefix(hello) || hello[43] != 32 {
		return nil
	}
	return hello
}

var mimicHelloFallbackLog sync.Once
