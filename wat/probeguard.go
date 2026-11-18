package wat

// probeguard.go: opt-in active-probe guard for the ws/wss/h2/h2c/grpc pool carriers (3.3.8, both ends).
// Without it, a scanner that GETs the tunnel path with a websocket Upgrade (or POSTs it as h2/grpc) receives a
// real 101/200 before any PSK check - the HTTP family's one active-probe oracle (audit 2026-11-18: pathMux
// answers the tunnel path before the decoy, and auth only happens later at the pool-session layer). With it,
// the server demands a key-derived token in X-Request-Id BEFORE accepting the request and hands everything else
// to the decoy or the nginx pages, so a probe learns nothing. The header name is deliberately ordinary: real
// web apps carry X-Request-Id. Both ends must set it (the client stamps, the server demands); the default off
// keeps older peers interoperable, and the token check is skipped entirely when the key is empty.

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"time"
)

const probeGuardHdr = "X-Request-Id"

// ProbeGuardKey derives the token key from the PSK (hdrmask.go pattern: domain-separated SHA-256). Exported so
// the binary passes the same derived key to its client (stamps) and server (demands) options.
func ProbeGuardKey(psk []byte) []byte {
	h := sha256.New()
	h.Write([]byte("wattun probe guard v1\x00"))
	h.Write(psk)
	return h.Sum(nil)
}

// probeGuardToken builds the header value: 4 fresh bytes (per-request, not authenticated) + 10 bytes of
// HMAC-SHA256(key, bucket || method || path), where bucket is the unix time floored to 5 minutes. The server
// accepts bucket-1..bucket+1, so +-5 min of clock skew between the ends is tolerated.
func probeGuardToken(key []byte, method, path string, now time.Time) string {
	var nb [4]byte
	crand.Read(nb[:])
	mac := probeGuardMac(key, method, path, uint64(now.Unix()/300))
	return hex.EncodeToString(nb[:]) + hex.EncodeToString(mac)
}

func probeGuardMac(key []byte, method, path string, bucket uint64) []byte {
	mac := hmac.New(sha256.New, key)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], bucket)
	mac.Write(b[:])
	mac.Write([]byte(method))
	mac.Write([]byte(path))
	return mac.Sum(nil)[:10]
}

// probeGuardOK verifies an X-Request-Id token against the guard key; r's method and path must match what the
// client MACed. Constant-time compares throughout.
func probeGuardOK(key []byte, r *http.Request, now time.Time) bool {
	v := r.Header.Get(probeGuardHdr)
	if len(v) != 28 { // 8 hex nonce bytes + 20 hex mac bytes
		return false
	}
	got, err := hex.DecodeString(v[8:])
	if err != nil {
		return false
	}
	bucket := uint64(now.Unix() / 300)
	for _, d := range [3]uint64{0, 1, ^uint64(0)} { // 0, +1, -1 (wraps: one bucket before zero is not a real time)
		want := probeGuardMac(key, r.Method, r.URL.Path, bucket+d)
		if hmac.Equal(got, want) {
			return true
		}
	}
	return false
}
