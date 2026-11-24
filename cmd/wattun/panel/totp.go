package panel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP is RFC 6238 with the parameters every authenticator app understands: HMAC-SHA1, 6 digits, 30 s steps.

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns 20 random bytes as unpadded base32.
func NewTOTPSecret() string {
	k := make([]byte, 20)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return b32.EncodeToString(k)
}

func totpAt(secret string, step int64) (string, bool) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", false
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	h := m.Sum(nil)
	off := h[len(h)-1] & 0x0f
	v := binary.BigEndian.Uint32(h[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), true
}

// VerifyTOTP checks code at now ±1 step and refuses any step <= last (a code is good once). It returns the step
// that matched, which the caller stores as the new last.
func VerifyTOTP(secret, code string, now time.Time, last int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	cur := now.Unix() / 30
	for _, s := range []int64{cur - 1, cur, cur + 1} {
		if s <= last {
			continue
		}
		if want, ok := totpAt(secret, s); ok && hmac.Equal([]byte(want), []byte(code)) {
			return s, true
		}
	}
	return 0, false
}

// TOTPURI is the otpauth:// URI the QR code carries. issuer is the panel title, never the product name: anyone
// holding the owner's phone can read the authenticator list.
func TOTPURI(issuer, user, secret string) string {
	label := url.PathEscape(issuer + ":" + user)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "digits": {"6"}, "period": {"30"}, "algorithm": {"SHA1"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}
