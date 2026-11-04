package wat

// M1/M15 (audit 2026-11-04): an explicit -mtu must not exceed what the carrier itself frames. Shaped carriers used to
// overflow the wire (dnscrypt-udp: 1400 + 11 header, padded to 1472 B) because NewSession only consulted the profile
// for the default payload; a direct pool must keep its larger MaxMTU ceiling (explicit mtu may intentionally exceed
// its default MTU).

import "testing"

func TestExplicitMTUClampedToCarrier(t *testing.T) {
	for _, c := range []struct {
		name     string
		prof     Profile
		explicit int
		want     int
	}{
		{"shaped udp ceiling", Profile{MTU: 1326}, 1400, 1326},
		{"raw sit ceiling", Profile{MTU: 1360}, 1400, 1360},
		{"under the ceiling is kept", Profile{MTU: 1326}, 1200, 1200},
		{"direct pool keeps MaxMTU", poolProfile, 1 << 20, poolMaxMTU},
		{"no profile keeps the explicit value", Profile{}, 1400, 1400},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := profSession(t, c.prof, Config{MaxPayload: c.explicit})
			if got := s.maxPlain + overhead; got != c.want {
				t.Fatalf("profile %+v with -mtu %d gave payload %d, want %d", c.prof, c.explicit, got, c.want)
			}
		})
	}
}
