package panel

// Where the servers are, for the overview map. The binary asks a public IP-location service (through the update
// proxy) once per address and keeps the answer in geo.json; the page then fits the map around the real points.

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Geo is one address's place. Zero Lat/Lon with an empty CC means unknown.
type Geo struct {
	Lat  float64 `json:"lat"`
	Lon  float64 `json:"lon"`
	CC   string  `json:"cc"`             // ISO country code
	City string  `json:"city,omitempty"` // may be empty
}

type geoCache struct {
	mu    sync.Mutex
	m     map[string]Geo
	tried map[string]time.Time // last failed lookup, retried after an hour
}

func (s *Server) geoFile() string { return filepath.Join(s.dataDir, "geo.json") }

func (s *Server) geoLoad() {
	s.geo.mu.Lock()
	defer s.geo.mu.Unlock()
	s.geo.m, s.geo.tried = map[string]Geo{}, map[string]time.Time{}
	if s.dataDir == "" {
		return
	}
	if b, err := os.ReadFile(s.geoFile()); err == nil {
		json.Unmarshal(b, &s.geo.m)
	}
}

// geoAll is the known places, keyed by address as the overview names it (host.ip, kharej[].host).
func (s *Server) geoAll() map[string]Geo {
	s.geo.mu.Lock()
	defer s.geo.mu.Unlock()
	out := make(map[string]Geo, len(s.geo.m))
	for k, v := range s.geo.m {
		out[k] = v
	}
	return out
}

// publicAddr: a name or a public IP worth asking about (private, loopback and empty are not).
func publicAddr(a string) bool {
	if a == "" {
		return false
	}
	ip := net.ParseIP(a)
	return ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
}

// geoRefresh looks up every address of this server and its Kharej servers that has no place yet.
func (s *Server) geoRefresh(now time.Time) {
	want := []string{s.be.Host().IP}
	s.khMu.Lock()
	for _, k := range s.kh {
		want = append(want, k.Host)
	}
	s.khMu.Unlock()
	changed := false
	for _, a := range want {
		if !publicAddr(a) {
			continue
		}
		s.geo.mu.Lock()
		_, have := s.geo.m[a]
		last := s.geo.tried[a]
		s.geo.mu.Unlock()
		if have || now.Sub(last) < time.Hour {
			continue
		}
		g, err := s.be.Geo(a)
		s.geo.mu.Lock()
		if err != nil || g.CC == "" {
			s.geo.tried[a] = now
		} else {
			s.geo.m[a], changed = g, true
		}
		s.geo.mu.Unlock()
	}
	if changed && s.dataDir != "" {
		s.geo.mu.Lock()
		b, _ := json.Marshal(s.geo.m)
		s.geo.mu.Unlock()
		os.WriteFile(s.geoFile(), b, 0o600)
	}
}

// pollGeo runs geoRefresh soon after start (the Kharej list needs one poll first), then every 2 minutes.
func (s *Server) pollGeo(ctx context.Context) {
	for d := 20 * time.Second; ; d = 2 * time.Minute {
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
		s.geoRefresh(time.Now())
	}
}
