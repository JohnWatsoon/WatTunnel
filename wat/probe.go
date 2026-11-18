package wat

// Filter probe (-fake-mode auto). Before the first pool dial the client measures which fake-SNI mode keeps a
// flow alive on this route, and the result picks the mode. Client only; the server sees a few short connections
// it rejects like any stray client.
//
// 3.0.0 method (the 2.9.0 one judged a flow by whether two tiny writes returned no error, which a cut flow passes:
// the kernel accepts writes long after a filter starts dropping). Each candidate runs on its own throwaway TCP
// connection to the real peer port:
//
//  1. dial, wrap with that mode's Desync (nothing for "none"), exactly like a pool dial;
//  2. write probeBytes of filler shaped like the carrier's own first bytes (see probeFiller);
//  3. the flow survives if the kernel saw all of it acknowledged (TCP_INFO bytes_acked) within probeWait.
//
// The SNI allowlist filters seen in the field let the handshake and a few KB through and then drop the flow
// (field 2.10.12), so 32 KB acked is the signal, not the handshake. Candidates in order, first survivor wins:
//
//	none    the route does not filter this name: run without fake-SNI (no marker, no startup wait)
//	rst     the field's working mode on the CF-whitelist routes (2.10.12)
//	synrst  rst plus a marker before the handshake completes
//	seq     the 2.7.0 default, for SNI-allowlist filters only
//
// No survivor ("route-cut") means no mode helps from this source; the tunnel runs rst and keeps retrying.
// The verdict is logged and exposed through /stats (filter_profile).

import (
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// FilterProfile is the startup probe's verdict, for /stats and the manager.
type FilterProfile struct {
	Mode      string `json:"mode"`       // the fake-mode the tunnel runs: none|rst|synrst|seq
	Verdict   string `json:"verdict"`    // the probe's result: the surviving mode, or route-cut (3.0.0)
	SeqOK     bool   `json:"seq_ok"`     // the seq candidate survived (kept for 2.x readers)
	SumOK     bool   `json:"sum_ok"`     // always false since 3.0.0: sum modes are no longer probed
	ConnAlive bool   `json:"conn_alive"` // some candidate survived
	Probed    bool   `json:"probed"`     // a probe ran at all (false = disabled, off-platform, or it failed)
}

var (
	filterMu      sync.Mutex
	filterProfile = FilterProfile{}
)

// FilterProfileNow reports the startup probe's verdict (the zero value says no probe ran).
func FilterProfileNow() FilterProfile {
	filterMu.Lock()
	defer filterMu.Unlock()
	return filterProfile
}

const (
	probeTimeout = 1500 * time.Millisecond // dial bound per candidate
	probeWait    = 2 * time.Second         // how long the filler may take to be acknowledged
	probeBytes   = 32 << 10
	probeGap     = 300 * time.Millisecond // between candidates, so a filter's per-flow state is not shared
	// probeBudget: no new candidate starts after this, so startup stays under ~18 s (one candidate is at most
	// dial 1.5 s + Wrap 2 s + probeWait 2 s); the pool dials wait on the probe.
	probeBudget = 12 * time.Second
)

var errNoTCPInfo = errors.New("wat: TCP_INFO unavailable")

// probeCandidates in the order tried; tests may shorten it.
var probeCandidates = []string{"none", "rst", "synrst", "paws", "seq"}

// ProbeFakeMode tries the candidate modes against peer (path: the tunnel's URL path, for the ws and h2c filler) and returns the one to run: "none" means run without
// fake-SNI. carrier and name (the TLS SNI or the HTTP Host) shape the filler like the real carrier's first bytes,
// so the filter judges what it would see. Called by cmd/wattun when -fake-mode auto. Any failure to run the probe
// (no raw socket, no TCP_INFO, a non-IP peer) degrades to rst without stopping the tunnel.
func ProbeFakeMode(cfg DesyncConfig, peer, carrier, name, path string, logf func(string, ...any)) string {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ip, port := desyncPeerHostPort(peer)
	if net.ParseIP(ip) == nil || port == "" {
		logf("fake-mode auto: need an IP host:port peer, running rst")
		return "rst"
	}
	addr := net.JoinHostPort(ip, port)
	verdict, mode := "route-cut", "rst"
	t0 := time.Now()
	for i, m := range probeCandidates {
		if i > 0 {
			if time.Since(t0) > probeBudget {
				logf("fake-mode auto: probe time budget spent, %s and later not tried", m)
				break
			}
			time.Sleep(probeGap)
		}
		ok, err := probeOnce(cfg, m, addr, peer, probeFiller(carrier, name, path))
		if err != nil {
			logf("fake-mode auto: probe unavailable (%v), running rst", err)
			return "rst"
		}
		logf("fake-mode auto: %s %s", m, map[bool]string{true: "survived", false: "cut"}[ok])
		if ok {
			verdict, mode = m, m
			break
		}
		// shortcut: "none" only proves the first 32 KB passed; a filter that cuts on volume or after minutes is
		// not seen. Set fake-mode explicitly if an auto tunnel dies later.
	}
	filterMu.Lock()
	filterProfile = FilterProfile{Mode: mode, Verdict: verdict, SeqOK: verdict == "seq", ConnAlive: verdict != "route-cut", Probed: true}
	filterMu.Unlock()
	logf("fake-mode auto: verdict %s, running %s", verdict, mode)
	return mode
}

// probeOnce: one candidate on one fresh connection. err means the probe itself cannot run here.
func probeOnce(cfg DesyncConfig, mode, addr, peer string, filler []byte) (bool, error) {
	var d *Desync
	if mode != "none" {
		var err error
		if d, err = NewDesync(DesyncConfig{SNI: cfg.SNI, Mode: mode, TTL: cfg.TTL}, peer); err != nil {
			return false, err
		}
		defer d.Close()
	}
	nc, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return false, nil // a dial that fails is a cut too (or the peer is down: every mode fails alike)
	}
	defer nc.Close()
	if d != nil {
		if nc, err = d.Wrap(nc); err != nil {
			return false, nil
		}
	}
	tc, _ := nc.(*net.TCPConn)
	if tc == nil {
		return false, nil
	}
	if _, ok := bytesAcked(tc); !ok {
		return false, errNoTCPInfo
	}
	deadline := time.Now().Add(probeWait)
	_ = tc.SetWriteDeadline(deadline)
	for off := 0; off < len(filler); off += 4 << 10 {
		if _, err := tc.Write(filler[off:min(off+4<<10, len(filler))]); err != nil {
			return false, nil
		}
	}
	for time.Now().Before(deadline) {
		if n, _ := bytesAcked(tc); n >= uint64(len(filler)) {
			return true, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false, nil
}

// probeFiller is probeBytes shaped like the carrier's first bytes, so the filter classifies the probe like a pool
// connection and the server keeps reading instead of closing early (a close would stop the acks):
//
//	tls carriers  one ClientHello carrying name, its handshake length raised so it never completes
//	ws, h2c       an HTTP/1 request for the tunnel path (path, "/" when empty) whose header never ends
//	tcp           a pool hello id that is not a mimic prefix, then frames the server drops at AEAD
func probeFiller(carrier, name, path string) []byte {
	b := make([]byte, probeBytes)
	_, _ = rand.Read(b)
	switch carrier {
	case "tls", "wss", "h2", "grpc":
		hello := FakeClientHello(name)
		if hello == nil {
			hello = FakeClientHello("www.cloudflare.com")
		}
		// records of <=16 KB; the first carries the hello, the handshake length claims more than we send
		out := make([]byte, 0, probeBytes+64)
		body := hello[5:]
		body[1], body[2], body[3] = 0x00, 0xfd, 0xe8 // handshake length 65000
		for rest := append(body, b[:probeBytes-len(body)]...); len(rest) > 0; {
			n := min(len(rest), 16<<10)
			out = append(out, 0x16, 0x03, 0x01, byte(n>>8), byte(n))
			out = append(out, rest[:n]...)
			rest = rest[n:]
		}
		return out
	case "ws", "h2c":
		if path == "" {
			path = "/"
		} else if path[0] != '/' {
			path = "/" + path
		}
		h := "GET " + path + " HTTP/1.1\r\nHost: " + name + "\r\nX-Pad: "
		const pad = "abcdefghijklmnopqrstuvwxyz0123456789"
		for i := range b {
			b[i] = pad[int(b[i])%len(pad)]
		}
		return append([]byte(h), b[len(h):]...)
	default: // tcp
		b[0] = 0
		for off := 8; off+2 < len(b); off += 1002 {
			n := min(1000, len(b)-off-2)
			b[off], b[off+1] = byte(n>>8), byte(n)
		}
		return b
	}
}

// ProbeName is the name the probe's filler carries for a carrier: the TLS SNI, or the HTTP Host.
func ProbeName(carrier, sni, host, peer string) string {
	if carrier == "ws" || carrier == "h2c" {
		if host != "" {
			return host
		}
	}
	if sni != "" {
		return sni
	}
	first, _, _ := strings.Cut(peer, ",")
	first = strings.TrimSpace(first)
	if h, _, err := net.SplitHostPort(first); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(first, "[]")
}

// note is the package-level log line of the fake-SNI layer (raw-send failures); it keeps the injector free of a
// logf thread. It is silent until SetNote wires it, which cmd/wattun does at startup.
var note = func(format string, args ...any) {}

// SetNote routes the fake-SNI layer's one-time warnings to logf. Call it once, before NewDesync.
func SetNote(logf func(format string, args ...any)) {
	if logf != nil {
		note = logf
	}
}

// RawSendFails is how many fake-SNI fires could not be injected (raw socket open/bind/send failure).
// A rising counter with healthy tunnels means the real SNI is going out unprotected: switch carrier.
func RawSendFails() uint64 { return rawSendFails.Load() }
