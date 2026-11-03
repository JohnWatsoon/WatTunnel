package main

import (
	"net"
	"sync"
	"sync/atomic"
)

// Public TCP listeners otherwise have no cap: a stranger can open connections until every stream slot in the
// session (8192) is taken. The limits are per process, and a slot comes back when its connection closes.
const (
	maxPublicConns = 4096
	maxPublicPerIP = 256
)

var publicConns = newConnLimiter(maxPublicConns, maxPublicPerIP)

var (
	connLimitDrops  atomic.Uint64 // connections the public listeners refused
	connLimitActive atomic.Int64  // connections they currently hold
)

// connLimiter caps accepted connections in total and per source IP.
type connLimiter struct {
	mu     sync.Mutex
	perIP  map[string]int
	total  int
	max    int
	maxPer int
}

func newConnLimiter(max, maxPerIP int) *connLimiter {
	return &connLimiter{perIP: make(map[string]int), max: max, maxPer: maxPerIP}
}

// acquire reserves a slot for ip; false means the caller must close the connection instead of handling it.
func (l *connLimiter) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.max || l.perIP[ip] >= l.maxPer {
		return false
	}
	l.total++
	l.perIP[ip]++
	return true
}

// release frees the slot acquire reserved for ip.
func (l *connLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.perIP[ip]--; l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
}

// remoteIP returns the source IP of addr; an address that does not split as host:port is used whole.
func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}
