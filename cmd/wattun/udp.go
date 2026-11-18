package main

// UDP port forwarding over the session's unreliable datagrams (wat.Session.SendDatagram).
//
//	client (Iran):   listens on UDP port P; every source address is a flow (random 64-bit id); datagrams go to the
//	                 server tagged (flow, target port); replies by flow id go back to that source address.
//	server (Kharej): per (session, flow) one UDP socket connected to 127.0.0.1:port; its replies are sent back.
//
// Both ends must run wattun >= 1.2.0 before a udp port is configured: an older peer ignores datagram frames.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

const maxUDPFlows = 4096 // per listening port (client) / per session (server)

// process-wide counters for /stats
var (
	udpFlowsActive atomic.Int64
	udpRejected    atomic.Uint64 // server: datagrams for a port that is not allowed
	udpFlowCapDrop atomic.Uint64 // flows refused because the cap was reached
)

type cflow struct {
	id   uint64
	src  netip.AddrPort
	l    *udpListener
	last atomic.Int64
	sess *wat.Session // chosen once, kept while it lives: re-picking per datagram lets a flapping session reorder the flow
}

// dgramClient is the client-side UDP forwarder for the tunnel's sessions; each flow sticks to one session (cflow.session).
type dgramClient struct {
	tun  *tunnel
	idle time.Duration
	mu   sync.Mutex
	byID map[uint64]*cflow
}

func newDgramClient(tun *tunnel, idle time.Duration) *dgramClient {
	c := &dgramClient{tun: tun, idle: idle, byID: map[uint64]*cflow{}}
	go tun.eachDatagram(c.reply)
	go c.janitor()
	return c
}

// reply delivers a datagram from the server to the flow's local sender (replies may come in on any session).
func (c *dgramClient) reply(d wat.Datagram) {
	c.mu.Lock()
	f := c.byID[d.Flow]
	c.mu.Unlock()
	if f == nil {
		return
	}
	f.last.Store(time.Now().UnixNano())
	if !f.l.stat.dgramOK(false, len(d.Data)) {
		return
	}
	f.l.stat.dgram(false, len(d.Data))
	f.l.conn.WriteToUDPAddrPort(d.Data, f.src)
}

func (c *dgramClient) janitor() {
	tk := time.NewTicker(max(c.idle/4, 20*time.Millisecond))
	defer tk.Stop()
	for {
		select {
		case <-tk.C:
			cut := time.Now().Add(-c.idle).UnixNano()
			c.mu.Lock()
			for id, f := range c.byID {
				if f.last.Load() < cut {
					c.drop(f, id)
				}
			}
			c.mu.Unlock()
		case <-c.tun.Done():
			return
		}
	}
}

// drop removes f; c.mu is held.
func (c *dgramClient) drop(f *cflow, id uint64) {
	delete(c.byID, id)
	f.l.mu.Lock()
	delete(f.l.flows, f.src)
	f.l.mu.Unlock()
	udpFlowsActive.Add(-1)
	f.l.stat.udpFlows.Add(-1)
	dbg("udp flow %016x (%s) closed", id, f.src)
}

type udpListener struct {
	c      *dgramClient
	conn   *net.UDPConn
	target int
	stat   *portStat
	mu     sync.Mutex
	closed bool
	flows  map[netip.AddrPort]*cflow
}

// listen binds addr (UDP) and forwards everything arriving there to server port target.
func (c *dgramClient) listen(addr string, target int) (*udpListener, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	l := &udpListener{c: c, conn: conn, target: target, stat: portReg.get("c", conn.LocalAddr().(*net.UDPAddr).Port), flows: map[netip.AddrPort]*cflow{}}
	go l.readLoop()
	return l, nil
}

func (l *udpListener) Addr() net.Addr { return l.conn.LocalAddr() }

func (l *udpListener) readLoop() {
	buf := make([]byte, 64<<10)
	for {
		n, src, err := l.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) { // not a string match: Windows reports "forcibly closed" for a vanished UDP sender
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue // e.g. Windows "forcibly closed" after a reply to a vanished sender
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		l.mu.Lock()
		f := l.flows[src]
		l.mu.Unlock()
		if !l.stat.dgramOK(true, n) {
			continue
		}
		if f == nil {
			if f = l.newFlow(src); f == nil {
				continue
			}
		}
		f.last.Store(time.Now().UnixNano())
		l.stat.dgram(true, n)
		f.session().SendDatagram(f.id, l.target, buf[:n]) // full queue / oversize: dropped and counted by the session
	}
}

// session is the flow's session: chosen on first use (or when it dies) and then kept for the flow's life, so a
// session that flaps does not pull the flow back and reorder its datagrams. readLoop is its only caller.
func (f *cflow) session() *wat.Session {
	if f.sess == nil || !f.sess.Alive() {
		f.sess = f.l.c.tun.forFlow(f.id)
	}
	return f.sess
}

func (l *udpListener) newFlow(src netip.AddrPort) *cflow {
	var b [8]byte
	rand.Read(b[:])
	f := &cflow{id: binary.BigEndian.Uint64(b[:]) | 1, src: src, l: l}
	f.last.Store(time.Now().UnixNano())
	// Lock order matches dgramClient.drop: c.mu -> l.mu so Close() cannot miss a concurrent insert.
	l.c.mu.Lock()
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		l.c.mu.Unlock()
		return nil
	}
	if len(l.flows) >= maxUDPFlows {
		l.mu.Unlock()
		l.c.mu.Unlock()
		udpFlowCapDrop.Add(1)
		return nil
	}
	for l.c.byID[f.id] != nil { // astronomically unlikely, but a clash would cross two users' replies
		rand.Read(b[:])
		f.id = binary.BigEndian.Uint64(b[:]) | 1
	}
	l.c.byID[f.id] = f
	l.flows[src] = f
	l.mu.Unlock()
	l.c.mu.Unlock()
	udpFlowsActive.Add(1)
	l.stat.udpFlows.Add(1)
	l.stat.connsTotal.Add(1)
	dbg("udp flow %016x: %s -> server :%d", f.id, src, l.target)
	return f
}

// Close stops the listener and forgets its flows.
func (l *udpListener) Close() {
	l.conn.Close()
	l.c.mu.Lock()
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	for id, f := range l.c.byID {
		if f.l == l {
			l.c.drop(f, id)
		}
	}
	l.c.mu.Unlock()
}

// udpListeners is the live set of public UDP ports (same apply semantics as listeners for tcp).
type udpListeners struct {
	mu     sync.Mutex
	active map[portMap]*udpListener
	open   func(listen, target int) (*udpListener, error)
}

func newUDPListeners(open func(listen, target int) (*udpListener, error)) *udpListeners {
	return &udpListeners{active: map[portMap]*udpListener{}, open: open}
}

func (u *udpListeners) apply(want []portMap) []error {
	u.mu.Lock()
	defer u.mu.Unlock()
	set := map[portMap]bool{}
	for _, m := range want {
		set[m] = true
	}
	for m, l := range u.active {
		if !set[m] {
			l.Close()
			delete(u.active, m)
			log.Printf("stopped listening on udp port %d (-> %d)", m.Listen, m.Target)
		}
	}
	var errs []error
	for _, m := range want {
		if u.active[m] == nil {
			l, err := u.open(m.Listen, m.Target)
			if err != nil {
				errs = append(errs, fmt.Errorf("listen udp port %d: %v", m.Listen, err))
				continue
			}
			u.active[m] = l
		}
	}
	return errs
}

func (u *udpListeners) has(p int) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for m := range u.active {
		if m.Listen == p {
			return true
		}
	}
	return false
}

// ---- server side ----

type sflow struct {
	conn *net.UDPConn
	port int
	stat *portStat
	last atomic.Int64
}

// serveDgrams terminates the datagram flows of one session until it ends.
func serveDgrams(sess *wat.Session, lo, hi int, al *allow, idle time.Duration) {
	var mu sync.Mutex
	flows := map[uint64]*sflow{}
	defer func() {
		mu.Lock()
		for id, f := range flows {
			f.conn.Close()
			delete(flows, id)
			udpFlowsActive.Add(-1)
			f.stat.udpFlows.Add(-1)
		}
		mu.Unlock()
	}()
	tk := time.NewTicker(max(idle/4, 20*time.Millisecond))
	defer tk.Stop()
	warned := map[int]bool{}
	for {
		select {
		case <-sess.Done():
			return
		case <-tk.C:
			cut := time.Now().Add(-idle).UnixNano()
			mu.Lock()
			for id, f := range flows {
				if f.last.Load() < cut {
					f.conn.Close() // its reader goroutine exits
					delete(flows, id)
					udpFlowsActive.Add(-1)
					f.stat.udpFlows.Add(-1)
					dbg("server udp flow %016x idle, closed", id)
				}
			}
			mu.Unlock()
		case d := <-sess.Datagrams():
			mu.Lock()
			f := flows[d.Flow]
			full := len(flows) >= maxUDPFlows
			mu.Unlock()
			if f != nil && f.port != d.Port {
				continue // a flow is bound to the port of its first datagram
			}
			if f == nil {
				if !al.udpOK(d.Port, lo, hi) {
					udpRejected.Add(1)
					if !warned[d.Port] {
						warned[d.Port] = true
						log.Printf("udp port %d is not allowed, datagrams dropped", d.Port)
					}
					continue
				}
				if full {
					udpFlowCapDrop.Add(1)
					continue
				}
				stat := portReg.get("s", d.Port)
				if !stat.dgramOK(true, len(d.Data)) {
					continue
				}
				conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: d.Port})
				if err != nil {
					continue
				}
				f = &sflow{conn: conn, port: d.Port, stat: stat}
				f.stat.udpFlows.Add(1)
				f.stat.connsTotal.Add(1)
				mu.Lock()
				flows[d.Flow] = f
				mu.Unlock()
				udpFlowsActive.Add(1)
				dbg("server udp flow %016x -> %d", d.Flow, d.Port)
				go replyPump(sess, d.Flow, f)
			}
			f.last.Store(time.Now().UnixNano())
			if !f.stat.dgramOK(true, len(d.Data)) {
				continue
			}
			f.stat.dgram(true, len(d.Data))
			if _, err := f.conn.Write(d.Data); err != nil {
				f.stat.errs.Add(1)
			}
		}
	}
}

// replyPump sends what the target answers back through the session until the flow's socket is closed.
func replyPump(sess *wat.Session, id uint64, f *sflow) {
	// 4 KB fits DNS (EDNS0 max) and QUIC/WireGuard replies; 4096 flows x 64 KB was a 256 MB-per-session
	// OOM vector (audit 2026-10-22). A larger UDP reply is truncated (UDP has no partial read).
	buf := make([]byte, 4096)
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			// a connected UDP socket reports an earlier ICMP port-unreachable as a read error, and a >4 KB
			// local datagram returns EMSGSIZE/WSAEMSGSIZE (the reply is truncated or dropped): keep the flow alive.
			msg := err.Error()
			if strings.Contains(msg, "refused") || strings.Contains(msg, "forcibly closed") {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			if strings.Contains(msg, "message too long") || strings.Contains(msg, "larger than the internal message buffer") {
				continue
			}
			return
		}
		f.last.Store(time.Now().UnixNano())
		if f.stat.dgramOK(false, n) {
			f.stat.dgram(false, n)
			sess.SendDatagram(id, f.port, buf[:n])
		}
	}
}

// parseUDPMap parses one -udp entry: PORT or listen:server, optionally @bindaddr; offset is -port-offset.
func parseUDPMap(m, defBind string, offset int) (addr string, target int, err error) {
	bind, orig := strings.Trim(strings.TrimSpace(defBind), "[]"), m
	if at := strings.IndexByte(m, '@'); at >= 0 {
		bind, m = strings.Trim(strings.TrimSpace(m[at+1:]), "[]"), m[:at]
	}
	lp, sp := m, m
	if i := strings.IndexByte(m, ':'); i >= 0 {
		lp, sp = m[:i], m[i+1:]
	}
	l, e1 := strconv.Atoi(strings.TrimSpace(lp))
	t, e2 := strconv.Atoi(strings.TrimSpace(sp))
	pub := l + offset
	if e1 != nil || e2 != nil || l < 1 || l > 65535 || t < 1 || t > 65535 || pub < 1 || pub > 65535 {
		return "", 0, fmt.Errorf("bad -udp entry %q", orig)
	}
	return net.JoinHostPort(bind, strconv.Itoa(pub)), t, nil
}
