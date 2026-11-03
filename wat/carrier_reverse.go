package wat

import "net"

// Reverse mode: the pool carriers with the transport direction swapped. The session roles stay the same (the Iran
// side is the session client that opens streams, the Kharej side is the session server), but the Kharej side DIALS
// out and the Iran side LISTENS, for networks where only outbound connections to Iran work. Nothing is copied: the
// listener is the normal TCPPoolServer (all conns merged into one pool) and the dialer the normal TCPPoolClient
// (redial/backoff, N conns). The session's AEAD drops foreign packets, so any stranger who connects to the listener
// only occupies one of the 64 capped slots.

const reverseKey = "reverse"

// ReverseListenIO is the PacketIO of the session client when the pool listener lives on its side.
type ReverseListenIO struct{ ps *TCPPoolServer }

// NewReverseListenIO turns a pool listener (tcp, tls, ws, wss, h2, h2c or grpc server) into the session client's
// PacketIO. Call it before any peer can reach the listener.
func NewReverseListenIO(ps *TCPPoolServer) *ReverseListenIO {
	ps.merge.Store(true)
	return &ReverseListenIO{ps: ps}
}

func (r *ReverseListenIO) Send(p []byte, path int) error {
	return r.ps.SendTo(p, path, poolAddr{key: reverseKey})
}

// PeerAuthenticated pins the merged reverse pool to a source address that delivered a packet the session could
// authenticate. Without it, any stranger who opened a TCP connection to the listener joined the one pool, received
// the tunnel's packets (the send side picks the least-queued connection) and could hold every slot.
func (r *ReverseListenIO) PeerAuthenticated(a net.Addr) {
	pa, ok := a.(poolAddr)
	if !ok || pa.ip == "" {
		return
	}
	r.ps.addTrustedIP(pa.ip)
}

func (r *ReverseListenIO) Recv() ([]byte, int, net.Addr, error) { return r.ps.Recv() }
func (r *ReverseListenIO) SetPeer(net.Addr)                     {}
func (r *ReverseListenIO) Close() error                         { return r.ps.Close() }

// Conns reports how many dialed-in connections are up; Addr is the bound address.
func (r *ReverseListenIO) Conns() int     { return r.ps.Conns() }
func (r *ReverseListenIO) Addr() net.Addr { return r.ps.Addr() }

// ReverseDialRaw is the RawIO of the session server when it dials the pool out: one pool, one fixed source address.
type ReverseDialRaw struct{ c *TCPPoolClient }

// NewReverseDialRaw wraps a pool client (any NewXxxPoolClient) as the session server's RawIO.
func NewReverseDialRaw(c *TCPPoolClient) *ReverseDialRaw { return &ReverseDialRaw{c: c} }

func (r *ReverseDialRaw) Recv() ([]byte, int, net.Addr, error) { return r.c.Recv() }
func (r *ReverseDialRaw) SendTo(p []byte, lane int, _ net.Addr) error {
	return r.c.Send(p, lane)
}
func (r *ReverseDialRaw) Close() error { return r.c.Close() }

// Conns reports how many outbound connections are up.
func (r *ReverseDialRaw) Conns() int { return r.c.Conns() }

// Both reverse wrappers report the pool's backlog and carry its profile.
func (r *ReverseListenIO) Backlogged() bool            { return r.ps.BackloggedTo(poolAddr{key: reverseKey}) }
func (r *ReverseDialRaw) BackloggedTo(_ net.Addr) bool { return r.c.Backlogged() }

func (r *ReverseListenIO) Profile() Profile { return r.ps.Profile() }
func (r *ReverseDialRaw) Profile() Profile  { return r.c.Profile() }
