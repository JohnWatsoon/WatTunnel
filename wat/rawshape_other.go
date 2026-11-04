//go:build !linux

package wat

import (
	"errors"
	"net"
)

// ShapedRawIO (F19 raw-tier shaped carriers: sit, 6to4, xfrm-ipsec, etherip, l2tpv3) exists on Linux only (raw sockets);
// every constructor fails elsewhere.
type ShapedRawIO struct{}

func NewShapedRaw(name string, server bool, peerIP, srcIP string, key []byte) (*ShapedRawIO, error) {
	return nil, errors.New("the " + name + " (raw-tier shaped) carrier needs Linux with CAP_NET_RAW")
}

func (*ShapedRawIO) Send([]byte, int) error               { return net.ErrClosed }
func (*ShapedRawIO) Recv() ([]byte, int, net.Addr, error) { return nil, 0, nil, net.ErrClosed }
func (*ShapedRawIO) SendTo([]byte, int, net.Addr) error   { return net.ErrClosed }
func (*ShapedRawIO) SetPeer(net.Addr)                     {}
func (*ShapedRawIO) Close() error                         { return nil }
