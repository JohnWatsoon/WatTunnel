//go:build !linux

package wat

import (
	"errors"
	"net"
)

// RawIPIO (gre/ipip) exists on Linux only (raw sockets + BPF); every constructor fails elsewhere.
type RawIPIO struct{}

func NewRawIPIO(gre, server bool, peerIP, srcIP string, key []byte) (*RawIPIO, error) {
	return nil, errors.New("the gre and ipip carriers need Linux")
}

func (*RawIPIO) Send([]byte, int) error               { return net.ErrClosed }
func (*RawIPIO) Recv() ([]byte, int, net.Addr, error) { return nil, 0, nil, net.ErrClosed }
func (*RawIPIO) SendTo([]byte, int, net.Addr) error   { return net.ErrClosed }
func (*RawIPIO) SetPeer(net.Addr)                     {}
func (*RawIPIO) Close() error                         { return nil }
