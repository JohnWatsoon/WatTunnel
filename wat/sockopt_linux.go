//go:build linux

package wat

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// setNotsentLowat caps how much unsent data the kernel queues on a pool socket, so the writer blocks as soon as the
// connection stops moving instead of after megabytes of tcp_wmem (stall detection, carrier_tcp.go).
func setNotsentLowat(tc *net.TCPConn, n int) {
	rc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	rc.Control(func(fd uintptr) { unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n) })
}

// setCongestion switches one socket's TCP congestion control (TCP_CONGESTION). As root the kernel loads the module
// (tcp_bbr) on demand. It returns the algorithm the socket ends up with ("" when it cannot be read).
func setCongestion(tc *net.TCPConn, name string) string {
	rc, err := tc.SyscallConn()
	if err != nil {
		return ""
	}
	var got string
	rc.Control(func(fd uintptr) {
		if name != "" {
			unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, name)
		}
		got, _ = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	})
	return got
}

// setUserTimeout closes the connection once sent data stays unacknowledged for d (TCP_USER_TIMEOUT).
func setUserTimeout(tc *net.TCPConn, d time.Duration) {
	rc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	rc.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(d.Milliseconds()))
	})
}
