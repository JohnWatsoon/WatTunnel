package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// The cockpit's way into a running client unit (Handoff 4, R1): the unit owns the ONE scepter stream its session
// allows (sid 0), and a local unix socket lets the manager run commands over it. The old path started a
// second, one-shot tunnel per command: a new session handshake per click, and on a reverse pool carrier the
// one-shot had to bind the listen port the running unit already holds, so it could never work there.

// scepterSockPath is the control socket of the unit whose config is cfgPath: next to the config (/etc/wattun
// is 0700 and writable inside the unit sandbox), so the manager and the -scepter-call fallback derive the same
// name from the same -config.
func scepterSockPath(cfgPath string) string {
	name := strings.TrimSuffix(filepath.Base(cfgPath), filepath.Ext(cfgPath))
	return filepath.Join(filepath.Dir(cfgPath), "."+name+".scepter.sock")
}

// scepterHub serializes every scepter call of this client unit over one ScepterClient: the keep-alive ping and
// the manager's socket requests share the reserved stream, and the client's decoder is single-reader.
type scepterHub struct {
	mu    sync.Mutex
	dial  func() (*wat.ScepterClient, error)
	c     *wat.ScepterClient
	up    bool // last known channel state, for one log line per change
	logf  func(string, ...any)
	onNew func(*wat.ScepterClient) // a fresh client (after the hello): the claim store hooks in here
}

func (h *scepterHub) callRaw(cmd string, args map[string]any, id string, w io.Writer) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.c == nil {
		c, err := h.dial()
		if err != nil {
			if c != nil {
				c.Abort()
			}
			h.mark(false, err)
			return wat.CodeInternal, err
		}
		h.c = c
		if h.onNew != nil {
			h.onNew(c)
		}
	}
	code, err := h.c.CallRaw(cmd, args, id, w)
	if err != nil {
		h.c.Abort()
		h.c = nil
		h.mark(false, err)
		return code, err
	}
	h.mark(true, nil)
	return code, nil
}

func (h *scepterHub) mark(up bool, err error) {
	if up == h.up {
		return
	}
	h.up = up
	if up {
		h.logf("scepter: channel up")
	} else {
		h.logf("scepter: channel down (%v); the tunnel keeps running", err)
	}
}

// keepAlive pings every 30 s: it keeps the channel warm and re-dials after a session or channel drop.
func (h *scepterHub) keepAlive(done <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		h.callRaw("scepter.ping", nil, "", io.Discard)
		select {
		case <-done:
			return
		case <-t.C:
		}
	}
}

// scepterSockReq is one socket request: the -scepter-call contract (cmd, args, optional id for retries).
type scepterSockReq struct {
	Cmd  string         `json:"cmd"`
	Args map[string]any `json:"args,omitempty"`
	ID   string         `json:"id,omitempty"`
}

// scepterSockErr is the line the socket writes instead of an answer when the channel failed; -scepter-call
// turns it into its exit 1 + stderr (the manager's transport-failure contract).
type scepterSockErr struct {
	Err string `json:"transport_error"`
}

// serveScepterSock listens on path (mode 0600) and answers one request per connection.
func serveScepterSock(path string, h *scepterHub) (io.Closer, error) {
	_ = os.Remove(path) // a stale socket from a killed unit
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// the config dir is 0700 already; 0600 on the socket is the second fence (Windows dev boxes cannot chmod one)
	if err := os.Chmod(path, 0o600); err != nil && runtime.GOOS != "windows" {
		l.Close()
		return nil, err
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go serveScepterConn(conn, h)
		}
	}()
	return l, nil
}

func serveScepterConn(conn net.Conn, h *scepterHub) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Minute)) // a call waits behind at most a few 30 s calls
	br := bufio.NewReaderSize(conn, 64<<10)
	line, err := br.ReadSlice('\n')
	if err != nil {
		return
	}
	var req scepterSockReq
	if json.Unmarshal(line, &req) != nil || req.Cmd == "" {
		json.NewEncoder(conn).Encode(scepterSockErr{"bad request"})
		return
	}
	var out strings.Builder // buffered: a transport error must not leave a half answer behind it
	if _, err := h.callRaw(req.Cmd, req.Args, req.ID, &out); err != nil && out.Len() == 0 {
		json.NewEncoder(conn).Encode(scepterSockErr{err.Error()})
		return
	}
	io.WriteString(conn, out.String())
}

// errNoSock: no unit listens on the socket (not running, or an older binary without one).
var errNoSock = errors.New("no running unit socket")

// scepterCallSock runs one command through a running unit's socket and copies the answer lines to w.
func scepterCallSock(path, cmd string, args map[string]any, id string, w io.Writer) error {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return errNoSock
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Minute))
	b, _ := json.Marshal(scepterSockReq{Cmd: cmd, Args: args, ID: id})
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return err
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		var te scepterSockErr
		if json.Unmarshal(sc.Bytes(), &te) == nil && te.Err != "" {
			return errors.New(te.Err)
		}
		fmt.Fprintf(w, "%s\n", sc.Bytes())
		n++
	}
	if n == 0 {
		return errors.New("the unit closed without an answer")
	}
	return nil
}

// startScepterClient wires a paired client unit: the hub, its keep-alive and (with a config file) the socket.
func startScepterClient(tun *tunnel, cfgPath string, onNew func(*wat.ScepterClient)) *scepterHub {
	h := &scepterHub{dial: func() (*wat.ScepterClient, error) { return wat.DialScepter(tun.pick()) }, logf: log.Printf, onNew: onNew}
	go h.keepAlive(nil)
	if cfgPath != "" {
		p := scepterSockPath(cfgPath)
		if _, err := serveScepterSock(p, h); err != nil {
			log.Printf("scepter: control socket %s: %v (the cockpit falls back to a one-shot dial)", p, err)
		}
	}
	return h
}
