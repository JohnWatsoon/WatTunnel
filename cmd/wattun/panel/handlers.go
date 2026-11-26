package panel

// Phase-1 handlers adapted to the route table, and the panel audit log.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// body puts the already-read request body back for the handlers that read r.Body themselves.
func (c *call) body2r() *http.Request {
	c.r.Body = io.NopCloser(bytes.NewReader(c.body))
	return c.r
}

func (s *Server) apiMe(c *call) {
	cfg := s.conf()
	c.ok(map[string]any{"user": cfg.User, "twofa": cfg.TOTP != "", "recovery_left": len(cfg.Recovery), "title": cfg.Title, "cli": cliName,
		"product": product, "repo": productRepo})
}

func (s *Server) apiOverviewR(c *call) { s.apiOverview(c.w) }
func (s *Server) apiLiveR(c *call)     { s.apiLive(c.w, c.r) }

func (s *Server) apiLogout(c *call) {
	s.g.drop(c.r)
	setCookie(c.w, s.cookiePath(), "", -1)
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) apiLogoutAll(c *call) {
	s.g.dropAll()
	setCookie(c.w, s.cookiePath(), "", -1)
	s.audit(c, "sign out everywhere", "", "ok")
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) api2FASetupR(c *call) { s.api2FASetup(c.w) }
func (s *Server) api2FAEnableR(c *call) {
	s.api2FAEnable(c.w, c.body2r())
	s.audit(c, "2fa on", "", "")
}
func (s *Server) api2FADisableR(c *call) {
	s.api2FADisable(c.w, c.body2r())
	s.audit(c, "2fa off", "", "")
}
func (s *Server) apiPasswordR(c *call) {
	s.apiPassword(c.w, c.body2r())
	s.audit(c, "password", "", "")
}

func (s *Server) apiSessions(c *call) { c.ok(map[string]any{"sessions": s.g.list(c.r)}) }

func (s *Server) apiSessionDrop(c *call) {
	if !s.g.dropID(c.arg[0]) {
		c.fail(http.StatusNotFound, "no such session")
		return
	}
	s.audit(c, "sign out a session", c.arg[0], "ok")
	c.ok(map[string]bool{"ok": true})
}

// ---- audit: every change, who, from where, what came of it (features §2) ----

type auditRow struct {
	T      int64  `json:"t"`
	User   string `json:"user"`
	IP     string `json:"ip"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Result string `json:"result,omitempty"`
}

var auditMu sync.Mutex

func (s *Server) audit(c *call, action, target, result string) {
	if s.dataDir == "" {
		return
	}
	row := auditRow{T: time.Now().Unix(), IP: c.ip, Action: action, Target: target, Result: result}
	if c.sess != nil {
		row.User = c.sess.User
	}
	b, _ := json.Marshal(row)
	auditMu.Lock()
	defer auditMu.Unlock()
	f := filepath.Join(s.dataDir, "audit.jsonl")
	if fi, err := os.Stat(f); err == nil && fi.Size() > 5<<20 {
		os.Rename(f, f+".1")
	}
	if fh, err := os.OpenFile(f, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		fh.Write(append(b, '\n'))
		fh.Close()
	}
}

func (s *Server) apiAudit(c *call) {
	rows := []auditRow{}
	readJSONL(filepath.Join(s.dataDir, "audit.jsonl"), func(b []byte) {
		var r auditRow
		if json.Unmarshal(b, &r) == nil {
			rows = append(rows, r)
		}
	})
	if len(rows) > 300 {
		rows = rows[len(rows)-300:]
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	c.ok(map[string]any{"rows": rows})
}

func readJSONL(file string, fn func([]byte)) {
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fn(sc.Bytes())
	}
}

func appendJSONL(file string, v any) {
	b, _ := json.Marshal(v)
	if fh, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		fh.Write(append(b, '\n'))
		fh.Close()
	}
}
