package panel

// The API is one table: every route names its tier, and one gate checks it (plan "every panel API route maps to a
// scepter command or a manager function": the table test walks this list).
//   read   any signed-in session
//   manage any signed-in session; the change is audited
//   full   the request carries the password again, plus a fresh 2FA code when 2FA is on (features §2): a stolen
//          session cookie never reaches a full action; with 2FA on, a stolen password without the phone neither.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

type tier int

const (
	tierRead tier = iota
	tierManage
	tierFull
)

type call struct {
	w    http.ResponseWriter
	r    *http.Request
	sess *session
	ip   string
	arg  []string // the * segments of the pattern, in order
	body []byte
}

func (c *call) json(v any) error {
	if len(c.body) == 0 {
		return nil
	}
	return json.Unmarshal(c.body, v)
}

func (c *call) ok(v any)                { writeJSON(c.w, http.StatusOK, v) }
func (c *call) fail(code int, m string) { writeJSON(c.w, code, map[string]string{"error": m}) }

type route struct {
	method, pattern string
	tier            tier
	maxBody         int64
	h               func(s *Server, c *call)
}

// routes: pattern segments "*" match one path segment. Order matters only for overlapping patterns.
var routes = []route{
	{"GET", "me", tierRead, 0, (*Server).apiMe},
	{"GET", "overview", tierRead, 0, (*Server).apiOverviewR},
	{"GET", "live", tierRead, 0, (*Server).apiLiveR},
	{"POST", "logout", tierRead, 0, (*Server).apiLogout},
	{"POST", "logout-all", tierRead, 0, (*Server).apiLogoutAll},
	{"GET", "tunnels/*/history", tierRead, 0, (*Server).apiHistory},
	{"GET", "tunnels/*/logs", tierRead, 0, (*Server).apiLogs},

	// phase 2: actions
	{"POST", "tunnels/*/start", tierManage, 0, (*Server).apiUnit},
	{"POST", "tunnels/*/stop", tierManage, 0, (*Server).apiUnit},
	{"POST", "tunnels/*/restart", tierManage, 0, (*Server).apiUnit},
	{"POST", "bulk", tierManage, 0, (*Server).apiBulk},
	{"PUT", "tunnels/*/ports", tierManage, 0, (*Server).apiPorts},
	{"PUT", "tunnels/*/limit", tierManage, 0, (*Server).apiLimit},
	{"POST", "tunnels/*/speedtest", tierManage, 0, (*Server).apiSpeedTest},
	{"POST", "tunnels/*/retest", tierManage, 0, (*Server).apiRetest},
	{"POST", "tunnels/*/use", tierManage, 0, (*Server).apiUse},
	{"GET", "tunnels/*/paths", tierRead, 0, (*Server).apiPaths},
	{"GET", "tunnels/*/settings", tierRead, 0, (*Server).apiTunnelSettings},
	{"GET", "tunnels/*/carriers", tierRead, 0, (*Server).apiCarriers},
	{"POST", "tunnels/*/move-ports", tierManage, 0, (*Server).apiMovePorts},
	{"POST", "tunnels/*/tool", tierManage, 0, (*Server).apiTunnelTool},
	{"POST", "server-tool", tierManage, 0, (*Server).apiServerTool},
	{"PUT", "tunnels/*/settings", tierManage, 0, (*Server).apiTunnelSettingsSet},
	{"POST", "tunnels/*/boot", tierManage, 0, (*Server).apiBoot},
	{"POST", "tunnels/*/ac-preset", tierManage, 0, (*Server).apiACPreset},
	{"POST", "tunnels/*/ac-test", tierManage, 0, (*Server).apiACTest},
	{"POST", "tunnels/*/diagnose", tierManage, 0, (*Server).apiDiagnose},
	{"POST", "tunnels/*/bond-mode", tierManage, 0, (*Server).apiBondMode},
	{"POST", "tunnels/*/mute", tierManage, 0, (*Server).apiMute},
	{"POST", "tunnels/*/token", tierFull, 0, (*Server).apiToken},
	{"POST", "tunnels/*/delete", tierFull, 0, (*Server).apiDelete},
	{"GET", "tunnels/*/ports", tierRead, 0, (*Server).apiTunnelPorts},
	{"POST", "tunnels/*/quota-reset", tierManage, 0, (*Server).apiQuotaReset},
	{"POST", "tunnels/*/pair-forget", tierFull, 0, (*Server).apiPairForget},
	{"POST", "kharej/*/pair-rotate", tierFull, 0, (*Server).apiPairRotate},
	{"POST", "kharej/*/delete", tierFull, 0, (*Server).apiKharejDelete},
	{"POST", "kharej/*/remove", tierFull, 0, (*Server).apiKharejRemove},
	{"POST", "kharej-add", tierFull, 0, (*Server).apiKharejAdd},
	{"GET", "pairing", tierRead, 0, (*Server).apiPairing},
	{"POST", "pairing", tierFull, 0, (*Server).apiPairingMake},
	{"POST", "new", tierManage, 0, (*Server).apiNew},
	{"POST", "kharej/*/tunnel", tierManage, 0, (*Server).apiKharejUnit},
	{"POST", "kharej/*/keyrotate", tierFull, 0, (*Server).apiKharejKeyRotate},
	{"POST", "kharej/*/update", tierFull, 0, (*Server).apiKharejUpdate},
	{"POST", "kharej/*/backup", tierFull, 0, (*Server).apiKharejBackup},
	{"GET", "kharej/*/status", tierRead, 0, (*Server).apiKharejStatus},
	{"GET", "kharej/*/audit", tierRead, 0, (*Server).apiKharejAudit},
	{"POST", "update", tierFull, 0, (*Server).apiUpdateHere},
	{"POST", "update-all", tierFull, 0, (*Server).apiUpdateAll},
	{"POST", "rollback", tierFull, 0, (*Server).apiRollback},
	{"GET", "backups", tierRead, 0, (*Server).apiBackups},
	{"POST", "backups", tierManage, 0, (*Server).apiBackupNow},
	{"POST", "backups/*/download", tierFull, 0, (*Server).apiBackupGet},
	{"POST", "backups/*/delete", tierManage, 0, (*Server).apiBackupDel},
	{"POST", "restore", tierFull, 12 << 20, (*Server).apiRestore},
	{"POST", "restore/preview", tierManage, 12 << 20, (*Server).apiRestorePreview},
	{"GET", "jobs", tierRead, 0, (*Server).apiJobs},
	{"GET", "jobs/*", tierRead, 0, (*Server).apiJob},
	{"POST", "jobs/*/ctl", tierManage, 0, (*Server).apiJobCtl},

	// phase 3: traffic, alerts, schedules
	{"GET", "traffic", tierRead, 0, (*Server).apiTraffic},
	{"GET", "traffic.csv", tierRead, 0, (*Server).apiTrafficCSV},
	{"GET", "speedtests", tierRead, 0, (*Server).apiSpeedTests},
	{"GET", "alerts", tierRead, 0, (*Server).apiAlerts},
	{"GET", "audit", tierRead, 0, (*Server).apiAudit},

	// settings (account: phase 1; panel, certificate, allowlist, alerts: phase 4)
	{"GET", "settings", tierRead, 0, (*Server).apiSettings},
	{"PUT", "settings/alerts", tierManage, 0, (*Server).apiSettingsAlerts},
	{"PUT", "settings/panel", tierFull, 0, (*Server).apiSettingsPanel},
	{"POST", "settings/cert", tierFull, 64 << 10, (*Server).apiCertOwner},
	{"POST", "settings/cert/self", tierFull, 0, (*Server).apiCertSelf},
	{"POST", "settings/cert/ca", tierFull, 0, (*Server).apiCertCA},
	{"POST", "settings/cert/acme", tierFull, 0, (*Server).apiCertACME},
	{"GET", "settings/ca.crt", tierRead, 0, (*Server).apiCACert},
	{"GET", "settings/random-port", tierRead, 0, (*Server).apiRandomPort},
	{"GET", "settings/sessions", tierRead, 0, (*Server).apiSessions},
	{"POST", "settings/sessions/*/drop", tierManage, 0, (*Server).apiSessionDrop},
	{"POST", "settings/2fa/setup", tierRead, 0, (*Server).api2FASetupR},
	{"POST", "settings/2fa/enable", tierRead, 0, (*Server).api2FAEnableR},
	{"POST", "settings/2fa/disable", tierRead, 0, (*Server).api2FADisableR},
	{"POST", "settings/password", tierRead, 0, (*Server).apiPasswordR},
}

// match reports whether PATH fits PATTERN and returns the * segments.
func match(pattern, path string) ([]string, bool) {
	ps, xs := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(ps) != len(xs) {
		return nil, false
	}
	var arg []string
	for i := range ps {
		switch {
		case ps[i] == "*":
			if xs[i] == "" {
				return nil, false
			}
			arg = append(arg, xs[i])
		case ps[i] != xs[i]:
			return nil, false
		}
	}
	return arg, true
}

// dispatch runs the route for a signed-in session.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, path, ip string, sess *session) {
	known := false
	for _, rt := range routes {
		arg, ok := match(rt.pattern, path)
		if !ok {
			continue
		}
		known = true
		if rt.method != r.Method {
			continue
		}
		c := &call{w: w, r: r, sess: sess, ip: ip, arg: arg}
		if r.Method != http.MethodGet {
			limit := rt.maxBody
			if limit == 0 {
				limit = 64 << 10
			}
			b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
			if err != nil {
				c.fail(http.StatusRequestEntityTooLarge, "request too large")
				return
			}
			c.body = b
		}
		if rt.tier == tierFull && !s.reauth(c) {
			return
		}
		rt.h(s, c)
		return
	}
	if known {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "wrong method"})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such call"})
}

// reauth checks the password, and a fresh 2FA code when 2FA is on, carried in a full-tier request. With 2FA off it
// asked for a code the owner never set up (3.6.1: it refused outright, so the panel's own buttons were dead). Failures count toward the ban
// like a failed sign-in (a stolen cookie must not brute-force the password here) and answer 403, not 401, so
// the page asks again instead of signing out.
func (s *Server) reauth(c *call) bool {
	var in struct {
		Pass string `json:"password"`
		Code string `json:"code"`
	}
	c.json(&in)
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	cfg := s.cfg
	if cfg.TOTP == "" {
		if !checkPassword(cfg, cfg.User, in.Pass) {
			s.g.fail(c.ip)
			s.audit(c, "reauth", "", "refused")
			writeJSON(c.w, http.StatusForbidden, map[string]any{"error": "The password is wrong.", "reauth": true})
			return false
		}
		return true
	}
	step, codeOK := VerifyTOTP(cfg.TOTP, in.Code, time.Now(), cfg.TOTPLast)
	if !checkPassword(cfg, cfg.User, in.Pass) || !codeOK {
		s.g.fail(c.ip)
		s.audit(c, "reauth", "", "refused")
		writeJSON(c.w, http.StatusForbidden, map[string]any{"error": "Password or code is wrong.", "reauth": true})
		return false
	}
	cfg.TOTPLast = step
	cfg.Save()
	return true
}
