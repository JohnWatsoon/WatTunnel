package panel

// Phase 2: actions. Every one calls the console's own function (Backend) or runs the console's unattended
// command as a job (Backend.ManagerArgv); nothing here knows how a tunnel is built.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)

// domainRe: a DNS name with at least one dot (the Cloudflare domain of an auto tunnel).
var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func (s *Server) tunnel(name string) (Tunnel, bool) {
	for _, t := range s.be.Tunnels() {
		if t.Name == name {
			return t, true
		}
	}
	return Tunnel{}, false
}

func (s *Server) kharejSnap() []Kharej {
	s.khMu.Lock()
	defer s.khMu.Unlock()
	return s.kh
}

// lastLink: NAME is the only running paired tunnel to its Kharej, so stopping, deleting or re-keying it cuts the
// panel off from that Kharej (features §3.3). Returns the Kharej host when so.
func (s *Server) lastLink(name string) (string, bool) {
	t, ok := s.tunnel(name)
	if !ok || t.Role != "Iran" || !t.Paired || !t.Active {
		return "", false
	}
	active := map[string]bool{}
	for _, x := range s.be.Tunnels() {
		active[x.Name] = x.Active
	}
	for _, k := range s.kharejSnap() {
		mine, up := false, 0
		for _, v := range k.Via {
			if v == name {
				mine = true
			}
			if active[v] {
				up++
			}
		}
		if mine {
			return k.Host, up <= 1
		}
	}
	return "", false
}

// guardLast answers 409 with the warning unless CONFIRM is the tunnel's name.
func (s *Server) guardLast(c *call, name, confirm string) bool {
	host, last := s.lastLink(name)
	if !last || confirm == name {
		return true
	}
	writeJSON(c.w, http.StatusConflict, map[string]any{"lastlink": true, "name": name, "host": host,
		"error": "This is the last link to " + host + ". After this, " + host + " can only be managed from its own console. Type the tunnel name to go ahead."})
	return false
}

func lastSeg(p string) string { return p[strings.LastIndex(p, "/")+1:] }

func (s *Server) apiUnit(c *call) {
	name, action := c.arg[0], lastSeg(c.r.URL.Path)
	var in struct{ Confirm string }
	c.json(&in)
	if _, ok := s.tunnel(name); !ok {
		c.fail(http.StatusNotFound, "no such tunnel")
		return
	}
	if action == "stop" && !s.guardLast(c, name, in.Confirm) {
		return
	}
	err := s.be.Unit(name, action)
	s.audit(c, action, name, errText(err))
	if err != nil {
		c.fail(http.StatusInternalServerError, err.Error())
		return
	}
	c.ok(map[string]bool{"ok": true})
}

func errText(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}

func (s *Server) apiBulk(c *call) {
	var in struct {
		Action  string
		Names   []string
		Confirm []string
	}
	if c.json(&in) != nil || (in.Action != "start" && in.Action != "stop" && in.Action != "restart") {
		c.fail(http.StatusBadRequest, "action is start, stop or restart")
		return
	}
	if len(in.Names) == 0 {
		for _, t := range s.be.Tunnels() {
			in.Names = append(in.Names, t.Name)
		}
	}
	confirmed := map[string]bool{}
	for _, n := range in.Confirm {
		confirmed[n] = true
	}
	if in.Action == "stop" {
		for _, n := range in.Names {
			ok := ""
			if confirmed[n] {
				ok = n
			}
			if !s.guardLast(c, n, ok) {
				return
			}
		}
	}
	res := map[string]string{}
	for _, n := range in.Names {
		if _, ok := s.tunnel(n); !ok {
			res[n] = "no such tunnel"
			continue
		}
		res[n] = errText(s.be.Unit(n, in.Action))
	}
	s.audit(c, "bulk "+in.Action, strings.Join(in.Names, ","), fmt.Sprint(res))
	c.ok(map[string]any{"results": res})
}

func (s *Server) apiPorts(c *call) {
	var in struct{ Ports []string }
	if c.json(&in) != nil {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	if _, ok := s.tunnel(c.arg[0]); !ok {
		c.fail(http.StatusNotFound, "no such tunnel")
		return
	}
	err := s.be.SetPorts(c.arg[0], in.Ports)
	s.audit(c, "ports", c.arg[0], errText(err))
	if err != nil {
		c.fail(http.StatusBadRequest, err.Error())
		return
	}
	c.ok(map[string]any{"ok": true, "note": "Saved. The tunnel picks the new ports up within a few seconds, no restart."})
}

func (s *Server) apiLimit(c *call) {
	var in struct{ Port, Rate, Quota, Period string }
	if c.json(&in) != nil {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	if _, ok := s.tunnel(c.arg[0]); !ok {
		c.fail(http.StatusNotFound, "no such tunnel")
		return
	}
	err := s.be.SetLimit(c.arg[0], in.Port, in.Rate, in.Quota, in.Period)
	s.audit(c, "limit", c.arg[0]+":"+in.Port, errText(err))
	if err != nil {
		c.fail(http.StatusBadRequest, err.Error())
		return
	}
	c.ok(map[string]bool{"ok": true})
}

// ---- speed tests ----

type speedRun struct {
	T       int64   `json:"t"`
	Name    string  `json:"name"`
	Carrier string  `json:"carrier"`
	MB      int     `json:"mb"`
	Down    float64 `json:"down"` // MB/s, 0 = failed
	Up      float64 `json:"up"`
	Error   string  `json:"error,omitempty"`
	Auto    bool    `json:"auto,omitempty"` // scheduled
}

func (s *Server) runSpeedTest(t Tunnel, mb int, auto bool, say func(string, ...any)) error {
	run := speedRun{T: time.Now().Unix(), Name: t.Name, Carrier: t.Carrier, MB: mb, Auto: auto}
	// a stopped or unlinked tunnel cannot be measured: say so now instead of after a minute of "connection refused"
	if !t.Active {
		return fmt.Errorf("%s is stopped: start it, then run the test", t.Name)
	}
	if c, ok := s.be.Stats(t.Name); ok && !c.Alive {
		return fmt.Errorf("%s has no session with Kharej right now: the test needs a live link (Re-test carriers, or check the journal)", t.Name)
	}
	var errs []string
	for _, dir := range []string{"down", "up"} {
		say("%s: %d MB %s ...", t.Name, mb, map[string]string{"down": "download", "up": "upload"}[dir])
		end := s.speedProgress(t.Name, dir, say)
		r, err := s.be.SpeedTest(t.Name, dir, mb)
		end()
		if err != nil || !r.OK {
			// the usual cause of "session closed" / "connection refused" mid-test: the tunnel was stopped or restarted
			if now, ok := s.tunnel(t.Name); ok && !now.Active {
				errs = append(errs, dir+": "+t.Name+" was stopped during the test")
				break
			}
		}
		switch {
		case err != nil:
			errs = append(errs, err.Error())
		case !r.OK:
			errs = append(errs, dir+": "+r.Error)
		default:
			say("%s: %.2f MB/s in %.1f s", dir, r.MBps, r.Seconds)
			if dir == "down" {
				run.Down = r.MBps
			} else {
				run.Up = r.MBps
			}
		}
	}
	run.Error = strings.Join(errs, "; ")
	appendJSONL(filepath.Join(s.dataDir, "speedtests.jsonl"), run)
	if run.Error != "" {
		return fmt.Errorf("%s", run.Error)
	}
	if auto {
		s.speedCheck(t.Name, run.Down, time.Now())
	}
	say("RESULT=%.2f/%.2f", run.Down, run.Up)
	return nil
}

// speedProgress says, once a second while one direction runs, the rate the tunnel moves in that direction and
// the MB so far, as PROG=dir|MB/s|MB (the dialog draws it; the rate includes any user traffic at the time).
func (s *Server) speedProgress(name, dir string, say func(string, ...any)) (end func()) {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		prev, ok := s.be.Stats(name)
		if !ok {
			return
		}
		pick := func(c Counters) float64 {
			if dir == "down" {
				return c.BytesIn
			}
			return c.BytesOut
		}
		start, last := pick(prev), time.Now()
		tk := time.NewTicker(time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			c, ok := s.be.Stats(name)
			if !ok || pick(c) < pick(prev) {
				continue
			}
			now := time.Now()
			say("PROG=%s|%.2f|%.1f", dir, (pick(c)-pick(prev))/now.Sub(last).Seconds()/1048576, (pick(c)-start)/1048576)
			prev, last = c, now
		}
	}()
	return func() { close(stop); <-done } // no PROG line after the result
}

// speedMB reads {"mb": N} from a speed-test request. The dialog's field sends the number as a string ("100"):
// decoding into an int failed silently and every test ran the 10 MB default.
func speedMB(body []byte) int {
	var in struct {
		MB json.Number `json:"mb"`
	}
	json.Unmarshal(body, &in)
	mb, err := strconv.Atoi(in.MB.String())
	if err != nil || mb <= 0 || mb > 500 {
		return 10
	}
	return mb
}

func (s *Server) apiSpeedTest(c *call) {
	mb := speedMB(c.body)
	t, ok := s.tunnel(c.arg[0])
	if !ok || t.Role != "Iran" {
		c.fail(http.StatusBadRequest, "The speed test runs on Iran tunnels of this server.")
		return
	}
	id, err := s.jobs.do("speedtest", "Speed test of "+t.Name, c.sess.User, func(say func(string, ...any)) error {
		return s.runSpeedTest(t, mb, false, say)
	})
	s.jobReply(c, "speed test", t.Name, id, err)
}

func (s *Server) apiSpeedTests(c *call) {
	rows := []speedRun{}
	readJSONL(filepath.Join(s.dataDir, "speedtests.jsonl"), func(b []byte) {
		var r speedRun
		if json.Unmarshal(b, &r) == nil {
			rows = append(rows, r)
		}
	})
	if len(rows) > 200 {
		rows = rows[len(rows)-200:]
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].T > rows[j].T })
	c.ok(map[string]any{"rows": rows})
}

func (s *Server) jobReply(c *call, action, target, id string, err error) {
	s.audit(c, action, target, "job "+id+" "+errText(err))
	if err != nil {
		c.fail(http.StatusInternalServerError, err.Error())
		return
	}
	c.ok(map[string]string{"job": id})
}

func (s *Server) apiRetest(c *call) {
	t, ok := s.tunnel(c.arg[0])
	if !ok || t.Role != "Iran" {
		c.fail(http.StatusBadRequest, "Carrier re-tests run on Iran tunnels made from an auto token.")
		return
	}
	var in struct{ Test, Pick string }
	if c.json(&in) != nil || !testPresets[in.Test] || !picks[in.Pick] {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	a := []string{"auto-test", t.Name, "--yes"}
	if in.Test != "" {
		a = append(a, "--test", in.Test)
	}
	if in.Pick != "" {
		a = append(a, "--pick", in.Pick)
	}
	id, err := s.jobs.run("retest", "Re-test the carriers of "+t.Name, c.sess.User, s.be.ManagerArgv(a...))
	s.jobReply(c, "carrier re-test", t.Name, id, err)
}

var (
	testPresets = map[string]bool{"": true, "normal": true, "fast": true, "anti": true, "reverse": true, "extended": true}
	picks       = map[string]bool{"": true, "best": true, "bond": true}
	labelRe     = regexp.MustCompile(`^[A-Za-z0-9 :./_+()-]{1,64}$`) // "l2tpv3 (shape only)"
)

// apiUse switches an auto Iran tunnel to rows of a finished carrier test (two or more = a bond), no re-test.
func (s *Server) apiUse(c *call) {
	t, ok := s.tunnel(c.arg[0])
	var in struct{ Labels []string }
	if !ok || t.Role != "Iran" || c.json(&in) != nil || len(in.Labels) == 0 || len(in.Labels) > 8 {
		c.fail(http.StatusBadRequest, "Pick one tested carrier, or several to bond them.")
		return
	}
	for _, l := range in.Labels {
		if !labelRe.MatchString(l) {
			c.fail(http.StatusBadRequest, "bad carrier label")
			return
		}
	}
	what := strings.Join(in.Labels, " + ")
	id, err := s.jobs.run("use", "Switch "+t.Name+" to "+what, c.sess.User, s.be.ManagerArgv("auto-use", t.Name, strings.Join(in.Labels, ","), "--yes"))
	s.jobReply(c, "switch carrier "+what, t.Name, id, err)
}

// The Settings tab (4.0.1). Every change goes through the console's own checks (mgr.ApplySettings, the preset
// and diagnose commands); the panel only shows the choices.
func (s *Server) apiTunnelSettings(c *call) {
	if _, ok := s.tunnel(c.arg[0]); !ok {
		c.fail(http.StatusNotFound, "no such tunnel")
		return
	}
	c.ok(s.be.Settings(c.arg[0]))
}

func (s *Server) apiTunnelSettingsSet(c *call) {
	var in struct{ Set map[string]string }
	if _, ok := s.tunnel(c.arg[0]); !ok || c.json(&in) != nil || len(in.Set) == 0 || len(in.Set) > 32 {
		c.fail(http.StatusBadRequest, "nothing to change")
		return
	}
	keys := make([]string, 0, len(in.Set))
	for k, v := range in.Set {
		keys = append(keys, k+"="+v)
	}
	sort.Strings(keys)
	err := s.be.ApplySettings(c.arg[0], in.Set)
	s.audit(c, "settings "+strings.Join(keys, " "), c.arg[0], errText(err))
	if err != nil {
		c.fail(http.StatusConflict, err.Error())
		return
	}
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) apiBoot(c *call) {
	var in struct{ On bool }
	if _, ok := s.tunnel(c.arg[0]); !ok || c.json(&in) != nil {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	err := s.be.SetBoot(c.arg[0], in.On)
	s.audit(c, map[bool]string{true: "start at boot", false: "no start at boot"}[in.On], c.arg[0], errText(err))
	if err != nil {
		c.fail(http.StatusInternalServerError, err.Error())
		return
	}
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) apiACPreset(c *call) {
	var in struct{ Preset string }
	if _, ok := s.tunnel(c.arg[0]); !ok || c.json(&in) != nil {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	argv, err := s.be.ACPreset(c.arg[0], in.Preset)
	if err != nil || argv == nil {
		s.audit(c, "anti-censor "+in.Preset+" on Kharej", c.arg[0], errText(err))
		if err != nil {
			c.fail(http.StatusConflict, err.Error())
			return
		}
		c.ok(map[string]bool{"ok": true})
		return
	}
	id, err := s.jobs.run("preset", "Anti-censorship "+in.Preset+" on "+c.arg[0], c.sess.User, s.be.ManagerArgv(argv...))
	s.jobReply(c, "anti-censor "+in.Preset, c.arg[0], id, err)
}

func (s *Server) apiACTest(c *call) {
	if _, ok := s.tunnel(c.arg[0]); !ok {
		c.fail(http.StatusNotFound, "no such tunnel")
		return
	}
	id, err := s.jobs.run("actest", "Anti-censorship test of "+c.arg[0], c.sess.User, s.be.ManagerArgv("test-anticensor", c.arg[0], "--yes"))
	s.jobReply(c, "anti-censor test", c.arg[0], id, err)
}

func (s *Server) apiDiagnose(c *call) {
	if _, ok := s.tunnel(c.arg[0]); !ok {
		c.fail(http.StatusNotFound, "no such tunnel")
		return
	}
	id, err := s.jobs.run("diagnose", "Diagnose "+c.arg[0], c.sess.User, s.be.ManagerArgv("test", c.arg[0]))
	s.jobReply(c, "diagnose", c.arg[0], id, err)
}

// apiMovePorts moves port mappings to another Iran tunnel (4.0.3).
func (s *Server) apiMovePorts(c *call) {
	var in struct {
		To    string
		Ports []string
	}
	if c.json(&in) != nil || len(in.Ports) == 0 {
		c.fail(http.StatusBadRequest, "Tick at least one port.")
		return
	}
	f, ok := s.tunnel(c.arg[0])
	t, ok2 := s.tunnel(in.To)
	if !ok || !ok2 || f.Role != "Iran" || t.Role != "Iran" {
		c.fail(http.StatusBadRequest, "Ports move between two Iran tunnels.")
		return
	}
	err := s.be.MovePorts(f.Name, t.Name, in.Ports)
	s.audit(c, "move-ports", f.Name+" -> "+t.Name+" "+strings.Join(in.Ports, ","), errText(err))
	if err != nil {
		c.fail(http.StatusBadRequest, err.Error())
		return
	}
	c.ok(map[string]any{"ok": true, "note": "Moved to " + t.Name + ". Both tunnels pick it up within a few seconds."})
}

// The manager's tuning tools as panel jobs (4.0.3): each runs unattended and applies its own best result.
var tunnelTools = map[string]struct{ title, cmd string }{
	"acmatrix":     {"Find the best anti-censorship for ", "matrix"},
	"cdntune":      {"Tune the Cloudflare path of ", "cdn-tune"},
	"bondretest":   {"Re-test the bond legs of ", "bond-retest"},
	"resettraffic": {"Reset the traffic counters of ", "reset-traffic"},
}

func (s *Server) apiTunnelTool(c *call) {
	var in struct{ Op string }
	_ = c.json(&in)
	tool, known := tunnelTools[in.Op]
	t, ok := s.tunnel(c.arg[0])
	if !known || !ok || (in.Op != "resettraffic" && t.Role != "Iran") {
		c.fail(http.StatusBadRequest, "That tool runs on an Iran tunnel.")
		return
	}
	id, err := s.jobs.run("tool", tool.title+t.Name, c.sess.User, s.be.ManagerArgv(tool.cmd, t.Name, "--yes"))
	s.jobReply(c, tool.cmd, t.Name, id, err)
}

var serverTools = map[string]struct {
	title string
	argv  []string
}{
	"boost":      {"Kernel speed boost (BBR, 64 MB buffers, FQ)", []string{"boost", "--yes"}},
	"boost-undo": {"Undo the kernel speed boost", []string{"boost", "--undo", "--yes"}},
	"optimize":   {"Re-test every auto tunnel now", []string{"auto-optimize"}},
	"fw-on":      {"Iranian addresses only on the client ports", []string{"iran-firewall", "on", "--yes"}},
	"fw-off":     {"Every address on the client ports", []string{"iran-firewall", "off", "--yes"}},
}

func (s *Server) apiServerTool(c *call) {
	var in struct{ Op string }
	_ = c.json(&in)
	tool, known := serverTools[in.Op]
	if !known {
		c.fail(http.StatusBadRequest, "unknown tool")
		return
	}
	id, err := s.jobs.run("tool", tool.title, c.sess.User, s.be.ManagerArgv(tool.argv...))
	s.jobReply(c, in.Op, "here", id, err)
}

// apiCarriers is the tunnel's last carrier test, kept by the manager, so a switch needs no new test (4.0.2).
func (s *Server) apiCarriers(c *call) {
	t, ok := s.tunnel(c.arg[0])
	if !ok || t.Role != "Iran" {
		c.fail(http.StatusNotFound, "no such Iran tunnel")
		return
	}
	at, preset, rows, use := s.be.Carriers(t.Name)
	if rows == nil {
		rows = []string{}
	}
	c.ok(map[string]any{"at": at, "preset": preset, "rows": rows, "use": use})
}

func (s *Server) apiPaths(c *call) {
	if _, ok := s.tunnel(c.arg[0]); !ok {
		c.fail(http.StatusNotFound, "no such tunnel")
		return
	}
	mode, ps := s.be.Paths(c.arg[0])
	if ps == nil {
		ps = []Path{}
	}
	c.ok(map[string]any{"mode": mode, "paths": ps})
}

func (s *Server) apiBondMode(c *call) {
	t, ok := s.tunnel(c.arg[0])
	var in struct{ Mode string }
	if !ok || c.json(&in) != nil || !map[string]bool{"balanced": true, "active-backup": true, "replicate": true}[in.Mode] {
		c.fail(http.StatusBadRequest, "Mode is balanced, active-backup or replicate.")
		return
	}
	if !strings.Contains(t.Carrier, "+") {
		c.fail(http.StatusBadRequest, "This tunnel has one carrier; bond modes need two or more.")
		return
	}
	id, err := s.jobs.run("bond", "Bond mode of "+t.Name+": "+in.Mode, c.sess.User, s.be.ManagerArgv("bond-mode", t.Name, in.Mode))
	s.jobReply(c, "bond mode "+in.Mode, t.Name, id, err)
}

// apiMute takes one leg of a bond out of use (or back); live, no restart.
func (s *Server) apiMute(c *call) {
	t, ok := s.tunnel(c.arg[0])
	var in struct {
		Path string
		Mute bool
	}
	if !ok || c.json(&in) != nil || !labelRe.MatchString(in.Path) {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	verb := map[bool]string{true: "mute", false: "unmute"}[in.Mute]
	id, err := s.jobs.run("bond", strings.ToUpper(verb[:1])+verb[1:]+" "+in.Path+" on "+t.Name, c.sess.User, s.be.ManagerArgv(verb, t.Name, in.Path))
	s.jobReply(c, verb+" "+in.Path, t.Name, id, err)
}

func (s *Server) apiToken(c *call) {
	tok := s.be.Token(c.arg[0])
	s.audit(c, "show token", c.arg[0], "ok")
	if tok == "" {
		c.fail(http.StatusNotFound, "This tunnel has no saved token.")
		return
	}
	q, err := EncodeQR(tok)
	svg := ""
	if err == nil {
		svg = q.SVG()
	}
	c.ok(map[string]string{"token": tok, "svg": svg})
}

func (s *Server) apiDelete(c *call) {
	var in struct{ Confirm, Kharej string }
	c.json(&in)
	name := c.arg[0]
	if _, ok := s.tunnel(name); !ok {
		c.fail(http.StatusNotFound, "no such tunnel")
		return
	}
	if !s.guardLast(c, name, in.Confirm) {
		return
	}
	if in.Kharej != "" { // delete on Kharej too: first, while this tunnel's channel still exists
		host := s.hostOf(name)
		if host == "" || !nameRe.MatchString(in.Kharej) {
			c.fail(http.StatusBadRequest, "This tunnel has no pairing to delete through.")
			return
		}
		if s.kharejDelete(c, host, in.Kharej) != nil {
			return
		}
	}
	id, err := s.jobs.run("delete", "Delete "+name, c.sess.User, s.be.ManagerArgv("delete", name, "--yes"))
	s.jobReply(c, "delete", name, id, err)
}

// ---- new tunnel ----

var kharejCarriers = map[string]bool{"auto": true, "wss": true, "grpc": true, "tcp": true, "tls": true, "ws": true,
	"h2": true, "h2c": true, "udp": true, "icmp": true, "ptcp": true, "spray": true, "gre": true, "ipip": true,
	"reverse-tcp": true, "reverse-tls": true, "reverse-wss": true, "reverse-ws": true, "reverse-grpc": true,
	"reverse-h2": true, "reverse-h2c": true, "reverse-udp": true}

func (s *Server) apiNew(c *call) {
	var in struct{ Where, Token, Map, Name, Via, Carrier, Test, Pick, Domain string }
	if c.json(&in) != nil {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	in.Map = strings.ReplaceAll(strings.TrimSpace(in.Map), " ", "")
	if in.Map == "" || strings.ContainsAny(in.Map, "\n\t") {
		c.fail(http.StatusBadRequest, "Give the ports, for example 39901:18999,8443:443 (public port here : port on Kharej).")
		return
	}
	if in.Name != "" && !nameRe.MatchString(in.Name) {
		c.fail(http.StatusBadRequest, "Name: letters, digits, - and _, up to 32.")
		return
	}
	if !testPresets[in.Test] || !picks[in.Pick] {
		c.fail(http.StatusBadRequest, "unknown test preset or pick")
		return
	}
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	if in.Domain != "" && (in.Carrier != "auto" || !domainRe.MatchString(in.Domain)) {
		c.fail(http.StatusBadRequest, "Cloudflare domain: a name like cdn.example.com, for an auto tunnel.")
		return
	}
	iranArgs := func(tok string) []string {
		a := []string{"iran", "--token", tok, "--map", in.Map}
		if in.Name != "" {
			a = append(a, "--name", in.Name)
		}
		if in.Test != "" {
			a = append(a, "--test", in.Test)
		}
		if in.Pick != "" {
			a = append(a, "--pick", in.Pick)
		}
		return append(a, "--yes")
	}
	switch in.Where {
	case "here":
		in.Token = strings.TrimSpace(in.Token)
		if !strings.HasPrefix(in.Token, "wat1:") || strings.ContainsAny(in.Token, " \n\t") {
			c.fail(http.StatusBadRequest, "Paste the token Kharej printed (it starts with wat1:).")
			return
		}
		id, err := s.jobs.run("create", "New tunnel from a token", c.sess.User, s.be.ManagerArgv(iranArgs(in.Token)...))
		s.jobReply(c, "new tunnel (token)", in.Name, id, err)
	case "both":
		if !kharejCarriers[in.Carrier] {
			c.fail(http.StatusBadRequest, "Pick a carrier.")
			return
		}
		// via is a Kharej host (the page's choice since 3.6.1) or, from older pages, a paired tunnel here
		viaName := ""
		if t, ok := s.tunnel(in.Via); ok && t.Paired && t.Active {
			viaName = t.Name
		} else if v, ok := s.via(c, in.Via); ok {
			viaName = v
		} else {
			return
		}
		var kports []string
		for _, m := range strings.Split(in.Map, ",") {
			p := m[strings.LastIndex(m, ":")+1:]
			if p != "" {
				kports = append(kports, p)
			}
		}
		id, err := s.jobs.doID("create", "New tunnel on Kharej and here", c.sess.User, func(id string, say func(string, ...any)) error {
			say("Creating the tunnel on Kharej (%s, ports %s) ...", in.Carrier, strings.Join(kports, ","))
			tok, err := s.be.KharejCreate(viaName, in.Name, in.Carrier, strings.Join(kports, ","), in.Domain)
			if err != nil {
				return err
			}
			say("Kharej made it. Writing this side and starting it ...")
			return runInto(s.be.ManagerArgv(iranArgs(tok)...), say, "WAT_AT_CTL="+s.jobs.path(id, "ctl"))
		})
		s.jobReply(c, "new tunnel (both sides)", in.Name, id, err)
	default:
		c.fail(http.StatusBadRequest, "where is here or both")
	}
}

// runInto runs ARGV unattended and copies its output lines through say.
func runInto(argv []string, say func(string, ...any), env ...string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(append(os.Environ(), "NONINTERACTIVE=1", "NO_COLOR=1", "WAT_NO_ANIM=1"), env...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		say("%s", sc.Text())
	}
	return cmd.Wait()
}

// ---- Kharej ----

// via is the first running paired tunnel to HOST (the panel only reaches Kharej through one).
func (s *Server) via(c *call, host string) (string, bool) {
	v, code, msg := s.viaOf(host)
	if v == "" {
		c.fail(code, msg)
	}
	return v, v != ""
}

func (s *Server) viaOf(host string) (string, int, string) {
	for _, k := range s.kharejSnap() {
		if k.Host != host {
			continue
		}
		for _, v := range k.Via {
			if v == k.Link && k.Online { // the pairing link is hidden from the tunnel list; it answered the last poll
				return v, 0, ""
			}
			if t, ok := s.tunnel(v); ok && t.Active {
				return v, 0, ""
			}
		}
		return "", http.StatusConflict, "No running tunnel reaches " + host + ": start one, or use Kharej's own console."
	}
	return "", http.StatusNotFound, "no such Kharej server"
}

// kharejDo runs CMD on Kharej; TARGET is "host" or "host/tunnel" (the audit's target).
func (s *Server) kharejDo(c *call, action, target, cmd string, args map[string]any) (map[string]any, bool) {
	host, _, _ := strings.Cut(target, "/")
	via, ok := s.via(c, host)
	if !ok {
		return nil, false
	}
	p, refused, err := s.be.KharejCall(via, cmd, args)
	switch {
	case err != nil:
		s.audit(c, action, target, err.Error())
		c.fail(http.StatusBadGateway, "No answer from Kharej: "+err.Error())
		return nil, false
	case refused != "":
		s.audit(c, action, target, refused)
		c.fail(http.StatusConflict, refused)
		return nil, false
	}
	return p, true
}

func (s *Server) apiKharejUnit(c *call) {
	var in struct{ Name, Action string }
	if c.json(&in) != nil || !nameRe.MatchString(in.Name) || (in.Action != "start" && in.Action != "stop" && in.Action != "restart") {
		c.fail(http.StatusBadRequest, "name and action (start, stop, restart) are needed")
		return
	}
	if _, ok := s.kharejDo(c, "kharej "+in.Action, c.arg[0]+"/"+in.Name, "tunnel."+in.Action, map[string]any{"name": in.Name}); ok {
		s.audit(c, "kharej "+in.Action, c.arg[0]+"/"+in.Name, "ok")
		s.refreshKharej()
		c.ok(map[string]bool{"ok": true})
	}
}

func (s *Server) refreshKharej() {
	go func() {
		kh := s.be.Kharej()
		s.khMu.Lock()
		s.kh = kh
		s.khMu.Unlock()
	}()
}

func (s *Server) apiKharejKeyRotate(c *call) {
	var in struct{ Name, Confirm string }
	if c.json(&in) != nil || !nameRe.MatchString(in.Name) {
		c.fail(http.StatusBadRequest, "name is needed")
		return
	}
	via, ok := s.via(c, c.arg[0])
	if !ok {
		return
	}
	if _, twin := s.tunnel(in.Name); twin && !s.guardLast(c, in.Name, in.Confirm) {
		return
	}
	local, tok, err := s.be.KharejKeyRotate(via, in.Name)
	s.audit(c, "kharej key rotate", c.arg[0]+"/"+in.Name, errText(err))
	if err != nil && tok == "" {
		c.fail(http.StatusConflict, err.Error())
		return
	}
	out := map[string]any{"ok": err == nil, "local": local, "token": tok}
	if err != nil {
		out["warning"] = err.Error()
	}
	c.ok(out)
}

func (s *Server) apiKharejUpdate(c *call) {
	p, ok := s.kharejDo(c, "kharej update", c.arg[0], "update.run", nil)
	if !ok {
		return
	}
	s.audit(c, "kharej update", c.arg[0], "accepted")
	c.ok(map[string]any{"ok": true, "run": p["run"], "to": p["to"], "already_running": p["already_running"],
		"note": "Kharej updates itself. Its tunnels restart, so this page loses it for about two minutes."})
}

func (s *Server) apiKharejBackup(c *call) {
	p, ok := s.kharejDo(c, "kharej backup", c.arg[0], "backup.export", nil)
	if !ok {
		return
	}
	raw, err := s.be.KharejBackup(p)
	s.audit(c, "kharej backup", c.arg[0], errText(err))
	if err != nil {
		c.fail(http.StatusBadGateway, err.Error())
		return
	}
	sendBackup(c, "kharej-"+c.arg[0]+"-"+time.Now().UTC().Format("20060102-1504")+".tar", "application/x-tar", raw)
}

func attach(w http.ResponseWriter, name, ctype string, b []byte) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(name, `"`, "")+`"`)
	w.Write(b)
}

func (s *Server) apiKharejStatus(c *call) {
	if p, ok := s.kharejDo(c, "", c.arg[0], "update.status", nil); ok {
		c.ok(p)
	}
}

func (s *Server) apiKharejAudit(c *call) {
	if p, ok := s.kharejDo(c, "", c.arg[0], "audit.tail", map[string]any{"n": 100}); ok {
		c.ok(p)
	}
}

// ---- updates of this server ----

func (s *Server) apiUpdateHere(c *call) {
	if s.jobs.busy("update") {
		c.fail(http.StatusConflict, "An update is already running.")
		return
	}
	id, err := s.jobs.run("update", "Update this server", c.sess.User, s.be.ManagerArgv("update"))
	s.jobReply(c, "update", "here", id, err)
}

// apiUpdateAll updates every server that runs an older version than the newest release: the reachable Kharej
// servers first (each updates itself and rolls back on failure), then this one as its own job, since it restarts
// this panel.
func (s *Server) apiUpdateAll(c *call) {
	if s.jobs.busy("update") {
		c.fail(http.StatusConflict, "An update is already running.")
		return
	}
	latest := s.latestVersion()
	if latest == "" {
		c.fail(http.StatusBadGateway, "The newest version is not known yet: GitHub did not answer. Try again in a minute.")
		return
	}
	here := s.be.Host().Version
	id, err := s.jobs.do("update-all", "Update every server to "+latest, c.sess.User, func(say func(string, ...any)) error {
		for _, k := range s.kharejSnap() {
			switch {
			case !k.Online:
				say("%s: unreachable, skipped. Update it from its own console.", k.Host)
				continue
			case k.Version != "" && !newer(latest, k.Version):
				say("%s: already on %s.", k.Host, k.Version)
				continue
			}
			via, _, msg := s.viaOf(k.Host)
			if via == "" {
				say("%s: %s", k.Host, msg)
				continue
			}
			p, refused, err := s.be.KharejCall(via, "update.run", nil)
			switch {
			case err != nil:
				say("%s: no answer (%v).", k.Host, err)
			case refused != "":
				say("%s: refused: %s", k.Host, refused)
			default:
				say("%s: updating to %v. Its tunnels restart; it is back in about two minutes.", k.Host, orAny(p["to"], latest))
			}
		}
		if !newer(latest, here) {
			say("This server is already on %s.", here)
			return nil
		}
		say("This server updates now; the page reconnects by itself.")
		_, err := s.jobs.run("update", "Update this server", c.sess.User, s.be.ManagerArgv("update"))
		return err
	})
	s.jobReply(c, "update all", latest, id, err)
}

func orAny(v any, def string) any {
	if v == nil || v == "" {
		return def
	}
	return v
}

func (s *Server) apiRollback(c *call) {
	if s.jobs.busy("update") {
		c.fail(http.StatusConflict, "An update is running.")
		return
	}
	id, err := s.jobs.run("update", "Roll back to the previous version", c.sess.User, s.be.ManagerArgv("rollback", "--yes"))
	s.jobReply(c, "rollback", "here", id, err)
}

func (s *Server) apiJobs(c *call) { c.ok(map[string]any{"jobs": s.jobs.list()}) }

func (s *Server) apiJob(c *call) {
	v, ok := s.jobs.get(c.arg[0])
	if !ok {
		c.fail(http.StatusNotFound, "no such job")
		return
	}
	c.ok(v)
}

// apiJobCtl: the carrier test's buttons. skip ends the probe of LABEL (the one running now); stop ends the test,
// and the manager ranks what it measured so far and goes on as if the plan ended there.
func (s *Server) apiJobCtl(c *call) {
	var in struct{ Cmd, Label string }
	if c.json(&in) != nil || (in.Cmd != "skip" && in.Cmd != "stop") || len(in.Label) > 96 || strings.ContainsAny(in.Label, "\r\n") {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	line := in.Cmd
	if in.Cmd == "skip" {
		if in.Label == "" {
			c.fail(http.StatusBadRequest, "which carrier?")
			return
		}
		line += " " + in.Label
	}
	if err := s.jobs.ctl(c.arg[0], line); err != nil {
		c.fail(http.StatusConflict, err.Error())
		return
	}
	s.audit(c, "carrier test "+in.Cmd, in.Label, "ok")
	c.ok(map[string]bool{"ok": true})
}

// ---- backups of this server ----

func (s *Server) backupDir() string { return filepath.Join(s.dataDir, "backups") }

type backupRow struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	T    int64  `json:"t"`
	Auto bool   `json:"auto"`
}

func (s *Server) backupList() []backupRow {
	out := []backupRow{}
	m, _ := filepath.Glob(filepath.Join(s.backupDir(), "*.tar.gz"))
	for _, f := range m {
		if fi, err := os.Stat(f); err == nil {
			n := filepath.Base(f)
			out = append(out, backupRow{Name: n, Size: fi.Size(), T: fi.ModTime().Unix(), Auto: strings.HasPrefix(n, "auto-")})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T > out[j].T })
	return out
}

func (s *Server) apiBackups(c *call) { c.ok(map[string]any{"backups": s.backupList()}) }

// backupNow runs the console's `backup FILE` as a job; auto backups prune themselves to backup-keep.
func (s *Server) backupNow(user string, auto bool) (string, error) {
	os.MkdirAll(s.backupDir(), 0o700)
	n := "manual-"
	if auto {
		n = "auto-"
	}
	f := filepath.Join(s.backupDir(), n+time.Now().UTC().Format("20060102-150405")+".tar.gz")
	id, err := s.jobs.run("backup", "Back up this server", user, s.be.ManagerArgv("backup", f))
	if auto {
		keep := s.conf().BackupKeep
		n := 0
		for _, b := range s.backupList() {
			if b.Auto {
				if n++; n > keep {
					os.Remove(filepath.Join(s.backupDir(), b.Name))
				}
			}
		}
	}
	return id, err
}

func (s *Server) apiBackupNow(c *call) {
	id, err := s.backupNow(c.sess.User, false)
	s.jobReply(c, "backup", "here", id, err)
}

func (s *Server) backupFile(c *call) (string, bool) {
	n := c.arg[0]
	if n != path.Base(n) || !strings.HasSuffix(n, ".tar.gz") || strings.HasPrefix(n, ".") {
		c.fail(http.StatusBadRequest, "bad name")
		return "", false
	}
	f := filepath.Join(s.backupDir(), n)
	if _, err := os.Stat(f); err != nil {
		c.fail(http.StatusNotFound, "no such backup")
		return "", false
	}
	return f, true
}

func (s *Server) apiBackupGet(c *call) {
	f, ok := s.backupFile(c)
	if !ok {
		return
	}
	b, err := os.ReadFile(f)
	if err != nil {
		c.fail(http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(c, "download backup", c.arg[0], "ok")
	sendBackup(c, c.arg[0], "application/gzip", b)
}

func (s *Server) apiBackupDel(c *call) {
	f, ok := s.backupFile(c)
	if !ok {
		return
	}
	err := os.Remove(f)
	s.audit(c, "delete backup", c.arg[0], errText(err))
	c.ok(map[string]bool{"ok": err == nil})
}

// apiRestore takes an uploaded backup (base64 in JSON: the body stays one small request), checks it is a tar.gz
// of one config directory with no path tricks, lists what it holds into the job log, and runs `restore FILE`.
func (s *Server) apiRestore(c *call) {
	raw, files, ok := s.backupInput(c)
	if !ok {
		return
	}
	os.MkdirAll(s.backupDir(), 0o700)
	f := filepath.Join(s.backupDir(), "restore-"+time.Now().UTC().Format("20060102-150405")+".tar.gz")
	if err := os.WriteFile(f, raw, 0o600); err != nil {
		c.fail(http.StatusInternalServerError, err.Error())
		return
	}
	argv := s.be.ManagerArgv("restore", f)
	id, err := s.jobs.do("restore", "Restore from a backup", c.sess.User, func(say func(string, ...any)) error {
		say("The backup holds %d files:", len(files))
		for _, n := range files {
			say("  %s", n)
		}
		return runInto(argv, say)
	})
	s.jobReply(c, "restore", filepath.Base(f), id, err)
}

func tarList(raw []byte) ([]string, string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, "", fmt.Errorf("not gzip")
	}
	tr := tar.NewReader(zr)
	var out []string
	top := ""
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", err
		}
		n := path.Clean(h.Name)
		if strings.HasPrefix(n, "/") || n == ".." || strings.HasPrefix(n, "../") || strings.Contains(n, "/../") {
			return nil, "", fmt.Errorf("unsafe path %q", h.Name)
		}
		if h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink {
			return nil, "", fmt.Errorf("links are not allowed (%q)", h.Name)
		}
		t, _, _ := strings.Cut(n, "/")
		if top == "" {
			top = t
		} else if t != top {
			return nil, "", fmt.Errorf("more than one top folder")
		}
		if h.Typeflag == tar.TypeReg {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf("it is empty")
	}
	return out, top, nil
}
