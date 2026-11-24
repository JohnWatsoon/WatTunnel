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
	"strings"
	"time"
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)

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
	var errs []string
	for _, dir := range []string{"down", "up"} {
		say("%s: %d MB %s ...", t.Name, mb, map[string]string{"down": "download", "up": "upload"}[dir])
		r, err := s.be.SpeedTest(t.Name, dir, mb)
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

func (s *Server) apiSpeedTest(c *call) {
	var in struct{ MB int }
	c.json(&in)
	if in.MB <= 0 || in.MB > 500 {
		in.MB = 10
	}
	t, ok := s.tunnel(c.arg[0])
	if !ok || t.Role != "Iran" {
		c.fail(http.StatusBadRequest, "The speed test runs on Iran tunnels of this server.")
		return
	}
	id, err := s.jobs.do("speedtest", "Speed test of "+t.Name, c.sess.User, func(say func(string, ...any)) error {
		return s.runSpeedTest(t, in.MB, false, say)
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
	labelRe     = regexp.MustCompile(`^[A-Za-z0-9 :./_+-]{1,48}$`)
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
	"h2": true, "h2c": true, "udp": true, "icmp": true}

func (s *Server) apiNew(c *call) {
	var in struct{ Where, Token, Map, Name, Via, Carrier, Test, Pick string }
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
		id, err := s.jobs.do("create", "New tunnel on Kharej and here", c.sess.User, func(say func(string, ...any)) error {
			say("Creating the tunnel on Kharej (%s, ports %s) ...", in.Carrier, strings.Join(kports, ","))
			tok, err := s.be.KharejCreate(viaName, in.Name, in.Carrier, strings.Join(kports, ","))
			if err != nil {
				return err
			}
			say("Kharej made it. Writing this side and starting it ...")
			return runInto(s.be.ManagerArgv(iranArgs(tok)...), say)
		})
		s.jobReply(c, "new tunnel (both sides)", in.Name, id, err)
	default:
		c.fail(http.StatusBadRequest, "where is here or both")
	}
}

// runInto runs ARGV unattended and copies its output lines through say.
func runInto(argv []string, say func(string, ...any)) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "NONINTERACTIVE=1", "NO_COLOR=1", "WAT_NO_ANIM=1")
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
	for _, k := range s.kharejSnap() {
		if k.Host != host {
			continue
		}
		for _, v := range k.Via {
			if v == k.Link && k.Online { // the pairing link is hidden from the tunnel list; it answered the last poll
				return v, true
			}
			if t, ok := s.tunnel(v); ok && t.Active {
				return v, true
			}
		}
		c.fail(http.StatusConflict, "No running tunnel reaches "+host+": start one, or use Kharej's own console.")
		return "", false
	}
	c.fail(http.StatusNotFound, "no such Kharej server")
	return "", false
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
