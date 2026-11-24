package panel

// Phase 3: traffic history, alerts and the scheduler (speed tests, backups, ACME renewal).
//
// Traffic: the 1 s sampler adds each tunnel's moved bytes into the current hour; a finished hour is one line of
// DATA/traffic.jsonl ({t, n, d, u}); the open hour is saved to DATA/traffic.cur every minute so a restart loses at
// most a minute. Lines older than 400 days are dropped at start.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type trafficRow struct {
	T int64   `json:"t"` // hour start, unix
	N string  `json:"n"`
	D float64 `json:"d"` // bytes users downloaded
	U float64 `json:"u"`
}

type traffic struct {
	mu    sync.Mutex
	file  string
	hour  int64
	cur   map[string][2]float64
	saved time.Time
}

func newTraffic(dir string) *traffic {
	t := &traffic{cur: map[string][2]float64{}}
	if dir == "" {
		return t
	}
	t.file = filepath.Join(dir, "traffic.jsonl")
	if b, err := os.ReadFile(t.file + ".cur"); err == nil {
		var c struct {
			Hour int64
			Cur  map[string][2]float64
		}
		if json.Unmarshal(b, &c) == nil && c.Cur != nil {
			t.hour, t.cur = c.Hour, c.Cur
		}
	}
	t.prune(time.Now().AddDate(0, 0, -400).Unix())
	return t
}

func (t *traffic) prune(before int64) {
	var keep []trafficRow
	n := 0
	readJSONL(t.file, func(b []byte) {
		var r trafficRow
		if json.Unmarshal(b, &r) == nil {
			n++
			if r.T >= before {
				keep = append(keep, r)
			}
		}
	})
	if len(keep) == n {
		return
	}
	var sb strings.Builder
	for _, r := range keep {
		b, _ := json.Marshal(r)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	if os.WriteFile(t.file+".tmp", []byte(sb.String()), 0o600) == nil {
		os.Rename(t.file+".tmp", t.file)
	}
}

func (t *traffic) add(name string, down, up float64, now time.Time) {
	h := now.Truncate(time.Hour).Unix()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.hour != h {
		t.flushLocked()
		t.hour = h
	}
	v := t.cur[name]
	v[0] += down
	v[1] += up
	t.cur[name] = v
	if t.file != "" && now.Sub(t.saved) > time.Minute {
		t.saved = now
		b, _ := json.Marshal(map[string]any{"Hour": t.hour, "Cur": t.cur})
		if os.WriteFile(t.file+".cur.tmp", b, 0o600) == nil {
			os.Rename(t.file+".cur.tmp", t.file+".cur")
		}
	}
}

func (t *traffic) flushLocked() {
	if t.hour != 0 && t.file != "" {
		names := make([]string, 0, len(t.cur))
		for n := range t.cur {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if v := t.cur[n]; v[0]+v[1] > 0 {
				appendJSONL(t.file, trafficRow{T: t.hour, N: n, D: v[0], U: v[1]})
			}
		}
	}
	t.cur = map[string][2]float64{}
}

// rows is every hour row since FROM, the open hour included.
func (t *traffic) rows(from int64) []trafficRow {
	var out []trafficRow
	readJSONL(t.file, func(b []byte) {
		var r trafficRow
		if json.Unmarshal(b, &r) == nil && r.T >= from {
			out = append(out, r)
		}
	})
	t.mu.Lock()
	for n, v := range t.cur {
		if t.hour >= from {
			out = append(out, trafficRow{T: t.hour, N: n, D: v[0], U: v[1]})
		}
	}
	t.mu.Unlock()
	return out
}

func (s *Server) apiTraffic(c *call) {
	days := 30
	fmt.Sscan(c.r.URL.Query().Get("days"), &days)
	if days < 1 || days > 400 {
		days = 30
	}
	now := time.Now()
	from := now.AddDate(0, 0, -days).Truncate(24 * time.Hour)
	rows := s.tr.rows(from.Unix())
	type dayRow struct {
		Day     string                `json:"day"`
		Tunnels map[string][2]float64 `json:"tunnels"`
	}
	byDay := map[string]*dayRow{}
	hours := map[int64][2]float64{}
	tot := map[string]map[string][2]float64{} // tunnel -> today|week|month
	today := now.Format("2006-01-02")
	weekAgo, monthAgo := now.AddDate(0, 0, -7).Unix(), now.AddDate(0, -1, 0).Unix()
	for _, r := range rows {
		d := time.Unix(r.T, 0).Format("2006-01-02")
		if byDay[d] == nil {
			byDay[d] = &dayRow{Day: d, Tunnels: map[string][2]float64{}}
		}
		v := byDay[d].Tunnels[r.N]
		byDay[d].Tunnels[r.N] = [2]float64{v[0] + r.D, v[1] + r.U}
		if r.T >= now.Add(-48*time.Hour).Unix() {
			h := hours[r.T]
			hours[r.T] = [2]float64{h[0] + r.D, h[1] + r.U}
		}
		if tot[r.N] == nil {
			tot[r.N] = map[string][2]float64{}
		}
		for k, ok := range map[string]bool{"today": d == today, "week": r.T >= weekAgo, "month": r.T >= monthAgo} {
			if ok {
				x := tot[r.N][k]
				tot[r.N][k] = [2]float64{x[0] + r.D, x[1] + r.U}
			}
		}
	}
	dl := []*dayRow{}
	for _, d := range byDay {
		dl = append(dl, d)
	}
	sort.Slice(dl, func(i, j int) bool { return dl[i].Day < dl[j].Day })
	type hourRow struct {
		T int64   `json:"t"`
		D float64 `json:"d"`
		U float64 `json:"u"`
	}
	hl := []hourRow{}
	for t, v := range hours {
		hl = append(hl, hourRow{t, v[0], v[1]})
	}
	sort.Slice(hl, func(i, j int) bool { return hl[i].T < hl[j].T })
	c.ok(map[string]any{"days": dl, "hours": hl, "totals": tot})
}

func (s *Server) apiTrafficCSV(c *call) {
	var sb strings.Builder
	sb.WriteString("hour_utc,tunnel,download_bytes,upload_bytes\n")
	for _, r := range s.tr.rows(0) {
		fmt.Fprintf(&sb, "%s,%s,%.0f,%.0f\n", time.Unix(r.T, 0).UTC().Format("2006-01-02T15:00Z"), r.N, r.D, r.U)
	}
	attach(c.w, "traffic-"+time.Now().UTC().Format("20060102")+".csv", "text/csv; charset=utf-8", []byte(sb.String()))
}

// ---- alerts (features §5) ----

type alert struct {
	Key     string `json:"key"`
	Kind    string `json:"kind"` // down | loss | kharej | disk | ram | cert | logins
	Text    string `json:"text"`
	Since   int64  `json:"since"`
	Cleared int64  `json:"cleared,omitempty"`
}

type alerts struct {
	mu      sync.Mutex
	file    string
	active  map[string]*alert
	pending map[string]time.Time // condition seen since; raised once it held long enough
}

func newAlerts(dir string) *alerts {
	a := &alerts{active: map[string]*alert{}, pending: map[string]time.Time{}}
	if dir != "" {
		a.file = filepath.Join(dir, "alerts.jsonl")
	}
	return a
}

// set records that condition KEY holds (on) or not; it becomes an alert after it held for HOLD.
func (a *alerts) set(key, kind, text string, on bool, hold time.Duration, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !on {
		delete(a.pending, key)
		if al := a.active[key]; al != nil {
			al.Cleared = now.Unix()
			if a.file != "" {
				appendJSONL(a.file, al)
			}
			delete(a.active, key)
		}
		return
	}
	since, ok := a.pending[key]
	if !ok {
		since = now
		a.pending[key] = now
	}
	if al := a.active[key]; al != nil {
		al.Text = text
		return
	}
	if now.Sub(since) >= hold {
		a.active[key] = &alert{Key: key, Kind: kind, Text: text, Since: since.Unix()}
	}
}

// keep drops conditions under PREFIX whose key is not in SEEN (a deleted tunnel's alert clears).
func (a *alerts) keep(prefix string, seen map[string]bool, now time.Time) {
	a.mu.Lock()
	var gone []string
	for k := range a.pending {
		if strings.HasPrefix(k, prefix) && !seen[k] {
			gone = append(gone, k)
		}
	}
	a.mu.Unlock()
	for _, k := range gone {
		a.set(k, "", "", false, 0, now)
	}
}

func (a *alerts) list() []alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := []alert{}
	for _, al := range a.active {
		out = append(out, *al)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since > out[j].Since })
	return out
}

// checkAlerts runs every 5 s from the sampler.
func (s *Server) checkAlerts(tun []Tunnel, rows map[string]*liveRow, now time.Time) {
	cfg := s.conf()
	seen := map[string]bool{}
	for _, t := range tun {
		r := rows[t.Name]
		want := t.Enabled || t.Active
		up := t.Active && (r == nil || !r.Metrics || r.Alive)
		k := "down:" + t.Name
		seen[k] = true
		s.al.set(k, "down", t.Name+" is down", want && !up, 30*time.Second, now)
		k = "loss:" + t.Name
		seen[k] = true
		lossy := r != nil && r.Metrics && r.Alive && r.Loss >= cfg.AlertLoss
		text := t.Name + " is losing packets"
		if r != nil {
			text = fmt.Sprintf("%s has lost %.1f%% of packets for 5 minutes", t.Name, r.Loss)
		}
		s.al.set(k, "loss", text, lossy, 5*time.Minute, now)
	}
	s.al.keep("down:", seen, now)
	s.al.keep("loss:", seen, now)
	kseen := map[string]bool{}
	for _, k := range s.kharejSnap() {
		key := "kharej:" + k.Host
		kseen[key] = true
		s.al.set(key, "kharej", k.Host+" cannot be reached", !k.Online, 2*time.Minute, now) // a channel reset is normal for ~2 min
	}
	s.al.keep("kharej:", kseen, now)
	h := s.hostCached(now)
	s.al.set("disk", "disk", fmt.Sprintf("Disk is %.0f%% full", h.DiskPct), h.DiskPct >= cfg.AlertDisk, 0, now)
	s.al.set("ram", "ram", fmt.Sprintf("RAM is %.0f%% used", h.MemPct), h.MemPct >= cfg.AlertRAM, 2*time.Minute, now)
	exp := s.certs.expires()
	s.al.set("cert", "cert", "The panel certificate expires on "+exp.Format("2006-01-02"),
		!exp.IsZero() && exp.Sub(now) < 14*24*time.Hour, 0, now)
	n := s.g.recentFails(now, 10*time.Minute)
	s.al.set("logins", "logins", fmt.Sprintf("%d failed sign-ins in 10 minutes", n), n >= 10, 0, now)
}

func (s *Server) hostCached(now time.Time) Host {
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	if now.Sub(s.hostAt) > time.Minute {
		s.host, s.hostAt = s.be.Host(), now
	}
	return s.host
}

func (s *Server) apiAlerts(c *call) {
	hist := []alert{}
	readJSONL(s.al.file, func(b []byte) {
		var a alert
		if json.Unmarshal(b, &a) == nil {
			hist = append(hist, a)
		}
	})
	if len(hist) > 200 {
		hist = hist[len(hist)-200:]
	}
	for i, j := 0, len(hist)-1; i < j; i, j = i+1, j-1 {
		hist[i], hist[j] = hist[j], hist[i]
	}
	c.ok(map[string]any{"active": s.al.list(), "history": hist})
}

// ---- scheduler: scheduled speed tests and backups, ACME renewal ----

type schedState struct {
	Speed  int64 `json:"speed"`
	Backup int64 `json:"backup"`
	ACME   int64 `json:"acme"`
}

func (s *Server) schedule(ctx context.Context) {
	f := filepath.Join(s.dataDir, "schedule.json")
	var st schedState
	if b, err := os.ReadFile(f); err == nil {
		json.Unmarshal(b, &st)
	}
	save := func() {
		b, _ := json.Marshal(st)
		os.WriteFile(f, b, 0o600)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
		cfg, now := s.conf(), time.Now()
		if cfg.SpeedEvery > 0 && now.Sub(time.Unix(st.Speed, 0)) >= time.Duration(cfg.SpeedEvery)*time.Hour {
			st.Speed = now.Unix()
			save()
			var list []Tunnel
			for _, t := range s.be.Tunnels() {
				if t.Role == "Iran" && t.Active {
					list = append(list, t)
				}
			}
			if len(list) > 0 {
				s.jobs.do("speedtest", "Scheduled speed test", "schedule", func(say func(string, ...any)) error {
					var errs []string
					for _, t := range list {
						if err := s.runSpeedTest(t, 10, true, say); err != nil {
							errs = append(errs, t.Name+": "+err.Error())
						}
					}
					if len(errs) > 0 {
						return fmt.Errorf("%s", strings.Join(errs, "; "))
					}
					return nil
				})
			}
		}
		if cfg.BackupEvery > 0 && now.Sub(time.Unix(st.Backup, 0)) >= time.Duration(cfg.BackupEvery)*time.Hour {
			st.Backup = now.Unix()
			save()
			s.backupNow("schedule", true)
		}
		if cfg.CertKind == "acme" && cfg.ACMEName != "" && s.certs.expires().Sub(now) < 30*24*time.Hour &&
			now.Sub(time.Unix(st.ACME, 0)) >= 24*time.Hour {
			st.ACME = now.Unix()
			save()
			s.startACME("schedule", cfg.ACMEName)
		}
	}
}

func (s *Server) apiSettingsAlerts(c *call) {
	var in struct {
		Loss, Disk, RAM               float64
		SpeedEvery, BackupEvery, Keep int
	}
	if c.json(&in) != nil || in.Loss <= 0 || in.Loss > 100 || in.Disk <= 0 || in.Disk > 100 || in.RAM <= 0 || in.RAM > 100 ||
		in.SpeedEvery < 0 || in.SpeedEvery > 24*30 || in.BackupEvery < 0 || in.BackupEvery > 24*30 || in.Keep < 1 || in.Keep > 100 {
		c.fail(http.StatusBadRequest, "Check the numbers: percents 1-100, hours 0-720 (0 = off), keep 1-100.")
		return
	}
	s.cfgMu.Lock()
	s.cfg.AlertLoss, s.cfg.AlertDisk, s.cfg.AlertRAM = in.Loss, in.Disk, in.RAM
	s.cfg.SpeedEvery, s.cfg.BackupEvery, s.cfg.BackupKeep = in.SpeedEvery, in.BackupEvery, in.Keep
	err := s.cfg.Save()
	s.cfgMu.Unlock()
	s.audit(c, "alert and schedule settings", "", errText(err))
	if err != nil {
		c.fail(http.StatusInternalServerError, err.Error())
		return
	}
	c.ok(map[string]bool{"ok": true})
}
