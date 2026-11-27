package main

// The web panel's data comes from the manager's own functions (cmd/wattun/mgr), so the panel shows exactly what
// the console shows (AGENTS.md, "Every feature reaches every surface"). Kharej is read through the pairing with the
// same scepter commands the cockpit uses; the pairing's caps decide what answers.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JohnWatsoon/WatTunnel/cmd/wattun/mgr"
	"github.com/JohnWatsoon/WatTunnel/cmd/wattun/panel"
	"github.com/JohnWatsoon/WatTunnel/wat"
)

func runPanel(file string) error {
	if err := mgr.InitPaths(); err != nil {
		return err
	}
	mgr.WireSystem() // the real public-IP, port and firewall helpers (only the manager's Run wired them before)
	return panel.Run(file, mgrBackend{})
}

type mgrBackend struct{}

func (mgrBackend) Host() panel.Host {
	h := panel.Host{Version: wat.Version, IP: mgr.PublicIPCached(), Role: mgr.ServerSide()}
	h.Name, _ = os.Hostname()
	hostRes(&h)
	h.ClockNTP = clockSynced()
	h.CPUPct, h.WatCPUPct, h.WatMemMB, h.WatProcs = cpuUse()
	return h
}

// cpuUse is the machine's CPU use and wattun's share since the last call, from /proc: the busy jiffies of
// /proc/stat, and utime+stime of every process whose command is wattun (tunnels, the panel, heal), with their RSS.
// A Kharej often runs other heavy services (xray, panels, bots); this tells the owner which part is ours.
var cpuPrev struct {
	sync.Mutex
	at          time.Time
	busy, total float64
	wat         map[int]float64
}

func cpuUse() (cpu, wat, memMB float64, procs int) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return -1, -1, 0, 0
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	var busy, total float64
	for i, f := range strings.Fields(line)[1:] {
		v, _ := strconv.ParseFloat(f, 64)
		total += v
		if i != 3 && i != 4 { // idle, iowait
			busy += v
		}
	}
	cur := map[int]float64{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		st, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(st)
		o, c := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if o < 0 || c < o || s[o+1:c] != "wattun" {
			continue
		}
		f := strings.Fields(s[c+1:]) // f[0] is the state; utime, stime are fields 14, 15 of the line
		if len(f) < 22 {
			continue
		}
		u, _ := strconv.ParseFloat(f[11], 64)
		k, _ := strconv.ParseFloat(f[12], 64)
		rss, _ := strconv.ParseFloat(f[21], 64)
		cur[pid] = u + k
		memMB += rss * float64(os.Getpagesize()) / (1 << 20)
		procs++
	}
	cpuPrev.Lock()
	defer cpuPrev.Unlock()
	if dt := total - cpuPrev.total; cpuPrev.total > 0 && dt > 0 {
		cpu = (busy - cpuPrev.busy) / dt * 100
		var w float64
		for pid, t := range cur {
			if p, ok := cpuPrev.wat[pid]; ok && t >= p {
				w += t - p
			}
		}
		// /proc/stat sums every core; a process's jiffies are per process: both share USER_HZ
		wat = w / dt * 100
	}
	cpuPrev.busy, cpuPrev.total, cpuPrev.wat, cpuPrev.at = busy, total, cur, time.Now()
	return
}

// hostRes fills the cheap /proc numbers: uptime, load, cores, memory and disk use.
func hostRes(h *panel.Host) {
	h.CPUs = runtime.NumCPU()
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f, _ := strconv.ParseFloat(strings.Fields(string(b) + " 0")[0], 64)
		h.Uptime = int64(f)
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		h.Load1, _ = strconv.ParseFloat(strings.Fields(string(b) + " 0")[0], 64)
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail float64
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseFloat(f[1], 64)
			switch f[0] {
			case "MemTotal:":
				total = v
			case "MemAvailable:":
				avail = v
			}
		}
		if total > 0 {
			h.MemPct = (total - avail) * 100 / total
		}
	}
	h.DiskPct = diskUsedPct("/")
}

// Kharej's answer to scepter.hello carries these, so the Iran panel can draw its gauges (3.6.1; an older Kharej
// leaves them out and the card shows none)
func init() {
	wat.ScepterHostInfo = func() map[string]any {
		var h panel.Host
		hostRes(&h)
		// ip (4.0.1): an Iran tunnel with no peer address (reverse, auto-linked) learns which server this is from it
		return map[string]any{"load1": h.Load1, "cpus": h.CPUs, "mem_pct": h.MemPct, "disk_pct": h.DiskPct, "uptime_s": h.Uptime,
			"ip": mgr.PublicIPCached()}
	}
}

var (
	ntpMu sync.Mutex
	ntpAt time.Time
	ntpOK bool
)

// clockSynced asks timedatectl at most every 5 minutes: the overview reads Host every 10 s.
func clockSynced() bool {
	ntpMu.Lock()
	defer ntpMu.Unlock()
	if time.Since(ntpAt) > 5*time.Minute {
		out, err := exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value").Output()
		ntpOK, ntpAt = err == nil && strings.TrimSpace(string(out)) == "yes", time.Now()
	}
	return ntpOK
}

// Tunnels is read by the 1 s live sampler, the overview and most actions: it is cached for tunnelsTTL and
// reads every unit's state in one systemctl call (see mgr.UnitStates). An action drops the cache (dropTunnels)
// so the page shows a start or stop at once.
func (mgrBackend) Tunnels() []panel.Tunnel {
	tunMu.Lock()
	defer tunMu.Unlock()
	if time.Since(tunAt) < tunnelsTTL {
		return tunCache
	}
	names := mgr.Tunnels()
	units := make([]string, len(names))
	for i, n := range names {
		units[i] = mgr.Unit(n)
	}
	st := mgr.UnitStates(units)
	var out []panel.Tunnel
	for _, n := range names {
		u := st[mgr.Unit(n)]
		t := panel.Tunnel{
			Name: n, Role: mgr.Role(n), Carrier: mgr.Cfg(n, "carrier"), Reverse: mgr.IsReverse(n),
			Active: u.Active, Enabled: u.Enabled, Paired: mgr.IsPaired(n), Uptime: u.Uptime, Restarts: u.Restarts,
		}
		if t.Role == "Iran" {
			t.Peer = mgr.Cfg(n, "peer")
		}
		for _, m := range mgr.YmlMaps(n) {
			t.Ports = append(t.Ports, mgr.SpecHuman(m))
		}
		out = append(out, t)
	}
	tunCache, tunAt = out, time.Now()
	return out
}

const tunnelsTTL = 3 * time.Second

var (
	tunMu    sync.Mutex
	tunAt    time.Time
	tunCache []panel.Tunnel
)

func dropTunnels() {
	tunMu.Lock()
	tunAt = time.Time{}
	tunMu.Unlock()
}

func (mgrBackend) Stats(name string) (panel.Counters, bool) {
	addr := mgr.Cfg(name, "metrics")
	if addr == "" {
		return panel.Counters{}, false
	}
	st, err := mgr.FetchStats(addr)
	if err != nil {
		return panel.Counters{}, false
	}
	in, _ := strconv.ParseFloat(st.BytesIn, 64)
	out, _ := strconv.ParseFloat(st.BytesOut, 64)
	return panel.Counters{Alive: st.Alive, RTTms: st.RTTms, LossPct: st.LossPct, BytesIn: in, BytesOut: out,
		Streams: st.Streams, Conns: st.ConnsActive, PktsOut: float64(st.PktsOut), Retrans: float64(st.Retrans)}, true
}

var panelHTTP = &http.Client{Timeout: 2 * time.Second}

func (mgrBackend) History(name string) []byte {
	addr := mgr.Cfg(name, "metrics")
	if addr == "" {
		return nil
	}
	r, err := panelHTTP.Get("http://" + addr + "/stats/history")
	if err != nil {
		return nil
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || r.StatusCode != http.StatusOK {
		return nil
	}
	return b
}

func (mgrBackend) Logs(name string, n int) []string {
	out, err := exec.Command("journalctl", "-u", mgr.Unit(name), "-n", strconv.Itoa(n), "--no-pager", "-o", "short-iso").Output()
	if err != nil {
		return nil
	}
	s := strings.TrimRight(string(out), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// Kharej groups this server's paired Iran tunnels by their Kharej host and asks each host once, through the
// first running paired tunnel to it: hello (version, caps) and tunnels.list.
func (mgrBackend) Kharej() []panel.Kharej {
	byHost := map[string]*panel.Kharej{}
	var order []string
	names := mgr.ManagedTunnels()
	sort.SliceStable(names, func(i, j int) bool { return mgr.ExplicitPaired(names[i]) && !mgr.ExplicitPaired(names[j]) }) // ask through a 3.5+ pair before a legacy one
	for _, n := range names {
		if mgr.Role(n) != "Iran" || !mgr.IsPaired(n) {
			continue
		}
		host := mgr.PairHost(n)
		if host == "" {
			host = learnedHost(n)
		}
		k := byHost[host]
		if k == nil {
			k = &panel.Kharej{Host: host, Tunnels: []panel.RemoteTunnel{}}
			byHost[host] = k
			order = append(order, host)
		}
		if mgr.IsLinkTunnel(n) { // the link is up whenever the pair is: ask through it first
			k.Link = n
			k.Via = append([]string{n}, k.Via...)
		} else {
			k.Via = append(k.Via, n)
		}
	}
	var units []string
	for _, k := range byHost {
		for _, via := range k.Via {
			units = append(units, mgr.Unit(via))
		}
	}
	st := mgr.UnitStates(units)
	out := []panel.Kharej{}
	for _, h := range order {
		k := byHost[h]
		for _, via := range k.Via {
			if !st[mgr.Unit(via)].Active {
				continue
			}
			if err := askKharej(k, via); err != nil {
				k.Err = err.Error()
				continue
			}
			k.Online, k.Err, k.Seen = true, "", time.Now().Unix()
			break
		}
		if !k.Online && k.Err == "" {
			k.Err = "no running tunnel to this server"
		}
		out = append(out, *k)
	}
	return out
}

// learned is the Kharej address a tunnel without a peer address (reverse, auto-linked) heard in the hello: the panel
// lists that server by its address, not by the tunnel's name. Until the first answer the name stands in.
var (
	learnMu sync.Mutex
	learned = map[string]string{}
)

func learnedHost(n string) string {
	learnMu.Lock()
	defer learnMu.Unlock()
	if ip := learned[n]; ip != "" {
		return ip
	}
	return n
}

// kharejMu serializes every pairing call of the panel (the 15 s poller and the actions): one channel at a time.
var kharejMu sync.Mutex

func askKharej(k *panel.Kharej, via string) error {
	kharejMu.Lock()
	defer kharejMu.Unlock()
	cl, err := mgr.DialScepter(via)
	if err != nil {
		return err
	}
	r, err := cl.Call("scepter.hello", nil)
	if err != nil {
		return err
	}
	if r.Code != wat.CodeOK {
		return fmt.Errorf("Kharej refused (code %d)", r.Code)
	}
	k.Version, _ = r.Params["ver"].(string)
	k.Caps, _ = r.Params["caps"].(string)
	if m, ok := r.Params["host"].(map[string]any); ok {
		f := func(k string) float64 { v, _ := m[k].(float64); return v }
		k.Res = &panel.Host{Load1: f("load1"), CPUs: int(f("cpus")), MemPct: f("mem_pct"), DiskPct: f("disk_pct"), Uptime: int64(f("uptime_s"))}
		if ip, _ := m["ip"].(string); ip != "" && mgr.PairHost(via) == "" {
			learnMu.Lock()
			learned[via] = ip
			learnMu.Unlock()
		}
	}
	r, err = cl.Call("tunnels.list", nil)
	if err != nil {
		return err
	}
	k.Tunnels = []panel.RemoteTunnel{}
	if r.Code != wat.CodeOK {
		return nil // hello worked: online, but this pairing may not list tunnels
	}
	list, _ := r.Params["tunnels"].([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		s := func(k string) string { v, _ := m[k].(string); return v }
		k.Tunnels = append(k.Tunnels, panel.RemoteTunnel{Name: s("name"), Carrier: s("carrier"), Ports: s("ports"),
			State: s("state"), Health: s("health")})
	}
	return nil
}

// ---- actions (phase 2): the console's own functions ----

func (mgrBackend) Unit(name, action string) error {
	defer dropTunnels()
	u := mgr.Unit(name)
	switch action {
	case "start":
		return mgr.Start(u)
	case "stop":
		return mgr.Stop(u)
	case "restart":
		return mgr.Restart(u)
	}
	return fmt.Errorf("unknown action %q", action)
}

func (mgrBackend) SetPorts(name string, specs []string) error {
	defer dropTunnels()
	return mgr.SetPorts(name, specs)
}

func (mgrBackend) SetLimit(name, port, rate, quota, period string) error {
	return mgr.SetPortLimit(name, port, rate, quota, period)
}

func (mgrBackend) SpeedTest(name, dir string, mb int) (panel.Speed, error) {
	r, err := mgr.SpeedTestOnce(name, dir, mb)
	return panel.Speed{Dir: r.Dir, OK: r.OK, MBps: r.MBps, Seconds: r.Seconds, Error: r.Error}, err
}

func (mgrBackend) Token(name string) string { return mgr.TokenOf(name) }

func (mgrBackend) ManagerArgv(args ...string) []string {
	self, err := os.Executable()
	if err != nil {
		self = "wattun"
	}
	return append([]string{self}, args...)
}

func (mgrBackend) KharejCall(via, cmd string, args map[string]any) (map[string]any, string, error) {
	kharejMu.Lock()
	defer kharejMu.Unlock()
	return mgr.KharejCall(via, cmd, args)
}

func (mgrBackend) KharejCreate(via, name, carrier, ports, domain string) (string, error) {
	kharejMu.Lock()
	defer kharejMu.Unlock()
	return mgr.KharejCreate(via, name, carrier, ports, domain)
}

func (mgrBackend) KharejKeyRotate(via, name string) (string, string, error) {
	kharejMu.Lock()
	defer kharejMu.Unlock()
	return mgr.KharejKeyRotate(via, name)
}

func (mgrBackend) KharejBackup(p map[string]any) ([]byte, error) { return mgr.KharejBackup(p) }

func (mgrBackend) Settings(name string) any { return mgr.Settings(name) }

func (mgrBackend) ApplySettings(name string, set map[string]string) error {
	kharejMu.Lock()
	defer kharejMu.Unlock()
	return mgr.ApplySettings(name, set)
}

func (mgrBackend) SetBoot(name string, on bool) error { return mgr.SetBoot(name, on) }

func (mgrBackend) MovePorts(from, to string, specs []string) error {
	kharejMu.Lock()
	defer kharejMu.Unlock()
	return mgr.MovePorts(from, to, specs)
}

func (mgrBackend) Carriers(name string) (int64, string, []string, []string) {
	at, pr, rows := mgr.AutoResults(name)
	return at, pr, rows, mgr.AutoInUse(name)
}

func (mgrBackend) ACPreset(name, preset string) ([]string, error) {
	kharejMu.Lock()
	defer kharejMu.Unlock()
	return mgr.ACPreset(name, preset)
}

func (mgrBackend) RestartSelf() {
	_ = exec.Command("systemctl", "--no-block", "restart", mgr.PanelUnit()+".service").Run()
}

func (mgrBackend) Ports(name string) []panel.PortUse {
	addr := mgr.Cfg(name, "metrics")
	if addr == "" {
		return nil
	}
	r, err := panelHTTP.Get("http://" + addr + "/ports")
	if err != nil {
		return nil
	}
	defer r.Body.Close()
	var m map[string]map[string]any
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&m) != nil {
		return nil
	}
	f := func(v any) float64 { x, _ := v.(float64); return x }
	var out []panel.PortUse
	for port, p := range m {
		u := panel.PortUse{Port: port, Up: f(p["bytes_up_total"]), Down: f(p["bytes_down_total"]), RateUp: f(p["rate_bps_up"]),
			RateDown: f(p["rate_bps_down"]), Conns: f(p["conns_active"]), RateLimit: f(p["rate_limit_bps"]),
			QuotaLimit: f(p["quota_limit"]), QuotaUsed: f(p["quota_used"]), ResetsAt: int64(f(p["quota_resets_at"]))}
		u.Exceeded, _ = p["quota_exceeded"].(bool)
		u.Period, _ = p["quota_period"].(string)
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := strconv.Atoi(out[i].Port)
		b, _ := strconv.Atoi(out[j].Port)
		return a < b
	})
	return out
}

func (mgrBackend) QuotaReset(name string, port int) error {
	addr := mgr.Cfg(name, "metrics")
	if addr == "" {
		return fmt.Errorf("the tunnel has no metrics server")
	}
	r, err := panelHTTP.Post("http://"+addr+"/quota/reset?port="+strconv.Itoa(port), "", nil)
	if err != nil {
		return err
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("the tunnel answered %s", r.Status)
	}
	return nil
}

func (mgrBackend) LatestVersion() string { return mgr.LatestVersion() }
func (mgrBackend) Paths(name string) (string, []panel.Path) {
	mode, ps := mgr.BondPaths(name)
	out := make([]panel.Path, len(ps))
	for i, p := range ps {
		out[i] = panel.Path{Name: p.Name, Alive: p.Alive, Muted: p.Muted, RTT: p.RTT, Loss: p.Loss, Share: p.Share}
	}
	return mode, out
}

func (mgrBackend) Pairing() (string, string) { return mgr.PairingTokenNow(), mgr.PairingState() }

func (mgrBackend) Geo(addr string) (panel.Geo, error) {
	lat, lon, cc, city, err := mgr.GeoLookup(addr)
	return panel.Geo{Lat: lat, Lon: lon, CC: cc, City: city}, err
}
func (mgrBackend) PairRotate(via []string) error {
	kharejMu.Lock()
	defer kharejMu.Unlock()
	return mgr.KharejPairRotate(via)
}
func (mgrBackend) PairForget(name string) error  { return mgr.PairForget(name) }
func (mgrBackend) PanelFirewall(open, close int) { mgr.PanelFirewall(open, close) }
