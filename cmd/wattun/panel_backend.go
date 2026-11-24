package main

// The web panel's data comes from the manager's own functions (cmd/wattun/mgr), so the panel shows exactly what
// the console shows (AGENTS.md, "Every feature reaches every surface"). Kharej is read through the pairing with the
// same scepter commands the cockpit uses; the pairing's caps decide what answers.

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
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
	return panel.Run(file, mgrBackend{})
}

type mgrBackend struct{}

func (mgrBackend) Host() panel.Host {
	h := panel.Host{Version: wat.Version, CPUs: runtime.NumCPU()}
	h.Name, _ = os.Hostname()
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
	if out, err := exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value").Output(); err == nil {
		h.ClockNTP = strings.TrimSpace(string(out)) == "yes"
	}
	return h
}

func (mgrBackend) Tunnels() []panel.Tunnel {
	var out []panel.Tunnel
	for _, n := range mgr.Tunnels() {
		t := panel.Tunnel{
			Name: n, Role: mgr.Role(n), Carrier: mgr.Cfg(n, "carrier"), Reverse: mgr.IsReverse(n),
			Active: mgr.IsActive(mgr.Unit(n)), Enabled: mgr.IsEnabled(mgr.Unit(n)), Paired: mgr.IsPaired(n),
			Uptime: mgr.UptimeOf(n),
		}
		if t.Role == "Iran" {
			t.Peer = mgr.Cfg(n, "peer")
		}
		for _, m := range mgr.YmlMaps(n) {
			t.Ports = append(t.Ports, mgr.SpecHuman(m))
		}
		out = append(out, t)
	}
	return out
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
		Streams: st.Streams, Conns: st.ConnsActive}, true
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
	for _, n := range mgr.Tunnels() {
		if mgr.Role(n) != "Iran" || !mgr.IsPaired(n) {
			continue
		}
		host, _ := mgr.SplitHP(mgr.Cfg(n, "peer"))
		if host == "" {
			host = n
		}
		k := byHost[host]
		if k == nil {
			k = &panel.Kharej{Host: host, Tunnels: []panel.RemoteTunnel{}}
			byHost[host] = k
			order = append(order, host)
		}
		k.Via = append(k.Via, n)
	}
	out := []panel.Kharej{}
	for _, h := range order {
		k := byHost[h]
		for _, via := range k.Via {
			if !mgr.IsActive(mgr.Unit(via)) {
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

func (mgrBackend) SetPorts(name string, specs []string) error { return mgr.SetPorts(name, specs) }

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

func (mgrBackend) KharejCreate(via, name, carrier, ports string) (string, error) {
	kharejMu.Lock()
	defer kharejMu.Unlock()
	return mgr.KharejCreate(via, name, carrier, ports)
}

func (mgrBackend) KharejKeyRotate(via, name string) (string, string, error) {
	kharejMu.Lock()
	defer kharejMu.Unlock()
	return mgr.KharejKeyRotate(via, name)
}

func (mgrBackend) KharejBackup(p map[string]any) ([]byte, error) { return mgr.KharejBackup(p) }

func (mgrBackend) RestartSelf() {
	_ = exec.Command("systemctl", "--no-block", "restart", mgr.PanelUnit()+".service").Run()
}
