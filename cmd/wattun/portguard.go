package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// The Kharej port guard (Handoff 4 R5): a remote tunnel.create/edit forwards to 127.0.0.1:target on Kharej, so a
// stolen or careless pairing could expose any local-only service. These targets are refused whatever the caps:
// sshd, every tunnel's own metrics (pprof lives there) and latch port, the probe range, and what the owner listed
// locally in -scepter-deny-ports (a Kharej-local key: the cockpit can neither set nor clear it).

const sshdConfigDefault = "/etc/ssh/sshd_config"

// sshdPorts reads the Port lines of sshd_config and its drop-ins; none found means sshd's default 22.
func sshdPorts(conf string) []int {
	files := []string{conf}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(conf), "sshd_config.d", "*.conf")); m != nil {
		files = append(files, m...)
	}
	var out []int
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) >= 2 && strings.EqualFold(fs[0], "Port") {
				if p, err := strconv.Atoi(fs[1]); err == nil && p > 0 && p < 65536 {
					out = append(out, p)
				}
			}
		}
		fh.Close()
	}
	if len(out) == 0 {
		out = []int{22}
	}
	return out
}

// portOf returns the port of a "host:port", ":port" or "port" value (0 when there is none).
func portOf(v string) int {
	if i := strings.LastIndex(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	p, _ := strconv.Atoi(strings.TrimSpace(v))
	return p
}

// deniedTargets maps every refused target port to the reason the cockpit is told.
func (o *fileScepterOps) deniedTargets() map[int]string {
	d := map[int]string{}
	for _, p := range sshdPorts(orStr(o.sshdConf, sshdConfigDefault)) {
		d[p] = "sshd"
	}
	m, _ := filepath.Glob(filepath.Join(o.conf, "*.yml"))
	for _, f := range m {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch strings.TrimSpace(k) {
			case "metrics":
				if p := portOf(v); p > 0 {
					d[p] = "a tunnel's metrics"
				}
			case "latch-port":
				if p := portOf(v); p > 0 {
					d[p] = "the scepter latch"
				}
			}
		}
	}
	for _, s := range strings.Split(o.denyExtra, ",") {
		if p := portOf(s); p > 0 {
			d[p] = "denied by the Kharej owner"
		}
	}
	return d
}

// checkTargets refuses a port list that forwards to a guarded target.
func (o *fileScepterOps) checkTargets(ports []portSpec) (map[string]any, int) {
	deny := o.deniedTargets()
	for _, p := range ports {
		why := deny[p.Target]
		if why == "" && p.Target >= 20500 && p.Target < 21000 {
			why = "the probe range"
		}
		if why != "" {
			return map[string]any{"port": p.Target, "why": why}, wat.CodePortDenied
		}
	}
	return nil, wat.CodeOK
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
