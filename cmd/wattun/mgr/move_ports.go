package mgr

import (
	"fmt"
	"strconv"
	"strings"
)

// MovePorts moves the port mappings SPECS (as YmlMaps lists them) from Iran tunnel FROM to Iran tunnel TO (4.0.3).
// The Kharej side of TO must allow each target port: a paired TO gets the missing ones added to its Kharej
// allowlist first (tunnel.edit restarts that unit); an unpaired one must already allow them. Then FROM drops the
// ports before TO takes them, since both cannot listen on one public port, and FROM gets them back if TO's write fails.
func MovePorts(from, to string, specs []string) error {
	if from == to {
		return fmt.Errorf("pick another tunnel")
	}
	if !cfgFileExists(from) || !cfgFileExists(to) || Role(from) != "Iran" || Role(to) != "Iran" {
		return fmt.Errorf("ports move between Iran tunnels")
	}
	a, b := YmlMaps(from), YmlMaps(to)
	move := map[string]bool{}
	for _, s := range specs {
		n, err := NormSpec(s)
		if err != nil {
			return fmt.Errorf("%q: %v", s, err)
		}
		for _, x := range n {
			move[x] = true
		}
	}
	var keep, moved []string
	for _, m := range a {
		if move[m] {
			moved = append(moved, m)
			delete(move, m)
		} else {
			keep = append(keep, m)
		}
	}
	if len(move) > 0 || len(moved) == 0 {
		return fmt.Errorf("%s does not forward those ports", from)
	}
	if len(keep) == 0 {
		return fmt.Errorf("%s needs at least one port left", from)
	}
	for _, m := range moved {
		for _, x := range b {
			if SpecL(x) == SpecL(m) && SpecP(x) == SpecP(m) {
				return fmt.Errorf("%s already listens on port %s", to, SpecL(m))
			}
		}
	}
	if err := allowOnKharej(to, moved); err != nil {
		return err
	}
	if err := WritePorts(from, keep); err != nil {
		return err
	}
	if err := WritePorts(to, append(b, moved...)); err != nil {
		_ = WritePorts(from, a)
		return err
	}
	return nil
}

// allowOnKharej makes sure Kharej's side of tunnel N allows the target ports of MAPS.
func allowOnKharej(n string, maps []string) error {
	cur, paired := "", IsPaired(n)
	if paired {
		doc, err := scepterFetchDocOr(n)
		if err != nil {
			return fmt.Errorf("cannot reach Kharej for %s: %v", n, err)
		}
		found := false
		for _, r := range doc.Tunnels {
			if r.Name == n {
				cur, found = r.Ports, true
			}
		}
		if !found {
			return fmt.Errorf("Kharej has no tunnel %s", n)
		}
	} else if tok, err := ReadToken(TokenOf(n)); err == nil {
		cur = tok.Ports
	}
	var add []string
	for _, t := range strings.Split(MapsAllowStr(maps), ",") {
		if !allowHas(cur, t) {
			add = append(add, t)
		}
	}
	if len(add) == 0 {
		return nil
	}
	if !paired {
		return fmt.Errorf("Kharej's side of %s does not allow port %s; add it there first (Kharej console: the tunnel's ports)", n, strings.Join(add, ", "))
	}
	_, refused, err := KharejCall(n, "tunnel.edit", map[string]any{"name": n, "ports": strings.Join(append([]string{cur}, add...), ",")})
	if err != nil {
		return err
	}
	if refused != "" {
		return fmt.Errorf("%s", refused)
	}
	return nil
}

// allowHas: does the Kharej allowlist LIST ("443,2000-2010,53/udp"; empty = every port) admit target T ("443",
// "53/udp")?
func allowHas(list, t string) bool {
	if strings.TrimSpace(list) == "" {
		return true
	}
	port, proto, _ := strings.Cut(t, "/")
	p, _ := strconv.Atoi(port)
	for _, e := range strings.Split(list, ",") {
		e = strings.TrimSpace(e)
		ep, eproto, _ := strings.Cut(e, "/")
		if eproto != proto {
			continue
		}
		lo, hi, isRange := strings.Cut(ep, "-")
		l, _ := strconv.Atoi(lo)
		h := l
		if isRange {
			h, _ = strconv.Atoi(hi)
		}
		if p >= l && p <= h {
			return true
		}
	}
	return false
}
