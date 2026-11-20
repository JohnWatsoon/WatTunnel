package mgr

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Iran-only client ports: an ipset of Iran's IPv4 ranges and iptables rules that
// accept a client port only from it (bash iran_firewall_cmd).

func init() {
	Register("iran_firewall_cmd", func(a ...string) int { return b2rc(iranFirewallCmd(a)) })
}

const (
	iranIPSet = "wattun_iran"
	iranIPURL = "https://www.ipdeny.com/ipblocks/data/countries/ir.zone"
)

func iranCache() string { return filepath.Join(P.Conf, ".iran_cidrs.zone") }

var (
	rePortLine = regexp.MustCompile(`^\s*-\s+["']?([0-9]+)`)
	reModeLine = regexp.MustCompile(`(?m)^mode:\s*["']?([a-z]+)`)
)

// iranFWPorts lists the public ports of every client tunnel here.
func iranFWPorts() []string {
	seen := map[int]bool{}
	fs, _ := filepath.Glob(filepath.Join(P.Conf, "*.yml"))
	for _, f := range fs {
		txt := p2ReadText(f)
		if m := reModeLine.FindStringSubmatch(txt); m != nil && m[1] != "client" {
			continue
		}
		for _, l := range strings.Split(txt, "\n") {
			if m := rePortLine.FindStringSubmatch(l); m != nil {
				if p := atoi(m[1]); p >= 1 && p <= 65535 {
					seen[p] = true
				}
			}
		}
	}
	ps := make([]int, 0, len(seen))
	for p := range seen {
		ps = append(ps, p)
	}
	sort.Ints(ps)
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = strconv.Itoa(p)
	}
	return out
}

// fwPortArgs splits "443,8443 2053" style arguments into ports; none = every client port.
func fwPortArgs(args []string) []string {
	var out []string
	for _, a := range args {
		for _, p := range strings.FieldsFunc(a, func(r rune) bool { return r == ',' || r == ' ' }) {
			if isDigits(p) {
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		return iranFWPorts()
	}
	return out
}

func iranFWFetch() bool {
	_ = os.MkdirAll(P.Conf, 0o700)
	tmp := iranCache() + ".tmp"
	err := spin("Downloading official Iran IPv4 ranges (ipdeny.com)", func() error { return download(tmp, iranIPURL) })
	if st, e := os.Stat(tmp); err == nil && e == nil && st.Size() > 0 {
		_ = os.Rename(tmp, iranCache())
		Ok(fmt.Sprintf("Downloaded %d Iranian CIDR blocks.", len(fields(mustRead(iranCache())))))
		return true
	}
	_ = os.Remove(tmp)
	if c := fields(mustRead(iranCache())); len(c) > 0 {
		Warn(fmt.Sprintf("Download failed; using previously cached Iran CIDR list (%d ranges).", len(c)))
		return true
	}
	Err("Download failed and there is no cached list, so nothing was changed. Check this server's internet access and try again.")
	return false
}

func ipt(args ...string) error { return exec.Command("iptables", args...).Run() }

func iranFWDrop(pt string) {
	for _, pr := range []string{"tcp", "udp"} {
		_ = ipt("-D", "INPUT", "-p", pr, "--dport", pt, "-m", "set", "--match-set", iranIPSet, "src", "-j", "ACCEPT")
		_ = ipt("-D", "INPUT", "-p", pr, "--dport", pt, "-j", "DROP")
	}
}

func iranFWApply(args []string) bool {
	ports := fwPortArgs(args)
	if len(ports) == 0 {
		Err("No client ports found or specified. Usage: " + P.Self + " iran-firewall on [port,port...]")
		return false
	}
	if _, err := exec.LookPath("ipset"); err != nil {
		if !step("Installing ipset", func() bool {
			return exec.Command("apt-get", "update", "-qq").Run() == nil && exec.Command("apt-get", "install", "-y", "-qq", "ipset").Run() == nil
		}) {
			Err("Failed to install ipset.")
			return false
		}
	}
	if !iranFWFetch() {
		return false
	}
	step("Creating ipset "+iranIPSet, func() bool {
		return exec.Command("ipset", "create", iranIPSet, "hash:net", "maxelem", "65536", "-exist").Run() == nil
	})
	// ipset restore takes every range in one call instead of one process per range.
	var b strings.Builder
	for _, cidr := range fields(mustRead(iranCache())) {
		if _, n, err := net.ParseCIDR(cidr); err == nil && n.IP.To4() != nil {
			b.WriteString("add -exist " + iranIPSet + " " + cidr + "\n")
		}
	}
	step("Populating Iranian IP blocks into ipset", func() bool {
		c := exec.Command("ipset", "restore")
		c.Stdin = strings.NewReader(b.String())
		return c.Run() == nil
	})
	if cnt := iranSetCount(); cnt < 50 { // a real list has hundreds of ranges; a short one would lock everyone out
		_ = exec.Command("ipset", "destroy", iranIPSet).Run()
		Err(fmt.Sprintf("The Iran range list has only %d entries (expected hundreds). Nothing was changed.", cnt))
		return false
	}
	for _, pt := range ports {
		iranFWDrop(pt)
		for _, pr := range []string{"tcp", "udp"} {
			_ = ipt("-I", "INPUT", "-p", pr, "--dport", pt, "-j", "DROP")
			_ = ipt("-I", "INPUT", "-p", pr, "--dport", pt, "-m", "set", "--match-set", iranIPSet, "src", "-j", "ACCEPT")
		}
		Ok("Port " + pt + ": protected (Iran-only allowed, foreign IPs dropped)")
	}
	if _, err := exec.LookPath("netfilter-persistent"); err == nil {
		_ = exec.Command("netfilter-persistent", "save").Run() // the ipset itself is not saved by this
	} else if fileExists("/etc/iptables") {
		if out, err := exec.Command("iptables-save").Output(); err == nil {
			_ = os.WriteFile("/etc/iptables/rules.v4", out, 0o644)
		}
	}
	Ok("Iran-only protection is ON: client ports accept connections from Iranian addresses only.")
	Warn("The rules and the address set are not kept across a reboot: run  " + P.Self + " iran-firewall on  again after one (or install iptables-persistent and ipset-persistent).")
	return true
}

func iranFWRemove(args []string) {
	for _, pt := range fwPortArgs(args) {
		iranFWDrop(pt)
		Ok("Port " + pt + ": protection removed (open to all IPs)")
	}
	Ok("Iran-only protection is OFF.")
}

func iranSetCount() int {
	out, err := exec.Command("ipset", "list", iranIPSet).Output()
	if err != nil {
		return -1
	}
	c := 0
	for _, l := range strings.Split(string(out), "\n") {
		if l != "" && l[0] >= '0' && l[0] <= '9' {
			c++
		}
	}
	return c
}

func iranFWRules() []string {
	out, _ := exec.Command("iptables", "-S", "INPUT").Output()
	var rs []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, iranIPSet) {
			rs = append(rs, l)
		}
	}
	return rs
}

func iranFWStatus() {
	ClearScreen()
	Title(Stdout, "Iran-only client ports", "")
	if c := iranSetCount(); c >= 0 {
		Say("  " + kv("iran ipset", fmt.Sprintf("%son%s %s(%d ranges)%s", GRN, RST, GRY, c, RST)))
	} else {
		Say("  " + kv("iran ipset", GRY+"off"+RST))
	}
	Say("  " + kv("client ports", orStr(strings.Join(iranFWPorts(), " "), GRY+"none"+RST)))
	fmt.Fprintln(Stdout)
	Say("  " + GRY + "iptables rules" + RST)
	if rs := iranFWRules(); len(rs) > 0 {
		for _, r := range rs {
			Say("    " + GRN + r + RST)
		}
	} else {
		Say("    " + GRY + "none" + RST)
	}
}

func iranFirewallCmd(a []string) bool {
	rest := []string{}
	if len(a) > 1 {
		rest = a[1:]
	}
	switch arg(a, 0) {
	case "on", "enable":
		return iranFWApply(rest)
	case "off", "disable":
		iranFWRemove(rest)
	case "status":
		iranFWStatus()
	case "update":
		if !iranFWFetch() {
			return false
		}
		Ok("Updated cached Iran CIDRs.")
	default:
		iranFWStatus()
		fmt.Fprintln(Stdout)
		Say("  Client ports accept connections only from Iranian addresses. Scanners, probes")
		Say("  and your own users abroad are dropped.")
		Hint(P.Self + " iran-firewall on|off [ports] · status · update")
		fmt.Fprintln(Stdout)
		on := len(iranFWRules()) > 0
		q := "Turn protection on now?"
		if on {
			q = "Turn protection off now?"
		}
		if !Confirm(q, !on) {
			return true
		}
		if on {
			iranFWRemove(nil)
		} else {
			return iranFWApply(nil)
		}
	}
	return true
}
