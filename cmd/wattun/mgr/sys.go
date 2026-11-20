package mgr

// The live system probes behind the p2*/env* adapter vars: firewall, busy ports,
// free ports, public IP, link wait, systemd-run, syslog. Ports of the bash
// helpers named in each comment. Run wires them in (wireSystem); tests keep the
// inert defaults so they never touch the host.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var (
	cfHTTPSPorts = []int{2053, 2083, 2087, 2096, 8443}
	cfHTTPPorts  = []int{2052, 2082, 2086, 2095, 8880, 8080}
)

// wireSystem swaps the inert adapter defaults for the live probes.
func wireSystem() {
	p2FWOpen, envFWOpen = fwOpen, fwOpen
	p2FWClose, envFWClose = fwClose, fwClose
	p2PortBusy = func(port int, proto string) bool { return portBusy(port, proto, false) }
	p2PortUser = portUser
	p2TunnelUsingPublic = tunnelUsingPublic
	p2LocalAnswers = func(port string) bool {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 2*time.Second)
		if err == nil {
			c.Close()
		}
		return err == nil
	}
	p2WaitLink = waitLink
	p2PublicIP, envPublicIP = publicIP, publicIP
	p2FreeMetricsPort, envFreeMetricsPort = freeMetricsPort, freeMetricsPort
	p2DefaultListen = func(c string) string {
		p, err := randOpenPort(p2Rproto(c), nil)
		if err != nil {
			return ""
		}
		return fmt.Sprint(p)
	}
	envRandOpenPort = randOpenPort
	p2ShapedSupported = shapedSupportedLive
	envSystemdRun = systemdRun
	envLogger = func(tag, msg string) { _ = exec.Command("logger", "-t", tag, msg).Run() }
}

func randPathLive() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("/api/%x", b)
}

func randU16() int {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint16(b[:]))
}

// ---- firewall (bash fw_kind / fw_open / fw_close) ----

func fwKind() string {
	if _, err := exec.LookPath("ufw"); err == nil {
		if out, _ := exec.Command("ufw", "status").Output(); strings.Contains(string(out), "Status: active") {
			return "ufw"
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		if exec.Command("firewall-cmd", "--state").Run() == nil {
			return "firewalld"
		}
	}
	return ""
}

// fwOpen opens "443/tcp" style specs in ufw/firewalld; without one it says
// which ports a cloud firewall must pass.
func fwOpen(specs ...string) {
	if len(specs) == 0 {
		return
	}
	fw := fwKind()
	if fw == "" {
		Warn("No active ufw/firewalld found on this server.")
		Hint("If a cloud firewall is in front, open: " + strings.Join(specs, " "))
		return
	}
	for _, p := range specs {
		if fw == "ufw" {
			if exec.Command("ufw", "allow", p).Run() == nil {
				Ok("ufw: allowed " + p)
			}
		} else if exec.Command("firewall-cmd", "-q", "--permanent", "--add-port="+p).Run() == nil {
			Ok("firewalld: allowed " + p)
		}
	}
	if fw == "firewalld" {
		_ = exec.Command("firewall-cmd", "-q", "--reload").Run()
	}
}

func fwClose(specs ...string) {
	fw := fwKind()
	if fw == "" {
		return
	}
	for _, p := range specs {
		if fw == "ufw" {
			if exec.Command("ufw", "delete", "allow", p).Run() == nil {
				Ok("ufw: closed " + p)
			}
		} else if exec.Command("firewall-cmd", "-q", "--permanent", "--remove-port="+p).Run() == nil {
			Ok("firewalld: closed " + p)
		}
	}
	if fw == "firewalld" {
		_ = exec.Command("firewall-cmd", "-q", "--reload").Run()
	}
}

// ---- ports (bash port_busy / tunnel_using_* / rand_open_port / free_metrics_port) ----

// portBusy: is something listening on port (bind: bound at all) for proto
// tcp, udp or any? ss first, /proc/net when ss is missing or fails.
func portBusy(port int, proto string, bind bool) bool {
	if port < 1 || port > 65535 {
		return true
	}
	if _, err := exec.LookPath("ss"); err == nil {
		fl := map[string]string{"tcp": "-Hltn", "udp": "-Hlun"}[proto]
		if fl == "" {
			fl = "-Hltnu"
		}
		if bind {
			fl = map[string]string{"tcp": "-Htan", "udp": "-Haun"}[proto]
			if fl == "" {
				fl = "-Htaun"
			}
		}
		if out, err := exec.Command("ss", fl, fmt.Sprintf("( sport = :%d )", port)).Output(); err == nil {
			return strings.TrimSpace(string(out)) != ""
		}
	}
	files := map[string][]string{"tcp": {"tcp", "tcp6"}, "udp": {"udp", "udp6"}}[proto]
	if files == nil {
		files = []string{"tcp", "tcp6", "udp", "udp6"}
	}
	hex := fmt.Sprintf(":%04X", port)
	for _, f := range files {
		b, err := os.ReadFile("/proc/net/" + f)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if i == 0 || len(fs) < 4 || !strings.HasSuffix(strings.ToUpper(fs[1]), hex) {
				continue
			}
			if bind || strings.HasPrefix(f, "udp") || fs[3] == "0A" {
				return true
			}
		}
	}
	return false
}

func ymlFiles() []string {
	fs, _ := filepath.Glob(filepath.Join(P.Conf, "*.yml"))
	return fs
}

// tunnelUsingKey returns the tunnel whose config has a keyRe: line ending in :port.
func tunnelUsingKey(keyRe string, port, exclude string) string {
	re := regexp.MustCompile(`(?m)^` + keyRe + `:[ \t]*["']?[^"'#\n]*:` + regexp.QuoteMeta(port) + `["']?([ \t]*(#.*)?)?$`)
	for _, f := range ymlFiles() {
		n := strings.TrimSuffix(filepath.Base(f), ".yml")
		if n == exclude {
			continue
		}
		if b, err := os.ReadFile(f); err == nil && re.Match(b) {
			return n
		}
	}
	return ""
}

func tunnelUsingListen(port, exclude string) string {
	return tunnelUsingKey(`listen(-[a-z0-9-]+)?`, port, exclude)
}

func tunnelUsingMisc(port, exclude string) string {
	return tunnelUsingKey(`(metrics|dns-listen)`, port, exclude)
}

// tunnelUsingPublic: another Iran tunnel already publishing port/proto.
func tunnelUsingPublic(port, proto, exclude string) string {
	for _, n := range Tunnels() {
		if n == exclude || Role(n) != "Iran" {
			continue
		}
		for _, it := range YmlMaps(n) {
			if it != "" && SpecL(it) == port && SpecP(it) == proto {
				return n
			}
		}
	}
	return ""
}

func portReserved(p int, excl []string) bool {
	if p >= 18990 && p <= 18999 || p >= 19700 && p <= 20999 {
		return true
	}
	for _, e := range excl {
		if e == fmt.Sprint(p) {
			return true
		}
	}
	return false
}

func listenBlocked(proto string, p int) bool {
	ps := fmt.Sprint(p)
	return portBusy(p, proto, true) || tunnelUsingListen(ps, "") != "" ||
		tunnelUsingPublic(ps, proto, "") != "" || tunnelUsingMisc(ps, "") != ""
}

// randOpenPort picks a free random port in 10000-32767 (below the kernel's
// ephemeral range), then 40000-60000, then a sweep.
func randOpenPort(proto string, excl []string) (int, error) {
	try := func(p int) bool { return !portReserved(p, excl) && !listenBlocked(proto, p) }
	for i := 0; i < 200; i++ {
		if p := 10000 + randU16()%22768; try(p) {
			return p, nil
		}
	}
	for i := 0; i < 100; i++ {
		if p := 40000 + randU16()%20001; try(p) {
			return p, nil
		}
	}
	start := randU16() % 22768
	for i := 0; i < 256; i++ {
		if p := 10000 + (start+i*103)%22768; try(p) {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free %s port", proto)
}

// pickCFPort: a free Cloudflare-proxyable port for a CDN carrier (never 443/80),
// else a random open one; fallback reports the latter.
func pickCFPort(c string, excl []string) (port int, fallback bool, err error) {
	var pool []int
	switch c {
	case "wss", "grpc", "h2":
		pool = cfHTTPSPorts
	case "ws", "h2c":
		pool = cfHTTPPorts
	default:
		p, err := randOpenPort(p2Rproto(c), excl)
		return p, false, err
	}
	off := randU16() % len(pool)
	for i := range pool {
		p := pool[(off+i)%len(pool)]
		if !portReserved(p, excl) && !listenBlocked("tcp", p) {
			return p, false, nil
		}
	}
	p, err := randOpenPort("tcp", excl)
	return p, true, err
}

// freeMetricsPort: the first free metrics port from WAT_METRICS_BASE (19750,
// sandbox 19850), skipping the reserved ranges; 0 when none (no /stats then).
func freeMetricsPort() int {
	p := atoi(os.Getenv("WAT_METRICS_BASE"))
	if p < 1000 || p > 65535 {
		p = 19750
		if P.Sandbox {
			p = 19850
		}
	}
	lim := p + 650
	if p < 20400 && lim > 20400 {
		lim = 20400
	}
	if lim > 65535 {
		lim = 65535
	}
	for ; p < lim; p++ {
		if p >= 18990 && p <= 18999 || p >= 19700 && p <= 19709 || p >= 20400 && p <= 20999 {
			continue
		}
		ps := fmt.Sprint(p)
		if !portBusy(p, "tcp", true) && tunnelUsingMisc(ps, "") == "" &&
			tunnelUsingListen(ps, "") == "" && tunnelUsingPublic(ps, "tcp", "") == "" {
			return p
		}
	}
	fmt.Fprintf(Stderr, "  ! No free metrics port below %d; this tunnel gets no /stats listener (auto-heal cannot read it).\n", lim)
	return 0
}

// ---- public IP (bash public_ip) ----

func ipPrivate(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		(ip.To4() != nil && ip.To4()[0] == 100 && ip.To4()[1]&0xc0 == 64)
}

// publicIP: a public address on an interface first (no third-party lookup),
// then ipify/ifconfig.me for NAT'd servers; IPv6 only when there is no IPv4.
func publicIP() string {
	if c, err := net.Dial("udp4", "1.1.1.1:53"); err == nil {
		ip := c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
		if !ipPrivate(ip) {
			return ip.String()
		}
	}
	cl := &http.Client{Timeout: 5 * time.Second}
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me"} {
		if r, err := cl.Get(u); err == nil {
			b, _ := io.ReadAll(io.LimitReader(r.Body, 64))
			r.Body.Close()
			if ip := net.ParseIP(strings.TrimSpace(string(b))); ip != nil && ip.To4() != nil {
				return ip.String()
			}
		}
	}
	if c, err := net.Dial("udp6", "[2606:4700::1111]:53"); err == nil {
		ip := c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
		if !ipPrivate(ip) && !strings.HasPrefix(strings.ToLower(ip.String()), "fc") && !strings.HasPrefix(strings.ToLower(ip.String()), "fd") {
			return ip.String()
		}
	}
	return ""
}

// ---- link wait (bash wait_link) ----

// LinkRTT holds the round trip wait_link saw when the link came up.
var LinkRTT string

func linkStats(n string) map[string]any {
	m, err := p1Stats(n)
	if err != nil {
		return nil
	}
	return m
}

// waitLink waits up to secs for the tunnel to report alive (45 s minimum for a
// reverse tunnel: the dialer backs off up to 30 s), with a spinner and bar.
func waitLink(n string, secs int) bool {
	if secs <= 0 {
		secs = 25
	}
	if IsReverse(n) && secs < 45 {
		secs = 45
	}
	spin := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
	if UseAnim {
		CurHide()
		defer CurShow()
	} else {
		fmt.Fprintf(Stdout, "  Waiting for the link (up to %ds)...\n", secs)
	}
	t0 := time.Now()
	for i := 0; ; i++ {
		if m := linkStats(n); m != nil && get(m, "alive") == "true" {
			if UseAnim {
				fmt.Fprint(Stdout, "\r\x1b[K")
			}
			rtt := getF(m, "rtt_ms")
			if rtt == 0 {
				rtt = getF(m, "srtt_ms")
			}
			LinkRTT = Ms(rtt)
			return true
		}
		el := int(time.Since(t0).Seconds())
		if el >= secs || !IsActive(Unit(n)) {
			break
		}
		if UseAnim {
			for f := 0; f < 4; f++ {
				fmt.Fprintf(Stdout, "\r\x1b[K  %s%c%s Waiting for the link  %s  %s%ds / %ds%s",
					CYN, spin[(i*4+f)%len(spin)], RST, tbarC(float64(el), float64(secs), 20), GRY, el, secs, RST)
				time.Sleep(120 * time.Millisecond)
			}
		} else {
			time.Sleep(time.Second)
		}
	}
	if UseAnim {
		fmt.Fprint(Stdout, "\r\x1b[K")
	}
	return false
}

// ---- shaped carriers / systemd-run (bash shaped_supported_here) ----

func shapedSupportedLive(list string) (bool, string) {
	shaped, raw := false, false
	for _, c := range strings.Split(list, "+") {
		if IsShapedCarrier(c) {
			shaped = true
			raw = raw || isShapedRaw(c)
		}
	}
	if !shaped {
		return true, ""
	}
	if raw && runtime.GOOS != "linux" {
		return false, "The raw-tier shaped carriers (sit, 6to4, xfrm-ipsec, etherip, l2tpv3) need Linux + root/CAP_NET_RAW on both ends (raw sockets); this server is not Linux."
	}
	if !BinVerOK("3.3.0") {
		v := Ver
		if v == "" {
			v = "an unknown version"
		}
		return false, fmt.Sprintf("Shaped carriers need wattun 3.3.0 or newer on BOTH ends; this server has %s. Run: %s update", v, P.Self)
	}
	return true, ""
}

// systemdRun starts a transient unit that stops itself after maxSec.
func systemdRun(unit string, maxSec int, args ...string) error {
	a := append([]string{"--unit=" + unit, "--quiet", "--collect", fmt.Sprintf("--property=RuntimeMaxSec=%d", maxSec)}, args...)
	return exec.Command("systemd-run", a...).Run()
}
