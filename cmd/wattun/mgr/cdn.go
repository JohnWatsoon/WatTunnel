package mgr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The Cloudflare side of a CDN tunnel (ws, wss, h2, h2c, grpc through a proxied domain):
// pick the edges that serve the domain over ECH, then the TLS settings that get through.
// Callers: cdn-tune, the Iran wizard, auto test and auto-heal (bash cdn_*).

func init() {
	Register("cdn_tune_cmd", func(a ...string) int { return b2rc(cdnTuneCmd(arg(a, 0), arg(a, 1) == "full")) })
}

const cdnMinVer = "2.2.0" // fp / ech / tls-frag / several peers

var (
	csV4 = strings.Fields("162.159.140.220 162.159.141.1 162.159.141.100 162.159.135.1 162.159.135.100 162.159.136.1 162.159.136.100 162.159.128.1 162.159.128.100 104.16.0.1 104.17.0.1 104.18.0.1 104.19.0.1 104.21.0.1 104.24.0.1 172.64.0.1 172.64.80.1 172.65.0.1 172.66.0.1 172.67.0.1 172.67.74.1 188.114.96.1 188.114.97.6")
	csV6 = strings.Fields("2a06:98c1:3121::7 2a06:98c1:3120::7 2606:4700:3030::1 2606:4700:3033::1 2606:4700::6810:1 2606:4700:20::1")
)

// cdnScanRes is one edge scan: Edges are the best 3 to use, Reach every edge the engine
// saw carry a connection, Total the TCP-reachable count. Fallback: none was verified,
// Edges are then the domain's own addresses.
type cdnScanRes struct {
	Edges, Reach []string
	Total        int
	Fallback     bool
	Ran          bool
}

var csLast cdnScanRes // the last scan, for auto test's variant list

func cdnOK() bool { return binVerOK(cdnMinVer) }

func isCDNCar(c string) bool {
	switch c {
	case "ws", "wss", "h2", "h2c", "grpc":
		return true
	}
	return false
}

// cdnPickEdges keeps up to 3 of ips (fastest first): one per /24 (v6: /48) while there
// are alternatives, then fills up in order.
func cdnPickEdges(ips []string) []string {
	var out, rest []string
	seen := map[string]bool{}
	for _, ip := range ips {
		k := ip[:strings.LastIndex(ip, ".")+1]
		if strings.Contains(ip, ":") {
			k = strings.Join(strings.SplitN(ip, ":", 4)[:3], ":")
		}
		if !seen[k] && len(out) < 3 {
			seen[k] = true
			out = append(out, ip)
		} else {
			rest = append(rest, ip)
		}
	}
	for _, ip := range rest {
		if len(out) >= 3 {
			break
		}
		out = append(out, ip)
	}
	return out
}

// cdnPeerList: edges and a port -> "ip:port,[v6]:port".
func cdnPeerList(edges []string, port string) string {
	ps := make([]string, len(edges))
	for i, e := range edges {
		ps[i] = JoinHP(e, port)
	}
	return strings.Join(ps, ",")
}

// cdnParseEdges reads the edges the engine reports as up from /stats ("edges": [{"addr","up"}]).
func cdnParseEdges(raw string) []string {
	var st struct {
		Edges []struct {
			Addr string `json:"addr"`
			Up   bool   `json:"up"`
		} `json:"edges"`
	}
	if json.Unmarshal([]byte(raw), &st) != nil {
		return nil
	}
	var out []string
	for _, e := range st.Edges {
		if e.Up {
			h, _ := SplitHP(e.Addr)
			out = append(out, h)
		}
	}
	return out
}

var reV4Hint = regexp.MustCompile(`(?i)ipv4hint=([0-9.,]+)`)

// cdnIPv4Hints: the IPv4 addresses in the domain's HTTPS record (dig, else DoH); silent on failure.
func cdnIPv4Hints(dom string) []string {
	s := ""
	if _, err := exec.LookPath("dig"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		out, _ := exec.CommandContext(ctx, "dig", "+short", "+time=2", "+tries=1", "HTTPS", dom).Output()
		cancel()
		s = string(out)
	}
	if !reV4Hint.MatchString(s) {
		c := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil}}
		req, _ := http.NewRequest("GET", "https://8.8.8.8/resolve?name="+dom+"&type=HTTPS", nil)
		req.Header.Set("accept", "application/dns-json")
		if resp, err := c.Do(req); err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
			s = string(b)
		}
	}
	var out []string
	for _, m := range reV4Hint.FindAllStringSubmatch(s, -1) {
		for _, ip := range strings.Split(m[1], ",") {
			if isIPv4(ip) {
				out = append(out, ip)
			}
		}
	}
	return out
}

// cdnScan picks the Cloudflare edges that serve dom, judged by the tunnel engine itself:
// a TCP pre-filter, then one throw-away client (-fp chrome -ech auto, one pool connection
// per candidate) whose /stats says which edges really carried a connection. It needs
// atKeyFile for that second step. ok=false: nothing to choose from at all.
func cdnScan(dom, port, path, car string) (r cdnScanRes, ok bool) {
	if isIPv4(dom) || ipOK(dom) {
		return r, false // an IP address has no Cloudflare edges to choose from
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	v6 := exec.Command("ip", "-6", "route", "get", "2606:4700::1").Run() == nil // DNS may return AAAA without a v6 route
	seen := map[string]bool{}
	var own, cand []string
	addOwn := func(ip string) {
		if !seen[ip] {
			seen[ip] = true
			own = append(own, ip)
			cand = append(cand, ip)
		}
	}
	// the HTTPS record's ipv4hint first: the edges the zone advertises to browsers; then its A (and AAAA) records
	for _, ip := range cdnIPv4Hints(dom) {
		addOwn(ip)
	}
	if ips, err := net.LookupIP(dom); err == nil {
		var s4, s6 []string
		for _, ip := range ips {
			if ip.To4() != nil {
				s4 = append(s4, ip.String())
			} else if v6 {
				s6 = append(s6, ip.String())
			}
		}
		sort.Strings(s4)
		sort.Strings(s6)
		for _, ip := range append(s4, s6...) {
			addOwn(ip)
		}
	}
	known := csV4
	if v6 {
		known = append(append([]string{}, csV4...), csV6...)
	}
	for _, ip := range known {
		if !seen[ip] {
			seen[ip] = true
			cand = append(cand, ip)
		}
	}
	r.Ran = true

	// fast pre-filter: drop what cannot even open a TCP connection; fastest connect first
	ms := make([]time.Duration, len(cand))
	var wg sync.WaitGroup
	for i, ip := range cand {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			t0 := time.Now()
			if c, err := net.DialTimeout("tcp", JoinHP(ip, port), 2*time.Second); err == nil {
				c.Close()
				ms[i] = time.Since(t0)
			}
		}(i, ip)
	}
	wg.Wait()
	var reach []string
	for i, ip := range cand {
		if ms[i] > 0 {
			reach = append(reach, ip)
		}
	}
	idx := map[string]time.Duration{}
	for i, ip := range cand {
		idx[ip] = ms[i]
	}
	sort.SliceStable(reach, func(a, b int) bool { return idx[reach[a]] < idx[reach[b]] })
	r.Total = len(reach)
	if r.Total == 0 {
		if len(own) == 0 {
			return r, false
		}
		r.Fallback, r.Edges = true, own[:min(3, len(own))]
		return r, true
	}
	if len(reach) > 24 {
		reach = reach[:24]
	}

	if atKeyFile != "" {
		mp := envFreeMetricsPort()
		if dmap, ok := atFreePort(mp+1, map[int]bool{mp: true}); ok {
			a := []string{"-mode", "client", "-carrier", car, "-key-file", atKeyFile, "-peer", cdnPeerList(reach, port),
				"-metrics", "127.0.0.1:" + strconv.Itoa(mp), "-conns", strconv.Itoa(len(reach)),
				"-path", path, "-sni", dom, "-host", dom, "-map", fmt.Sprintf("%d:1@127.0.0.1", dmap)}
			if car == "wss" || car == "grpc" || car == "h2" {
				a = append(a, "-fp", "chrome", "-ech", "auto")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			cmd := exec.CommandContext(ctx, P.Bin, a...)
			var up []string
			if cmd.Start() == nil {
				for t := 0; t < 12; t++ {
					sleep(time.Second)
					if up = cdnParseEdges(p1FetchStats("127.0.0.1:" + strconv.Itoa(mp))); len(up) >= len(reach) {
						break
					}
				}
				cancel()
				_ = cmd.Wait()
			}
			cancel()
			isUp := map[string]bool{}
			for _, ip := range up {
				isUp[ip] = true
			}
			for _, ip := range reach {
				if isUp[ip] {
					r.Reach = append(r.Reach, ip)
				}
			}
		}
	}
	if len(r.Reach) > 0 {
		r.Edges = cdnPickEdges(r.Reach)
	} else {
		r.Fallback = true
		if len(own) > 0 {
			r.Edges = own[:min(3, len(own))]
		} else {
			r.Edges = reach[:min(3, len(reach))]
		}
	}
	return r, true
}

func cdnScanSay(r cdnScanRes) {
	switch {
	case len(r.Reach) > 0:
		Ok(fmt.Sprintf("CF edges: %d ECH / %d reachable", len(r.Reach), r.Total))
	case r.Total > 0:
		Warn(fmt.Sprintf("CF edges: 0/%d served ECH — using domain addresses", r.Total))
	default:
		Warn("CF edges: 0 addresses accepted TCP")
	}
}

// ---- tuning: which TLS settings get through Cloudflare ----

var (
	ctSNI  string
	ctFull bool
)

// cdnTry adds one CDN variant, probes it and prints the result; it returns its index.
func cdnTry(car, label, peer, fp, ech, frag string, wait int) int {
	avAdd(label, car, "c", peer, "", ctSNI, fp, ech, frag, "", "", "")
	i := len(av) - 1
	atProbe(i, wait)
	if !atQuiet {
		atPrint(Stdout, i, av, ar, atMB)
	}
	return i
}

// cdnVariants tries TLS variants in preference order: chrome+ech, chrome, go; tls-frag only
// when all failed (or as a diagnostic in a full run). skip: chrome+ech was tested already (index ci).
func cdnVariants(car, pa, pd string, skip bool, ci int) {
	eok := false
	if skip {
		eok = ci >= 0 && ar[ci].OK
	} else {
		// ECH is what works against an SNI filter: every non-ECH variant failed through Cloudflare from Iran
		eok = ar[cdnTry(car, car+" · chrome+ech", pa, "chrome", "auto", "", 12)].OK
	}
	if eok && !ctFull {
		return
	}
	anyOK := eok
	anyOK = ar[cdnTry(car, car+" · chrome", pa, "chrome", "", "", 8)].OK || anyOK
	anyOK = ar[cdnTry(car, car+" · go", pd, "", "", "", 8)].OK || anyOK
	// the ClientHello cut comes after the handshake, so it rarely helps against an SNI filter: last resort only
	if !anyOK {
		cdnTry(car, car+" · frag", pa, "chrome", "", "100", 8)
	} else if ctFull {
		cdnTry(car, car+" · frag (diagnostic)", pa, "chrome", "", "100", 8)
	}
}

// cdnAutoExtras: in auto test, the remaining variants of each CDN carrier whose chrome+ech failed (or all, when full).
func cdnAutoExtras() {
	var list []int
	for i := range av {
		if av[i].Kind == "c" {
			list = append(list, i)
		}
	}
	for _, i := range list {
		if !ctFull && ar[i].OK {
			continue
		}
		port := portOf(strings.Split(av[i].Peer, ",")[0])
		cdnVariants(av[i].Car, av[i].Peer, ctSNI+":"+port, true, i)
	}
}

// cdnTune scans and tests one CDN tunnel's variants. It returns the best index, or -1.
func cdnTune(car, peer, sni, path, key string, full bool) (int, error) {
	av, ar, ctSNI, ctFull = nil, nil, sni, full
	port := portOf(strings.Split(peer, ",")[0])
	pd := peer
	if strings.Contains(pd, ",") {
		pd = sni + ":" + port
	}
	if car == "h2" && !atQuiet {
		Hint("h2 does not work through Cloudflare; use grpc or wss")
	}
	if full && !atQuiet {
		switch car {
		case "wss":
			Hint("grpc: not offered by this Kharej tunnel")
		case "grpc":
			Hint("wss: not offered by this Kharej tunnel")
		}
	}
	kd, err := atPrep(key)
	if err != nil {
		return -1, err
	}
	defer kd.cleanup()
	atKeyFile, atTok = kd.dir+"/key", Token{Path: orStr(path, "/wat")}
	defer func() { atKeyFile = "" }()
	t0 := time.Now()
	var r cdnScanRes
	_ = spin("Cloudflare edges", func() error { r, _ = cdnScan(sni, port, orStr(path, "/wat"), car); return nil })
	csLast = r
	if r.Ran && !atQuiet {
		cdnScanSay(r)
		fmt.Fprintln(Stdout)
	}
	pa, label := pd, car
	if len(r.Edges) > 0 {
		pa, label = cdnPeerList(r.Edges, port), fmt.Sprintf("%s · %d edges", car, len(r.Edges))
	}
	switch car {
	case "wss", "grpc", "h2":
		cdnVariants(car, pa, pd, false, -1)
	default: // plain ws / h2c only get the edge choice; the default is tried only when that failed
		if !ar[cdnTry(car, label, pa, "", "", "", 8)].OK {
			cdnTry(car, car+" · default", pd, "", "", "", 8)
		}
	}
	atSecs = int(time.Since(t0).Seconds())
	for _, i := range atRank(av, ar, "") {
		if !strings.HasSuffix(av[i].Label, "(diagnostic)") { // the diagnostic row is never chosen
			return i, nil
		}
	}
	return -1, nil
}

// cdnDesc: "chrome fingerprint, ECH (hidden domain), 3 Cloudflare edges".
func cdnDesc(v variant) string {
	var out []string
	if v.FP != "" && v.FP != "go" {
		out = append(out, v.FP+" fingerprint")
	}
	if v.ECH != "" && v.ECH != "off" {
		out = append(out, "ECH (hidden domain)")
	}
	if v.Frag != "" && v.Frag != "0" {
		out = append(out, v.Frag+"-byte TLS fragments")
	}
	if h, _ := SplitHP(strings.Split(v.Peer, ",")[0]); ipOK(h) {
		n := len(strings.Split(v.Peer, ","))
		s := ""
		if n > 1 {
			s = "s"
		}
		out = append(out, fmt.Sprintf("%d Cloudflare edge%s", n, s))
	}
	if len(out) == 0 {
		return "default settings"
	}
	return strings.Join(out, ", ")
}

func cdnResultLine(i int) string {
	return fmt.Sprintf("Best: %s, %.1f/%.1f MB/s", cdnDesc(av[i]), ar[i].Down, ar[i].Up)
}

// cdnSettings: the peer/fp/ech/tls-frag signature cdn-tune compares before restarting.
func cdnSettings(peer, fp, ech, frag string) string { return peer + "/" + fp + "/" + ech + "/" + frag }

// dropKeyLines removes every line of n's config whose key matches re.
func dropKeyLines(n string, re *regexp.Regexp) {
	f := filepath.Join(P.Conf, n+".yml")
	var out []string
	for _, l := range strings.Split(p2ReadText(f), "\n") {
		if !re.MatchString(l) {
			out = append(out, l)
		}
	}
	_ = atomicWrite(f, []byte(strings.Join(out, "\n")), 0o600)
}

var reCDNKeys = regexp.MustCompile(`^(peer|fp|ech|ech-cache|tls-frag):`)

// cdnApply writes variant v's peer, sni and TLS settings into n's config and restarts it.
func cdnApply(n string, v variant, quiet bool) bool {
	dropKeyLines(n, reCDNKeys)
	SetValue(n, "peer", v.Peer)
	if Cfg(n, "sni") == "" {
		SetValue(n, "sni", v.SNI)
	}
	if Cfg(n, "host") == "" {
		SetValue(n, "host", v.SNI)
	}
	if v.FP != "" && v.FP != "go" {
		SetValue(n, "fp", v.FP)
	}
	if v.ECH != "" && v.ECH != "off" {
		SetValue(n, "ech", v.ECH)
		if v.ECH == "auto" && binVerOK("2.2.3") { // older engines reject unknown keys
			SetValue(n, "ech-cache", filepath.Join(P.Conf, n+".ech"))
		}
	}
	if v.Frag != "" && v.Frag != "0" {
		SetValue(n, "tls-frag", v.Frag)
	}
	if quiet {
		_ = Restart(Unit(n))
		return true
	}
	step("Restarting "+Unit(n), func() bool { return Restart(Unit(n)) == nil })
	if waitLink(n, 25) {
		Ok("CONNECTED (RTT " + LinkRTT + " ms)")
		return true
	}
	Warn("Not connected yet.")
	return !NonInteractive
}

// cdnLoad reads a CDN tunnel's carrier, peer, sni, path and key.
func cdnLoad(n string) (car, peer, sni, path, key string, ok bool) {
	if !cdnTunnelP(n) {
		return
	}
	kf := Cfg(n, "key-file")
	if !fileReadable(kf) {
		kf = filepath.Join(P.Conf, n+".key")
	}
	key = strings.TrimSpace(strings.SplitN(mustRead(kf), "\n", 2)[0])
	return Cfg(n, "carrier"), Cfg(n, "peer"), orStr(Cfg(n, "sni"), Cfg(n, "host")), Cfg(n, "path"), key, key != ""
}

// cdnTuneCmd re-runs the CDN tuning for an Iran CDN tunnel, shows the table and applies the best.
func cdnTuneCmd(n string, full bool) bool {
	if !cdnOK() {
		Err("CDN tuning needs wattun " + cdnMinVer + " or newer (this is " + BinVersion() + "). Run: " + P.Self + " update")
		return false
	}
	car, peer, sni, path, key, ok := cdnLoad(n)
	if !ok {
		Err("'" + n + "' is not an Iran tunnel on a CDN carrier (ws, wss, h2, h2c, grpc) with a domain.")
		return false
	}
	cur := cdnSettings(peer, Cfg(n, "fp"), Cfg(n, "ech"), Cfg(n, "tls-frag"))
	ClearScreen()
	Title(Stdout, "CDN tune", n)
	Hint("Testing from this server. The running tunnel is not touched until you confirm.")
	fmt.Fprintln(Stdout)
	atQuiet, atMB, atSkip, atStop = false, 20, "", false
	best, err := cdnTune(car, peer, sni, path, key, full)
	if err != nil {
		Err("Could not prepare the test (" + err.Error() + ").")
		return false
	}
	if best < 0 {
		fmt.Fprintln(Stdout)
		Err("No CDN variant got a working link from this server. Nothing was changed.")
		Hint("Check that the Kharej tunnel is running and the domain is proxied by Cloudflare.")
		return false
	}
	atTable(Stdout, av, ar, atRank(av, ar, ""), atMB, atSecs)
	fmt.Fprintln(Stdout)
	Ok(cdnResultLine(best))
	v := av[best]
	nfp, nech := v.FP, v.ECH
	if nfp == "go" {
		nfp = ""
	}
	if nech == "off" {
		nech = ""
	}
	nfrag := v.Frag
	if nfrag == "0" {
		nfrag = ""
	}
	nw := cdnSettings(v.Peer, nfp, nech, nfrag)
	if nw == cur {
		Ok("'" + n + "' already uses these settings.")
		return true
	}
	// same TLS settings and only the edge list differs: keep the running tunnel when every edge it uses is up
	// (a restart drops every open connection; edge order varies between scans)
	if strings.SplitN(nw, "/", 2)[1] == strings.SplitN(cur, "/", 2)[1] {
		if st := StatsRaw(n); strings.Contains(st, `"edges"`) && !regexp.MustCompile(`"up":\s*false`).MatchString(st) {
			Ok("'" + n + "' already uses these settings and all its Cloudflare edges are up; not restarting.")
			return true
		}
	}
	if !Confirm("Apply to '"+n+"'? (restarts the tunnel, open connections drop)", true) {
		Warn("No change.")
		return true
	}
	return cdnApply(n, v, false)
}

// cdnRefreshEdges (auto-heal, unattended): rescan and replace edges that no longer serve the domain.
func cdnRefreshEdges(n string) {
	if !cdnOK() {
		return
	}
	car, peer, dom, path, key, ok := cdnLoad(n)
	if !ok {
		return
	}
	if h, _ := SplitHP(strings.Split(peer, ",")[0]); !ipOK(h) {
		return // plain domain: Cloudflare DNS already hands out live edges
	}
	port := portOf(strings.Split(peer, ",")[0])
	kd, err := atPrep(key)
	if err != nil {
		return
	}
	atKeyFile = kd.dir + "/key"
	r, ok := cdnScan(dom, port, path, car)
	atKeyFile = ""
	kd.cleanup()
	switch {
	case !ok:
		envLogger("wattun-heal", "cdn scan for "+n+": no Cloudflare edge to choose from")
		return
	case r.Fallback:
		envLogger("wattun-heal", "cdn scan for "+n+": no edge served the domain over ECH right now, peer left as is")
		return
	}
	live := map[string]bool{}
	for _, ip := range r.Reach {
		live[ip] = true
	}
	bad := false
	for _, p := range strings.Split(peer, ",") {
		if h, _ := SplitHP(p); !live[h] {
			bad = true
		}
	}
	if !bad {
		envLogger("wattun-heal", "cdn scan for "+n+": all edges still serve the domain")
		return
	}
	nw := cdnPeerList(r.Edges, port)
	envLogger("wattun-heal", "cdn scan for "+n+": replacing dead edges, peer is now "+nw)
	SetValue(n, "peer", nw)
	_ = Restart(Unit(n))
}

// cdnWizardTune: Iran wizard, token accepted: a CDN carrier with a domain gets its best edges and
// TLS settings without questions. It returns the chosen variant, or ok=false to keep the token's.
func cdnWizardTune(tok Token) (variant, bool) {
	dom := tok.SNI
	if dom == "" {
		if h, _ := SplitHP(strings.Split(tok.Peer, ",")[0]); !ipOK(h) && !strings.Contains(h, ":") {
			dom = h
		}
	}
	if tok.Rev == "1" || !isCDNCar(tok.Carrier) || !cdnOK() || dom == "" {
		return variant{}, false
	}
	fmt.Fprintln(Stdout)
	q := atQuiet
	atQuiet, atMB, atSkip, atStop = true, 20, "", false
	best, err := cdnTune(tok.Carrier, tok.Peer, dom, tok.Path, tok.Key, false)
	atQuiet = q
	if err != nil || best < 0 {
		Warn("CDN tuning found no working edge — keeping token settings")
		return variant{}, false
	}
	if csLast.Ran {
		cdnScanSay(csLast)
	}
	if NonInteractive {
		atTable(Stdout, av, ar, atRank(av, ar, ""), atMB, atSecs)
	}
	Ok(cdnResultLine(best))
	return av[best], true
}

// cdnExtra: the fp / tls-frag / ech-cache config lines of a tuned CDN variant for a new
// tunnel; its ECH mode goes into *ech so the wizard writes the ech key once.
func cdnExtra(n string, v variant, ech *string) []string {
	var l []string
	if v.FP != "" && v.FP != "go" {
		l = append(l, "fp: "+v.FP)
	}
	if v.ECH != "" && v.ECH != "off" {
		*ech = v.ECH
		if v.ECH == "auto" && binVerOK("2.2.3") {
			l = append(l, "ech-cache: "+filepath.Join(P.Conf, n+".ech"))
		}
	}
	if v.Frag != "" && v.Frag != "0" {
		l = append(l, "tls-frag: "+v.Frag)
	}
	return l
}
