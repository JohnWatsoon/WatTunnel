// Package mgr — P2: the new-tunnel wizards. Faithful port of wattun-manager
// (bash): wizard_kharej (2684), wizard_iran (3382), pick_carrier (2633) with the
// shaped-tier picker (pick_shaped_carrier 2616), and the write_server /
// write_client heredocs (2816 / 3656). Depends only on the P1 core (untagged)
// plus the p2* adapters in tunnels.go.

package mgr

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

func init() {
	Register("wizard_kharej", func(args ...string) int { return b2i(wizardKharej()) })
	Register("wizard_iran", func(args ...string) int { return b2i(wizardIran()) })
	Register("new_tunnel", func(args ...string) int { newTunnelScreen(); return 0 })
}

func base64StdEncode(s string) string  { return base64.StdEncoding.EncodeToString([]byte(s)) }
func cryptoRead(b []byte) (int, error) { return rand.Read(b) }

// bash SHAPED_RAW / SHAPED_UDP (1301-1302): raw tier first in the picker order.
var p2ShapedRawList = []string{"sit", "6to4", "xfrm-ipsec", "etherip", "l2tpv3"}
var p2ShapedUDPList = []string{"fou-gre", "gue-ipip", "vxlan", "geneve", "dnscrypt-udp", "ntp-direct", "openvpn-dco", "srtp-direct"}

// shaped_raw_proto (bash): IP protocol numbers shown in the picker.
func shapedRawProto(c string) string {
	switch c {
	case "sit", "6to4":
		return "41"
	case "xfrm-ipsec":
		return "50"
	case "etherip":
		return "97"
	case "l2tpv3":
		return "115"
	}
	return "?"
}

func shapedSupportedHere(c string) bool {
	if ok, why := p2ShapedSupported(c); !ok {
		Err(why)
		return false
	}
	return true
}

// pick_shaped_carrier (bash 2616): numbered shaped list -> carrier; "" = cancelled.
func pickShapedCarrier() string {
	opts := append(append([]string{}, p2ShapedRawList...), p2ShapedUDPList...)
	fmt.Fprintln(Stdout)
	Say("  " + BOLD + "More transports" + RST + " " + GRY + "(advanced; wattun-internal wire shapes, NOT the real protocols)" + RST)
	Say("  " + GRY + "Both ends need wattun 3.3.0; single carrier only; raw tier needs root/CAP_NET_RAW." + RST)
	i := 0
	for _, c := range p2ShapedRawList {
		i++
		Say("   " + KeyLabel(strconv.Itoa(i)) + " " + c + "  " + GRY + "raw tier, IP protocol " + shapedRawProto(c) + RST)
	}
	for _, c := range p2ShapedUDPList {
		i++
		Say("   " + KeyLabel(strconv.Itoa(i)) + " " + c + "  " + GRY + "UDP shape, random open port" + RST)
	}
	fmt.Fprintln(Stdout)
	r := Ask(fmt.Sprintf("Number 1-%d (Enter = cancel)", i), "")
	if r == "" {
		return ""
	}
	n, err := strconv.Atoi(r)
	if err != nil || n < 1 || n > len(opts) {
		Err("No shaped carrier number '" + r + "'.")
		return ""
	}
	c := opts[n-1]
	if !VCarrierList(c) {
		return ""
	}
	if !shapedSupportedHere(c) {
		return ""
	}
	p2ShapedWarn(c)
	return c
}

// pick_carrier (bash 2633): key-driven picker; "" = cancelled.
func pickCarrier(auto bool) string {
	var opts, descs []string
	if auto {
		opts = append(opts, "auto")
		descs = append(descs, BOLD+"Auto (recommended)"+RST+": this server accepts every type; the Iran server tests them all and\n        keeps the best. Later, on the Iran server, you can switch to another type or join several (tunnel page, m).")
	}
	opts = append(opts, "icmp", "udp", "tcp", "tls", "wss", "ws", "grpc", "h2", "gre", "ipip")
	descs = append(descs,
		"icmp  ping packets; works when everything else is blocked (the usual case on filtered routes)",
		"udp   fastest and lowest latency, if UDP passes",
		"tcp   plain TCP, if TCP passes",
		"tls   TCP that looks like a normal HTTPS site",
		"wss   WebSocket over TLS; works behind Cloudflare or another CDN",
		"ws    WebSocket without TLS (CDN on port 80, or a proxy that adds TLS)",
		"grpc  gRPC, for CDNs that allow it",
		"h2    HTTP/2",
		"gre   GRE (IP protocol 47); raw-IP like icmp, root and Linux only",
		"ipip  IP-in-IP (protocol 4); raw-IP like icmp, root and Linux only")
	n := len(opts)
	Say("  " + BOLD + "Connection type" + RST + ": how the two servers talk to each other")
	for i := 0; i < n; i++ {
		switch opts[i] {
		case "icmp":
			if opts[0] == "auto" {
				Say("  " + GRY + "Or choose one type yourself (fixed; to change it later, make a new tunnel):" + RST)
			}
			Say("   " + GRY + "Gets through the strictest filters" + RST)
		case "udp":
			Say("   " + GRY + "Fast and simple, if your route lets them through" + RST)
		case "tls":
			Say("   " + GRY + "Looks like web traffic: harder to block, and the only kind a CDN carries" + RST)
		}
		Say("    " + CYN + strconv.Itoa(i+1) + RST + " " + descs[i])
	}
	Say("    " + CYN + "0" + RST + " h2c  HTTP/2 without TLS (a CDN or proxy that terminates TLS)")
	Say("    " + CYN + "m" + RST + " More transports (advanced) … 13 shaped carriers, both ends 3.3.0, single only")
	for t := 0; t < 3; t++ {
		k, _, _ := KeyRead(0)
		switch {
		case k == "enter":
			return opts[0]
		case k == "0":
			return "h2c"
		case k == "m" || k == "M":
			if c := pickShapedCarrier(); c != "" {
				return c
			}
		case k >= "1" && k <= "9":
			i, _ := strconv.Atoi(k)
			if i <= n {
				return opts[i-1]
			}
			fmt.Fprintln(Stdout)
			Warn(fmt.Sprintf("Press 1-%d, 0 for h2c, or m for the shaped carriers.", n))
		case k == "esc" || k == "q":
			fmt.Fprintln(Stdout)
			return ""
		default:
			fmt.Fprintln(Stdout)
			Warn(fmt.Sprintf("Press 1-%d, 0 for h2c, or m for the shaped carriers.", n))
		}
	}
	return ""
}

// ======================================================================================
// Kharej wizard (bash wizard_kharej 2684)
// ======================================================================================

// kharejParams: everything write_server writes (plus the token fields).
type kharejParams struct {
	Name, Carrier, Listen, LisIP, Path, SNI, IcmpType, Mbps, FEC string
	UDPdns                                                       bool
	Rev                                                          bool
	IranIP                                                       string
	Allow                                                        string // "443,53/udp" ("" = any)
	MetricsPort                                                  int
	Key                                                          string
}

// allowToMaps: the ports: rows of an allow string (443:443/tcp ...).
func allowToMaps(allow string) []string {
	var out []string
	for _, it := range allowToArray(allow) {
		out = append(out, SpecT(it)+":"+SpecT(it)+"/"+SpecP(it))
	}
	return out
}

// kharejYML: the write_server heredoc, key for key (bash 2816-2842).
func kharejYML(p kharejParams) string {
	var b strings.Builder
	b.WriteString("# WatTunnel - Kharej (server). Created by wattun-manager.\n")
	b.WriteString("mode: server\n")
	b.WriteString("key-file: " + P.Conf + "/" + p.Name + ".key" + "\n")
	b.WriteString("carrier: " + p.Carrier + "\n")
	if p.Listen != "" && (!p.Rev || p.Carrier == "udp") { // reverse udp binds it as the source port
		b.WriteString("listen: \"" + JoinHP(p.LisIP, p.Listen) + "\"\n")
	}
	if p.UDPdns {
		b.WriteString("udp-dns: true\n")
	}
	if p.Path != "" {
		b.WriteString("path: " + p.Path + "\n")
	}
	if p.IcmpType != "" && p.IcmpType != "echo" {
		b.WriteString("icmp-type: " + p.IcmpType + "\n")
	}
	if p.Rev {
		b.WriteString("reverse: true\n")
		if IsRpool(p.Carrier) {
			b.WriteString("peer: " + JoinHP(p.IranIP, p.Listen) + "\n")
			if p.SNI != "" {
				b.WriteString("sni: " + p.SNI + "\n")
				b.WriteString("host: " + p.SNI + "\n")
			}
			b.WriteString("pool-rotate: 30m\n")
		} else {
			b.WriteString("peer: " + p.IranIP + "\n")
		}
	}
	if p.Mbps != "" {
		b.WriteString("max-mbps: " + p.Mbps + "\n")
	}
	if p.FEC == "auto" {
		b.WriteString("fec: auto\n")
	}
	if p.MetricsPort > 0 { // F25: no free port; write no invalid line
		b.WriteString("metrics: 127.0.0.1:" + strconv.Itoa(p.MetricsPort) + "\n")
	}
	if maps := allowToMaps(p.Allow); len(maps) > 0 {
		b.WriteString("ports:\n")
		for _, m := range maps {
			b.WriteString("  - " + SpecYaml(m) + "\n")
		}
	}
	return b.String()
}

// summary_line (bash 2682)
func summaryLine(l, v string) {
	fmt.Fprintf(Stdout, "    %s%-14s%s %s\n", GRY, l, RST, v)
}

func wizardKharej() bool {
	Page("New tunnel", "Kharej")
	name := suggestName("kharej")
	cr := pickCarrier(true)
	if cr == "" {
		return false
	}
	if cr == "auto" {
		// wizard_kharej_auto (bash 4056) is the auto pass's screen; route to it.
		if registered("wizard_kharej_auto") {
			return dispatch("wizard_kharej_auto", name) == 0
		}
		Warn("The auto carrier needs the auto-plan writer (not ported yet); pick a fixed type.")
		cr = pickCarrier(false)
		if cr == "" {
			return false
		}
	}
	if isShapedList(cr) {
		if !shapedSupportedHere(cr) {
			return false
		}
		p2ShapedWarn(cr)
	}
	var path, listen, sni, itype, mbps, fec, iranip, addr, allow, lisip string
	var rev, udpdns bool
	switch cr {
	case "ws", "wss", "grpc", "h2", "h2c":
		path = p2RandPath()
	}
	if cr == "udp" {
		fmt.Fprintln(Stdout)
		Hint("Some routes cut UDP flows but pass DNS-looking UDP on port 53. Needs wattun 3.0.0+ on both ends.")
		if Confirm("Use DNS-shaped UDP on port 53? (only if plain udp does not work on your route)", false) {
			udpdns = true
			listen = "53"
			lisip = p2PublicIP() // port 53 is often held by the local resolver on 127.0.0.53 only
		}
	}
	// address Iran connects to (bash 2728-2749)
	addr = p2PublicIP()
	if addr == "" {
		if !AskOK("Public IP or domain", "", vHost) {
			return false
		}
		addr = ReplyV
	} else {
		Ok("Public address  " + addr)
	}
	switch cr {
	case "wss", "grpc", "h2", "ws", "h2c": // behind a CDN, Iran dials the domain
		if !AskOK("CDN domain (Enter to keep "+addr+")", addr, vHost) {
			return false
		}
		addr = ReplyV
	}
	if carrierWriteListen(cr) && listen == "" {
		listen = p2DefaultListen(cr)
		if listen == "" {
			Err("Could not find a free open port on this server.")
			return false
		}
	}

	// advanced (bash 2761-2793)
	fmt.Fprintln(Stdout)
	def := name + " · " + addr
	if listen != "" {
		def += ":" + listen
	}
	if path != "" {
		def += " " + path
	}
	Hint("Defaults: " + def + " · unlimited · FEC off")
	if Confirm("Edit advanced settings?", false) {
		if !AskOK("Tunnel name", name, vName) {
			return false
		}
		name = ReplyV
		if !AskOK("Public IP or domain", addr, vHost) {
			return false
		}
		addr = ReplyV
		if cr == "icmp" {
			if !AskOK("ICMP type (echo, timestamp)", "echo", vIcmp) {
				return false
			}
			itype = ReplyV
			fmt.Fprintln(Stdout)
			reverseHint("icmp")
			if Confirm("Reverse direction (Kharej pings Iran)?", false) {
				if !AskOK("Iran IPv4 address", "", vIPv4) {
					return false
				}
				iranip, rev = ReplyV, true
			}
		} else {
			if carrierWriteListen(cr) {
				if !AskOK("Listen port", listen, vPort) {
					return false
				}
				listen = ReplyV
			}
			if IsRpool(cr) && !strings.Contains(cr, "+") {
				fmt.Fprintln(Stdout)
				reverseHint(cr)
				if Confirm(fmt.Sprintf("Reverse direction (Kharej dials Iran:%s)?", listen), false) {
					if !AskOK("Iran IP address", "", vHost) {
						return false
					}
					iranip = strings.TrimSuffix(strings.TrimPrefix(ReplyV, "["), "]")
					rev = true
				}
			}
		}
		switch cr {
		case "ws", "wss", "grpc", "h2", "h2c":
			if !AskOK("URL path", path, vPath) {
				return false
			}
			path = ReplyV
		}
		switch cr {
		case "wss", "tls", "grpc", "h2":
			sni = Ask("SNI (empty = none)", sni)
		}
		if !AskOK("Speed limit MB/s (empty = none)", mbps, vMbps) {
			return false
		}
		mbps = ReplyV
		if !askFec("off") {
			return false
		}
		fec = ReplyV
	}
	if !vName(name) {
		Err("The name '" + name + "' is not available.")
		return false
	}
	addr, _ = SplitHP(addr)
	switch cr {
	case "wss", "grpc", "h2", "tls":
		if sni == "" && !ipOK(addr) {
			sni = addr
		}
	}

	// summary (bash 2798-2811)
	fmt.Fprintln(Stdout)
	summaryLine("Name", name+" (Kharej)")
	car := cr
	if itype != "" {
		car += " (" + itype + ")"
	}
	if listen != "" {
		car += " :" + listen
	}
	if path != "" {
		car += " " + path
	}
	if udpdns {
		car += " (DNS-shaped)"
	}
	summaryLine("Carrier", car)
	summaryLine("Address", addr)
	if rev {
		if cr == "icmp" {
			summaryLine("Direction", "reverse → "+iranip)
		} else {
			summaryLine("Direction", "reverse → "+JoinHP(iranip, listen))
		}
	}
	summaryLine("Allow ports", orStr(allow, "any"))
	if mbps != "" {
		summaryLine("Speed limit", mbps+" MB/s")
	}
	if fec == "auto" {
		summaryLine("FEC", "auto")
	}
	fmt.Fprintln(Stdout)
	if !Confirm("Create tunnel '"+name+"'?", true) {
		Warn("Cancelled.")
		return false
	}
	fmt.Fprintln(Stdout)

	key := p2NewKey()
	mp := p2FreeMetricsPort()
	peer := JoinHP(addr, listen)
	p := kharejParams{
		Name: name, Carrier: cr, Listen: listen, LisIP: lisip, Path: path, SNI: sni,
		IcmpType: itype, Mbps: mbps, FEC: fec, UDPdns: udpdns, Rev: rev, IranIP: iranip,
		Allow: allow, MetricsPort: mp, Key: key,
	}
	atomicWrite(filepath.Join(P.Conf, name+".key"), []byte(key+"\n"), 0o600)
	atomicWrite(filepath.Join(P.Conf, name+".yml"), []byte(kharejYML(p)), 0o600)
	tp := path
	if tp == "" && udpdns {
		tp = "dns"
	}
	tok := MakeToken(cr, peer, key, tp, sni, itype, allow, revFlag(rev), "")
	atomicWrite(filepath.Join(P.Conf, name+".token"), []byte(tok+"\n"), 0o600)
	p2StartUnit(name)
	if listen != "" && !rev {
		p2FWOpen(listen + "/" + p2Rproto(cr))
	}
	if rev && IsRpool(cr) {
		Hint("Cloud firewall: allow outbound to " + iranip + ":" + listen + "/" + p2Rproto(cr) + ".")
	} else if rev || cr == "icmp" {
		Hint("Cloud firewall: allow ICMP.")
	}
	fmt.Fprintln(Stdout)
	fmt.Fprintf(Stdout, "  %s◆%s %s%s%s\n", GRN, RST, BOLD, "Kharej tunnel '"+name+"' ready", RST)
	fmt.Fprintln(Stdout)
	fmt.Fprintf(Stdout, "  %s%s%s\n\n", BOLD+YEL, tok, RST)
	Say("  Next on Iran: run " + CYN + P.Self + RST + " → " + KeyLabel("n") + " → paste token")
	Hint("Token contains secret key — share privately (" + P.Self + " token " + name + ")")
	return true
}

func revFlag(b bool) string {
	if b {
		return "1"
	}
	return ""
}

// reverse_hint (bash 1452)
func reverseHint(cr string) {
	if cr == "udp" {
		Hint("Reverse: Kharej sends first and Iran only answers. For filters that punish flows Iran starts.")
		Hint("Set it on both sides (wattun 3.0.0+).")
	} else if IsPool(cr) {
		Hint("Reverse: Kharej connects to Iran. For when Iran cannot reach Kharej's port, but Kharej can reach Iran.")
		Hint("Set it on both sides.")
	} else {
		Hint("Reverse: Kharej pings Iran. For a one-way block where Iran cannot ping Kharej.")
		Hint("Set it on both sides (wattun 2.0.0+).")
	}
}

// ask_fec (bash 1531): off, auto, or a (auto + loss-band rows later).
func askFec(def string) bool {
	Hint("auto sends parity only while loss is above 2 %; a here lets you tune the band.")
	r := strings.ToLower(Ask("FEC: off, auto, or a (auto + open the loss-band rows)", def))
	switch r {
	case "", "off", "default":
		ReplyV = "off"
		return true
	case "auto", "a":
		ReplyV = "auto"
		return true
	}
	Err("Use off, auto or a.")
	return false
}

// ======================================================================================
// Iran wizard (bash wizard_iran 3382)
// ======================================================================================

// iranParams: everything write_client writes.
type iranParams struct {
	Name, Carrier, Peer, Key string
	LegC, LegP               []string // a bond token's per-leg endpoints (M1)
	Path, SNI                string
	FakeSNI, FakeMode        string
	FakeTTL, PoolRot         string
	PoolBytes, ECH           string
	Governor, DNSListen      string
	SrcIP, IcmpType          string
	Rev                      bool
	ListenPort               string
	Extra                    []string // auto-plan extra lines (AT_EXTRA)
	Bind, Mbps, FEC          string
	MetricsPort              int
	Maps                     []string
}

// iranYML: the write_client heredoc, key for key (bash 3656-3695).
func iranYML(p iranParams) string {
	var b strings.Builder
	b.WriteString("# WatTunnel - Iran (client). Created by wattun-manager.\n")
	b.WriteString("mode: client\n")
	b.WriteString("key-file: " + P.Conf + "/" + p.Name + ".key" + "\n")
	b.WriteString("carrier: " + p.Carrier + "\n")
	b.WriteString("peer: " + p.Peer + "\n")
	// M1: a bond token's per-leg endpoints (empty for a single carrier); each leg
	// dials its own. A directional leg (:up/:down, 3.3.9) dials the same address as
	// its base carrier, and the engine registers per-carrier flags under the base
	// name, so the key loses the suffix.
	for i, l := range p.LegC {
		b.WriteString("peer-" + CarrierLegBase(l) + ": " + p.LegP[i] + "\n")
	}
	if p.Carrier == "udp" && p.Path == "dns" {
		b.WriteString("udp-dns: true\n") // DNS-shaped udp: the token's path field carries "dns"
	} else if p.Path != "" {
		b.WriteString("path: " + p.Path + "\n")
	}
	if p.SNI != "" {
		b.WriteString("sni: " + p.SNI + "\n")
		b.WriteString("host: " + p.SNI + "\n")
	}
	if p.FakeSNI != "" {
		b.WriteString("fake-sni: " + p.FakeSNI + "\n")
		if p.FakeMode != "" {
			b.WriteString("fake-mode: " + p.FakeMode + "\n")
		}
		if p.FakeMode == "ttl" && p.FakeTTL != "" {
			b.WriteString("fake-ttl: " + p.FakeTTL + "\n")
		}
	}
	if p.PoolRot != "" && p.PoolRot != "0" && p.PoolRot != "off" {
		b.WriteString("pool-rotate: " + p.PoolRot + "\n")
	}
	if p.PoolBytes != "" && p.PoolBytes != "0" && p.PoolBytes != "off" {
		b.WriteString("pool-rotate-bytes: " + p.PoolBytes + "\n")
	}
	if p.ECH != "" && p.ECH != "off" {
		b.WriteString("ech: " + p.ECH + "\n")
	}
	if p.Governor == "true" {
		b.WriteString("governor: true\n")
	}
	if p.DNSListen != "" && p.DNSListen != "off" {
		b.WriteString("dns-listen: " + p.DNSListen + "\n")
	}
	if p.SrcIP != "" && p.SrcIP != "off" {
		b.WriteString("src-ip: " + p.SrcIP + "\n")
	}
	if p.IcmpType != "" && p.IcmpType != "echo" {
		b.WriteString("icmp-type: " + p.IcmpType + "\n")
	}
	if p.Rev {
		b.WriteString("reverse: true\n")
	}
	if p.ListenPort != "" {
		b.WriteString("listen: \":" + p.ListenPort + "\"\n")
	}
	for _, l := range p.Extra {
		b.WriteString(l + "\n")
	}
	if p.Bind != "" && p.Bind != "0.0.0.0" {
		b.WriteString("bind: " + p.Bind + "\n")
	}
	if p.Mbps != "" {
		b.WriteString("max-mbps: " + p.Mbps + "\n")
	}
	if p.FEC == "auto" {
		b.WriteString("fec: auto\n")
	}
	if p.MetricsPort > 0 {
		b.WriteString("metrics: 127.0.0.1:" + strconv.Itoa(p.MetricsPort) + "\n")
	}
	b.WriteString(MapsYamlBlock(p.Maps))
	return b.String()
}

func wizardIran() bool {
	Page("New tunnel", "Iran")
	name := suggestName("iran")
	fmt.Fprintln(Stdout)
	if !AskOK("Token from Kharej (wat1:...)", "", vToken) {
		return false
	}
	t, err := ReadToken(ReplyV)
	if err != nil {
		return false
	}
	if t.Carrier == "auto" {
		// TODO(P4): auto_iran_front — the auto token front-end is the auto pass's.
		Err("Auto tokens are not ported in this build yet; ask Kharej for a fixed type.")
		return false
	}
	if !VCarrierList(t.Carrier) { // D7: refuses shaped carriers in a hand-made bond
		return false
	}
	if err := t.TokenBondLegs(); err != nil { // M1: split a bond token's endpoints
		Err(err.Error())
		return false
	}
	if isShapedList(t.Carrier) {
		if !shapedSupportedHere(t.Carrier) {
			return false
		}
		p2ShapedWarn(t.Carrier)
	}
	peer0 := t.Peer
	if i := strings.IndexAny(peer0, ",:"); i >= 0 {
		peer0 = peer0[:i]
	}
	Ok("Token · " + t.Carrier + p2OptPar(t.Icmp) + " · " + peer0 + " · allows " + orStr(t.Ports, "any port"))
	if t.Rev == "1" {
		if IsRpool(t.Carrier) {
			Hint("Reverse: Kharej dials Iran :" + p2LastPort(t.Peer))
		} else {
			Hint("Reverse: Kharej sends pings, Iran replies")
		}
	}

	// port mappings: pre-fill from the token allowlist (bash 3436-3462)
	pe := &portEditor{Role: "Iran", Tunnel: name, Allow: allowToArray(t.Ports)}
	if len(pe.Allow) > 0 {
		pe.Msg = append(pe.Msg, GRN+"✔"+RST+" Pre-filled from token (Enter keeps, e # edits)")
		skipped := 0
		for _, it := range pe.Allow {
			if !pe.tryAdd(SpecT(it)+":"+SpecT(it)+"/"+SpecP(it), -1) {
				skipped++
			}
		}
		if skipped > 0 {
			pe.Msg = append(pe.Msg, YEL+"!"+RST+" "+strconv.Itoa(skipped)+" port(s) conflicted — map manually (e.g. 8443:443)")
		}
	}
	if !pe.run() {
		Warn("Cancelled.")
		return false
	}
	// the reverse carrier port must differ from a published row (bash 3455-3460)
	if t.Rev == "1" && !strings.Contains(t.Carrier, "+") && IsRpool(t.Carrier) {
		rp := p2LastPort(t.Peer)
		for _, m := range pe.Maps {
			if SpecL(m) == rp && SpecP(m) == p2Rproto(t.Carrier) {
				Err("Port " + rp + "/" + p2Rproto(t.Carrier) + " is also a port you publish here. The carrier port must differ: pick another one on Kharej and make a new token.")
				return false
			}
		}
	}

	// advanced (bash 3464-3475)
	fmt.Fprintln(Stdout)
	var bind, mbps, fec, sni, path, itype string
	if Confirm("Change advanced settings?", false) {
		if !AskOK("Tunnel name", name, vName) {
			return false
		}
		name = ReplyV
		if !AskOK("Bind address for the public ports", "0.0.0.0", vBind) {
			return false
		}
		bind = ReplyV
		if !AskOK("Speed ceiling in MB/s (empty = no cap; icmp alone: 16)", mbps, vMbps) {
			return false
		}
		mbps = ReplyV
		if !askFec("off") {
			return false
		}
		fec = ReplyV
		if t.Carrier == "icmp" {
			if !AskOK("ICMP type (must match Kharej)", orStr(t.Icmp, "echo"), vIcmp) {
				return false
			}
			itype = ReplyV
		}
		switch t.Carrier {
		case "wss", "tls", "grpc", "h2":
			sni = Ask("Domain / SNI (empty = none)", t.SNI)
		}
		switch t.Carrier {
		case "ws", "wss", "grpc", "h2", "h2c":
			if !AskOK("URL path", orStr(t.Path, "/wat"), vPath) {
				return false
			}
			path = ReplyV
		}
	}
	// anti-censor profile (bash 3521-3567): one explicit ask, pool carriers only
	var fakesni, fakemode, poolrot, poolbytes, ech, governor string
	if t.Rev != "1" {
		if IsPoolList(t.Carrier) {
			fmt.Fprintln(Stdout)
			Say("  Anti-censor profile            " + GRY + "sni          mode  churn          ech" + RST)
			Say("  " + KeyLabel("1") + " MCI whitelist              " + GRY + "mci.ir       rst   30m / 500MB    ladder" + RST)
			Say("  " + KeyLabel("2") + " Irancell whitelist         " + GRY + "irancell.ir  seq   20m / 300MB    ladder" + RST)
			Say("  " + KeyLabel("3") + " Blackout                   " + GRY + "mci.ir       rst   90s / 100MB    ladder" + RST)
			Say("  " + KeyLabel("4") + " Low churn                  " + GRY + "mci.ir       seq   4h / 4GB       auto" + RST)
			Say("  " + KeyLabel("5") + " Custom                     " + GRY + "pick each value" + RST)
			Say("  " + KeyLabel("6") + " Skip                       " + GRY + "no disguise" + RST)
			Hint("2 and 4 (seq mode) only help against SNI-allowlist filters.")
			fmt.Fprintf(Stdout, "  %s?%s Profile %s[1]%s ", CYN, RST, GRY, RST)
			k, _, _ := KeyRead(0)
			switch k {
			case "1", "enter":
				fakesni, fakemode, poolrot, poolbytes, ech, governor = "mci.ir", "rst", "30m", "500MB", "ladder", "true"
			case "2":
				fakesni, fakemode, poolrot, poolbytes, ech, governor = "irancell.ir", "seq", "20m", "300MB", "ladder", "true"
			case "3":
				fakesni, fakemode, poolrot, poolbytes, ech, governor = "mci.ir", "rst", "90s", "100MB", "ladder", "true"
			case "4":
				fakesni, fakemode, poolrot, poolbytes, ech, governor = "mci.ir", "seq", "4h", "4GB", "auto", "true"
			case "6", "esc", "q":
			}
		} else if t.Carrier == "icmp" {
			fmt.Fprintln(Stdout)
			Say("  " + BOLD + "ICMP resilience" + RST + ": the volume governor, not an SNI profile.")
			if Confirm("Enable the ICMP volume governor (prevents reroute blackouts)?", true) {
				governor = "true"
			} else {
				governor = "false"
			}
		} else {
			Hint("Anti-censorship profiles apply to tcp/tls/ws/wss/h2/h2c/grpc; '" + t.Carrier + "' has no SNI to disguise. Skipping.")
		}
	}
	if !vName(name) {
		Err("The name '" + name + "' is not available.")
		return false
	}

	// summary (bash 3594-3641)
	fmt.Fprintln(Stdout)
	var note []string
	for _, m := range pe.Maps {
		note = append(note, SpecHuman(m))
	}
	summaryLine("Name", name)
	summaryLine("Carrier", t.Carrier+p2OptPar(itype))
	summaryLine("Kharej", t.Peer)
	if fakesni != "" {
		summaryLine("Fake SNI", fakesni+" ("+orStr(fakemode, "seq")+" mode)")
	}
	if poolrot != "" && poolrot != "0" && poolrot != "off" {
		s := poolrot
		if poolbytes != "" {
			s += " / " + poolbytes
		}
		summaryLine("Pool rotate", s)
	}
	if ech != "" && ech != "off" {
		summaryLine("ECH", ech)
	}
	if governor == "true" {
		summaryLine("Governor", "on")
	}
	if t.Rev == "1" {
		if rp := p2LastPort(t.Peer); rp != "" {
			summaryLine("Direction", "reverse (Kharej dials :"+rp+")")
		} else {
			summaryLine("Direction", "reverse (Kharej sends pings)")
		}
	}
	summaryLine("Publishes", strings.Join(note, " "))
	if bind != "" && bind != "0.0.0.0" {
		summaryLine("Bind", bind)
	}
	if mbps != "" {
		summaryLine("Speed limit", mbps+" MB/s")
	}
	if fec == "auto" {
		summaryLine("FEC", "auto")
	}
	if udl := UndisguisedLegs(t.Carrier); udl != "" && (fakesni+poolrot+poolbytes) != "" {
		Warn("Bond leg(s) '" + udl + "' stay undisguised (only TCP/TLS/HTTP legs use fake-SNI).")
	}
	fmt.Fprintln(Stdout)
	if !Confirm("Create this tunnel?", true) {
		Warn("Nothing was created.")
		return false
	}

	mp := p2FreeMetricsPort()
	rport := ""
	if t.Rev == "1" && IsRpool(t.Carrier) {
		rport = p2LastPort(t.Peer)
	}
	p := iranParams{
		Name: name, Carrier: t.Carrier, Peer: t.Peer, Key: t.Key, LegC: t.LegC, LegP: t.LegP,
		Path: t.Path, SNI: t.SNI, FakeSNI: fakesni, FakeMode: fakemode,
		PoolRot: poolrot, PoolBytes: poolbytes, ECH: ech, Governor: governor,
		IcmpType: orStr(itype, t.Icmp), Rev: t.Rev == "1", ListenPort: rport,
		Bind: bind, Mbps: mbps, FEC: fec, MetricsPort: mp, Maps: pe.Maps,
	}
	if path != "" {
		p.Path = path
	}
	if sni != "" {
		p.SNI = sni
	}
	atomicWrite(filepath.Join(P.Conf, name+".key"), []byte(t.Key+"\n"), 0o600)
	atomicWrite(filepath.Join(P.Conf, name+".yml"), []byte(iranYML(p)), 0o600)
	p2StartUnit(name)
	var newPub []string
	for _, m := range pe.Maps {
		newPub = append(newPub, SpecL(m)+"/"+SpecP(m))
	}
	p2FWOpen(newPub...)
	fmt.Fprintln(Stdout)
	if p2WaitLink(name, 25) {
		Ok("Connected")
	} else {
		Err("Not connected yet — running doctor")
		if registered("test_tunnel") {
			runFlow("test_tunnel", name)
		}
	}
	return true
}

func p2OptPar(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// p2LastPort: the port of the token peer's first endpoint.
func p2LastPort(peer string) string {
	first := peer
	if i := strings.Index(peer, ","); i >= 0 {
		first = peer[:i]
	}
	_, p := SplitHP(first)
	return p
}

// newTunnelScreen: the dashboard's n menu (bash main_menu case n).
func newTunnelScreen() {
	Say("  " + BOLD + "New tunnel" + RST)
	fmt.Fprintln(Stdout)
	MenuLine(Stdout, "k", "Kharej (server)", "i", "Iran (client, paste token)", "0", "back")
	for {
		k, _, _ := KeyRead(0)
		switch k {
		case "k":
			runFlow("wizard_kharej")
			return
		case "i":
			runFlow("wizard_iran")
			return
		case "0", "esc", "q":
			return
		}
	}
}
