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
	"io"
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

// wizHead: the wizard's title and step bar (done ✓, current bold, later dim).
func wizHead(w io.Writer, role string, cur int, steps []string) {
	Title(w, "New tunnel", role)
	var parts []string
	for i, s := range steps {
		switch {
		case i < cur:
			parts = append(parts, GRN+"✓ "+s+RST)
		case i == cur:
			parts = append(parts, BOLD+CYN+s+RST)
		default:
			parts = append(parts, GRY+s+RST)
		}
	}
	fmt.Fprintf(w, "  %s\n\n", strings.Join(parts, GRY+"  ›  "+RST))
}

// wizStep clears the screen and draws the head for a step that prompts line by line.
func wizStep(role string, cur int, steps []string) {
	ClearScreen()
	wizHead(Stdout, role, cur, steps)
}

var (
	kharejSteps = []string{"Carrier", "Address", "Settings", "Create"}
	iranSteps   = []string{"Token", "Ports", "Settings", "Create"}
)

// pick_shaped_carrier (bash 2616): the 13 wire shapes; "" = cancelled.
func pickShapedCarrier(head func(io.Writer)) string {
	var opts []string
	var items []Item
	for _, c := range p2ShapedRawList {
		opts = append(opts, c)
		items = append(items, Item{Label: c, Desc: "raw tier, IP protocol " + shapedRawProto(c)})
	}
	for _, c := range p2ShapedUDPList {
		opts = append(opts, c)
		items = append(items, Item{Label: c, Desc: "UDP shape, random open port"})
	}
	h := func(w io.Writer) {
		head(w)
		fmt.Fprintf(w, "  %sMore transports%s\n", BOLD, RST)
		hintLine(w, "wattun-internal wire shapes, NOT the real protocols. Both ends need wattun 3.3.0;")
		hintLine(w, "single carrier only; the raw tier needs root or CAP_NET_RAW.")
		fmt.Fprintln(w)
	}
	sel := 0
	for {
		i, k := Choose(h, items, &sel, []string{"⏎", "pick", "esc", "back"}, 0)
		if i < 0 {
			if k == "esc" || k == "q" || k == "eof" || k == "0" {
				return ""
			}
			continue
		}
		c := opts[i]
		if !VCarrierList(c) || !shapedSupportedHere(c) {
			return ""
		}
		p2ShapedWarn(c)
		return c
	}
}

// pick_carrier (bash 2633): the connection-type list; "" = cancelled.
// Numbers 1-9 still pick the first nine rows, 0 is h2c and m opens the shapes.
func pickCarrier(auto bool, head func(io.Writer)) string {
	var vals []string
	var items []Item
	add := func(key, v, desc string) {
		vals = append(vals, v)
		items = append(items, Item{Key: key, Label: v, Desc: desc})
	}
	if auto {
		add("", "auto", "recommended · accepts every type; the Iran server tests them and keeps the best")
	}
	add("", "icmp", "ping packets; gets through the strictest filters")
	add("", "udp", "fastest and lowest latency, if UDP passes")
	add("", "tcp", "plain TCP, if TCP passes")
	add("", "tls", "TCP that looks like a normal HTTPS site")
	add("", "wss", "WebSocket over TLS; works behind Cloudflare or another CDN")
	add("", "ws", "WebSocket without TLS (CDN on port 80, or a proxy that adds TLS)")
	add("", "grpc", "gRPC, for CDNs that allow it")
	add("", "h2", "HTTP/2")
	add("", "gre", "GRE (IP protocol 47); raw IP like icmp, root and Linux only")
	add("", "ipip", "IP-in-IP (protocol 4); raw IP like icmp, root and Linux only")
	add("0", "h2c", "HTTP/2 without TLS (a CDN or proxy that ends TLS)")
	add("m", "more…", "13 shaped carriers · both ends 3.3.0 · single carrier only")
	h := func(w io.Writer) {
		head(w)
		fmt.Fprintf(w, "  %sConnection type%s  %show the two servers talk to each other%s\n", BOLD, RST, GRY, RST)
		if auto {
			hintLine(w, "A fixed type stays until you make a new tunnel; auto can be switched later on Iran.")
		}
		fmt.Fprintln(w)
	}
	sel := 0
	for {
		i, k := Choose(h, items, &sel, []string{"⏎", "pick", "1-9", "quick pick", "esc", "cancel"}, 0)
		switch {
		case i >= 0 && vals[i] == "more…":
			if c := pickShapedCarrier(head); c != "" {
				return c
			}
		case i >= 0:
			return vals[i]
		case k == "esc" || k == "q" || k == "eof":
			return ""
		}
	}
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

// wizSummary collects the summary rows the wizards show in a box before creating.
type wizSummary []string

func (s *wizSummary) add(l, v string) { *s = append(*s, kv(l, v)) }

func wizardKharej() bool {
	kHead := func(w io.Writer) { wizHead(w, "Kharej", 0, kharejSteps) }
	name := suggestName("kharej")
	cr := pickCarrier(true, kHead)
	if cr == "" {
		return false
	}
	if cr == "auto" {
		// wizard_kharej_auto (bash 4056) is the auto pass's screen; route to it.
		if registered("wizard_kharej_auto") {
			return dispatch("wizard_kharej_auto", name) == 0
		}
		Warn("The auto carrier needs the auto-plan writer (not ported yet); pick a fixed type.")
		cr = pickCarrier(false, kHead)
		if cr == "" {
			return false
		}
	}
	wizStep("Kharej", 1, kharejSteps)
	Ok("Carrier  " + cr)
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
	wizStep("Kharej", 2, kharejSteps)
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
	wizStep("Kharej", 3, kharejSteps)
	var sum wizSummary
	sum.add("Name", name+" (Kharej)")
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
	sum.add("Carrier", car)
	sum.add("Address", addr)
	if rev {
		if cr == "icmp" {
			sum.add("Direction", "reverse → "+iranip)
		} else {
			sum.add("Direction", "reverse → "+JoinHP(iranip, listen))
		}
	}
	sum.add("Allow ports", orStr(allow, "any"))
	if mbps != "" {
		sum.add("Speed limit", mbps+" MB/s")
	}
	if fec == "auto" {
		sum.add("FEC", "auto")
	}
	Box(Stdout, "Summary", sum...)
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
	fmt.Fprintf(Stdout, "  %s✓%s %sKharej tunnel '%s' is ready%s\n\n", GRN, RST, BOLD, name, RST)
	fmt.Fprintf(Stdout, "  %sToken%s  %scontains the secret key; share it privately%s\n", BOLD, RST, GRY, RST)
	fmt.Fprintf(Stdout, "  %s%s%s\n\n", BOLD+YEL, tok, RST)
	fmt.Fprintf(Stdout, "  %sNext, on the Iran server%s\n", BOLD, RST)
	fmt.Fprintf(Stdout, "  %s1%s  run %s%s%s\n", CYN, RST, CYN, P.Self, RST)
	fmt.Fprintf(Stdout, "  %s2%s  New tunnel › Iran\n", CYN, RST)
	fmt.Fprintf(Stdout, "  %s3%s  paste the token\n", CYN, RST)
	Hint("Show it again any time: " + P.Self + " token " + name)
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
	wizStep("Iran", 0, iranSteps)
	name := suggestName("iran")
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
	// CDN carrier + domain: automatic edge / TLS tuning (wattun >= 2.2.0), silent otherwise
	cdnV, cdnTuned := cdnWizardTune(t)
	if cdnTuned {
		t.Peer, t.SNI = cdnV.Peer, cdnV.SNI
	}

	// port mappings: pre-fill from the token allowlist (bash 3436-3462)
	pe := &portEditor{Role: "Iran", Tunnel: name, Allow: allowToArray(t.Ports),
		Head: func(w io.Writer) { wizHead(w, "Iran", 1, iranSteps) }}
	if len(pe.Allow) > 0 {
		pe.Msg = append(pe.Msg, GRN+"✓"+RST+" Pre-filled from token (Enter keeps, e # edits)")
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
	wizStep("Iran", 2, iranSteps)
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
			profs := [][6]string{ // sni, mode, rotate, bytes, ech, governor; "" row = no disguise
				{"mci.ir", "rst", "30m", "500MB", "ladder", "true"},
				{"irancell.ir", "seq", "20m", "300MB", "ladder", "true"},
				{"mci.ir", "rst", "90s", "100MB", "ladder", "true"},
				{"mci.ir", "seq", "4h", "4GB", "auto", "true"},
				{}, {},
			}
			items := []Item{
				{Label: "MCI whitelist", Desc: "mci.ir       rst   30m / 500MB   ladder"},
				{Label: "Irancell whitelist", Desc: "irancell.ir  seq   20m / 300MB   ladder"},
				{Label: "Blackout", Desc: "mci.ir       rst   90s / 100MB   ladder"},
				{Label: "Low churn", Desc: "mci.ir       seq   4h / 4GB      auto"},
				{Label: "Custom", Desc: "pick each value later on the tunnel page (z)"},
				{Label: "Skip", Desc: "no disguise"},
			}
			head := func(w io.Writer) {
				wizHead(w, "Iran", 2, iranSteps)
				fmt.Fprintf(w, "  %sAnti-censor profile%s  %ssni · mode · churn · ech%s\n", BOLD, RST, GRY, RST)
				hintLine(w, "Irancell and Low churn (seq mode) only help against SNI-allowlist filters.")
				fmt.Fprintln(w)
			}
			sel, i := 0, -1
			for i < 0 {
				var k string
				i, k = Choose(head, items, &sel, []string{"⏎", "pick", "esc", "skip"}, 0)
				if i < 0 && (k == "esc" || k == "q" || k == "eof") {
					i = 5
				}
			}
			if p := profs[i]; p[0] != "" {
				fakesni, fakemode, poolrot, poolbytes, ech, governor = p[0], p[1], p[2], p[3], p[4], p[5]
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
	wizStep("Iran", 3, iranSteps)
	var sum wizSummary
	var note []string
	for _, m := range pe.Maps {
		note = append(note, SpecHuman(m))
	}
	sum.add("Name", name)
	sum.add("Carrier", t.Carrier+p2OptPar(itype))
	sum.add("Kharej", t.Peer)
	if fakesni != "" {
		sum.add("Fake SNI", fakesni+" ("+orStr(fakemode, "seq")+" mode)")
	}
	if poolrot != "" && poolrot != "0" && poolrot != "off" {
		s := poolrot
		if poolbytes != "" {
			s += " / " + poolbytes
		}
		sum.add("Pool rotate", s)
	}
	if ech != "" && ech != "off" {
		sum.add("ECH", ech)
	}
	if governor == "true" {
		sum.add("Governor", "on")
	}
	if t.Rev == "1" {
		if rp := p2LastPort(t.Peer); rp != "" {
			sum.add("Direction", "reverse (Kharej dials :"+rp+")")
		} else {
			sum.add("Direction", "reverse (Kharej sends pings)")
		}
	}
	sum.add("Publishes", strings.Join(note, " "))
	if bind != "" && bind != "0.0.0.0" {
		sum.add("Bind", bind)
	}
	if mbps != "" {
		sum.add("Speed limit", mbps+" MB/s")
	}
	if fec == "auto" {
		sum.add("FEC", "auto")
	}
	if udl := UndisguisedLegs(t.Carrier); udl != "" && (fakesni+poolrot+poolbytes) != "" {
		Warn("Bond leg(s) '" + udl + "' stay undisguised (only TCP/TLS/HTTP legs use fake-SNI).")
	}
	Box(Stdout, "Summary", sum...)
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
	if cdnTuned {
		p.Extra = append(p.Extra, cdnExtra(name, cdnV, &p.ECH)...)
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
	items := []Item{
		{Key: "k", Label: "Kharej", Desc: "server outside Iran · makes the token"},
		{Key: "i", Label: "Iran", Desc: "server users connect to · paste the Kharej token"},
	}
	sel := 0
	if serverSide() == "iran" {
		sel = 1
	}
	head := func(w io.Writer) {
		Title(w, "New tunnel", "which side is this server?")
		hintLine(w, "Set up Kharej first; its token sets up Iran.")
		fmt.Fprintln(w)
	}
	for {
		i, k := Choose(head, items, &sel, []string{"⏎", "pick", "esc", "back"}, 0)
		switch {
		case i == 0:
			runFlow("wizard_kharej")
			return
		case i == 1:
			runFlow("wizard_iran")
			return
		case k == "0" || k == "esc" || k == "q" || k == "eof":
			return
		}
	}
}
