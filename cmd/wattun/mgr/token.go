package mgr

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Connection token (wattun-manager L920-924):
//   wat1:BASE64("carrier|peer|key|path|sni|icmp-type|allowed-ports[|reverse][|auto-plan]")
// Field 7 (allowed ports on Kharej, comma list, empty = any) was added in 1.9.0;
// 6-field tokens still parse. Field 8 ("1" = reverse ICMP, >= 2.0.0) is written
// only when set. Field 9 (auto plan) only for carrier "auto" tokens, where
// field 8 stays empty; its d=/r= lists use only ; , : = , never '|'.

// Token mirrors the T_* variables of read_token.
type Token struct {
	Carrier string // T_CARRIER
	Peer    string // T_PEER
	Key     string // T_KEY
	Path    string // T_PATH
	SNI     string // T_SNI
	Icmp    string // T_ICMP
	Ports   string // T_PORTS
	Rev     string // T_REV
	Auto    string // T_AUTO

	LegC []string // T_LEG_C: per-leg carriers of a bond token (TokenBondLegs)
	LegP []string // T_LEG_P: per-leg endpoints, parallel to LegC
}

// MakeToken mirrors make_token(): fields 8/9 only when set, so every other
// token stays 7 fields and old peers keep parsing it.
func MakeToken(carrier, peer, key, path, sni, icmp, ports, rev, auto string) string {
	f := strings.Join([]string{carrier, peer, key, path, sni, icmp, ports}, "|")
	if auto != "" {
		f += "|" + rev + "|" + auto
	} else if rev == "1" {
		f += "|1"
	}
	// base64 -w0: standard alphabet with padding, so bash-made tokens compare equal
	return "wat1:" + base64.StdEncoding.EncodeToString([]byte(f))
}

// ReadToken mirrors read_token(): parse a wat1: token; error when the prefix,
// the base64 or the mandatory carrier/peer/key triple is missing.
func ReadToken(tok string) (Token, error) {
	var t Token
	b64, ok := strings.CutPrefix(tok, "wat1:")
	if !ok {
		return t, fmt.Errorf("not a wat1: token")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// tolerate an unpadded token too (base64 -d pads internally)
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(b64, "="))
		if err != nil {
			return t, fmt.Errorf("bad token base64: %w", err)
		}
	}
	fs := strings.Split(string(raw), "|")
	get := func(i int) string {
		if i < len(fs) {
			return fs[i]
		}
		return ""
	}
	t.Carrier, t.Peer, t.Key, t.Path, t.SNI, t.Icmp, t.Ports, t.Rev, t.Auto =
		get(0), get(1), get(2), get(3), get(4), get(5), get(6), get(7), get(8)
	if t.Carrier == "" || t.Peer == "" || t.Key == "" {
		return t, fmt.Errorf("token misses carrier, peer or key")
	}
	return t, nil
}

// TokenBondLegs mirrors token_bond_legs(): split a bond token's per-leg
// endpoints into LegC/LegP; Peer becomes the first leg's entry. An older
// manager's bond token has one endpoint for every leg and is left as-is.
// The returned error carries the same two messages as the bash.
func (t *Token) TokenBondLegs() error {
	t.LegC, t.LegP = nil, nil
	if !strings.Contains(t.Carrier, "+") || !strings.Contains(t.Peer, ",") {
		return nil
	}
	cs := strings.Split(t.Carrier, "+")
	ps := strings.Split(t.Peer, ",")
	if len(ps) != len(cs) {
		return fmt.Errorf("This token lists %d endpoints for %d carriers; it is damaged or hand-made.", len(ps), len(cs))
	}
	for i, c := range cs {
		if ps[i] == "" {
			return fmt.Errorf("This token has an empty endpoint for carrier '%s'.", c)
		}
		t.LegC = append(t.LegC, c)
		t.LegP = append(t.LegP, ps[i])
	}
	t.Peer = t.LegP[0]
	return nil
}

// BondPeerField mirrors bond_peer_field(): comma-separated per-leg endpoints for
// a bonded config, in carrier order. Bare-carrier legs (icmp, gre, ipip, raw
// shapes) dial a bare address and stay port-less; a leg without its own
// listen-<carrier>: key takes the config's global listen port.
func BondPeerField(name, host string) string {
	var out []string
	base := listenPortOf(Cfg(name, "listen"))
	for _, c := range strings.Split(Cfg(name, "carrier"), "+") {
		if !CarrierHasListen(c) {
			out = append(out, JoinHP(host, ""))
			continue
		}
		port := listenPortOf(Cfg(name, "listen-"+c))
		if port == "" {
			port = base
		}
		out = append(out, JoinHP(host, port))
	}
	return strings.Join(out, ",")
}

// listenPortOf extracts the numeric port of a listen value (":4443",
// "127.0.0.1:4443"); "" when there is none.
func listenPortOf(v string) string {
	if v == "" {
		return ""
	}
	_, p := SplitHP(v)
	if !isDigits(p) {
		return ""
	}
	return p
}

// RefreshToken mirrors refresh_token(): keep NAME.token in step with NAME.yml —
// the allowed ports always, and for a bonded Kharej config also the finalized
// carrier list, one endpoint per leg and the path, so the emergency token never
// carries the single-carrier tunnel that was armed over.
func RefreshToken(name string) error { return refreshToken(name, false) }

// refreshToken: fortress (arm-blackout only) lets an auto Kharej's token become the bond token. Without it an
// auto token stays the auto plan: its yml lists every carrier too, and showing the token used to rewrite it.
func refreshToken(name string, fortress bool) error {
	f := filepath.Join(P.Conf, name+".token")
	raw, err := os.ReadFile(f)
	if err != nil {
		return nil // no token file: nothing to refresh
	}
	tok, err := ReadToken(string(raw))
	if err != nil {
		return nil // the bash also gives up silently on an unreadable token
	}
	allow := MapsAllowStr(YmlMaps(name))
	if fileExists(filepath.Join(P.Conf, name+"-r.yml")) && IsAutoKharej(name) {
		if err := WritePorts(name+"-r", YmlMaps(name)); err != nil {
			return err // the auto reverse companion allows the same ports
		}
	}
	cr, bp := tok.Carrier, tok.Peer
	changed := allow != tok.Ports
	if Role(name) == "Kharej" && tok.Rev != "1" && (tok.Carrier != "auto" || fortress) {
		cc := Cfg(name, "carrier")
		if strings.Contains(cc, "+") {
			cr = cc
			dialHost, _ := SplitHP(strings.SplitN(tok.Peer, ",", 2)[0]) // the old token's first endpoint, without its stale port
			bp = BondPeerField(name, dialHost)
			if cr != tok.Carrier || bp != tok.Peer {
				changed = true
			}
			// the bond finalized path/sni/icmp-type too (arm-blackout writes a
			// fresh path); carry them, not pre-arming values
			if v := Cfg(name, "path"); v != tok.Path {
				tok.Path, changed = v, true
			}
			if v := Cfg(name, "sni"); v != tok.SNI {
				tok.SNI, changed = v, true
			}
			if v := Cfg(name, "icmp-type"); v != tok.Icmp {
				tok.Icmp, changed = v, true
			}
			if tok.Auto != "" {
				tok.Auto, changed = "", true // a fortress token is not an auto plan
			}
		}
	}
	if !changed {
		return nil
	}
	// umask 077 equivalent: the temp file is created 0600 and renamed in place
	out := MakeToken(cr, bp, tok.Key, tok.Path, tok.SNI, tok.Icmp, allow, tok.Rev, tok.Auto)
	return atomicWrite(f, []byte(out), 0o600)
}

// rebuildKharejToken mirrors bash rebuild_kharej_token (3.3.8): recover NAME.token that a 3.3.3-3.3.7 finalize (or a
// manual rm) removed. An auto tunnel gets a fresh plan on new ports, so it leaves NAME.repaste: Iran's saved plan is
// stale until the new token is pasted there (showToken clears it). true when NAME.token exists afterwards.
func rebuildKharejToken(n string) bool {
	tf := filepath.Join(P.Conf, n+".token")
	if Role(n) != "Kharej" {
		return false
	}
	if fileExists(tf) {
		return true
	}
	key := strings.TrimSpace(strings.SplitN(mustRead(filepath.Join(P.Conf, n+".key")), "\n", 2)[0])
	if key == "" {
		return false
	}
	allow := MapsAllowStr(YmlMaps(n))
	apath, sni, itype := Cfg(n, "path"), Cfg(n, "sni"), Cfg(n, "icmp-type")
	addr := ""
	if ents, _ := filepath.Glob(filepath.Join(P.Conf, "*.token")); len(ents) > 0 {
		for _, f := range ents {
			if t, err := ReadToken(strings.TrimSpace(mustRead(f))); err == nil && t.Peer != "" {
				addr, _ = SplitHP(strings.SplitN(t.Peer, ",", 2)[0]) // a bond token's first entry carries the host
				break
			}
		}
	}
	if addr == "" {
		addr = publicIP()
	}
	if addr == "" {
		return false
	}
	cr, rev := Cfg(n, "carrier"), ""
	if IsReverse(n) {
		rev = "1"
	}
	head := strings.SplitN(mustRead(filepath.Join(P.Conf, n+".yml")), "\n", 2)[0]
	if strings.Contains(head, "Kept by wattun-manager from auto tunnel") || strings.Contains(head, "auto: every carrier at once") {
		lp := ""
		if rev == "1" {
			pip := Cfg(n, "peer-icmp")
			if pip == "" {
				pip, lp = SplitHP(Cfg(n, "peer"))
			}
			if pip != "" {
				os.WriteFile(filepath.Join(P.Conf, n+".iranip"), []byte(pip+"\n"), 0o600)
			}
		} else {
			_, lp = SplitHP(Cfg(n, "listen"))
		}
		pk := autoPickPorts(sni != "")
		if pk.FAIL != "" {
			return false
		}
		rplan, err := autoPickRplan(intsToStrs(pk.Used))
		if err != nil {
			return false
		}
		dplan := pk.D
		if lp != "" && !strings.Contains(cr, "+") { // keep the live carrier on the port Iran already dials
			if rev == "1" {
				rplan = setPlanPort(rplan, cr, lp)
			} else if !IsShapedCarrier(cr) {
				dplan = setPlanPort(dplan, cr, lp)
			}
		}
		if apath == "" {
			apath = "/wat"
		}
		if atomicWrite(tf, []byte(MakeToken("auto", addr, key, apath, sni, "", allow, "", "d="+dplan+";r="+rplan)), 0o600) != nil {
			return false
		}
		os.WriteFile(filepath.Join(P.Conf, n+".repaste"), nil, 0o600)
		return true
	}
	_, lp := SplitHP(Cfg(n, "listen"))
	if lp == "" && rev == "1" {
		_, lp = SplitHP(Cfg(n, "peer"))
	}
	if Cfg(n, "udp-dns") == "true" {
		apath = "dns"
	}
	return atomicWrite(tf, []byte(MakeToken(cr, JoinHP(addr, lp), key, apath, sni, itype, allow, rev, "")), 0o600) == nil
}

// setPlanPort sets carrier c's port in a plan list "a:1,b:2" (bash sed s/(^|,)c:[0-9]+/\1c:p/).
func setPlanPort(plan, c, p string) string {
	es := strings.Split(plan, ",")
	for i, e := range es {
		if strings.HasPrefix(e, c+":") {
			es[i] = c + ":" + p
		}
	}
	return strings.Join(es, ",")
}

func intsToStrs(v []int) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = fmt.Sprint(x)
	}
	return out
}
