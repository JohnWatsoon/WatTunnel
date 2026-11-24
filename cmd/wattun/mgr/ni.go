package mgr

// The unattended flag surface of kharej/iran: the port of the bash ni_parse
// (wattun-manager 10025) and its NI_* answers (wattun-manager 137-138). The Go
// wizards read the same values the bash ones read from NI_*; a flag the bash
// rejects is rejected here with the same message, so `wattun kharej --yes ...`
// behaves like the bash manager's unattended run.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// niOpts holds the NI_* answers; "" (or 0) = the wizard's own default.
type niOpts struct {
	Carrier, Name, Listen, Path, Addr, SNI, CDN, Ports, Mbps string
	FakeSNI, FakeMode, FakeTTL, PoolRot, PoolBytes, Preset   string
	Test, ECH, Governor, DNSListen, SrcIP                    string
	Token, Map, Pick, Policy                                 string
	Sessions, Conns, MTU                                     int
	UDPDNS, Extended                                         bool
}

// NI mirrors the bash NI_* globals; Pick defaults to best (bash NI_PICK=best).
var NI = niOpts{Pick: "best"}

func niReset() { NI = niOpts{Pick: "best"} }

// niParse validates and stores the unattended flags (bash ni_parse 10025).
// The bash validators print their own errors, so the Go ones do the printing
// here and niParse only turns a rejection into a failure.
func niParse(args []string) error {
	NI = niOpts{Pick: "best"}
	set := func(f, v string) error {
		switch f {
		case "--carrier":
			if !VCarrierList(v) {
				return fmt.Errorf("bad --carrier %q", v)
			}
			NI.Carrier = v
		case "--preset":
			if c := PresetCanonical(v); v != "" && !IsBuiltinPreset(c) && c != "off" {
				Err("Unknown preset '" + v + "'. Available: cloudflare, rst-fast, mci, irancell, blackout, conservative")
				return fmt.Errorf("bad --preset %q", v)
			}
			NI.Preset = PresetCanonical(v)
		case "--name":
			if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`).MatchString(v) {
				Err("--name: use 1-32 letters, digits, - or _ (got '" + v + "')")
				return fmt.Errorf("bad --name %q", v)
			}
			NI.Name = v
		case "--listen":
			if !vPort(v) {
				return fmt.Errorf("bad --listen %q", v)
			}
			NI.Listen = strconv.Itoa(atoi(v))
		case "--path":
			if !vPath(v) {
				return fmt.Errorf("bad --path %q", v)
			}
			NI.Path = v
		case "--addr":
			if !vHost(v) {
				return fmt.Errorf("bad --addr %q", v)
			}
			NI.Addr = v
		case "--sni":
			if !vHost(v) {
				return fmt.Errorf("bad --sni %q", v)
			}
			NI.SNI = v
		case "--cdn-domain":
			if !vDomainOpt(v) {
				return fmt.Errorf("bad --cdn-domain %q", v)
			}
			NI.CDN = v
		case "--ports":
			if v == "" {
				Err("--ports needs a list such as 18999,2000,53/udp")
				return fmt.Errorf("bad --ports")
			}
			NI.Ports = v
		case "--max-mbps":
			if !vMbps(v) {
				return fmt.Errorf("bad --max-mbps %q", v)
			}
			NI.Mbps = v
		case "--fake-sni":
			if !vSNIName(v) {
				return fmt.Errorf("bad --fake-sni %q", v)
			}
			NI.FakeSNI = v
		case "--fake-mode":
			if !vFakeMode(v) {
				return fmt.Errorf("bad --fake-mode %q", v)
			}
			NI.FakeMode = v
		case "--fake-ttl":
			if !regexp.MustCompile(`^[0-9]{1,3}$`).MatchString(v) || atoi(v) > 255 {
				Err("--fake-ttl: use a hop count 0-255 (0 = auto, got '" + v + "')")
				return fmt.Errorf("bad --fake-ttl %q", v)
			}
			NI.FakeTTL = v
		case "--pool-rotate":
			if !vPoolRotate(v) {
				return fmt.Errorf("bad --pool-rotate %q", v)
			}
			NI.PoolRot = v
		case "--pool-rotate-bytes":
			if !vPoolBytes(v) {
				return fmt.Errorf("bad --pool-rotate-bytes %q", v)
			}
			NI.PoolBytes = v
		case "--test":
			switch v {
			case "normal", "anti", "fast", "reverse", "extended":
				NI.Test = v
			default:
				Err("--test: use normal, anti, fast, reverse or extended (got '" + v + "')")
				return fmt.Errorf("bad --test %q", v)
			}
		case "--token":
			if !vToken(v) {
				return fmt.Errorf("bad --token")
			}
			NI.Token = v
		case "--map":
			if v == "" {
				Err("--map needs a list such as 39901:18999,8443:443")
				return fmt.Errorf("bad --map")
			}
			NI.Map = v
		case "--pick":
			switch {
			case v == "best" || v == "bond" || v == "rbond":
				NI.Pick = v
			case regexp.MustCompile(`^[0-9]+([,+][0-9]+)+$`).MatchString(v):
				NI.Pick = v
			case regexp.MustCompile(`^[0-9]+$`).MatchString(v) && atoi(v) >= 1:
				NI.Pick = strconv.Itoa(atoi(v))
			default:
				Err("--pick: use best, bond, a row number or rows such as 1,3 (got '" + v + "')")
				return fmt.Errorf("bad --pick %q", v)
			}
		case "--sessions":
			if v != "" && !unsetWord(v) && !intIn(v, 1, engMaxSessions) {
				Err(fmt.Sprintf("Enter sessions count %d (or 0/default to unset).", engMaxSessions))
				return fmt.Errorf("bad --sessions %q", v)
			}
			NI.Sessions = atoi(v)
		case "--conns":
			if v != "" && !unsetWord(v) && !intIn(v, 1, engMaxConns) {
				Err(fmt.Sprintf("Enter conns count 1-%d (the engine caps a pool at %d; or 0/default to unset).", engMaxConns, engMaxConns))
				return fmt.Errorf("bad --conns %q", v)
			}
			NI.Conns = atoi(v)
		case "--mtu":
			if v != "" && !unsetWord(v) && !intIn(v, engMTUMin, engMTUMaxPool) {
				Err(fmt.Sprintf("Enter MTU %d-%d (or 0/default to unset).", engMTUMin, engMTUMaxPool))
				return fmt.Errorf("bad --mtu %q", v)
			}
			NI.MTU = atoi(v)
		case "--policy":
			switch v {
			case "speed", "latency", "direct", "bond":
				NI.Policy = v
			default:
				Err("--policy: use speed, latency, direct or bond (got '" + v + "')")
				return fmt.Errorf("bad --policy %q", v)
			}
		case "--ech":
			if !vEch(v) {
				return fmt.Errorf("bad --ech %q", v)
			}
			switch strings.ToLower(v) {
			case "off", "auto", "ladder":
				NI.ECH = strings.ToLower(v)
			default:
				NI.ECH = v
			}
		case "--dns-listen":
			if !vDNSListen(v) {
				return fmt.Errorf("bad --dns-listen %q", v)
			}
			NI.DNSListen = v
		case "--src-ip":
			if !vSrcIP(v) {
				return fmt.Errorf("bad --src-ip %q", v)
			}
			NI.SrcIP = v
		default:
			return fmt.Errorf("unhandled flag %s", f)
		}
		return nil
	}
	boolFlag := func(f string) error {
		switch f {
		case "--yes":
			return nil // handled by Run() (NONINTERACTIVE detection)
		case "--udp-dns":
			NI.UDPDNS = true
		case "--extended":
			NI.Extended = true
		default:
			return fmt.Errorf("unhandled flag %s", f)
		}
		return nil
	}
	governor := func(v string) error {
		switch strings.ToLower(v) {
		case "on", "off", "true", "false", "1", "0":
		default:
			Err("--governor: use on, off, true or false (got '" + v + "')")
			return fmt.Errorf("bad --governor %q", v)
		}
		switch strings.ToLower(v) {
		case "on", "1", "true":
			NI.Governor = "true"
		default:
			NI.Governor = "false"
		}
		return nil
	}
	for i := 0; i < len(args); i++ {
		f, v := args[i], ""
		if j := strings.Index(f, "="); j >= 0 {
			f, v = f[:j], f[j+1:]
		}
		switch f {
		case "--yes", "--udp-dns", "--extended":
			if err := boolFlag(f); err != nil {
				return err
			}
			continue
		case "--governor":
			if v == "" && i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				i++
				v = args[i]
			}
			if err := governor(v); err != nil {
				return err
			}
			continue
		}
		if !strings.HasPrefix(f, "--") {
			continue // positional words: NI_POS keeps only what iran needs, here the token comes via --token
		}
		if v == "" {
			if i+1 >= len(args) {
				Err(f + " needs a value")
				return fmt.Errorf("%s needs a value", f)
			}
			i++
			v = args[i]
		}
		if err := set(f, v); err != nil {
			return err
		}
	}
	return nil
}
