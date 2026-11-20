package mgr

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Resilience profiles: save one tunnel's anti-censor keys as NAME.env under
// $CONF/profiles and re-apply them to a tunnel later (bash profile_cmd).

func init() {
	Register("profile_cmd", func(a ...string) int { return b2rc(profileCmd(arg(a, 0), arg(a, 1), arg(a, 2))) })
}

// profKeys maps each profile variable to its config key, in file order.
var profKeys = [][2]string{
	{"FAKESNI", "fake-sni"}, {"FAKEMODE", "fake-mode"}, {"FAKETTL", "fake-ttl"},
	{"POOLROT", "pool-rotate"}, {"POOLBYTES", "pool-rotate-bytes"}, {"ECH", "ech"},
	{"GOVERNOR", "governor"}, {"DNSLISTEN", "dns-listen"}, {"SRCIP", "src-ip"},
}

var reProfName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)

func profPath(name string) string { return filepath.Join(P.Conf, "profiles", name+".env") }

func vProfName(s string) bool {
	if reProfName.MatchString(s) {
		return true
	}
	Err("Profile name: 1-32 letters, digits, - or _.")
	return false
}

func profNames() []string {
	fs, _ := filepath.Glob(filepath.Join(P.Conf, "profiles", "*.env"))
	for i, f := range fs {
		fs[i] = strings.TrimSuffix(filepath.Base(f), ".env")
	}
	return fs
}

// profRead returns the KEY=VALUE lines this manager wrote; comments and anything else are ignored.
func profRead(name string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(p2ReadText(profPath(name)), "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		for _, pk := range profKeys {
			if pk[0] == k {
				m[k] = v
			}
		}
	}
	return m
}

// profOnlyTunnel is the single Iran pool tunnel, when there is exactly one.
func profOnlyTunnel() string {
	pick, c := "", 0
	for _, n := range Tunnels() {
		if Role(n) == "Iran" && IsPoolList(Cfg(n, "carrier")) {
			pick, c = n, c+1
		}
	}
	if c == 1 {
		return pick
	}
	return ""
}

func profTunnel(sub, name, tun string) string {
	if tun == "" {
		tun = profOnlyTunnel()
	}
	if tun == "" {
		Err("Name the tunnel explicitly (profile " + sub + " " + name + " TUNNEL).")
		return ""
	}
	if !cfgFileExists(tun) {
		Err("No tunnel named '" + tun + "'.")
		return ""
	}
	return tun
}

func showBuiltinPreset(name string) {
	pr := PresetCanonical(name)
	v, _ := presetOf(pr)
	for _, c := range presetChoices {
		if c.name == pr {
			Title(Stdout, "Preset "+pr, c.label)
			Say("  " + c.desc)
		}
	}
	for _, kv2 := range [][2]string{{"fake-sni", v.fs}, {"fake-mode", v.fm}, {"fake-ttl", v.ft}, {"pool-rotate", v.rot},
		{"pool-rotate-bytes", v.rbytes}, {"ech", v.ech}, {"governor", v.gov}, {"sessions", v.sess}, {"conns", v.conns}} {
		if kv2[1] != "" {
			Say("  " + kv(kv2[0], kv2[1]))
		}
	}
}

func profileCmd(sub, name, tun string) bool {
	switch sub {
	case "save":
		if IsBuiltinPreset(name) {
			Err("'" + name + "' is a built-in preset name. Choose another name for your custom profile.")
			return false
		}
		if !vProfName(name) {
			return false
		}
		if tun = profTunnel(sub, name, tun); tun == "" {
			return false
		}
		if !isLinuxHost() {
			Err("Resilience profiles are a Linux feature (fake-SNI needs CAP_NET_RAW, like the icmp carrier).")
			return false
		}
		var b strings.Builder
		fmt.Fprintf(&b, "# WatTunnel resilience profile: %s\n# From tunnel %s, saved %s. Apply: %s profile apply %s TUNNEL\n",
			name, tun, time.Now().UTC().Format("2006-01-02 15:04 UTC"), P.Self, name)
		b.WriteString("# FAKESNI   allowlisted server name (e.g. mci.ir); empty = fake-SNI off\n" +
			"# FAKEMODE  seq | ttl | sum | seqsum | auto | rst | synrst | paws\n" +
			"# FAKETTL   hop count for fake-mode ttl; empty = auto-calibrate\n" +
			"# POOLROT   recycle each healthy pool connection after this long (90s, 30m, 4h); empty = off\n" +
			"# POOLBYTES recycle after this much traffic (500MB, 4G); empty = off\n" +
			"# ECH       ECH mode: ladder | auto | off\n" +
			"# GOVERNOR  ICMP volume pacer: true | false\n")
		for _, pk := range profKeys {
			b.WriteString(pk[0] + "=" + Cfg(tun, pk[1]) + "\n")
		}
		_ = os.MkdirAll(filepath.Dir(profPath(name)), 0o700)
		if atomicWrite(profPath(name), []byte(b.String()), 0o600) != nil {
			Err("Could not write " + profPath(name) + ".")
			return false
		}
		Ok("Profile '" + name + "' saved (from " + tun + "). Re-apply later: " + P.Self + " profile apply " + name + " TUNNEL.")
	case "list":
		Say("  " + BOLD + "Built-in presets" + RST)
		for _, c := range presetChoices {
			if c.name != "off" {
				Say(fmt.Sprintf("  %-13s %s", c.name, GRY+c.desc+RST))
			}
		}
		fmt.Fprintln(Stdout)
		Say("  " + BOLD + "Saved profiles" + RST)
		if ns := profNames(); len(ns) > 0 {
			for _, n := range ns {
				Say("  " + n)
			}
		} else {
			Hint("No custom saved profiles.")
		}
	case "show":
		if IsBuiltinPreset(name) {
			showBuiltinPreset(name)
			return true
		}
		if !vProfName(name) {
			return false
		}
		if !fileExists(profPath(name)) {
			Err("No profile named '" + name + "'.")
			return false
		}
		fmt.Fprint(Stdout, p2ReadText(profPath(name)))
	case "del", "delete", "rm":
		if IsBuiltinPreset(name) {
			Err("Cannot delete built-in preset '" + name + "'.")
			return false
		}
		if !vProfName(name) {
			return false
		}
		if !fileExists(profPath(name)) {
			Err("No profile named '" + name + "'.")
			return false
		}
		_ = os.Remove(profPath(name))
		Ok("Profile '" + name + "' deleted.")
	case "apply":
		if IsBuiltinPreset(name) {
			if tun = profTunnel(sub, name, tun); tun == "" {
				return false
			}
			return ApplyPreset(tun, name)
		}
		if !vProfName(name) {
			return false
		}
		if tun = profTunnel(sub, name, tun); tun == "" {
			return false
		}
		if Role(tun) != "Iran" || !IsPoolList(Cfg(tun, "carrier")) {
			Err("'" + tun + "' is not an Iran tunnel on a pool carrier (tcp, tls, ws, wss, h2, h2c, grpc, alone or bonded); these keys are client-only.")
			return false
		}
		if !fileExists(profPath(name)) {
			Err("No profile named '" + name + "'.")
			return false
		}
		return profApply(name, tun)
	default:
		Err("profile: use save, list, show, del or apply.")
		return false
	}
	return true
}

// profApply writes the tunnel's resilience keys from a saved profile, then restarts it.
func profApply(name, tun string) bool {
	p := profRead(name)
	need := func(ver, what string) bool {
		if binVerOK(ver) {
			return true
		}
		Err(what + " needs wattun " + ver + " or newer (run: " + P.Self + " update).")
		return false
	}
	off := func(v string) bool { return v == "" || v == "0" || v == "off" }
	// Check every version gate before writing anything, so a refusal leaves the tunnel as it was.
	fs, fm := p["FAKESNI"], p["FAKEMODE"]
	if fs != "" && !need("2.7.0", "fake-sni") {
		return false
	}
	if fs != "" && fm != "" {
		if !vFakeMode(fm) || revSumRefused(tun, fm) {
			return false
		}
		if v := map[string]string{"auto": "2.9.0", "rst": "2.9.0", "synrst": "2.10.5", "paws": "3.0.2", "seqsum": "2.8.0", "sum": "2.7.1"}[fm]; v != "" && !need(v, "fake-mode "+fm) {
			return false
		}
	}
	for _, g := range [][3]string{{"POOLROT", "2.8.0", "pool-rotate"}, {"POOLBYTES", "2.8.1", "pool-rotate-bytes"}, {"ECH", "2.9.0", "ech"}} {
		if !off(p[g[0]]) && !need(g[1], g[2]) {
			return false
		}
	}
	if (p["GOVERNOR"] == "true" || p["GOVERNOR"] == "on") && !need("2.9.0", "governor") {
		return false
	}
	changed := false
	put := func(k, v string, on bool) {
		if on {
			SetValue(tun, k, v)
			changed = true
		} else if Cfg(tun, k) != "" {
			UnsetValue(tun, k)
			changed = true
		}
	}
	if fs != "" {
		put("fake-sni", fs, true)
	} else if Cfg(tun, "fake-sni") != "" {
		for _, k := range []string{"fake-sni", "fake-mode", "fake-ttl"} {
			UnsetValue(tun, k)
		}
		changed = true
	}
	if fs != "" && fm != "" {
		put("fake-mode", fm, true)
		put("fake-ttl", p["FAKETTL"], fm == "ttl" && p["FAKETTL"] != "")
	}
	put("pool-rotate", p["POOLROT"], !off(p["POOLROT"]))
	put("pool-rotate-bytes", p["POOLBYTES"], !off(p["POOLBYTES"]))
	put("ech", p["ECH"], p["ECH"] != "" && p["ECH"] != "off")
	put("governor", "true", p["GOVERNOR"] == "true" || p["GOVERNOR"] == "on")
	put("dns-listen", p["DNSLISTEN"], p["DNSLISTEN"] != "" && p["DNSLISTEN"] != "off")
	put("src-ip", p["SRCIP"], p["SRCIP"] != "" && p["SRCIP"] != "off")
	if !changed {
		Hint("Nothing to change.")
		return true
	}
	Ok("Profile '" + name + "' applied to " + tun + ".")
	if !step("Restarting "+Unit(tun), func() bool { return Restart(Unit(tun)) == nil }) {
		Err("Restart failed: run  systemctl restart " + Unit(tun))
		return false
	}
	return true
}
