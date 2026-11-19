package mgr

import (
	"fmt"
	"runtime"
	"strings"
)

// PresetCanonical mirrors preset_canonical(): every alias to its canonical name;
// an unknown name passes through unchanged.
func PresetCanonical(p string) string {
	p = strings.ToLower(p)
	switch p {
	case "cloudflare", "cf", "cloudflare-tested", "tested", "worked":
		return "cloudflare"
	case "rst-fast", "fast":
		return "rst-fast"
	case "mci", "mci-whitelist", "hamrah", "hamrah-aval":
		return "mci"
	case "irancell", "mokhaberat", "tci", "irancell-whitelist":
		return "irancell"
	case "blackout", "emergency", "strict":
		return "blackout"
	case "conservative", "low-churn", "mild":
		return "conservative"
	case "iran whitelist - mci":
		return "mci"
	case "iran whitelist - irancell/mokhaberat", "iran whitelist - irancell", "iran whitelist - mokhaberat":
		return "irancell"
	case "emergency blackout mode":
		return "blackout"
	case "conservative / low-churn", "conservative/low-churn":
		return "conservative"
	case "off", "clear", "none":
		return "off"
	}
	return p
}

// IsBuiltinPreset mirrors is_builtin_preset().
func IsBuiltinPreset(p string) bool {
	switch PresetCanonical(p) {
	case "cloudflare", "rst-fast", "mci", "irancell", "blackout", "conservative":
		return true
	}
	return false
}

// preset values: exactly what apply_preset writes per preset (L3324-3339).
type presetVals struct {
	fs, fm, ft, rot, rbytes, ech, gov, sess, conns string
}

func presetOf(pr string) (presetVals, error) {
	switch pr {
	case "cloudflare":
		return presetVals{fs: "www.cloudflare.com", fm: "rst"}, nil
	case "rst-fast":
		return presetVals{fs: "www.cloudflare.com", fm: "rst", rot: "30m", sess: "4", conns: "4"}, nil
	case "mci":
		return presetVals{fs: "mci.ir", fm: "rst", rot: "30m", rbytes: "500MB", ech: "ladder", gov: "true"}, nil
	case "irancell":
		return presetVals{fs: "irancell.ir", fm: "seq", rot: "20m", rbytes: "300MB", ech: "ladder", gov: "true"}, nil
	case "blackout":
		return presetVals{fs: "mci.ir", fm: "rst", rot: "90s", rbytes: "100MB", ech: "ladder", gov: "true"}, nil
	case "conservative":
		return presetVals{fs: "mci.ir", fm: "seq", rot: "4h", rbytes: "4GB", ech: "auto", gov: "true"}, nil
	case "off", "clear", "none":
		return presetVals{}, nil
	}
	return presetVals{}, fmt.Errorf("Unknown preset '%s'. Available: cloudflare, rst-fast, mci, irancell, blackout, conservative", pr)
}

// Test seams: the tests stub the binary-version gate and the restart so a
// preset application can be checked without a systemd host.
var (
	binVerOKFn = BinVerOK
	restartFn  = Restart
)

// ApplyPreset mirrors apply_preset(): which keys each preset writes, in the same
// order, with the same unset fallbacks and the same restart at the end. Returns
// false (and prints) on failure, like a non-zero bash rc.
func ApplyPreset(tun, rawPreset string) bool {
	pr := PresetCanonical(rawPreset)
	cr := Cfg(tun, "carrier")
	r := Role(tun)
	if IsPoolList(cr) && IsReverse(tun) {
		if r != "Kharej" {
			Err(fmt.Sprintf("'%s' is a reverse Iran tunnel (the listener). Anti-censorship desync runs on the dialer (Kharej).", tun))
			return false
		}
	} else if r != "Iran" {
		Err(fmt.Sprintf("'%s' is not an Iran tunnel (anti-censorship presets run on the dialer).", tun))
		return false
	}
	if !binVerOKFn("2.7.0") {
		Err(fmt.Sprintf("Anti-censorship features need wattun 2.7.0 or newer (run: %s update).", P.Self))
		return false
	}
	if cr != "icmp" && !IsPoolList(cr) {
		Err(fmt.Sprintf("Carrier '%s' does not support anti-censorship features (only pool carriers and icmp are supported).", cr))
		return false
	}
	v, err := presetOf(pr)
	if err != nil {
		Err(err.Error())
		return false
	}

	changed := false
	if cr == "icmp" {
		if v.gov == "true" {
			SetValue(tun, "governor", "true")
			changed = true
		} else if pr == "off" {
			UnsetValue(tun, "governor")
			changed = true
		}
	}

	if IsPoolList(cr) {
		if v.fs != "" {
			SetValue(tun, "fake-sni", v.fs)
			changed = true
			SetValue(tun, "fake-mode", v.fm)
			changed = true
			if v.ft != "" {
				SetValue(tun, "fake-ttl", v.ft)
			} else {
				UnsetValue(tun, "fake-ttl")
			}
		} else if Cfg(tun, "fake-sni") != "" {
			UnsetValue(tun, "fake-sni")
			UnsetValue(tun, "fake-mode")
			UnsetValue(tun, "fake-ttl")
			changed = true
		}
		if v.rot != "" {
			SetValue(tun, "pool-rotate", v.rot)
			changed = true
		} else if Cfg(tun, "pool-rotate") != "" {
			UnsetValue(tun, "pool-rotate")
			changed = true
		}
		if v.rbytes != "" {
			SetValue(tun, "pool-rotate-bytes", v.rbytes)
			changed = true
		} else if Cfg(tun, "pool-rotate-bytes") != "" {
			UnsetValue(tun, "pool-rotate-bytes")
			changed = true
		}
		if v.conns != "" {
			SetValue(tun, "conns", v.conns)
			changed = true
		}
		// sessions > 1 is refused with -reverse (the server dials one pool), so
		// rst-fast skips it there
		if v.sess != "" && !IsReverse(tun) {
			SetValue(tun, "sessions", v.sess)
			changed = true
		}
		if HasEchList(cr) {
			if v.ech != "" {
				SetValue(tun, "ech", v.ech)
				changed = true
			} else if Cfg(tun, "ech") != "" {
				UnsetValue(tun, "ech")
				changed = true
			}
		}
	}

	if !changed {
		Hint(fmt.Sprintf("Preset '%s' already matches current settings.", pr))
		return true
	}
	Ok(fmt.Sprintf("Applied anti-censorship preset '%s' to %s.", pr, tun))
	if udl := UndisguisedLegs(cr); udl != "" && IsPoolList(cr) {
		Hint(fmt.Sprintf("The '%s' leg(s) of this bond stay undisguised.", udl))
	}
	unit := Unit(tun)
	if err := restartFn(unit); err != nil {
		Err(fmt.Sprintf("Restarting %s", unit))
		Err(fmt.Sprintf("Restart failed: run  systemctl restart %s", unit))
		return false
	}
	Ok("Restart applied.")
	return true
}

// AcDialer mirrors ac_dialer(): does THIS end dial the carrier (so presets run
// here)? Linux only.
func AcDialer(name string) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if IsPoolList(Cfg(name, "carrier")) && IsReverse(name) {
		return Role(name) == "Kharej"
	}
	return Role(name) == "Iran"
}

// DetectPreset mirrors detect_preset(): the dashboard's preset label for a
// tunnel's current anti-censorship keys (returns the coloured label).
func DetectPreset(n string) string {
	cr := Cfg(n, "carrier")
	if cr == "icmp" {
		if Cfg(n, "governor") == "true" {
			return GRN + "Governor Active (ICMP Pacer)" + RST
		}
		return GRY + "none / disabled" + RST
	}
	fs := Cfg(n, "fake-sni")
	fm := Cfg(n, "fake-mode")
	if fm == "" && fs != "" {
		fm = "seq"
	}
	rot := Cfg(n, "pool-rotate")
	if fs == "" && rot == "" && Cfg(n, "governor") != "true" {
		return GRY + "none / disabled" + RST
	}
	switch {
	case fs == "www.cloudflare.com" && fm == "rst" && rot == "":
		return GRN + "Cloudflare (field-tested)" + RST
	case fs == "www.cloudflare.com" && fm == "rst" && rot == "30m":
		return GRN + "rst-fast" + RST
	case fs == "mci.ir" && fm == "rst" && rot == "30m":
		return GRN + "Iran Whitelist - MCI" + RST
	case fs == "irancell.ir" && fm == "seq" && rot == "20m":
		return GRN + "Iran Whitelist - Irancell/Mokhaberat" + RST
	case fs == "mci.ir" && fm == "rst" && rot == "90s":
		return RED + "Emergency Blackout Mode" + RST
	case fs == "mci.ir" && fm == "seq" && rot == "4h":
		return BLU + "Conservative / Low-Churn" + RST
	}
	return CYN + "Custom" + RST
}
