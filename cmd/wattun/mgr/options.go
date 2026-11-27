package mgr

// The tunnel options as data (4.0.1): the Advanced page's rows with ready presets, for the web panel. The console
// keeps its own prompts (advanced.go); this model only says which settings a tunnel has, their values, the presets
// worth offering and the range a custom value may take, and applies a batch of changes TTY-free. Visibility follows
// the Advanced page: role, carrier, direction and engine version decide which rows exist.

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// OptChoice is one preset of an option; Value "" is the engine's default (the key is removed).
type OptChoice struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Hint  string `json:"hint,omitempty"`
}

// OptRange is the custom value an option also takes: a number in [Min, Max], or an address (IP).
type OptRange struct {
	Min   float64 `json:"min,omitempty"`
	Max   float64 `json:"max,omitempty"`
	Float bool    `json:"float,omitempty"`
	IP    bool    `json:"ip,omitempty"`
	Unit  string  `json:"unit,omitempty"`
}

// Option is one setting of a tunnel.
type Option struct {
	Key     string      `json:"key"`
	Label   string      `json:"label"`
	Group   string      `json:"group"`
	Help    string      `json:"help"`
	Value   string      `json:"value"` // as in the config; "" = the default
	Choices []OptChoice `json:"choices"`
	Custom  *OptRange   `json:"custom,omitempty"`
	// BothEnds: Kharej must run the same value, or the link drops; the panel changes Kharej first.
	BothEnds bool `json:"both_ends,omitempty"`
}

func optNums(unit string, def string, vals ...string) []OptChoice {
	out := []OptChoice{{Value: "", Label: def}}
	for _, v := range vals {
		out = append(out, OptChoice{Value: v, Label: strings.TrimSpace(v + " " + unit)})
	}
	return out
}

var optOnOff = []OptChoice{{Value: "", Label: "off"}, {Value: "true", Label: "on"}}

// TunnelOptions lists tunnel N's settings in the Advanced page's groups and order.
func TunnelOptions(n string) []Option {
	r, cr, rev := Role(n), Cfg(n, "carrier"), IsReverse(n)
	k33, k338, k339 := binVerOK("3.3.0"), binVerOK("3.3.8"), binVerOK("3.3.9")
	var out []Option
	add := func(on bool, o Option) {
		if on {
			o.Value = Cfg(n, o.Key)
			out = append(out, o)
		}
	}
	g := "Performance"
	add(true, Option{Key: "max-mbps", Label: "Speed limit", Group: g, Help: "A ceiling per direction and session, for a link you share or a plan with a cap.",
		Choices: optNums("MB/s", "no limit", "5", "10", "25", "50", "100"), Custom: &OptRange{Min: 1, Max: 9999, Unit: "MB/s"}})
	single := strings.Contains(" udp tcp tls ws wss h2 h2c grpc ", " "+cr+" ")
	add(r == "Iran" && !rev && single, Option{Key: "sessions", Label: "Sessions", Group: g,
		Help:    "Parallel encrypted sessions. More can pass a route that slows each flow; one is enough on a clean path.",
		Choices: optNums("", "auto", "1", "2", "4", "8"), Custom: &OptRange{Min: 1, Max: engMaxSessions}})
	add(true, Option{Key: "conns", Label: "Connections", Group: g, Help: "Connections per pool on tcp, tls, ws, h2 and grpc carriers. More spread the load over flows a filter throttles one by one.",
		Choices: optNums("", "auto", "2", "4", "8", "16", "32"), Custom: &OptRange{Min: 1, Max: engMaxConns}})
	hi := mtuMaxFor(cr)
	mtus := optNums("B", "auto", "1200", "1400")
	for len(mtus) > 1 && atoi(mtus[len(mtus)-1].Value) > hi { // icmp and a few carriers stop below 1400
		mtus = mtus[:len(mtus)-1]
	}
	add(true, Option{Key: "mtu", Label: "Packet size (MTU)", Group: g, Help: "Lower it when big packets vanish on the way (a speed test stalls, small pages load).",
		Choices: mtus, Custom: &OptRange{Min: engMTUMin, Max: float64(hi), Unit: "B"}})
	add(binVerOK("3.0.3"), Option{Key: "win-max", Label: "Window", Group: g, Help: "How much one stream may have in flight. Larger helps a single big download over a long route; it costs memory.",
		Choices: optNums("MB", "auto", "8", "16", "32", "64"), Custom: &OptRange{Min: 4, Max: 64, Unit: "MB"}})
	batchDef := "off"
	if cr == "icmp" {
		batchDef = "on"
	}
	add(cr == "icmp" || cr == "udp", Option{Key: "batch", Label: "Batching", Group: g, Help: "Sends and reads many packets per system call: less CPU at high rates.",
		Choices: []OptChoice{{Value: "", Label: "default (" + batchDef + ")"}, {Value: "on", Label: "on"}, {Value: "off", Label: "off"}}})
	add(k339 && r == "Iran" && !rev && strings.Contains("+"+cr+"+", "+udp+"), Option{Key: "udp-hop", Label: "UDP hop", Group: g,
		Help:    "A new source port every N packets: passes a filter that cuts each UDP flow after about 30 packets. 12 is the field setting.",
		Choices: []OptChoice{{Value: "", Label: "off"}, {Value: "12", Label: "12", Hint: "field setting"}, {Value: "24", Label: "24"}, {Value: "50", Label: "50"}},
		Custom:  &OptRange{Min: 2, Max: 1000, Unit: "packets"}})
	add(binVerOK("3.0.0"), Option{Key: "loss-ceiling", Label: "Slow down on loss", Group: g,
		Help: "Also lowers the rate on sudden loss. Off by default: on these routes loss is rarely congestion.", Choices: optOnOff})

	g = "Disguise"
	add(true, Option{Key: "fec", Label: "Error correction", Group: g, Help: "Sends parity when loss rises, so a lost packet is rebuilt instead of sent again. Costs some bandwidth.",
		Choices: []OptChoice{{Value: "", Label: "off"}, {Value: "auto", Label: "auto"}}})
	add(k33, Option{Key: "shape-data", Label: "Padding", Group: g, Help: "Pads packets so their sizes say less about what they carry. Spends bandwidth.",
		Choices: []OptChoice{{Value: "", Label: "off"}, {Value: "5", Label: "5 %"}, {Value: "10", Label: "10 %"}, {Value: "25", Label: "25 %"}},
		Custom:  &OptRange{Min: 0.1, Max: 25, Float: true, Unit: "%"}})
	nz := Option{Key: "noise", Label: "Idle traffic", Group: g, Help: "Keeps a little traffic flowing while the tunnel is idle, so silence does not stand out.",
		Choices: []OptChoice{{Value: "", Label: "off"}, {Value: "low", Label: "low", Hint: "about 11 MB a day"}, {Value: "med", Label: "medium", Hint: "about 88 MB a day"}}}
	if Cfg(n, "noise") == "custom" {
		nz.Choices = append(nz.Choices, OptChoice{Value: "custom", Label: "custom", Hint: Cfg(n, "noise-bps") + " B/s, set in the manager"})
	}
	add(k33, nz)
	// both-ends keys only on Iran: it changes Kharej first; from Kharej the Iran end would stay behind
	add(k338 && r == "Iran" && hasHTTPCarrier(cr), Option{Key: "probe-guard", Label: "Probe guard", Group: g, BothEnds: true,
		Help: "Answers only requests that carry the key's token; a scanner gets the decoy pages. Kharej changes first.", Choices: optOnOff})
	add(r == "Iran" && cr == "icmp", Option{Key: "icmp-type", Label: "ICMP type", Group: g, BothEnds: true, Help: "The ICMP message the tunnel rides in. Kharej changes first.",
		Choices: []OptChoice{{Value: "", Label: "echo"}, {Value: "timestamp", Label: "timestamp"}}})

	g = "Access"
	add(r == "Iran", Option{Key: "bind", Label: "Listen on", Group: g, Help: "Which of this server's addresses the forwarded ports accept users on.",
		Choices: []OptChoice{{Value: "", Label: "every IPv4 address", Hint: "0.0.0.0"}, {Value: "::", Label: "IPv4 and IPv6"}, {Value: "127.0.0.1", Label: "this server only"}},
		Custom:  &OptRange{IP: true}})
	add(k33, Option{Key: "state-save", Label: "Save counters every", Group: g, Help: "How often traffic totals and quotas are written to disk. They are always written at shutdown.",
		Choices: []OptChoice{{Value: "", Label: "30 s"}, {Value: "10", Label: "10 s"}, {Value: "60", Label: "1 min"}, {Value: "300", Label: "5 min"}, {Value: "0", Label: "shutdown only"}}})
	return out
}

// CheckOption says why VALUE is not a valid value of option O ("" = fine): one of its presets, or a custom value
// inside its range.
func CheckOption(o Option, value string) error {
	for _, c := range o.Choices {
		if c.Value == value {
			return nil
		}
	}
	cu := o.Custom
	if cu == nil {
		return fmt.Errorf("%s: pick one of the listed values", o.Label)
	}
	if cu.IP {
		h := strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
		if net.ParseIP(h) == nil {
			return fmt.Errorf("%s: enter an IPv4 or IPv6 address such as 10.0.0.5", o.Label)
		}
		return nil
	}
	f, err := strconv.ParseFloat(value, 64)
	if err != nil || (!cu.Float && f != float64(int64(f))) || f < cu.Min || f > cu.Max {
		kind := "a whole number"
		if cu.Float {
			kind = "a number"
		}
		return fmt.Errorf("%s: enter %s from %g to %g%s", o.Label, kind, cu.Min, cu.Max, strings.TrimSuffix(" "+cu.Unit, " "))
	}
	return nil
}

// SetTunnelOptions validates every change against TunnelOptions(N) and writes them all, or none. "" removes a
// key (the engine's default). The caller restarts the tunnel; both-ends keys must already be on Kharej.
func SetTunnelOptions(n string, set map[string]string) error {
	opts := map[string]Option{}
	for _, o := range TunnelOptions(n) {
		opts[o.Key] = o
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		o, ok := opts[k]
		if !ok {
			return fmt.Errorf("%s is not a setting of %s", k, n)
		}
		if err := CheckOption(o, set[k]); err != nil {
			return err
		}
		if k == "sessions" && set[k] != "" && set[k] != "1" && IsReverse(n) {
			return fmt.Errorf("Sessions: more than one does not work with reverse (Kharej dials one pool)")
		}
	}
	for _, k := range keys {
		if v := set[k]; v == "" {
			UnsetValue(n, k)
		} else {
			SetValue(n, k, v)
		}
		if k == "noise" && set[k] != "custom" {
			UnsetValue(n, "noise-bps")
		}
	}
	return nil
}

// SetBoot turns tunnel N's start at boot on or off.
func SetBoot(n string, on bool) error {
	if on {
		return systemctlErr("enable", Unit(n))
	}
	return systemctlErr("disable", Unit(n))
}

// TunnelSettings is what the panel's Settings tab shows: the options, start at boot, and where anti-censorship
// runs (Where: "here" = this end dials, "kharej" = a reverse tunnel's Kharej dials, "" = not on this carrier).
type TunnelSettings struct {
	Options []Option    `json:"options"`
	Boot    bool        `json:"boot"`
	ACWhere string      `json:"ac_where"`
	ACNow   string      `json:"ac_now,omitempty"` // the preset the keys here match ("" when Kharej holds them)
	Presets []OptChoice `json:"presets,omitempty"`
}

// acPresets are the anti-censorship presets, by the console's names; Kharej's catalog names two differently.
var acPresets = []OptChoice{
	{Value: "off", Label: "Off", Hint: "plain dialing"},
	{Value: "cloudflare", Label: "Cloudflare", Hint: "fake hello and RST, no churn; field-tested"},
	{Value: "rst-fast", Label: "Fast", Hint: "RST, more sessions, 30 min rotation"},
	{Value: "mci", Label: "MCI whitelist", Hint: "Hamrah Aval: RST, ECH ladder, governor"},
	{Value: "irancell", Label: "Irancell whitelist", Hint: "Irancell and TCI: seq, ECH ladder, governor"},
	{Value: "conservative", Label: "Low churn", Hint: "seq, 4 h rotation, for mild filtering"},
	{Value: "blackout", Label: "Blackout", Hint: "emergency: 90 s rotation; costs speed"},
}

var acKharejName = map[string]string{"cloudflare": "cf", "conservative": "low-churn"}

// Settings is tunnel N's Settings tab.
func Settings(n string) TunnelSettings {
	st := TunnelSettings{Options: TunnelOptions(n), Boot: IsEnabled(Unit(n))}
	cr := Cfg(n, "carrier")
	if cr != "icmp" && !IsPoolList(cr) {
		return st
	}
	switch {
	case AcDialer(n):
		st.ACWhere, st.ACNow = "here", StripANSI(DetectPreset(n))
	case Role(n) == "Iran" && IsReverse(n) && IsPaired(n):
		st.ACWhere = "kharej"
	default:
		return st
	}
	st.Presets = acPresets
	return st
}

// ApplySettings checks SET against tunnel N's options, changes the both-ends keys on Kharej first (through the
// pairing, which applies, restarts and rolls back on its own), then writes the rest here and restarts once.
// Nothing changes here when Kharej refuses.
func ApplySettings(n string, set map[string]string) error {
	opts := map[string]Option{}
	for _, o := range TunnelOptions(n) {
		opts[o.Key] = o
	}
	remote, rdrop := map[string]string{}, []string{}
	for k, v := range set {
		o, ok := opts[k]
		if !ok {
			return fmt.Errorf("%s is not a setting of %s", k, n)
		}
		if err := CheckOption(o, v); err != nil {
			return err
		}
		if !o.BothEnds || Role(n) != "Iran" || v == o.Value {
			continue
		}
		if v == "" {
			rdrop = append(rdrop, k)
		} else {
			remote[k] = v
		}
	}
	if len(remote)+len(rdrop) > 0 {
		if !IsPaired(n) {
			return fmt.Errorf("this setting must match on Kharej, and %s is not paired: change it on Kharej's console first, then here", n)
		}
		_, refused, err := KharejCall(n, "tunnel.edit", map[string]any{"name": n, "set": remote, "drop": rdrop})
		if err != nil {
			return fmt.Errorf("Kharej did not answer, nothing changed: %v", err)
		}
		if refused != "" {
			return fmt.Errorf("Kharej refused, nothing changed: %s", refused)
		}
	}
	if err := SetTunnelOptions(n, set); err != nil {
		return err
	}
	if err := Restart(Unit(n)); err != nil {
		return fmt.Errorf("saved, but %s did not restart: %v", n, err)
	}
	return nil
}

// ACPreset applies anti-censorship preset P to tunnel N. When this end dials, it returns the console command to
// run as a job (it restarts the tunnel and prints what it set); a reverse tunnel's preset goes to Kharej here.
func ACPreset(n, p string) (argv []string, err error) {
	ok := false
	for _, c := range acPresets {
		ok = ok || c.Value == p
	}
	if !ok {
		return nil, fmt.Errorf("unknown preset %q", p)
	}
	switch Settings(n).ACWhere {
	case "here":
		return []string{"preset", n, p, "--yes"}, nil
	case "kharej":
		kp := p
		if v, ok := acKharejName[p]; ok {
			kp = v
		}
		_, refused, err := KharejCall(n, "preset.apply", map[string]any{"name": n, "preset": kp})
		if err == nil && refused != "" {
			err = fmt.Errorf("Kharej refused: %s", refused)
		}
		return nil, err
	}
	return nil, fmt.Errorf("%s's carrier has no anti-censorship settings", n)
}
