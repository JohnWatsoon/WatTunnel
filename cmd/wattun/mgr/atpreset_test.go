package mgr

import (
	"strconv"
	"strings"
	"testing"
)

// The fast preset (2026-11-21) cuts the anti grid to rst/synrst x {mci.ir, irancell.ir,
// cloudflare.com} on top of the plain direct rows; reverse probes only the r= rows.
// Both ride the existing atToT/autoApply path — these tests pin the grids and the apply lines.
func atSetupPresets(t *testing.T) {
	t.Helper()
	old := engineVer
	atPreset = "normal"
	t.Cleanup(func() { engineVer, atPreset = old, "normal" })
	engineVer = func() string { return "9.9.9" }
}

func TestAutoVariantsFastGrid(t *testing.T) {
	atSetupPresets(t)
	atPreset = "fast"
	autoVariants(Token{Carrier: "auto", Peer: "203.0.113.10",
		Auto: "d=udp:4443,tcp:4443,tls:8443;r=tcp:24431,tls:24432"})
	var anti []variant
	for _, v := range av {
		if avAnti(v) {
			anti = append(anti, v)
		}
	}
	if len(anti) != 2*2*3 { // 2 anti carriers of the plan (tcp, tls) x 2 modes x 3 SNIs
		t.Fatalf("anti rows = %d: %+v", len(anti), anti)
	}
	modes, snis := map[string]bool{}, map[string]bool{}
	for _, v := range anti {
		modes[v.FM] = true
		snis[v.FS] = true
	}
	if len(modes) != 2 || !modes["rst"] || !modes["synrst"] {
		t.Errorf("modes = %v", modes)
	}
	want := map[string]bool{"mci.ir": true, "irancell.ir": true, "cloudflare.com": true}
	if len(snis) != 3 {
		t.Errorf("snis = %v (want the 3 fast SNIs)", snis)
	}
	for s := range snis {
		if !want[s] {
			t.Errorf("unexpected sni %q", s)
		}
	}
	// the winner rides the normal apply path: fake-sni/fake-mode come out of atToT
	for i := range av {
		if av[i].Label != "tcp rst mci.ir" {
			continue
		}
		c, err := atToT([]int{i})
		if err != nil || c.Carrier != "tcp" ||
			!strings.Contains(c.Extra, "fake-sni: mci.ir") || !strings.Contains(c.Extra, "fake-mode: rst") {
			t.Errorf("atToT(fast row) = %+v %v", c, err)
		}
	}
}

func TestAutoVariantsReverseOnly(t *testing.T) {
	atSetupPresets(t)
	atPreset = "reverse"
	autoVariants(Token{Carrier: "auto", Peer: "203.0.113.10", SNI: "cf.example.com",
		Auto: "d=udp:4443,tcp:4443,tls:8443;r=tcp:24431,tls:24432"})
	var labels []string
	for _, v := range av {
		if v.Kind != "r" {
			t.Fatalf("non-reverse row %q in the reverse preset", v.Label)
		}
		labels = append(labels, v.Label)
	}
	want := "icmp reverse,tcp reverse,tls reverse"
	if got := strings.Join(labels, ","); got != want {
		t.Errorf("rows = %q (want %q)", got, want)
	}
}

// ni_parse accepts exactly normal|anti|fast|reverse for --test (the bash twin is in test-manager.sh).
func TestNIParseTestFlag(t *testing.T) {
	for _, ok := range []string{"normal", "anti", "fast", "reverse"} {
		niReset()
		capture(t, func() {
			if err := niParse([]string{"--test", ok}); err != nil {
				t.Errorf("--test %s: %v", ok, err)
			}
		})
		if NI.Test != ok {
			t.Errorf("NI.Test = %q (want %q)", NI.Test, ok)
		}
	}
	niReset()
	capture(t, func() {
		if err := niParse([]string{"--test", "quick"}); err == nil {
			t.Error("--test quick accepted")
		}
	})
	niReset()
}

// The panel's "Re-test carriers" runs `auto-test NAME --yes --test reverse`: the preset must reach NI.Test
// (it was parsed only for kharej/iran, so every re-test ran the normal grid).
func TestAutoTestTakesTestFlag(t *testing.T) {
	t.Cleanup(func() { NI = niOpts{} })
	t.Setenv("WAT_CONF", t.TempDir())
	Run([]string{"auto-test", "no-such-tunnel", "--yes", "--test", "reverse", "--pick", "bond"})
	if NI.Test != "reverse" || NI.Pick != "bond" {
		t.Fatalf("NI.Test=%q NI.Pick=%q, want reverse/bond", NI.Test, NI.Pick)
	}
}

// 4.0.3: with a domain, Kharej puts wss/grpc on Cloudflare ports and Iran's normal test gets CDN rows. The 3.3.9 Go
// port lost wss/h2/grpc from the direct plan, so no auto tunnel ever had a CDN row.
func TestAutoCDNPortsGiveCDNRows(t *testing.T) {
	atSetupPresets(t)
	oldR, oldC := envRandOpenPort, envPickCFPort
	defer func() { envRandOpenPort, envPickCFPort = oldR, oldC }()
	n := 20000
	envRandOpenPort = func(string, []string) (int, error) { n++; return n, nil }
	cf := map[string]int{"wss": 2053, "grpc": 2083, "h2": 2087, "ws": 8880, "h2c": 2052}
	envPickCFPort = func(c string, _ []string) (int, bool, error) { return cf[c], false, nil }
	r := autoPickPorts(true)
	for c, p := range cf {
		if planPort(r.D, c) != strconv.Itoa(p) {
			t.Errorf("plan %q: %s should sit on %d", r.D, c, p)
		}
	}
	atPreset = "normal"
	autoVariants(Token{Carrier: "auto", Peer: "203.0.113.10", SNI: "cf.example.com", Auto: "d=" + r.D + ";r=tcp:24431"})
	var cdn []string
	for _, v := range av {
		if v.Kind == "c" {
			cdn = append(cdn, v.Label)
		}
	}
	if len(cdn) != 2 {
		t.Errorf("CDN rows = %q, want wss and grpc", cdn)
	}
}
