//go:build mgrp2

package mgr

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func writeT(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Kharej wizard yml: all keys, right defaults (bash write_server 2816).
func TestKharejYMLAllKeys(t *testing.T) {
	old := P
	P.Conf = "/etc/wattun"
	defer func() { P = old }()
	yml := kharejYML(kharejParams{
		Name: "kharej", Carrier: "tls", Listen: "443", SNI: "example.com",
		Mbps: "50", FEC: "auto", Allow: "443,53/udp", MetricsPort: 19750, Key: "kkk",
	})
	want := []string{
		"# WatTunnel - Kharej (server). Created by wattun-manager.\n",
		"mode: server\n",
		"key-file: /etc/wattun/kharej.key\n",
		"carrier: tls\n",
		"listen: \":443\"\n",
		"max-mbps: 50\n",
		"fec: auto\n",
		"metrics: 127.0.0.1:19750\n",
		"ports:\n",
		"  - 443\n",
		"  - 53/udp\n",
	}
	for _, w := range want {
		if !strings.Contains(yml, w) {
			t.Errorf("kharej yml missing %q;\ngot:\n%s", w, yml)
		}
	}
	for _, bad := range []string{"reverse", "icmp-type", "peer:", "path:"} {
		if strings.Contains(yml, bad) {
			t.Errorf("unexpected %q in kharej yml:\n%s", bad, yml)
		}
	}
}

// Defaults: icmp has no listen/metrics/ports; reverse & dns-shaped variants.
func TestKharejYMLDefaults(t *testing.T) {
	old := P
	P.Conf = "/etc/wattun"
	defer func() { P = old }()
	yml := kharejYML(kharejParams{Name: "k2", Carrier: "icmp"})
	for _, bad := range []string{"listen:", "metrics:", "ports:", "fec:", "max-mbps:"} {
		if strings.Contains(yml, bad) {
			t.Errorf("icmp default yml should not contain %q:\n%s", bad, yml)
		}
	}
	rev := kharejYML(kharejParams{Name: "k3", Carrier: "icmp", Rev: true, IranIP: "1.2.3.4"})
	if !strings.Contains(rev, "reverse: true\npeer: 1.2.3.4\n") {
		t.Errorf("reverse icmp yml:\n%s", rev)
	}
	dns := kharejYML(kharejParams{Name: "k4", Carrier: "udp", UDPdns: true, Listen: "53"})
	if !strings.Contains(dns, "udp-dns: true\n") || !strings.Contains(dns, "listen: \":53\"") {
		t.Errorf("dns-shaped yml:\n%s", dns)
	}
	rp := kharejYML(kharejParams{Name: "k5", Carrier: "tls", Rev: true, IranIP: "1.2.3.4", Listen: "443", SNI: "s.example"})
	for _, w := range []string{"reverse: true", "peer: 1.2.3.4:443", "sni: s.example", "host: s.example", "pool-rotate: 30m"} {
		if !strings.Contains(rp, w) {
			t.Errorf("reverse pool yml missing %q:\n%s", w, rp)
		}
	}
	if strings.Contains(rp, "listen:") {
		t.Errorf("reverse non-udp must not write listen:\n%s", rp)
	}
}

// Iran import from a bond token: per-leg peer keys appear (bash token_bond_legs
// 1031 + write_client 3656); a 3.3.9 :up suffix is stripped from the key name.
func TestIranBondTokenImport(t *testing.T) {
	tok := MakeToken("udp+h2:up", "1.1.1.1:5300,example.com:8443", "secretkey123", "", "", "", "443", "", "")
	tk, err := ReadToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := tk.TokenBondLegs(); err != nil {
		t.Fatal(err)
	}
	if tk.Carrier != "udp+h2:up" || tk.Peer != "1.1.1.1:5300" || len(tk.LegC) != 2 {
		t.Fatalf("carrier=%q peer=%q legs=%+v/%+v", tk.Carrier, tk.Peer, tk.LegC, tk.LegP)
	}
	yml := iranYML(iranParams{
		Name: "iran", Carrier: tk.Carrier, Peer: tk.Peer, LegC: tk.LegC, LegP: tk.LegP,
		Key: tk.Key, MetricsPort: 19751, Maps: []string{"8443:443/tcp"},
	})
	for _, w := range []string{
		"mode: client\n",
		"carrier: udp+h2:up\n",
		"peer: 1.1.1.1:5300\n",
		"peer-udp: 1.1.1.1:5300\n", // :up suffix dropped (3.3.9)
		"peer-h2: example.com:8443\n",
		"metrics: 127.0.0.1:19751\n",
		"ports:\n  - 8443:443\n",
	} {
		if !strings.Contains(yml, w) {
			t.Errorf("iran bond yml missing %q;\ngot:\n%s", w, yml)
		}
	}
	// a bond token with one endpoint (older manager) parses without a split;
	// a comma list must match the leg count (bash token_bond_legs)
	older := tk
	older.Carrier, older.Peer = "udp+h2", "only.one"
	if err := older.TokenBondLegs(); err != nil {
		t.Errorf("single-endpoint bond token must parse: %v", err)
	}
	bad := tk
	bad.Carrier, bad.Peer = "udp+h2", "a,b,c"
	if err := bad.TokenBondLegs(); err == nil || !strings.Contains(err.Error(), "it is damaged or hand-made") {
		t.Errorf("mismatched legs err = %v", err)
	}
	empty := tk
	empty.Carrier, empty.Peer = "udp+h2", "a,"
	if err := empty.TokenBondLegs(); err == nil || !strings.Contains(err.Error(), "empty endpoint") {
		t.Errorf("empty endpoint err = %v", err)
	}
}

// Token round trip: 7 fields stay 7, reverse flag appends |1.
func TestTokenRoundTrip(t *testing.T) {
	tok := MakeToken("tls", "example.com:443", "secretkey123", "/api/ab", "s.example", "", "443", "", "")
	raw := strings.TrimPrefix(tok, "wat1:")
	if strings.HasSuffix(raw, "|") {
		t.Error("7-field token must not carry empty trailing fields")
	}
	m, err := ReadToken(tok)
	if err != nil || m.Carrier != "tls" || m.Ports != "443" || m.Path != "/api/ab" || m.SNI != "s.example" {
		t.Errorf("fields = %+v err=%v", m, err)
	}
	rev := MakeToken("icmp", "1.2.3.4", "secretkey123", "", "", "", "", "1", "")
	m2, err := ReadToken(rev)
	if err != nil || m2.Rev != "1" {
		t.Errorf("rev token = %+v err=%v", m2, err)
	}
	if _, err := ReadToken("wat1:!!!not-base64!!!"); err == nil {
		t.Error("garbage token must fail")
	}
	if _, err := ReadToken("nope"); err == nil {
		t.Error("non-wat1 token must fail")
	}
}

// Port editor round-trip: bulk add, duplicate rejection, Kharej L!=T rejection.
func TestPortEditorRoundTrip(t *testing.T) {
	pe := &portEditor{Role: "Iran", Tunnel: "t1"}
	pe.bulk("443, 8443:443, 53/udp")
	if len(pe.Maps) != 3 {
		t.Fatalf("maps = %v", pe.Maps)
	}
	pe.bulk("443")
	if len(pe.Maps) != 3 {
		t.Errorf("duplicate Iran port accepted: %v", pe.Maps)
	}
	pe.remove("2")
	if len(pe.Maps) != 2 || SpecT(pe.Maps[1]) != "53" {
		t.Errorf("remove left %v", pe.Maps)
	}
	if MapsYamlBlock(pe.Maps) != "ports:\n  - 443\n  - 53/udp\n" {
		t.Errorf("yaml block = %q", MapsYamlBlock(pe.Maps))
	}
	// Kharej role: only same-port rows
	pk := &portEditor{Role: "Kharej", Tunnel: "k"}
	pk.bulk("8443->443")
	if len(pk.Maps) != 0 {
		t.Error("Kharej must reject L!=T rows")
	}
}

// Limits editor: set / replace / clear, period only with a quota (set_port_limit 873).
func TestSetPortLimit(t *testing.T) {
	base := "mode: server\ncarrier: tls\n"
	y := setPortLimitYAML(base, "443", "5MB", "100GB", "week")
	if !strings.HasSuffix(y, "limits:\n  - 443 rate=5MB quota=100GB period=week\n") {
		t.Fatalf("set = %q", y)
	}
	y2 := setPortLimitYAML(y, "443", "0", "500MB", "day")
	if strings.Count(y2, "- 443") != 1 || !strings.Contains(y2, "quota=500MB period=day") || strings.Contains(y2, "rate=") {
		t.Fatalf("replace = %q", y2)
	}
	y3 := setPortLimitYAML(y2, "8443", "300k", "0", "day")
	// the 443 row keeps its period; the new rate-only 8443 row must not carry one
	if !strings.Contains(y3, "- 443 quota=500MB period=day") {
		t.Fatalf("443 row lost its period = %q", y3)
	}
	if regexp.MustCompile(`- 8443[^\n]*period=`).MatchString(y3) || !strings.Contains(y3, "- 8443 rate=300k") {
		t.Fatalf("rate-only = %q", y3)
	}
	y4 := setPortLimitYAML(y3, "8443", "0", "0", "")
	if strings.Contains(y4, "8443") {
		t.Fatalf("clear = %q", y4)
	}
	y5 := setPortLimitYAML(y, "8443", "1MB", "", "")
	if !strings.Contains(y5, "- 443 rate=5MB quota=100GB period=week") || !strings.Contains(y5, "- 8443 rate=1MB") {
		t.Fatalf("two ports = %q", y5)
	}
}

// Delete cleanup sequence: companion -r and extended -e-* units first, in order
// (delete_tunnel 7187 + auto_drop_unit 4340).
func TestDeleteSequence(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"t1.yml", "t1-r.yml", "t1-e-vxlan.yml", "t1-e-geneve.yml"} {
		writeT(t, filepath.Join(dir, f), "mode: server\n")
	}
	old := P
	P.Conf = dir
	P.Prefix = "wattun"
	P.Run = "/run/wattun"
	defer func() { P = old }()
	seq := deleteSequence("t1")
	var out []string
	for _, c := range seq {
		out = append(out, c.String())
	}
	want := []string{
		"disable --now wattun@t1-r",
		"disable --now wattun@t1-e-geneve",
		"disable --now wattun@t1-e-vxlan",
		"stop wattun-autowatch-t1.service",
		"reset-failed wattun-autowatch-t1.service",
		"disable --now wattun@t1",
	}
	if strings.Join(out, "|") != strings.Join(want, "|") {
		t.Errorf("sequence = %v\nwant %v", out, want)
	}
	for _, f := range []string{"t1-r.yml", "t1-e-geneve.yml", "t1-e-vxlan.yml"} {
		os.Remove(filepath.Join(dir, f))
	}
	var out2 []string
	for _, c := range deleteSequence("t1") {
		out2 = append(out2, c.String())
	}
	want2 := []string{
		"stop wattun-autowatch-t1.service",
		"reset-failed wattun-autowatch-t1.service",
		"disable --now wattun@t1",
	}
	if strings.Join(out2, "|") != strings.Join(want2, "|") {
		t.Errorf("plain sequence = %v", out2)
	}
}

// runDelete executes the sequence through a systemctl recorder and removes configs.
func TestRunDeleteCallsSystemctlInOrder(t *testing.T) {
	dir := t.TempDir()
	writeT(t, filepath.Join(dir, "t2.yml"), "mode: server\n")
	writeT(t, filepath.Join(dir, "t2-r.yml"), "mode: server\n")
	writeT(t, filepath.Join(dir, "t2.token"), "wat1:x\n")
	old := P
	P.Conf = dir
	P.Prefix = "wattun"
	P.Run = t.TempDir()
	defer func() { P = old }()
	var calls []sysdCall
	oldSys := p2Systemctl
	p2Systemctl = func(args ...string) error {
		calls = append(calls, sysdCall{args})
		return nil
	}
	defer func() { p2Systemctl = oldSys }()
	NonInteractive = true // --yes is the confirmation
	defer func() { NonInteractive = false }()

	if !runDelete("t2") {
		t.Fatal("runDelete returned false")
	}
	var out []string
	for _, c := range calls {
		out = append(out, c.String())
	}
	want := []string{
		"disable --now wattun@t2-r",
		"stop wattun-autowatch-t2.service",
		"reset-failed wattun-autowatch-t2.service",
		"disable --now wattun@t2",
	}
	if strings.Join(out, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v\nwant %v", out, want)
	}
	if !fileExists(filepath.Join(P.Run, "x")) { // no-op sanity on the recorder
		_ = P.Run
	}
	for _, f := range []string{"t2.yml", "t2-r.yml", "t2.token"} {
		if fileExists(filepath.Join(P.Conf, f)) {
			t.Errorf("%s not removed", f)
		}
	}
}

// change_key Iran branch core: per-leg peer keys rewritten from the new bond token.
func TestChangeKeyBondRewrite(t *testing.T) {
	dir := t.TempDir()
	old := P
	P.Conf = dir
	defer func() { P = old }()
	f := filepath.Join(dir, "iran.yml")
	writeT(t, f, "mode: client\ncarrier: tls\npeer: old.example:443\npeer-tcp: old.example:443\nfake-sni: mci.ir\n")

	tok := MakeToken("udp+h2", "9.9.9.9:5300,new.example:8443", "newsecretkey", "", "", "", "443", "", "")
	tk, err := ReadToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := tk.TokenBondLegs(); err != nil {
		t.Fatal(err)
	}
	// the same call sequence as change_key's Iran branch (keepres=false: fake-* dropped)
	dropStaleKeys("iran", []string{"carrier", "peer", "fake-sni"})
	_ = SetValue("iran", "carrier", tk.Carrier)
	_ = SetValue("iran", "peer", tk.Peer)
	for i, lc := range tk.LegC {
		_ = SetValue("iran", "peer-"+CarrierLegBase(lc), tk.LegP[i])
	}
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, w := range []string{"peer-udp: 9.9.9.9:5300", "peer-h2: new.example:8443", "carrier: udp+h2"} {
		if !strings.Contains(out, w) {
			t.Errorf("rewrite missing %q:\n%s", w, out)
		}
	}
	for _, bad := range []string{"old.example", "peer-tcp", "fake-sni"} {
		if strings.Contains(out, bad) {
			t.Errorf("stale %q survived:\n%s", bad, out)
		}
	}
}

// wizard helpers: suggest_name, norm_spec texts, metrics port reserved ranges,
// carrier validation, token bond legs through the change_key path.
func TestWizardHelpers(t *testing.T) {
	dir := t.TempDir()
	old := P
	P.Conf = dir
	defer func() { P = old }()
	writeT(t, filepath.Join(dir, "kharej.yml"), "mode: server\n")
	writeT(t, filepath.Join(dir, "kharej-2.yml"), "mode: server\n")
	if got := suggestName("kharej"); got != "kharej-3" {
		t.Errorf("suggestName = %q", got)
	}
	if _, err := NormSpec("53/icmp"); err == nil || err.Error() != "unknown protocol 'icmp' (use tcp, udp or both)" {
		t.Errorf("NormSpec err = %v", err)
	}
	if _, err := NormSpec("1:2:3"); err == nil || err.Error() != "'1:2:3' has too many ':'" {
		t.Errorf("NormSpec err = %v", err)
	}
	if got, _ := NormSpec("53/both"); len(got) != 2 {
		t.Errorf("both = %v", got)
	}
	for _, p := range []int{18995, 19705, 20450} {
		if p2FreeMetricsPort() == p {
			t.Errorf("reserved port %d returned", p)
		}
	}
	if !VCarrierList("icmp+udp:down") {
		t.Error("icmp+udp:down must be a valid 3.3.9 bond list")
	}
	if VCarrierList("vxlan+tcp") {
		t.Error("shaped carriers must not bond (D7)")
	}
	if VCarrierList("udp:down") {
		t.Error("a :up/:down suffix on a lone carrier must be refused")
	}
	if !carrierWriteListen("icmp+tls") || carrierWriteListen("icmp") {
		t.Error("carrier_write_listen wrong")
	}
	if !IsRpool("tls") || !IsRpool("udp") || IsRpool("icmp") {
		t.Error("is_rpool wrong")
	}
	if p2Rproto("udp") != "udp" || p2Rproto("vxlan") != "udp" || p2Rproto("tls") != "tcp" {
		t.Error("rproto wrong")
	}
	if h, p := SplitHP("[::1]:443"); h != "::1" || p != "443" {
		t.Errorf("SplitHP bracket = %q %q", h, p)
	}
	if got := JoinHP("::1", "443"); got != "[::1]:443" {
		t.Errorf("JoinHP = %q", got)
	}
	if !ipOK("1.2.3.4") || ipOK("999.1.1.1") || !ipOK("::1") {
		t.Error("ipOK wrong")
	}
	// allowlist embed: token field 7 from a Kharej ports block
	if got := allowOfMaps([]string{"443:443/tcp", "53:53/udp"}); got != "443,53/udp" {
		t.Errorf("allowOfMaps = %q", got)
	}
	if !allowedHas(allowToArray("443,53/udp"), "53", "udp") || allowedHas(allowToArray("443"), "53", "udp") {
		t.Error("allowed_has wrong")
	}
	if got := allowToMaps("443,53/udp"); len(got) != 2 || SpecYaml(got[0]) != "443" || SpecYaml(got[1]) != "53/udp" {
		t.Errorf("allowToMaps = %v", got)
	}
}
