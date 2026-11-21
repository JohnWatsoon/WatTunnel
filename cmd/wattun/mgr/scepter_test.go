package mgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestPairingLineRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		uuid string
		caps ScepterCaps
		toks string
	}{
		{"tunnel tier", "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", CapTunnel, "tunnel"},
		{"create tier", "1B0E6A52-9F3D-4C2A-8E77-2F0A51D3C9E4", CapTunnel | CapCreate, "tunnel,create"},
		{"manage tier", "00000000-0000-0000-0000-000000000001", CapTunnel | CapCreate | CapManage, "tunnel,create,manage"},
		{"full tier", "ffffffff-ffff-ffff-ffff-ffffffffffff", CapTunnel | CapCreate | CapManage | CapFull, "tunnel,create,manage,full"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := MakePairingLine(ScepterVersion, c.uuid, testKey(), c.caps)
			if !strings.HasPrefix(line, "watp1:") {
				t.Fatalf("line %q lacks the watp1: prefix", line)
			}
			p, err := ReadPairingLine(line)
			if err != nil {
				t.Fatalf("ReadPairingLine: %v", err)
			}
			if p.UUID != strings.ToLower(c.uuid) {
				t.Errorf("UUID = %q, want lowercased %q", p.UUID, c.uuid)
			}
			if len(p.Key) != 32 || p.Key[0] != 1 || p.Key[31] != 32 {
				t.Errorf("key damaged: %d bytes", len(p.Key))
			}
			if p.Caps != c.caps {
				t.Errorf("caps = %d, want %d", p.Caps, c.caps)
			}
			// an unpadded key field (hand-trimmed '=' like an unpadded wat1:) reads too
			fs := strings.Split(strings.TrimPrefix(line, "watp1:"), "|")
			unpadded := strings.TrimSuffix(fs[2], "=")
			if _, err := ReadPairingLine("watp1:" + strings.Join([]string{fs[0], fs[1], unpadded, fs[3]}, "|")); err != nil {
				t.Errorf("unpadded key: %v", err)
			}
		})
	}
}

func TestReadPairingLineRejects(t *testing.T) {
	good := MakePairingLine(ScepterVersion, "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", testKey(), CapCreate)
	fields := func(repl ...string) string {
		fs := strings.Split(strings.TrimPrefix(good, "watp1:"), "|")
		for i, v := range repl {
			if v != "\x00" { // \x00 = leave the field as-is
				fs[i] = v
			}
		}
		return "watp1:" + strings.Join(fs, "|")
	}
	bad := []struct {
		name, line, wantErr string
	}{
		{"not a pairing line", "wat1:zzz", "not a watp1: pairing line"},
		{"three fields", "watp1:1|1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4|QUJD", "4 fields"},
		{"future version", fields("2", "\x00", "\x00"), "newer than this manager"},
		{"nonnumeric version", fields("x", "\x00", "\x00"), "bad pairing line version"},
		{"uuid shape", fields("\x00", "not-a-uuid", "\x00"), "not a pairing UUID"},
		{"uuid hex", fields("\x00", "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9gg", "\x00"), "not a pairing UUID"},
		{"key base64", fields("\x00", "\x00", "!!!"), "not valid base64"},
		{"key short", fields("\x00", "\x00", "QUJD", "\x00"), "want exactly 32"},
		{"unknown cap", fields("\x00", "\x00", "\x00", "root"), "unknown capability"},
		{"empty caps", fields("\x00", "\x00", "\x00", ""), "capabilities) is empty"},
		{"dup cap", fields("\x00", "\x00", "\x00", "tunnel,tunnel"), "listed twice"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := ReadPairingLine(c.line)
			if err == nil {
				t.Fatalf("no error for %q", c.line)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %q, want it to contain %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestCaps(t *testing.T) {
	// D4 tiers are cumulative: a token names a tier, the mask carries the tower
	for tok, want := range map[string]ScepterCaps{
		"tunnel": CapTunnel,
		"create": CapTunnel | CapCreate,
		"manage": CapTunnel | CapCreate | CapManage,
		"full":   CapTunnel | CapCreate | CapManage | CapFull,
	} {
		m, err := CapsFromTokens(strings.Split(tok, ","))
		if err != nil {
			t.Fatalf("CapsFromTokens(%q): %v", tok, err)
		}
		if m != want {
			t.Errorf("token %q -> mask %d, want %d", tok, m, want)
		}
		if got := m.Labels(); got != want.Labels() {
			t.Errorf("Labels(%q) = %q, want %q", tok, got, want.Labels())
		}
	}
	if s := ScepterCaps(0).Labels(); s != "" {
		t.Errorf("empty mask labels = %q, want \"\"", s)
	}
	full, _ := CapsFromTokens([]string{"full"})
	if !(CapTunnel | CapCreate | CapManage).Has(CapManage) || full.Has(CapFull) != true {
		t.Error("Has is broken")
	}
	if !full.Has(CapTunnel | CapCreate | CapManage | CapFull) {
		t.Error("full must have every bit")
	}
}

func TestVScepterPair(t *testing.T) {
	InitColor(false, 8)
	errN0 := ErrN()
	if !vScepterPair(MakePairingLine(ScepterVersion, "1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4", testKey(), CapManage)) {
		t.Error("valid line rejected")
	}
	if vScepterPair("watp1:1|x|y|z") {
		t.Error("garbage line accepted")
	}
	if ErrN() != errN0+1 {
		t.Errorf("validator must print exactly one error, got %d", ErrN()-errN0)
	}
}

func TestPairedBadge(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	ir := "mode: client\ncarrier: udp\npeer: 198.51.100.7:4443\n"
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte(ir), 0o600)
	os.WriteFile(filepath.Join(dir, "irp.yml"), []byte(ir+"pairing: true\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "kh.yml"), []byte("mode: server\ncarrier: udp\npairing: true\n"), 0o600)
	if got := PairedBadge("ir"); got != "" {
		t.Errorf("unpaired Iran badge = %q, want empty", got)
	}
	if got := PairedBadge("irp"); got != " [paired]" {
		t.Errorf("paired Iran badge = %q, want \" [paired]\"", got)
	}
	// pairing on a Kharej config is not the Iran badge (the Kharej side stores
	// the credential in .pairing, not in a tunnel yml — Phase A.2)
	if got := PairedBadge("kh"); got != "" {
		t.Errorf("Kharej badge = %q, want empty", got)
	}
	if !IsPaired("irp") || IsPaired("ir") || IsPaired("kh") {
		t.Error("IsPaired disagrees with PairedBadge")
	}
}

func TestScepterScreenStubTransport(t *testing.T) {
	InitColor(false, 8)
	dir := t.TempDir()
	old := P.Conf
	P.Conf = dir
	defer func() { P.Conf = old }()
	os.WriteFile(filepath.Join(dir, "ir.yml"), []byte("mode: client\ncarrier: udp\n"), 0o600)
	// the stub dialer refuses; the screen must say so, never invent rows
	out := capture(t, func() { scepterRead("ir", "state.get", "the state document") })
	if !strings.Contains(out, "state.get") || !strings.Contains(out, "3.5.0") {
		t.Errorf("stub refusal missing command/version:\n%s", out)
	}
	// a fake client proves the success path prints params, code errors print codes
	oldDial := scepterDial
	scepterDial = func(string) (ScepterClient, error) {
		return stubClient{ScepterResult{Code: 0, Params: map[string]any{"state_seq": 7}}}, nil
	}
	defer func() { scepterDial = oldDial }()
	out = capture(t, func() { scepterRead("ir", "state.get", "the state document") })
	if !strings.Contains(out, "state_seq") || !strings.Contains(out, "7") {
		t.Errorf("params not printed:\n%s", out)
	}
}

type stubClient struct{ r ScepterResult }

func (s stubClient) Call(string, map[string]any) (ScepterResult, error) { return s.r, nil }
