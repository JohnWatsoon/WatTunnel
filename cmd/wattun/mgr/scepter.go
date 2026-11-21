// Scepter — the Iran-side cockpit surface of the pairing plane (plan
// docs/handoff/PLAN-pairing.md, Phase A). Three parts live here:
//
//   - the watp1: pairing line (parse + validate + make): the credential a
//     Kharej owner pastes on Iran once (D4/D5);
//   - the capability bitmask and its human labels (tunnel/create/manage/full);
//   - the cockpit screen: pairing status of a tunnel, attach (the -pair-to
//     equivalent) and the read-only RPC views, behind a thin client seam so no
//     fake data can ever be shown as real.
//
// Engine pairing (the scepter stream, sid 0) and the -pair/-pair-to flags are
// the engine lane's; this file only consumes the config key `pairing: true`
// (Cfg reads the yml directly, so no engine API is assumed) and shells out to
// the binary for the attach step. Both ends need 3.5.0 for any live RPC
// (stated per the plan's version matrix).

package mgr

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ======================================================================================
// The pairing line: watp1:VERSION|UUID|KEY|CAPS (plain fields, one line — the
// same shape as the wat1: token, without the base64 wrap: the key field is
// base64 itself and no field may contain '|').
// ======================================================================================

// ScepterVersion is the pairing-line format version this manager reads (D4's
// credential "version" field). A future format bumps it and Kharej re-issues.
const ScepterVersion = "1"

// PairingLine is the parsed watp1: credential.
type PairingLine struct {
	Version string // format version ("1"), not the wattun engine version
	UUID    string // pairing UUID, lowercased canonical 8-4-4-4-12 hex
	Key     []byte // the 32-byte pairing key (raw, after base64 decode)
	Caps    ScepterCaps
}

var (
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	verRe   = regexp.MustCompile(`^[0-9]+$`)
	capName = map[string]ScepterCaps{
		"tunnel": CapTunnel,
		"create": CapCreate,
		"manage": CapManage,
		"full":   CapFull,
	}
)

// ReadPairingLine parses and validates a watp1: line. Every rejection names
// the field and the rule, the way ReadToken's errors do — a paste mistake must
// be fixable without guessing.
func ReadPairingLine(line string) (PairingLine, error) {
	var p PairingLine
	body, ok := strings.CutPrefix(line, "watp1:")
	if !ok {
		return p, fmt.Errorf("not a watp1: pairing line")
	}
	body = strings.TrimSpace(body)
	fs := strings.Split(body, "|")
	if len(fs) != 4 {
		return p, fmt.Errorf("a pairing line has 4 fields version|uuid|key|capabilities, this one has %d", len(fs))
	}
	if !verRe.MatchString(fs[0]) {
		return p, fmt.Errorf("bad pairing line version %q", fs[0])
	}
	if fs[0] != ScepterVersion {
		return p, fmt.Errorf("pairing line version %q is newer than this manager knows (%s); update wattun-manager", fs[0], ScepterVersion)
	}
	u := strings.ToLower(fs[1])
	if !uuidRe.MatchString(u) {
		return p, fmt.Errorf("field 2 is not a pairing UUID (expected 8-4-4-4-12 hex, like 1b0e6a52-9f3d-4c2a-8e77-2f0a51d3c9e4)")
	}
	// padding-tolerant like ReadToken: install.sh may emit either form
	k, err := base64.StdEncoding.DecodeString(fs[2])
	if err != nil {
		if k, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(fs[2], "=")); err != nil {
			return p, fmt.Errorf("field 3 (key) is not valid base64")
		}
	}
	if len(k) != 32 {
		return p, fmt.Errorf("field 3 (key) is %d bytes, want exactly 32", len(k))
	}
	caps, err := CapsFromTokens(strings.Split(fs[3], ","))
	if err != nil {
		return p, err
	}
	return PairingLine{Version: fs[0], UUID: u, Key: k, Caps: caps}, nil
}

// CapsFromTokens turns the line's comma list ("create" alone means the tier
// create, which includes tunnel — D4's tiers are cumulative, so the tokens
// name a tier and the mask carries every tier at or below it).
func CapsFromTokens(tokens []string) (ScepterCaps, error) {
	if len(tokens) == 0 || (len(tokens) == 1 && tokens[0] == "") {
		return 0, fmt.Errorf("field 4 (capabilities) is empty; use tunnel, create, manage or full")
	}
	var m ScepterCaps
	seen := map[string]bool{}
	for _, t := range tokens {
		t = strings.TrimSpace(strings.ToLower(t))
		bit, ok := capName[t]
		if !ok {
			return 0, fmt.Errorf("unknown capability %q (use tunnel, create, manage or full)", t)
		}
		if seen[t] {
			return 0, fmt.Errorf("capability %q is listed twice", t)
		}
		seen[t] = true
		m |= tierBits(bit)
	}
	return m, nil
}

// tierBits expands a tier token to every bit at or below it: create grants
// tunnel too, manage grants create, full grants everything.
func tierBits(tier ScepterCaps) ScepterCaps {
	switch tier {
	case CapFull:
		return CapTunnel | CapCreate | CapManage | CapFull
	case CapManage:
		return CapTunnel | CapCreate | CapManage
	case CapCreate:
		return CapTunnel | CapCreate
	}
	return CapTunnel
}

// MakePairingLine renders a watp1: line (standard padded base64 for the key,
// canonical lowercase UUID, tier tokens in D4 order) — the round-trip twin of
// ReadPairingLine and what a Kharej owner copies out of install.sh.
func MakePairingLine(version, uuid string, key []byte, caps ScepterCaps) string {
	var toks []string
	for _, c := range []ScepterCaps{CapTunnel, CapCreate, CapManage, CapFull} {
		if caps&c != 0 {
			toks = append(toks, capLabel(c))
		}
	}
	return fmt.Sprintf("watp1:%s|%s|%s|%s",
		version, strings.ToLower(uuid), base64.StdEncoding.EncodeToString(key), strings.Join(toks, ","))
}

// ======================================================================================
// Capability bitmask (D4). Bits are independent so a future scoped credential
// can mix them; today's lines only ever carry tier masks.
// ======================================================================================

type ScepterCaps uint8

const (
	CapTunnel ScepterCaps = 1 << iota // today's token, unchanged
	CapCreate                         // + create tunnels
	CapManage                         // + edit/delete/test/stats/events
	CapFull                           // + update orchestration
)

func capLabel(c ScepterCaps) string {
	switch c {
	case CapTunnel:
		return "tunnel"
	case CapCreate:
		return "create"
	case CapManage:
		return "manage"
	case CapFull:
		return "full"
	}
	return "?"
}

// Labels is the human form of a mask, low tier first ("tunnel,create"); ""
// for an empty mask.
func (c ScepterCaps) Labels() string {
	var out []string
	for _, b := range []ScepterCaps{CapTunnel, CapCreate, CapManage, CapFull} {
		if c&b != 0 {
			out = append(out, capLabel(b))
		}
	}
	return strings.Join(out, ",")
}

// Has reports whether every bit of need is set (gating a screen is UX; the
// Kharej side re-checks on every command — D3 trust boundary).
func (c ScepterCaps) Has(need ScepterCaps) bool { return c&need == need }

// ======================================================================================
// The client seam: one JSONL RPC over the scepter stream (reserved sid 0,
// request {"id","v","cmd","args"} / response {"id","code","params"} — D7).
// The default dialer refuses instead of inventing data; the engine lane's
// paired-session transport replaces it by swapping one var.
// ======================================================================================

// ScepterResult mirrors one response object: a machine code (never prose) and
// the params map.
type ScepterResult struct {
	Code   int
	Params map[string]any
}

// ScepterClient is the cockpit's whole view of the channel.
type ScepterClient interface {
	Call(cmd string, args map[string]any) (ScepterResult, error)
}

// scepterDial opens the scepter stream of tunnel NAME's paired session.
var scepterDial = func(tunnel string) (ScepterClient, error) {
	return nil, fmt.Errorf("pairing channel needs wattun 3.5.0 on both ends (engine support lands with Phase A)")
}

// scepterPairTo attaches a pairing line to a tunnel — the -pair-to equivalent.
// The engine owns where the credential is stored (Kharej: /etc/wattun/.pairing,
// 0600), so the manager shells out to the binary instead of writing files
// itself; the binary's own error reaches the user untouched.
var scepterPairTo = func(tunnel, line string) error {
	out, err := exec.Command(P.Bin, "-config", filepath.Join(P.Conf, tunnel+".yml"), "-pair-to", line).CombinedOutput()
	if err != nil {
		if len(out) > 0 {
			return fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
		return err
	}
	return nil
}

// The read-only Phase A commands (plan A.3) the screen can run, in menu order.
var scepterReadCmds = []struct{ key, cmd, desc string }{
	{"h", "scepter.hello", "versions, capabilities, state_seq of the paired Kharej"},
	{"s", "state.get", "the versioned state document (tunnels, health, cursor)"},
	{"t", "tunnels.list", "tunnels of the paired Kharej"},
	{"v", "tunnel.stats", "live /stats numbers of one remote tunnel"},
	{"l", "tunnel.logs", "remote journal tail (chunked)"},
	{"e", "events.since", "events since a state_seq cursor"},
	{"y", "history", "traffic history of one remote tunnel"},
}

// ======================================================================================
// The screen (Iran side): `wattun-manager scepter NAME`.
// ======================================================================================

func init() {
	Register("scepter_cmd", func(args ...string) int {
		if n := arg(args, 0); n != "" {
			scepterScreen(n)
		}
		return 0
	})
}

// IsPaired: the config carries `pairing: true` (engine key, Phase A.2). Iran
// side only — on Kharej the pairing lives in .pairing, not in a tunnel yml.
func IsPaired(name string) bool {
	return Role(name) == "Iran" && Cfg(name, "pairing") == "true"
}

// PairedBadge is the fleet/tunnel-view mark of a paired Iran tunnel; "" when
// the tunnel is not paired (nothing changes for existing configs).
func PairedBadge(name string) string {
	if !IsPaired(name) {
		return ""
	}
	return " " + GRN + "[paired]" + RST
}

func scepterScreen(n string) {
	for {
		Page("Scepter", n+" · Iran cockpit")
		if IsPaired(n) {
			Say("  " + GRN + "●" + RST + " paired — the management channel rides this tunnel's reserved stream")
		} else {
			Say("  " + GRY + "◌" + RST + " not paired — attach the pairing line from Kharej (install.sh prints it)")
		}
		Hint("Read-only views need wattun 3.5.0 on both ends; write intents come with Phase B.")
		fmt.Fprintln(Stdout)
		MenuLine(Stdout, "a", "attach pairing line", "h", "hello", "s", "state", "t", "tunnels",
			"v", "tunnel stats", "l", "tunnel logs", "e", "events", "y", "history", "0", "back")
		fmt.Fprintf(Stdout, "  %s▸%s ", CYN, RST)
		k, _, ok := KeyRead(0)
		if !ok || k == "0" || k == "q" || k == "esc" {
			return
		}
		switch k {
		case "a":
			scepterAttach(n)
			Pause()
		default:
			// the read-only items: each is one RPC behind the client seam
			found := false
			for _, c := range scepterReadCmds {
				if c.key == k {
					found = true
					scepterRead(n, c.cmd, c.desc)
					Pause()
				}
			}
			if !found {
				Hint("Press a, h, s, t, v, l, e, y or 0.")
				sleepMS(600)
			}
		}
	}
}

// scepterAttach: paste + validate the watp1: line, then hand it to the engine.
// Validation is local and instant; the engine re-validates and owns storage.
func scepterAttach(n string) {
	fmt.Fprintln(Stdout)
	if !AskOK("Pairing line from Kharej (watp1:...)", "", vScepterPair) {
		Warn("No pairing attached.")
		return
	}
	line := ReplyV
	pl, err := ReadPairingLine(line)
	if err != nil {
		Err(err.Error())
		return
	}
	if !Confirm(fmt.Sprintf("Pair with Kharej %s (capabilities: %s)?", pl.UUID, pl.Caps.Labels()), true) {
		return
	}
	if err := scepterPairTo(n, line); err != nil {
		Err(err.Error())
		return
	}
	Ok("Pairing attached to '" + n + "' (restarts with the next engine start).")
}

// scepterRead runs one read-only RPC and prints the honest outcome — the
// refusal of the stub dialer included, never fabricated rows.
func scepterRead(n, cmd, desc string) {
	fmt.Fprintln(Stdout)
	Hint(cmd + " — " + desc)
	cl, err := scepterDial(n)
	if err != nil {
		Warn(err.Error())
		return
	}
	res, err := cl.Call(cmd, map[string]any{})
	if err != nil {
		Warn("channel error: " + err.Error())
		return
	}
	if res.Code != 0 {
		Err(fmt.Sprintf("%s answered code %d", cmd, res.Code))
		return
	}
	for k, v := range res.Params {
		Say("  " + kv(k, fmt.Sprintf("%v", v)))
	}
}

// vScepterPair validates a pasted watp1: line for AskOK (the same contract as
// vToken: false with the reason already printed via theme.Err).
func vScepterPair(s string) bool {
	if _, err := ReadPairingLine(s); err == nil {
		return true
	}
	Err("That is not a valid pairing line. It starts with watp1: and is one long line: version|uuid|key|capabilities.")
	return false
}
