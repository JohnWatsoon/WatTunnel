// Scepter — the Iran-side cockpit surface of the pairing plane (plan
// docs/handoff/PLAN-pairing.md, phases A + B). Four parts live here:
//
//   - the watp1: pairing line (parse + validate + make): the credential a
//     Kharej owner pastes on Iran once (D4/D5);
//   - the capability bitmask and its human labels (tunnel/create/manage/full);
//   - the transport: the real client seam, one shell-out per call to the
//     binary's one-shot `-scepter-call` (raw JSONL in, parsed answer out);
//   - the attach screen (phase A); the fleet/wizard/tunnel pages live in
//     scepter_cockpit.go (phase B).
//
// Engine pairing (the scepter stream, sid 0) and the -pair/-pair-to flags are
// the engine lane's; this file only consumes the config key `pairing: true`
// (Cfg reads the yml directly, so no engine API is assumed) and shells out to
// the binary for everything that needs the paired session. Both ends need
// 3.5.0 for any live RPC (stated per the plan's version matrix).

package mgr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
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
	// Padded StdEncoding only, exactly the engine's ParsePairingLine rule: the
	// manager once accepted unpadded keys the engine refuses, and the pasted
	// line travels to -pair-to verbatim — a drift here surfaces only at attach
	// (round-2 finding, 2026-11-22). install.sh emits padded.
	k, err := base64.StdEncoding.DecodeString(fs[2])
	if err != nil {
		return p, fmt.Errorf("field 3 (key) is not valid base64 (padded, 32 bytes)")
	}
	if len(k) != 32 {
		return p, fmt.Errorf("field 3 (key) is %d bytes, want exactly 32", len(k))
	}
	// Exactly one tier word: the engine's ParsePairingLine reads field 4 with
	// CapFromName, which accepts only tunnel|create|manage|full (F10-parser,
	// 2026-11-22). A comma list validated here but the pasted line travels to
	// -pair-to verbatim, so anything the engine will refuse must be refused in
	// this validator — otherwise the owner hits the refusal only at attach.
	bit, ok := capName[fs[3]]
	if !ok {
		return p, fmt.Errorf("field 4 (capabilities) must be one tier word: tunnel, create, manage or full (got %q)", fs[3])
	}
	return PairingLine{Version: fs[0], UUID: u, Key: k, Caps: tierBits(bit)}, nil
}

// tierBits expands one tier word's bit to every bit at or below it: create
// grants tunnel too, manage grants create, full grants everything — the same
// tower CapFromName builds on the engine side.
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

// capTier is a mask's highest tier word — the ONE token the engine's
// ParsePairingLine accepts and its CapName renders ("" for an empty mask). A
// line field is a tier word, never a comma list (F10-parser, 2026-11-22).
func capTier(caps ScepterCaps) string {
	switch {
	case caps&CapFull != 0:
		return "full"
	case caps&CapManage != 0:
		return "manage"
	case caps&CapCreate != 0:
		return "create"
	case caps&CapTunnel != 0:
		return "tunnel"
	}
	return ""
}

// MakePairingLine renders a watp1: line (standard padded base64 for the key,
// canonical lowercase UUID, the mask's highest tier as one word) — the
// round-trip twin of ReadPairingLine and what a Kharej owner copies out of
// install.sh.
func MakePairingLine(version, uuid string, key []byte, caps ScepterCaps) string {
	return fmt.Sprintf("watp1:%s|%s|%s|%s",
		version, strings.ToLower(uuid), base64.StdEncoding.EncodeToString(key), capTier(caps))
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
// The real transport is one shell-out per Call to the binary's one-shot
// `-scepter-call` (same -config context as the run itself; it dials the
// reserved stream, prints every raw response line — chunks included — and
// exits 0 once answered, 1 on a transport failure). Tests swap this var.
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

// scepterDial opens the cockpit channel of tunnel NAME's paired session.
// Refusal is honest and local: an unpaired tunnel has no channel. Everything
// that can only be learned from Kharej (old peer, dead link, unknown flag)
// surfaces at Call time as the engine's own error text.
var scepterDial = func(tunnel string) (ScepterClient, error) {
	if !IsPaired(tunnel) {
		return nil, fmt.Errorf("tunnel '%s' is not paired — attach the watp1: line from Kharej first (Scepter screen, press a)", tunnel)
	}
	return scepterCLI{tunnel: tunnel}, nil
}

// scepterCallTimeout bounds one shell-out. runScepterCall answers or dies
// within its own deadlines (30 s pairing hello + 30 s response wait), so this
// only kills a wedged child; a healthy call returns in well under a second
// once the tunnel is up.
const scepterCallTimeout = 65 * time.Second

// scepterCLI is the real ScepterClient: every Call runs
// `wattun -config NAME.yml -scepter-call CMD -scepter-args JSON` and parses
// the JSONL answer. A write intent carries its command id inside args (the
// binary lifts it), so a retry after an unclear outcome replays the server
// journal instead of re-applying.
type scepterCLI struct{ tunnel string }

func (c scepterCLI) Call(cmd string, args map[string]any) (ScepterResult, error) {
	out, err := scepterExec(c.tunnel, cmd, args)
	if err != nil {
		return ScepterResult{}, err
	}
	return scepterParseCall(out)
}

// scepterExec runs one -scepter-call and returns its stdout (raw JSONL). The
// engine's own stderr reaches the user untouched — "pairing needs 3.5.0 on
// both ends" is exactly what an old peer must be told.
func scepterExec(tunnel, cmd string, args map[string]any) ([]byte, error) {
	if args == nil {
		args = map[string]any{}
	}
	aj, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), scepterCallTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, P.Bin, "-config", filepath.Join(P.Conf, tunnel+".yml"),
		"-scepter-call", cmd, "-scepter-args", string(aj))
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%s", msg)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("no answer within %s", scepterCallTimeout)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

// scepterRespLine is one JSONL line of the -scepter-call stdout.
type scepterRespLine struct {
	ID     string             `json:"id"`
	Code   int                `json:"code"`
	Params map[string]any     `json:"params"`
	Chunk  *scepterChunkPiece `json:"chunk"`
}

// scepterChunkPiece marks piece i of n of a large payload.
type scepterChunkPiece struct {
	I    int    `json:"chunk"`
	N    int    `json:"of"`
	Data string `json:"data"`
}

// scepterParseCall parses one -scepter-call stdout into the final answer. A
// chunked payload arrives as {"chunk":i,"of":n,"data":…} lines; the pieces
// concatenate in order and reassemble into {"logs": [...]} — the same shape
// wat.ScepterClient.waitResp answers. Any line without a chunk marker is the
// whole answer. Missing pieces, duplicate indexes and junk lines are transport
// failures: the parser never invents a field.
func scepterParseCall(out []byte) (ScepterResult, error) {
	var pieces map[int]string
	n, got, closeCode := 0, 0, 0
	saw := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r scepterRespLine
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return ScepterResult{}, fmt.Errorf("unparseable response line: %v", err)
		}
		saw = true
		if r.Chunk == nil {
			return ScepterResult{Code: r.Code, Params: r.Params}, nil
		}
		if n == 0 {
			n = r.Chunk.N
		}
		if r.Chunk.N != n || r.Chunk.N <= 0 || r.Chunk.I < 0 || r.Chunk.I >= n {
			return ScepterResult{}, fmt.Errorf("broken chunking (piece %d of %d, expected %d)", r.Chunk.I, r.Chunk.N, n)
		}
		if pieces == nil {
			pieces = map[int]string{}
		}
		if _, dup := pieces[r.Chunk.I]; dup {
			return ScepterResult{}, fmt.Errorf("chunk %d arrived twice", r.Chunk.I)
		}
		pieces[r.Chunk.I] = r.Chunk.Data
		closeCode = r.Code
		got++
		if got == n {
			var sb strings.Builder
			for i := 0; i < n; i++ {
				sb.WriteString(pieces[i])
			}
			return ScepterResult{Code: closeCode, Params: map[string]any{"logs": strings.Split(sb.String(), "\n")}}, nil
		}
	}
	if !saw {
		return ScepterResult{}, fmt.Errorf("no response on the command's stdout")
	}
	return ScepterResult{}, fmt.Errorf("chunked response ended early (%d of %d pieces)", got, n)
}

// ---- response codes (the engine's scepter wire codes, mirrored — mgr does
// not import the engine library; new codes append, never renumber) ----

const (
	scepterCodeOK           = 0
	scepterCodeBad          = 1 // malformed line, wrong version, bad args
	scepterCodeDenied       = 2 // capability insufficient
	scepterCodeStale        = 3 // intent TTL expired or built on an old state
	scepterCodeRate         = 4 // per-pair command rate exceeded
	scepterCodeUnknownCmd   = 5
	scepterCodeNotFound     = 6 // no such tunnel / event range
	scepterCodeInternal     = 7 // Kharej-side op failure (rolled-back write)
	scepterCodeTooLarge     = 8
	scepterCodeUnpaired     = 9
	scepterCodeNameTaken    = 10 // params {"name"}
	scepterCodePortBusy     = 11 // params {"port","user"}
	scepterCodeCarrierNeeds = 12 // params {"carrier","ver","need"}
	scepterCodePortDenied   = 13 // params {"port","why"}
)

// scepterCodeHint maps a code (with its params) to the short human hint the
// screens print under it — codes ride the wire, prose is local (the panel
// localizes later). A hint only explains what the code already says; it never
// invents state.
func scepterCodeHint(code int, p map[string]any) string {
	str := func(k string) string { s, _ := p[k].(string); return s }
	switch code {
	case scepterCodeOK:
		return ""
	case scepterCodeBad:
		if k := str("key"); k != "" {
			return fmt.Sprintf("Kharej refused %q (%s)", k, orStr(str("why"), "bad value"))
		}
		if s := str("ports"); s != "" {
			return "Kharej refused the ports: " + s
		}
		if s := str("name"); s != "" {
			return fmt.Sprintf("%q is not a valid tunnel name (1-32 letters, digits, - or _)", s)
		}
		return "Kharej refused the command (bad arguments)"
	case scepterCodeDenied:
		switch str("need") {
		case "proof":
			return "Kharej is paired with another Iran (or its pairing was reset) — on Kharej: Pairing, then allow a new Iran"
		case "hello":
			return "the channel opened without a hello — update wattun on this Iran"
		}
		return "needs the '" + orStr(str("need"), "higher") + "' permission on the pairing"
	case scepterCodeStale:
		return "the intent was built on an outdated state — retry on the fresh one"
	case scepterCodeRate:
		return "too many commands too fast — wait a moment and retry"
	case scepterCodeUnknownCmd:
		return "this Kharej does not know the command (needs wattun 3.5.0 there)"
	case scepterCodeNotFound:
		return "no such tunnel on Kharej (deleted from its console?)"
	case scepterCodeInternal:
		if rb, _ := p["rolled_back"].(bool); rb {
			return "Kharej failed to apply it and rolled back — nothing changed"
		}
		return "Kharej-side failure"
	case scepterCodeUnpaired:
		return "the pairing is not active on this session"
	case scepterCodeNameTaken:
		return "the name '" + orStr(str("name"), "?") + "' is already used on Kharej"
	case scepterCodePortBusy:
		// the port arrives as a JSON number; a string is accepted for stubs
		port := str("port")
		if port == "" {
			if f, ok := p["port"].(float64); ok {
				port = strconv.FormatInt(int64(f), 10)
			}
		}
		return "port " + orStr(port, "?") + " is already bound by " + orStr(str("user"), "another listener")
	case scepterCodeCarrierNeeds:
		return "carrier '" + orStr(str("carrier"), "?") + "' needs " + orStr(str("need"), "a different platform") + " on Kharej"
	case scepterCodePortDenied:
		port := ""
		if f, ok := p["port"].(float64); ok {
			port = strconv.FormatInt(int64(f), 10)
		}
		return "Kharej never forwards to port " + orStr(port, "?") + " (" + orStr(str("why"), "guarded") + ")"
	case scepterCodeTooLarge:
		if s := str("why"); s != "" {
			return "too large for the channel: " + s
		}
		return "the answer is too large for the channel (the payload caps)"
	}
	return ""
}

// scepterPairToTimeout bounds one -pair-to shell-out, like scepterCallTimeout
// does for -scepter-call: the standalone action answers in milliseconds, so
// this only kills a wedged child — a pre-b24af32 binary ran the tunnel forever
// after storing the credential, hanging the attach flow (attachPairing's fix
// comment). Var so the tests can shorten it.
var scepterPairToTimeout = scepterCallTimeout

// scepterPairTo attaches a pairing line to a tunnel — the -pair-to equivalent.
// The engine owns where the credential is stored (Kharej: /etc/wattun/.pairing,
// 0600), so the manager shells out to the binary instead of writing files
// itself; the binary's own error reaches the user untouched.
var scepterPairTo = func(tunnel, line string) error {
	ctx, cancel := context.WithTimeout(context.Background(), scepterPairToTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, P.Bin, "-config", filepath.Join(P.Conf, tunnel+".yml"), "-pair-to", line)
	out, err := c.CombinedOutput()
	if err != nil {
		if len(out) > 0 {
			return fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
		if ctx.Err() != nil {
			return fmt.Errorf("no answer within %s", scepterPairToTimeout)
		}
		return err
	}
	return nil
}

// ======================================================================================
// The screen (Iran side): `wattun-manager scepter NAME` (attach when unpaired;
// the paired cockpit lives in scepter_cockpit.go) and `scepter` (the fleet).
// ======================================================================================

func init() {
	Register("scepter_cmd", func(args ...string) int {
		if n := arg(args, 0); n != "" {
			scepterScreen(n)
		}
		return 0
	})
}

// IsPaired: the config carries `pairing: true` (engine key, Phase A.2), or a
// token-bootstrap pairing rides the tunnel's token (field 10 `pair`/`pair=<tier>`,
// owner directive 2026-11-22: pairing is derived from the minted token, the yml
// key is optional). `pairing: false` in the yml wins — the explicit off switch.
// Iran side only — on Kharej the pairing lives in .pairing, not in a tunnel yml.
func IsPaired(name string) bool {
	if Role(name) != "Iran" {
		return false
	}
	if Cfg(name, "pairing") == "false" {
		return false
	}
	return Cfg(name, "pairing") == "true" || tokenPairCaps(name) != 0
}

// tokenPairCaps reads the tunnel's token field 10 and returns its capability
// mask, 0 when there is none. Exactly the engine's ParsePairingTokenField gate
// (wat/scepter.go, L5-strict): only "pair" or "pair=<tier>" marks a credential,
// a lookalike ("pairxyz") is not one — the field must survive byte-for-byte.
func tokenPairCaps(name string) ScepterCaps {
	raw, err := os.ReadFile(filepath.Join(P.Conf, name+".token"))
	if err != nil {
		return 0
	}
	t, err := ReadToken(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0
	}
	f := t.Pair
	if f == "" || !strings.HasPrefix(f, "pair") {
		return 0
	}
	if rest := f[len("pair"):]; rest != "" && rest[0] != '=' {
		return 0 // a lookalike field (a future pair* extension): not a pairing credential
	}
	if _, v, ok := strings.Cut(f, "="); ok {
		bit, valid := capName[v]
		if !valid {
			return 0 // the engine refuses an unknown tier, so no pair
		}
		return tierBits(bit)
	}
	return CapTunnel
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
	if IsPaired(n) {
		scepterPairScreen(n)
		return
	}
	// Not paired: the only useful action is attaching the line. The read/write
	// views all need the channel, so they are not offered (they would only
	// print the dial refusal).
	for {
		Page("Scepter", n+" · Iran cockpit")
		Say("  " + GRY + "◌" + RST + " not paired — attach the pairing line from Kharej (install.sh prints it)")
		Hint("Pairing needs wattun 3.5.0 on both ends; the cockpit then rides this tunnel's reserved stream.")
		fmt.Fprintln(Stdout)
		MenuLine(Stdout, "a", "attach pairing line", "0", "back")
		fmt.Fprintf(Stdout, "  %s▸%s ", CYN, RST)
		k, _, ok := KeyRead(0)
		if !ok || k == "0" || k == "q" || k == "esc" {
			return
		}
		if k == "a" {
			scepterAttach(n)
			Pause()
		} else {
			Hint("Press a or 0.")
			sleepMS(600)
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
// transport refusal and rejection codes included, never fabricated rows.
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
	if res.Code != scepterCodeOK {
		scepterCodeErr(cmd, res)
		return
	}
	scepterPrintParams(res.Params)
}

// scepterPrintParams prints a successful answer's params as kv rows, sorted —
// a map's iteration order must not jitter the screen.
func scepterPrintParams(p map[string]any) {
	ks := make([]string, 0, len(p))
	for k := range p {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		Say("  " + kv(k, fmt.Sprintf("%v", p[k])))
	}
}

// scepterCodeErr prints a non-OK answer: the machine code, its hint and any
// detail Kharej attached.
func scepterCodeErr(cmd string, res ScepterResult) {
	Err(fmt.Sprintf("%s answered code %d", cmd, res.Code))
	if h := scepterCodeHint(res.Code, res.Params); h != "" {
		Hint(h)
	}
	if d, _ := res.Params["detail"].(string); d != "" {
		Hint("Kharej: " + d)
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
