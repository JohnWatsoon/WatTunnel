// Scepter operations from the cockpit (3.5.0, plan D; the pair screen's "o").
// Five flows, every answer straight from the RPC (docs/TECHNICAL.md, "Phase D
// commands: operations"; both ends need 3.5.0):
//
//   - update.status (manage): the remote engine's version, wattun.prev
//     evidence, unit states, the update mailbox and the staging state — local
//     reads on Kharej, the engine fetches nothing;
//   - update.run {to?} (full — the one CapFull command): Kharej updates its
//     own binary. Hard confirm (default no), the drop warning up front: the
//     channel dies mid-update by design and comes back through the latch; the
//     outcome survives in the journal and the update mailbox — after the
//     revival, update.status reveals applied/failed/rolled_back, and a retried
//     command id replays from the journal at-most-once;
//   - doctor.fetch (manage): the state document plus the doctor fragments,
//     flattened into structured rows;
//   - backup.export (manage): Kharej's config dir as a sha256-verified
//     tarball, reassembled with the transport's chunk parser and saved here;
//   - audit.tail {n} (manage): the last n raw lines of each audit source.
//
// Client-side capability gating is UX only — Kharej re-checks every command
// (D3; the full gate on update.run is UX too, the engine's is the real one).

package mgr

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ======================================================================================
// Arg shapes and answer parsers (pure; the tests pin them against the engine's
// strictly-typed readers in wat/scepter.go and cmd/wattun/scepter_ops.go).
// ======================================================================================

// scepterUpdateRunArgs builds update.run {id, to?}. `to` stays absent when
// empty (the engine's latest release); the id is lifted by -scepter-call into
// the command id — a resend after an unclear outcome replays the journal's
// recorded started answer instead of starting a second update.
func scepterUpdateRunArgs(to, id string) map[string]any {
	args := map[string]any{"id": id}
	if to != "" {
		args["to"] = to
	}
	return args
}

// scepterAuditTailArgs builds audit.tail {n}: empty means the engine's default
// (100), and the 1000 cap is mirrored client-side so the validator's promise
// ("the engine caps it") matches what is sent.
func scepterAuditTailArgs(n int) map[string]any {
	if n <= 0 {
		n = 100
	}
	if n > 1000 {
		n = 1000
	}
	return map[string]any{"n": n}
}

// scepterLogsOf reads the chunked-logs convention's params (backup.export,
// audit.tail): a chunked reassembly arrives as []string (the transport parser's
// own shape), a small answer as the JSON-roundtripped []any — both are the same
// list of newline-free documents after flattening.
func scepterLogsOf(p map[string]any) []string {
	if p == nil {
		return nil
	}
	switch l := p["logs"].(type) {
	case []string:
		return l
	case []any:
		out := make([]string, 0, len(l))
		for _, e := range l {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// scepterBackupDoc is the backup.export payload document {b64, sha256, size,
// files}; raw is the decoded tarball.
type scepterBackupDoc struct {
	B64, SHA256 string
	Size, Files int
}

// scepterParseBackupDoc decodes and verifies the payload: the document carries
// the tar's size and sha256 so a truncated or corrupted reassembly is caught
// here, honestly, before anything is written to disk.
func scepterParseBackupDoc(doc string) (scepterBackupDoc, []byte, error) {
	var d scepterBackupDoc
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		return d, nil, fmt.Errorf("backup document does not parse: %v", err)
	}
	if d.B64 == "" || d.SHA256 == "" || d.Size <= 0 {
		return d, nil, fmt.Errorf("backup document lacks b64, sha256 or size")
	}
	raw, err := base64.StdEncoding.DecodeString(d.B64)
	if err != nil {
		return d, nil, fmt.Errorf("backup tarball: %v", err)
	}
	if len(raw) != d.Size {
		return d, nil, fmt.Errorf("backup tarball is %d bytes, the document says %d (truncated transfer?)", len(raw), d.Size)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != d.SHA256 {
		return d, nil, fmt.Errorf("backup tarball checksum mismatch (want %s, got %s)", d.SHA256, got)
	}
	return d, raw, nil
}

// scepterUpdUnit is one row of update.status's unit list.
type scepterUpdUnit struct {
	Name   string
	Active bool
}

// scepterUpdMail is the update mailbox record (wat.ScepterUpdateStatus over
// the wire): the cross-restart news channel of the update orchestration.
type scepterUpdMail struct {
	Phase, Run, From, To, Detail string
	Ts                           int64
}

// scepterUpdStatus is the update.status answer's cockpit subset. Absent
// evidence stays absent — nothing is defaulted into looking real.
type scepterUpdStatus struct {
	Ver, Goos, Arch string
	Systemd         bool
	Bin, Conf       string
	PrevPresent     bool
	PrevPath        string
	PrevBytes       int64
	PrevMtime       int64
	PrevVer         string
	Units           []scepterUpdUnit
	Mail            *scepterUpdMail
	StagedBytes     int64
}

// scepterParseUpdStatus parses the answer; an empty params map is an error,
// never a blank screen that looks like a success.
func scepterParseUpdStatus(p map[string]any) (scepterUpdStatus, error) {
	var s scepterUpdStatus
	if len(p) == 0 {
		return s, fmt.Errorf("empty update.status answer")
	}
	s.Ver, _ = p["ver"].(string)
	s.Goos, _ = p["goos"].(string)
	s.Arch, _ = p["arch"].(string)
	s.Systemd, _ = p["systemd"].(bool)
	s.Bin, _ = p["bin"].(string)
	s.Conf, _ = p["conf"].(string)
	if prev, ok := p["prev"].(map[string]any); ok {
		s.PrevPresent, _ = prev["present"].(bool)
		s.PrevPath, _ = prev["path"].(string)
		s.PrevVer, _ = prev["ver"].(string)
		s.PrevBytes = int64(scepterU64(prev["bytes"]))
		s.PrevMtime = int64(scepterU64(prev["mtime"]))
	}
	if list, ok := p["units"].([]any); ok {
		for _, e := range list {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			u := scepterUpdUnit{}
			u.Name, _ = m["name"].(string)
			u.Active, _ = m["active"].(bool)
			s.Units = append(s.Units, u)
		}
	}
	if m, ok := p["update"].(map[string]any); ok {
		mail := &scepterUpdMail{}
		mail.Phase, _ = m["phase"].(string)
		mail.Run, _ = m["run"].(string)
		mail.From, _ = m["from"].(string)
		mail.To, _ = m["to"].(string)
		mail.Detail, _ = m["detail"].(string)
		mail.Ts = int64(scepterU64(m["ts"]))
		s.Mail = mail
	}
	if staged, ok := p["staged"].(map[string]any); ok {
		s.StagedBytes = int64(scepterU64(staged["bytes"]))
	}
	return s, nil
}

// scepterTs formats one unix timestamp for the ops rows; an absent one says ?.
func scepterTs(ts int64) string {
	if ts <= 0 {
		return "?"
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04")
}

// scepterRenderRows flattens one params map into sorted dotted-path rows:
// doctor.fetch's document nests maps (latch, unit, update, journal) and lists
// (recent, tunnels), and %v of those is noise, not rows. Lists render one row
// per element; an empty list renders nothing (no rows are invented).
func scepterRenderRows(p map[string]any) []string {
	var out []string
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch t := v.(type) {
		case map[string]any:
			ks := make([]string, 0, len(t))
			for k := range t {
				ks = append(ks, k)
			}
			sort.Strings(ks) // a map's iteration order must not jitter the rows
			for _, k := range ks {
				p := k
				if path != "" {
					p = path + "." + k
				}
				walk(p, t[k])
			}
		case []any:
			for i, e := range t {
				walk(fmt.Sprintf("%s[%d]", path, i), e)
			}
		case []string:
			for i, e := range t {
				walk(fmt.Sprintf("%s[%d]", path, i), e)
			}
		default:
			out = append(out, path+": "+fmt.Sprintf("%v", v))
		}
	}
	walk("", p)
	return out
}

// ======================================================================================
// Validators (they print their own reason, like every AskOK validator here).
// ======================================================================================

// vScepterTag mirrors the engine's ValidScepterTag: a dotted version, optionally
// v-prefixed; empty is the latest release (the engine's optional `to`). The
// engine re-validates and refuses the running version and pre-3.5.0 targets
// (those would come back without the cockpit channel).
func vScepterTag(s string) bool {
	if strings.TrimSpace(s) == "" {
		return true
	}
	t := strings.TrimPrefix(strings.TrimSpace(s), "v")
	fs := strings.Split(t, ".")
	if len(fs) == 3 {
		ok := true
		for _, f := range fs {
			if !isDigits(f) || len(f) > 3 {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	Err("Want a dotted version, optionally v-prefixed (v3.6.0).")
	return false
}

// vScepterAuditN: the audit.tail line count; empty takes the engine's default.
func vScepterAuditN(s string) bool {
	if s == "" {
		return true
	}
	if !isDigits(s) {
		Err("Digits only (empty = the default 100).")
		return false
	}
	if n := atoi(s); n > 1000 {
		Err("The engine caps the tail at 1000 lines.")
		return false
	}
	return true
}

// vScepterBackupPath: the local save path. The export is a plain (uncompressed)
// tar, so the name should say .tar; a one-line path only — it is typed.
func vScepterBackupPath(s string) bool {
	if s == "" || strings.ContainsAny(s, "\n\r") {
		Err("Give a file path ending in .tar.")
		return false
	}
	if !strings.HasSuffix(strings.ToLower(s), ".tar") {
		Err("The export is a plain tar — save it as *.tar.")
		return false
	}
	return true
}

// ======================================================================================
// Screen chrome: the U1 primitives on the scepter surfaces. The gradient band
// under each title is the screen's one bright moment; a spinner covers the
// seconds a channel call blocks; every number renders through the unit
// formatters. Colour off keeps every screen's plain look byte-for-byte (the
// band falls back to the grey ─ rule, the spinner never runs).
// ======================================================================================

// scepterSpinCore is the spinner line's engine: glyph() renders the moving
// mark, fn runs underneath. The stop handshake runs in a defer, so a panicking
// fn also stops the line (debug round 3, 2026-11-23); the order is close,
// wait for the goroutine, then the erase — no frame can follow it.
func scepterSpinCore(what string, glyph func() string, fn func()) {
	if !UseAnim || !IsTTY {
		fn()
		return
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped) // runs after CurShow: no frame can follow the erase
		CurHide()
		defer CurShow()
		for {
			select {
			case <-done:
				return
			case <-time.After(120 * time.Millisecond):
				fmt.Fprintf(Stdout, "\r\x1b[K  %s %s…", glyph(), what)
			}
		}
	}()
	defer func() {
		close(done)
		<-stopped // the spinner line is quiescent before the outcome prints over it
		fmt.Fprint(Stdout, "\r\x1b[K")
	}()
	fn()
}

// scepterSpin runs fn with a spinner line while it blocks (design-motion: a
// spinner while something works, nothing looping for no reason). fn must not
// print — the spinner owns the line and is stopped and erased before the
// outcome prints. Anim off (NONINTERACTIVE, WAT_NO_ANIM, tests): fn runs bare,
// so anim-off output stays byte-stable.
func scepterSpin(what string, fn func()) {
	var sp Spinner
	scepterSpinCore(what, func() string { return CYN + sp.Frame() + RST }, fn)
}

// scepterShimmer is scepterSpin's short-step variant: a two-frame brightness
// shimmer (no rotation) for sub-second work like the backup's sha256 verify —
// the glyph holds still and glows, then the outcome's ✓ lands over the line.
func scepterShimmer(what string, fn func()) {
	scepterSpinCore(what, func() string {
		if shimmerFrame() == 0 {
			return CYN + BOLD + "◈" + RST
		}
		return CYN + "◈" + RST
	}, fn)
}

// scepterActSpin is scepterAct with the channel call itself covered by the
// spinner; the honest outcome printing stays outside the spinner's line.
// (scepterAct lives in scepter_cockpit.go — this lane's screens spin without
// touching that file.)
func scepterActSpin(cl ScepterClient, cmd string, args map[string]any) (ScepterResult, bool) {
	var res ScepterResult
	var err error
	scepterSpin(cmd, func() { res, err = cl.Call(cmd, args) })
	if err != nil {
		Warn("channel: " + err.Error())
		return ScepterResult{}, false
	}
	if res.Code != scepterCodeOK {
		scepterCodeErr(cmd, res)
		return res, false
	}
	return res, true
}

// ======================================================================================
// The ops screen: the pair screen's "o". The menu hides what the pairing's
// capability does not cover (update.run without full), and each action repeats
// its own gate — a direct call must refuse, not fall through.
// ======================================================================================

// scepterOpsItems: one item per ops command. update.status first (the read the
// others are judged against), update.run last and in red — the scariest remote
// op in the plane.
func scepterOpsItems(caps ScepterCaps) []Item {
	if !caps.Has(CapManage) {
		return nil // every ops command needs at least manage
	}
	items := []Item{
		{Key: "s", Label: "Update status", Desc: "engine version, wattun.prev, unit states, the update mailbox"},
		{Key: "d", Label: "Doctor", Desc: "doctor.fetch — the pair's structured self-report"},
		{Key: "b", Label: "Export backup", Desc: "Kharej's config dir as a verified tarball, saved here"},
		{Key: "a", Label: "Audit trail", Desc: "the last audit + journal lines, raw"},
	}
	if caps.Has(CapFull) {
		items = append(items, Item{Key: "u", Label: RED + "Run update" + RST,
			Desc: "Kharej updates its own binary (drops this channel; rolls back on a dead engine)"})
	}
	return items
}

func scepterOpsHead(w io.Writer, pair string, caps ScepterCaps) {
	Title(w, "Operations", pair+" · caps "+orStr(caps.Labels(), "none"))
	GradBand(w, uiW()) // the screen's one bright moment
	hintLine(w, "The pair's ops console; every row below is Kharej's own answer.")
	fmt.Fprintln(w)
}

func scepterOpsScreen(pair string, cl ScepterClient, caps ScepterCaps) {
	sel := 0
	for {
		items := scepterOpsItems(caps)
		head := func(w io.Writer) { scepterOpsHead(w, pair, caps) }
		i, k := Choose(head, items, &sel, []string{"⏎", "run", "esc", "back"}, time.Second)
		switch {
		case i >= 0:
			k = items[i].Key
		case k == "tick" || k == "move":
			continue
		case k == "eof":
			return
		}
		switch k {
		case "s":
			scepterUpdateStatusView(cl)
			Pause()
		case "d":
			scepterDoctorView(pair, cl)
			Pause()
		case "b":
			scepterBackupExport(pair, cl)
			Pause()
		case "a":
			scepterAuditView(cl)
		case "u":
			scepterUpdateRun(pair, cl, caps)
			Pause()
		case "0", "esc", "q":
			return
		}
	}
}

// ---- update.status ----

func scepterUpdateStatusView(cl ScepterClient) {
	fmt.Fprintln(Stdout)
	Hint("update.status — the remote engine's update evidence (local reads only)")
	GradBand(Stdout, uiW())
	res, ok := scepterActSpin(cl, "update.status", nil)
	if !ok {
		return
	}
	st, err := scepterParseUpdStatus(res.Params)
	if err != nil {
		Warn(err.Error())
		return
	}
	scepterPrintUpdStatus(st)
}

func scepterPrintUpdStatus(st scepterUpdStatus) {
	sysd := "no"
	if st.Systemd {
		sysd = "yes"
	}
	Say("  " + KV(11, "Engine", st.Ver+" · "+st.Goos+"/"+st.Arch+" · systemd "+sysd))
	if st.Bin != "" {
		Say("  " + KV(11, "Binary", st.Bin))
	}
	if st.Conf != "" {
		Say("  " + KV(11, "Conf", st.Conf))
	}
	// The prev evidence is the watchdog's hard gate: without a backup path the
	// job aborts untouched, so say so instead of a silent empty row.
	if !st.PrevPresent || st.PrevPath == "" {
		Warn("No wattun.prev evidence — the update watchdog refuses to swap without a backup path.")
	} else {
		prev := fmt.Sprintf("%s · %s · %s", st.PrevPath, UnitBytes(float64(st.PrevBytes), 0), scepterTs(st.PrevMtime))
		if st.PrevVer != "" {
			prev += " · " + st.PrevVer
		}
		Say("  " + KV(11, "wattun.prev", prev))
	}
	for _, u := range st.Units {
		col, mark, txt := GRY, "◌", "stopped"
		if u.Active {
			col, mark, txt = GRN, "●", "up"
		}
		Say("  " + KV(11, "Unit", u.Name+"  "+col+mark+" "+txt+RST))
	}
	if st.Mail == nil {
		Hint("No update has run on this Kharej yet (no mailbox record).")
	} else {
		Say("  " + KV(11, "Update", scepterMailStr(*st.Mail)))
		key := st.Mail.Run
		if key == "" { // no run id in the record: the phase+ts still disambiguates reads
			key = fmt.Sprintf("mail-%s-%d", st.Mail.Phase, st.Mail.Ts)
		}
		scepterStepperShow(key, st.Mail.Phase, false)
		if st.Mail.Phase == "started" {
			Hint("A started record means an update was accepted; if the channel died before")
			Hint("the answer, the journal replays it for the same command id — and a record")
			Hint("silent past the job's watch window arrives as update_failed {interrupted}.")
		}
	}
	if st.StagedBytes > 0 {
		Say("  " + KV(11, "Staged", UnitBytes(float64(st.StagedBytes), 0)+" under .update (staging in progress or left over)"))
	}
}

// scepterMailStr renders the mailbox record; the phase carries the colour
// (applied green, started/rolled_back amber, failed red).
func scepterMailStr(m scepterUpdMail) string {
	col := YEL
	switch m.Phase {
	case "applied":
		col = GRN
	case "failed":
		col = RED
	}
	s := col + orStr(m.Phase, "?") + RST
	if m.Run != "" {
		s += " · run " + m.Run
	}
	if m.From != "" || m.To != "" {
		s += " · " + orStr(m.From, "?") + " → " + orStr(m.To, "?")
	}
	if m.Ts > 0 {
		s += " · " + scepterTs(m.Ts)
	}
	if m.Detail != "" {
		s += " · " + m.Detail
	}
	return s
}

// ---- the update stepper (owner directive 2026-11-23: purposeful motion) ----

// scepterStepperPhases are the update job's five phases in order. The mailbox
// records only the start and the terminal phase (wat's update orchestration),
// so a mid-flight record pins "started" at Download and a terminal one at the
// end — no intermediate phase is ever claimed complete without evidence.
var scepterStepperPhases = []string{"Download", "Verify", "Install", "Restart", "Watch"}

// scepterMailStepper maps a mailbox phase onto stepper coordinates: completed
// phases before active, active is the spinner index (-1: none, the run ended),
// failed marks the run's end red (failed/rolled_back — where it broke is in
// detail, not in the phase, so nothing before it is claimed done).
func scepterMailStepper(phase string) (completed, active int, failed bool) {
	switch phase {
	case "applied":
		return len(scepterStepperPhases), -1, false
	case "failed", "rolled_back":
		return 0, 0, true
	}
	return 0, 0, false // started, and anything unknown reads as the recorded start
}

// shimmerFrame is the 2-frame brightness toggle (~400 ms per frame) an active
// label breathes with; frame 0 whenever anim is off, so anim-off output is
// byte-stable across prints (the ui_anim contract).
func shimmerFrame() int {
	if !UseAnim {
		return 0
	}
	return int(animNow().UnixNano()/int64(400*time.Millisecond)) & 1
}

// scepterStepperStr renders one stepper row: completed phases carry the ramp
// (the update's bright moment), the active phase the spinner with a shimmering
// label, future phases grey; a failed run shows its mark red at the recorded
// start. Deterministic when anim is off (spinner frame 0, shimmer frame 0).
func scepterStepperStr(completed, active int, failed bool, sp *Spinner) string {
	var b strings.Builder
	for i, ph := range scepterStepperPhases {
		if i > 0 {
			b.WriteString(GRY + " ─→ " + RST)
		}
		switch {
		case i < completed:
			t := 0.0
			if len(scepterStepperPhases) > 1 {
				t = float64(i) / float64(len(scepterStepperPhases)-1)
			}
			b.WriteString(GradRGB(t) + BOLD + ph + RST)
		case i == active && failed:
			b.WriteString(RED + "✗ " + ph + RST)
		case i == active:
			pre := CYN + BOLD
			if shimmerFrame() == 1 {
				pre = CYN // the shimmer's dim frame
			}
			b.WriteString(pre + sp.Frame() + " " + ph + RST)
		default:
			b.WriteString(GRY + ph + RST)
		}
	}
	return b.String()
}

// scepterStepBy tweens the displayed completed-count per mailbox run id, so a
// revived update.status eases the stepper to the terminal phase instead of
// teleporting (design-motion: motion follows data). In-memory only, like the
// rotation markers; a manager restart just snaps.
var scepterStepBy = map[string]*Tween{}

// scepterStepperShow prints the stepper for one mailbox record. `live` is the
// update.run path: the job just started, the spinner runs and the caption says
// the channel returns via the latch. Otherwise the recorded phase is shown and
// a terminal `applied` settles its completed count through the per-run tween
// (one short settle burst, ~0.7 s, anim off snaps in one static line).
func scepterStepperShow(key, phase string, live bool) {
	completed, active, failed := scepterMailStepper(phase)
	if live {
		completed, active, failed = 0, 0, false
	}
	tw := scepterStepBy[key]
	if tw == nil {
		tw = NewTween(float64(completed))
		scepterStepBy[key] = tw
	}
	sp := &Spinner{}
	row := func() string {
		c := completed
		if active < 0 && !failed { // terminal: the eased completed count
			c = int(tw.Step(float64(completed)) + 0.5)
		}
		return "  " + scepterStepperStr(c, active, failed, sp)
	}
	if UseAnim && IsTTY && !NonInteractive {
		CurHide()
		for i := 0; i < 5; i++ {
			fmt.Fprintf(Stdout, "\r\x1b[K%s%s", row(), EL)
			time.Sleep(140 * time.Millisecond)
		}
		CurShow()
	}
	fmt.Fprintf(Stdout, "\r\x1b[K%s\n", row())
	if live {
		Hint("the stepper stays: the channel returns via the latch — after the revival,")
		Hint("Update status re-queries and the stepper eases to the terminal phase.")
	}
}

// ---- update.run ----

// scepterUpdateRun: the one CapFull command. The warnings are the contract
// (docs/TECHNICAL.md step 6): the channel drops mid-update and comes back via
// the latch; the outcome survives in the journal + mailbox, so update.status
// after the revival is the way to know. The intent rides scepterRun so a
// transport retry resends the SAME command id — the journal answers
// at-most-once, never a second update.
func scepterUpdateRun(pair string, cl ScepterClient, caps ScepterCaps) {
	if !caps.Has(CapFull) {
		Warn("Running an update needs the 'full' capability on the pairing line.")
		return
	}
	Page("Run update on Kharej", pair+" · update.run")
	GradBand(Stdout, uiW())
	Hint("Kharej downloads the release, verifies the signature, installs the binary")
	Hint("and restarts every unit that was up — the unit carrying this channel too.")
	Hint("A watchdog watches 40 s; a new engine that does not stay up rolls back to")
	Hint("wattun.prev and the units restart on it.")
	fmt.Fprintln(Stdout)
	Warn("The channel WILL drop mid-update. It comes back on its own: the scepter")
	Warn("latch arms while Kharej's units are down and revives the cockpit.")
	Hint("The outcome survives the drop: the answer is journaled. After the revival,")
	Hint("open Update status — the update mailbox carries applied/failed/rolled_back,")
	Hint("and a retried command id replays from the journal (never a second update).")
	fmt.Fprintln(Stdout)
	if !AskOK("Target version (empty = latest release)", "", vScepterTag) {
		return
	}
	to := ReplyV
	fmt.Fprintln(Stdout)
	if !Confirm("Send update.run to Kharej now?", false) { // hard confirm: default no
		Warn("Cancelled.")
		return
	}
	res, ok := scepterRun(cl, "update.run", func(_ uint64, id string) map[string]any {
		return scepterUpdateRunArgs(to, id)
	}, 0)
	if !ok || res.Code != scepterCodeOK {
		return // printed (a transport give-up or a rejection with its hint)
	}
	if b, _ := res.Params["already_running"].(bool); b {
		run, _ := res.Params["run"].(string)
		Warn("A job already owns the swap (run " + orStr(run, "?") + ") — Update status shows its progress.")
		scepterStepperShow(orStr(run, "running"), "started", true)
		return
	}
	run, _ := res.Params["run"].(string)
	toN, _ := res.Params["to"].(string)
	grace := int(scepterU64(res.Params["grace_s"]))
	Ok(fmt.Sprintf("Update accepted — run %s, target %s.", orStr(run, "?"), orStr(toN, "latest")))
	scepterStepperShow(orStr(run, "running"), "started", true)
	Hint(fmt.Sprintf("Nothing moves for %d s; then the channel drops as Kharej's units restart.", grace))
	Hint("Come back via Update status — the mailbox reveals the outcome.")
}

// ---- doctor.fetch ----

func scepterDoctorView(pair string, cl ScepterClient) {
	fmt.Fprintln(Stdout)
	Hint("doctor.fetch — the pair's structured self-report (state, recent commands, ops fragments)")
	GradBand(Stdout, uiW())
	res, ok := scepterActSpin(cl, "doctor.fetch", nil)
	if !ok {
		return
	}
	scepterLearnLatchPort(pair, res.Params)
	rows := scepterRenderRows(res.Params)
	if len(rows) == 0 {
		Warn("doctor.fetch answered nothing.")
		return
	}
	scepterPrintDoctorRows(Stdout, res.Params, rows)
}

// scepterLatchDot renders the doctor's latch fragment as a status dot:
// breathing (green/grey on a ~1.6 s sine — the only live dot on the screen,
// a latch revival is the thing that can happen while you read) while a latch
// refresh is plausible (the fragment says enabled), a static grey dot when
// not. Anim off reads the sine at frame 0, so the dot is static green —
// byte-stable across prints.
func scepterLatchDot(latch map[string]any) string {
	enabled, _ := latch["enabled"].(bool)
	if !enabled {
		return GRY + "●" + RST + " off — no automatic revival from this Kharej"
	}
	dot := GRN + "●" + RST
	if UseAnim {
		// breathing: the sine's sign alternates the brightness every ~800 ms
		if math.Sin(float64(animNow().UnixNano())/float64(800*time.Millisecond)) < 0 {
			dot = GRY + "●" + RST
		}
	}
	return dot + " enabled — a latch refresh can revive the channel"
}

// scepterRowGroup is a row's group key: the path's first segment (the
// document's top-level fragment — latch, recent, update, …); a scalar row
// groups under its own key.
func scepterRowGroup(row string) string {
	if i := strings.IndexAny(row, ".[: "); i > 0 {
		return row[:i]
	}
	return row
}

// scepterPrintDoctorRows prints the flattened rows one group per frame
// (staggered ~80 ms under anim; the document lands as a cascade instead of one
// dump — the groups are the fragments the reader scans by). The latch
// fragment's status dot rides above them. Rows keep their exact flattened
// text; only the pacing and the group label lines are new.
func scepterPrintDoctorRows(w io.Writer, params map[string]any, rows []string) {
	if latch, ok := params["latch"].(map[string]any); ok {
		fmt.Fprintln(w, "  "+KV(11, "Latch", scepterLatchDot(latch)))
	}
	last := ""
	for i, row := range rows {
		g := scepterRowGroup(row)
		if g != last {
			if i > 0 && UseAnim && IsTTY && !NonInteractive {
				time.Sleep(80 * time.Millisecond) // the cascade's frame gap
			}
			if last != "" {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "  %s%s%s\n", BOLD, g, RST)
			last = g
		}
		if j := strings.Index(row, ": "); j > 0 {
			fmt.Fprintf(w, "  %s%s%s %s\n", GRY, row[:j+1], RST, row[j+2:])
			continue
		}
		fmt.Fprintf(w, "  %s\n", row)
	}
}

// scepterLearnLatchPort self-heals the client-side latch-port key from the
// doctor answer (owner directive 2026-11-22: automatic revival needs the port
// on Iran, and Kharej's wizard may have moved off the 20443 default on a port
// collision — the doctor's latch fragment is the authority). A different or
// absent local value is rewritten; a doctor without a latch fragment (older
// engine, latch off) touches nothing.
func scepterLearnLatchPort(pair string, params map[string]any) {
	latch, ok := params["latch"].(map[string]any)
	if !ok || Cfg(pair, "reverse") == "true" { // no latch on reverse (Handoff 4 R6): Kharej's re-dial revives it
		return
	}
	if enabled, _ := latch["enabled"].(bool); !enabled {
		return
	}
	portf, ok := latch["port"].(float64)
	if !ok || portf <= 0 || portf > 65535 {
		return
	}
	port := fmt.Sprintf("%d", int(portf))
	if Cfg(pair, "latch-port") == port {
		return
	}
	if err := SetValue(pair, "latch-port", port); err == nil {
		Ok(fmt.Sprintf("Kharej's backup control port (%s) saved: the Kharej controls reconnect by themselves when the tunnel is down.", port))
	}
}

// ---- backup.export ----

func scepterBackupExport(pair string, cl ScepterClient) {
	Page("Export backup", pair+" · backup.export")
	GradBand(Stdout, uiW())
	Hint("A tarball of Kharej's config dir: ymls, keys, tokens, .bak states, the")
	Hint("pairing store and its audit — what a host rebuild restores from. Keys are")
	Hint("in it on purpose; the command journal is not (machine replay state).")
	Hint("Caps: 4 MB per file, 5 MB total — more is refused with too_large.")
	fmt.Fprintln(Stdout)
	Hint("Kharej is packaging and sending the config dir in chunks — a moment.")
	res, ok := scepterActSpin(cl, "backup.export", nil)
	if !ok {
		return
	}
	docs := scepterLogsOf(res.Params)
	if len(docs) != 1 {
		Warn(fmt.Sprintf("backup.export answered %d document(s), want exactly 1.", len(docs)))
		return
	}
	// The chunk counter and its GradBar fill are honest: n is the number of
	// transport chunks the reassembly actually delivered (the answer's own
	// `chunks` when the engine states it, the delivered document count
	// otherwise), and the fill eases to full as those chunks are counted in.
	chunks := int(scepterU64(res.Params["chunks"]))
	if chunks <= 0 {
		chunks = len(docs)
	}
	scepterChunkMeter(chunks)
	var d scepterBackupDoc
	var raw []byte
	var err error
	scepterShimmer("verifying sha256", func() { d, raw, err = scepterParseBackupDoc(docs[0]) })
	if err != nil {
		Err(err.Error())
		return
	}
	fmt.Fprintln(Stdout)
	def := filepath.Join(P.Conf, fmt.Sprintf("%s-backup-%d.tar", pair, time.Now().Unix()))
	if !AskOK("Save the backup as", def, vScepterBackupPath) {
		return
	}
	path := ReplyV
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		Err("Writing the backup failed: " + err.Error())
		return
	}
	Ok(fmt.Sprintf("Backup saved: %s (%s tar, %d file(s), sha256 verified).", path, Human(float64(len(raw))), d.Files))
}

// scepterChunkMeter tweens the reassembled-chunk counter to n with a GradBar
// fill (n/of): ~0.45 s of settling under anim, nothing at all without it —
// anim-off output keeps its exact byte shape.
func scepterChunkMeter(n int) {
	if !UseAnim || !IsTTY || NonInteractive || n <= 0 {
		return
	}
	f := NewFill(0)
	CurHide()
	for i := 0; i < 5; i++ {
		f.Step(1)
		fmt.Fprintf(Stdout, "\r\x1b[K  %schunks %d/%d%s %s%s", GRY, int(f.Val()*float64(n)+0.5), n, RST,
			GradBar(f.Val(), 1, 24), EL)
		time.Sleep(90 * time.Millisecond)
	}
	CurShow()
	fmt.Fprint(Stdout, "\r\x1b[K")
}

// ---- audit.tail ----

func scepterAuditView(cl ScepterClient) {
	Page("Audit trail", "Kharej · audit.tail")
	GradBand(Stdout, uiW())
	Hint("The last lines of Kharej's two append-only scepter records, raw:")
	Hint("  .pairing.audit   — the local console's credential audit (pair/rotate/revoke)")
	Hint("  .pairing.journal — every cockpit command with its recorded outcome")
	fmt.Fprintln(Stdout)
	if !AskOK("Lines per source (empty = 100, cap 1000)", "", vScepterAuditN) {
		return
	}
	n := ReplyV
	for {
		scepterAuditFetch(cl, n)
		fmt.Fprintln(Stdout)
		MenuLine(Stdout, "r", "refresh", "0", "back")
		fmt.Fprintf(Stdout, "  %s▸%s ", CYN, RST)
		k, _, ok := KeyRead(0)
		if !ok || k == "0" || k == "esc" || k == "q" {
			return
		}
		if k != "r" {
			Hint("Press r or 0.")
		}
	}
}

// scepterAuditFetch runs one audit.tail and prints both sources' raw lines.
// The lines are shown verbatim: the audit's schema is the manager's own, and
// re-encoding here could hide what it records.
func scepterAuditFetch(cl ScepterClient, nStr string) {
	n := 0
	if nStr != "" {
		n = atoi(nStr)
	}
	res, ok := scepterActSpin(cl, "audit.tail", scepterAuditTailArgs(n))
	if !ok {
		return
	}
	docs := scepterLogsOf(res.Params)
	if len(docs) != 2 {
		Warn(fmt.Sprintf("audit.tail answered %d source document(s), want 2 (audit + journal).", len(docs)))
		return
	}
	labels := []string{".pairing.audit", ".pairing.journal"}
	for i, doc := range docs {
		var d struct {
			Src     string   `json:"src"`
			Entries []string `json:"entries"`
		}
		if err := json.Unmarshal([]byte(doc), &d); err != nil {
			Warn(labels[i] + ": unparseable source document: " + err.Error())
			continue
		}
		fmt.Fprintln(Stdout)
		Say("  " + BOLD + orStr(d.Src, labels[i]) + RST + "  " + GRY +
			"(" + strconv.Itoa(len(d.Entries)) + " line(s))" + RST)
		if len(d.Entries) == 0 {
			Say("  " + GRY + "empty (nothing recorded yet, or the file does not exist)" + RST)
		}
		for _, e := range d.Entries {
			Say("  " + GRY + e + RST)
		}
	}
}
