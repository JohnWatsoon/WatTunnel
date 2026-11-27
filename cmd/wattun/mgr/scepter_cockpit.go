// Scepter cockpit screens (3.5.0, plan B.3): the write side of the pairing
// plane on Iran. Three surfaces live here:
//
//   - the fleet view of pairs (scepter-fleet): one row per paired Iran tunnel
//     with the remote state of its Kharej; ScepterFleetEntry is the top-level
//     menu entry the home screen wires;
//   - the pair screen (wattun-manager scepter NAME when paired): the remote
//     tunnel list of that Kharej plus the create wizard;
//   - the remote tunnel pages: state, stats, logs, edit/delete, unit actions —
//     every row and every answer comes from the RPC, never fabricated.
//
// The wizard prompts reuse the phase-A builders (pickCarrier, AskOK, vPort);
// they become intent builders producing a tunnel.create args map. Client-side
// capability gating is UX only — Kharej re-checks every command (D3).
//
// The restyle (UI swarm wave 2) rides the U1 primitives: one GradBand header
// per screen (the screen's one bright moment), Spinner while an RPC is in
// flight, Tween on the state_seq/uptime numbers. Colour off renders the plain
// look byte-for-byte (the primitives' own contract); anim off snaps the numbers.

package mgr

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func init() {
	Register("scepter_fleet", func(args ...string) int {
		return ScepterFleetEntry()
	})
}

// ScepterFleetEntry is the fleet screen as a top-level menu entry: the home
// lane wires its nav to this name via the Register lookup ("scepter_fleet").
func ScepterFleetEntry() int {
	scepterFleet()
	return 0
}

// ======================================================================================
// The state document (state.get): the versioned view Kharej serves; clients
// diff by state_seq, never by wall clock (the plan's state model).
// ======================================================================================

// scepterTunRow is one remote tunnel of the state document's tunnel list.
type scepterTunRow struct {
	Name, Carrier, Ports, State, Health, Metrics string
}

// scepterDoc is the state document's cockpit subset. Fields render as-is;
// absent fields stay zero — nothing is defaulted into looking real.
type scepterDoc struct {
	Ver      string
	StateSeq uint64
	UptimeS  int64
	Cursor   uint64
	PairUUID string
	PairCaps string
	Tunnels  []scepterTunRow
}

// scepterParseDoc parses the state.get params. JSON numbers arrive as
// float64; anything else is not invented around.
func scepterParseDoc(p map[string]any) (scepterDoc, error) {
	var d scepterDoc
	if p == nil {
		return d, fmt.Errorf("empty state document")
	}
	d.Ver, _ = p["ver"].(string)
	d.StateSeq = scepterU64(p["state_seq"])
	d.UptimeS = int64(scepterU64(p["uptime_s"]))
	d.Cursor = scepterU64(p["event_cursor"])
	if pair, ok := p["pair"].(map[string]any); ok {
		d.PairUUID, _ = pair["uuid"].(string)
		d.PairCaps, _ = pair["caps"].(string)
	}
	if list, ok := p["tunnels"].([]any); ok {
		for _, e := range list {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			var r scepterTunRow
			r.Name, _ = m["name"].(string)
			r.Carrier, _ = m["carrier"].(string)
			r.Ports, _ = m["ports"].(string)
			r.State, _ = m["state"].(string)
			r.Health, _ = m["health"].(string)
			r.Metrics, _ = m["metrics"].(string)
			d.Tunnels = append(d.Tunnels, r)
		}
	}
	if d.Ver == "" && d.StateSeq == 0 && len(d.Tunnels) == 0 {
		return d, fmt.Errorf("no state document in the answer")
	}
	return d, nil
}

// scepterU64 reads a JSON number as a uint64 (float64 on the wire; int forms
// are accepted for stub clients).
func scepterU64(v any) uint64 {
	switch n := v.(type) {
	case float64:
		if n > 0 {
			return uint64(n)
		}
	case uint64:
		return n
	case int64:
		if n > 0 {
			return uint64(n)
		}
	case int:
		if n > 0 {
			return uint64(n)
		}
	}
	return 0
}

// scepterFetchDoc runs state.get and parses the document; the error is a
// transport, code or parse failure — never a silent empty success.
func scepterFetchDoc(cl ScepterClient) (scepterDoc, error) {
	res, err := cl.Call("state.get", nil)
	if err != nil {
		return scepterDoc{}, err
	}
	if res.Code != scepterCodeOK {
		return scepterDoc{}, fmt.Errorf("Kharej did not send its state (code %d): %s", res.Code, scepterCodeHint(res.Code, res.Params))
	}
	return scepterParseDoc(res.Params)
}

// scepterCapsOf maps the hello answer's tier name to the local mask (the same
// tierBits the pairing line uses; Kharej's re-check is the real gate).
func scepterCapsOf(hello map[string]any) ScepterCaps {
	tier, _ := hello["caps"].(string)
	if bit, ok := capName[tier]; ok {
		return tierBits(bit)
	}
	return 0
}

// scepterPairCaps resolves the pair screen's local capability mask: Kharej's
// hello answer first; with no hello (dead link, old peer) a token-bootstrap
// pairing falls back to the token's own field-10 tier (owner directive
// 2026-11-22 — the mask never needs the yml pairing key). Client-side UX only:
// Kharej re-checks on every command, so a stale local tier can only ever
// over-offer an item.
func scepterPairCaps(n string, hello map[string]any, helloErr string) ScepterCaps {
	if helloErr == "" {
		return scepterCapsOf(hello)
	}
	return tokenPairCaps(n)
}

// scepterUp renders an uptime in seconds compactly.
func scepterUp(s int64) string {
	switch {
	case s <= 0:
		return "?"
	case s < 120:
		return fmt.Sprintf("%ds", s)
	case s < 7200:
		return fmt.Sprintf("%dm%02ds", s/60, s%60)
	case s < 172800:
		return fmt.Sprintf("%dh%02dm", s/3600, (s%3600)/60)
	default:
		return fmt.Sprintf("%dd%02dh", s/86400, (s%86400)/3600)
	}
}

// scepterRowDesc is the fleet/list description of one remote tunnel.
func scepterRowDesc(r scepterTunRow) string {
	col, dot, txt := scepterStateCell(r)
	parts := []string{orStr(r.Carrier, "?"), col + dot + " " + txt + RST}
	if r.Ports != "" {
		parts = append(parts, r.Ports)
	}
	return strings.Join(parts, " · ")
}

// scepterStateCell maps the state doc's active/inactive + ok/down to the
// manager's state marks (remote words, local look).
func scepterStateCell(r scepterTunRow) (col, dot, txt string) {
	switch {
	case r.State == "active" && r.Health == "ok":
		return GRN, "●", "up"
	case r.State == "active":
		return YEL, "!", "down"
	case r.State == "inactive" || r.State == "":
		return GRY, "◌", "stopped"
	}
	return YEL, "?", strings.TrimSpace(r.State + "/" + r.Health)
}

// ======================================================================================
// Intent plumbing: command ids, the submit loop with the stale retry, and the
// honest outcome printing every screen shares.
// ======================================================================================

// scepterTTLDefault is the plan's intent TTL (600 s), sent explicitly so the
// intent says what it means; the engine defaults to the same value.
const scepterTTLDefault = 600

// scepterIDSeq disambiguates command ids inside one process (nanoseconds can
// repeat on some Windows clocks — the engine's scepterCallSeq lesson).
var scepterIDSeq atomic.Uint64

// scepterPID seams the process id into every command id: two manager
// processes on Windows coarse clocks can mint the same nanosecond, and the
// engine's journal keys outcomes by id — a collision would replay the WRONG
// outcome into the other process. Var so tests can pin the seam.
var scepterPID = os.Getpid()

// scepterNewID mints one command id; retries of the SAME intent reuse it (the
// server journal answers at-most-once), a rebuilt intent gets a fresh one.
func scepterNewID() string {
	return fmt.Sprintf("mgr%d-%d-%d", scepterPID, time.Now().UnixNano(), scepterIDSeq.Add(1))
}

// scepterCall runs one RPC under the spinner (design-motion: motion only while
// something works — a -scepter-call shell-out takes a beat on a live link and
// up to its 65 s deadline on a dying one). Anim off calls straight through, so
// every non-anim path is byte-stable.
func scepterCall(cl ScepterClient, cmd string, args map[string]any) (ScepterResult, error) {
	if !UseAnim {
		return cl.Call(cmd, args)
	}
	type ans struct {
		res ScepterResult
		err error
	}
	ch := make(chan ans, 1)
	go func() {
		r, e := cl.Call(cmd, args)
		ch <- ans{r, e}
	}()
	sp := &Spinner{}
	CurHide()
	defer CurShow()
	for {
		select {
		case a := <-ch:
			fmt.Fprint(Stdout, "\r\x1b[K")
			return a.res, a.err
		case <-time.After(100 * time.Millisecond):
			fmt.Fprintf(Stdout, "\r\x1b[K  %s%s%s %s…", CYN, sp.Frame(), RST, cmd)
		}
	}
}

// scepterRun runs one write intent, argsf(baseSeq, id) building it fresh each
// send. Two retries, one id rule each (plan B: idempotent intents):
//
//   - transport failure: the outcome is unknown, so the SAME id resends and
//     the journal replays a possibly-applied intent instead of re-running it;
//   - code=stale: the intent never applied, so the state is refetched and the
//     retry (new base_seq, fresh id) is offered — the plan's "offer retry with
//     fresh state".
//
// Every answered non-OK code is printed (machine code + hint) before the
// answer is returned; ok=false means no answer arrived.
func scepterRun(cl ScepterClient, cmd string, argsf func(baseSeq uint64, id string) map[string]any, baseSeq uint64) (ScepterResult, bool) {
	id := scepterNewID()
	cur := baseSeq
	for {
		res, err := scepterCall(cl, cmd, argsf(cur, id))
		if err != nil {
			Warn("channel: " + err.Error())
			if !Confirm("No answer from Kharej. Try again (it never runs twice)?", true) {
				return ScepterResult{}, false
			}
			continue // id unchanged: at-most-once
		}
		if res.Code == scepterCodeOK {
			return res, true
		}
		scepterCodeErr(cmd, res)
		if res.Code != scepterCodeStale {
			return res, true
		}
		fresh, derr := scepterFetchDoc(cl)
		if derr != nil {
			Warn("could not refresh the state: " + derr.Error())
			return res, true
		}
		if !Confirm("Kharej changed meanwhile. Try again on its current state?", true) {
			return res, true
		}
		cur, id = fresh.StateSeq, scepterNewID()
	}
}

// scepterAct runs one command that has no base_seq (unit ops, delete) and
// prints the honest outcome; true when Kharej answered OK.
func scepterAct(cl ScepterClient, cmd string, args map[string]any) (ScepterResult, bool) {
	res, err := scepterCall(cl, cmd, args)
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
// The fleet view of pairs (plan B.3): one row per paired Iran tunnel, showing
// the remote state of its Kharej.
// ======================================================================================

// pairedTunnels lists the visible Iran tunnels IsPaired accepts — the fleet
// (`pairing: true` in the yml, or a token-bootstrap pair riding field 10 of
// the tunnel's token; owner directive 2026-11-22). Hidden helpers are never
// pairs (a companion carries no pairing line).
func pairedTunnels() []string {
	var out []string
	for _, n := range ManagedTunnels() {
		if IsPaired(n) {
			out = append(out, n)
		}
	}
	return out
}

// fleetTween carries one pair's animated numbers across refetches (design
// motion: the values settle instead of jumping; anim off snaps — byte-stable).
type fleetTween struct {
	seq, up *Tween
}

func scepterFleet() {
	sel := 0 // outside the redraw loop: the highlight must survive ticks and moves (round-2 finding, 2026-11-22)
	tweens := map[string]*fleetTween{}
	for {
		names := fleetPairs()
		if len(names) == 0 {
			Page("Kharej servers", "none paired yet")
			GradBand(Stdout, uiW())
			fmt.Fprintln(Stdout)
			Hint("On the Kharej server run wattun and press t: it shows the pairing token.")
			if !Confirm("Add a Kharej now?", true) {
				return
			}
			ClearScreen()
			if !addKharejCmd() || len(fleetPairs()) == 0 {
				Pause()
				return
			}
			Pause()
			ClearScreen()
			continue
		}
		live := map[string]bool{}
		for _, n := range names {
			live[n] = true
		}
		for n := range tweens {
			if !live[n] {
				delete(tweens, n)
			}
		}
		type pairRow struct {
			doc scepterDoc
			err string
		}
		rows := make([]pairRow, len(names))
		fetchAll := func() { // one state.get per pair; a pair that cannot answer says so
			for i, n := range names {
				rows[i] = pairRow{}
				cl, err := scepterDial(n)
				if err != nil {
					rows[i].err = err.Error()
					continue
				}
				doc, err := scepterFetchDoc(cl)
				if err != nil {
					rows[i].err = err.Error()
					continue
				}
				rows[i].doc = doc
			}
		}
		items := make([]Item, len(names))
		build := func() {
			for i, r := range rows {
				desc := ""
				if r.err != "" {
					desc = YEL + "unreachable: " + r.err + RST
				} else {
					tw := tweens[names[i]]
					if tw == nil {
						tw = &fleetTween{NewTween(float64(r.doc.StateSeq)), NewTween(float64(r.doc.UptimeS))}
						tweens[names[i]] = tw
					}
					seq := uint64(tw.seq.Step(float64(r.doc.StateSeq)))
					up := int64(tw.up.Step(float64(r.doc.UptimeS)))
					desc = fmt.Sprintf("%s · seq %d · %d tunnel(s) · up %s", r.doc.Ver, seq,
						len(r.doc.Tunnels), scepterUp(up))
				}
				items[i] = Item{Label: pairLabel(names[i]), Desc: desc}
			}
		}
		fetchAll() // fetched on entry and on r — never per tick (the loop used to
		build()    // re-dial every pair every second while idle; round-2 finding)
		head := func(w io.Writer) {
			Title(w, "Kharej servers", fmt.Sprintf("%d paired", len(names)))
			GradBand(w, uiW())
			hintLine(w, "One row per paired Kharej, live.")
			unreach := 0
			for _, r := range rows {
				if r.err != "" {
					unreach++
				}
			}
			if unreach > 0 {
				hintLine(w, fmt.Sprintf("! %d pair(s) unreachable — the row carries the honest why; r retries.", unreach))
			}
			fmt.Fprintln(w)
		}
		for {
			i, k := Choose(head, items, &sel, []string{"⏎", "open", "a", "add Kharej", "x", "remove", "r", "refresh", "esc", "back"}, time.Second)
			switch {
			case i >= 0:
				scepterScreen(names[i])
			case k == "r":
				fetchAll()
				build()
			case k == "a":
				ClearScreen()
				addKharejCmd()
				Pause()
				ClearScreen()
				i = 0 // rebuild the fleet
			case k == "x" && IsLink(names[sel]):
				ClearScreen()
				removeKharejCmd(linkHost(names[sel]))
				Pause()
				ClearScreen()
				i = 0
			case k == "x":
				Flash("This pair is a tunnel of its own: delete it in Tunnels.")
			case k == "eof":
				return
			case k == "tick" || k == "move":
				// idle: redraw the cached rows only — no RPC on a tick
			default:
				return
			}
			if i >= 0 {
				break // the open may have attached, unpaired or moved state: rebuild the fleet
			}
		}
	}
}

// ======================================================================================
// The pair screen: the remote tunnels of one paired tunnel's Kharej, plus the
// create wizard and the pair-level read views.
// ======================================================================================

func scepterPairScreen(n string) {
	cl, err := scepterDial(n)
	if err != nil {
		Page("Kharej server", n)
		GradBand(Stdout, uiW())
		Warn(err.Error())
		Hint("Check the tunnel's link (tunnel page, d), then open this screen again.")
		Pause()
		return
	}
	// One hello per entry: version and capabilities gate the write items
	// (client-side UX; Kharej re-checks). A failed hello keeps the reads.
	helloErr := ""
	var hello map[string]any
	if h, e := cl.Call("scepter.hello", nil); e != nil {
		helloErr = e.Error()
	} else if h.Code != scepterCodeOK {
		helloErr = fmt.Sprintf("Kharej refused this server (code %d)", h.Code)
	} else {
		hello = h.Params
	}
	caps := scepterPairCaps(n, hello, helloErr)
	refetch := func() (scepterDoc, string) {
		doc, err := scepterFetchDoc(cl)
		if err != nil {
			return scepterDoc{}, err.Error()
		}
		return doc, ""
	}
	doc, docErr := refetch()
	sel := 0
	seqTw, upTw := NewTween(float64(doc.StateSeq)), NewTween(float64(doc.UptimeS))
	for {
		items, rows := scepterPairItems(doc, docErr, caps)
		head := func(w io.Writer) {
			seq := uint64(seqTw.Step(float64(doc.StateSeq)))
			up := int64(upTw.Step(float64(doc.UptimeS)))
			scepterPairHead(w, n, doc, docErr, caps, helloErr, seq, up)
		}
		i, k := Choose(head, items, &sel, []string{"⏎", "open", "n", "create", "t", "test",
			"a", "auto", "o", "ops", "r", "refresh", "esc", "back"}, time.Second)
		switch {
		case i >= 0 && i < len(rows): // a remote tunnel row
			scepterTunnelPage(n, cl, caps, rows[i].Name)
			doc, docErr = refetch()
			continue
		case i >= 0:
			k = items[i].Key // an action item: fall into the switch by key
		case k == "tick" || k == "move":
			continue
		case k == "eof":
			return
		}
		switch k {
		case "n":
			if docErr != "" {
				Warn("No state document: " + docErr + " — press r to refresh.")
				Pause()
				continue
			}
			scepterWizardCreate(n, cl, doc)
			doc, docErr = refetch()
		case "t": // plan C.1: the remote carrier test is a pair-level action (it dials Kharej)
			scepterProbeTest(n, cl, caps)
			doc, docErr = refetch()
		case "a": // plan C.2: the fleet auto-test, ranked table, apply a row
			scepterFleetAuto(n, cl, caps, doc)
			doc, docErr = refetch()
		case "o": // plan D: the ops console (update, doctor, backup, audit, diagnostics)
			scepterOpsScreen(n, cl, caps)
			doc, docErr = refetch()
		case "r":
			doc, docErr = refetch()
		case "0", "esc", "q":
			return
		}
	}
}

// scepterPairItems builds the pair screen's list: the remote tunnels first
// (digits 1-9 open them), then the create item and the read views.
func scepterPairItems(doc scepterDoc, docErr string, caps ScepterCaps) ([]Item, []scepterTunRow) {
	var rows []scepterTunRow
	if docErr == "" {
		rows = doc.Tunnels
	}
	items := make([]Item, 0, len(rows)+4)
	for _, r := range rows {
		items = append(items, Item{Label: r.Name, Desc: scepterRowDesc(r)})
	}
	if caps.Has(CapCreate) {
		items = append(items, Item{Key: "n", Label: "New tunnel on Kharej and here", Desc: "makes both sides; no token to copy"})
	}
	if caps.Has(CapManage) {
		items = append(items,
			Item{Key: "t", Label: "Test a carrier", Desc: "open a test port on Kharej, measure it from here, close it"},
			Item{Key: "a", Label: "Find the best carrier", Desc: "rank what passes between this server and Kharej, apply one"},
		)
	}
	// Handoff 4 R7: the raw views (state, recent changes, versions) live under Operations, Diagnostics
	items = append(items, Item{Key: "o", Label: "Operations", Desc: "update, health check, backup, audit, diagnostics"})
	return items, rows
}

func scepterPairHead(w io.Writer, n string, doc scepterDoc, docErr string, caps ScepterCaps, helloErr string, seq uint64, up int64) {
	Title(w, n, "paired Kharej · access: "+orStr(capTier(caps), "none"))
	GradBand(w, uiW())
	if helloErr != "" {
		warnLine(w, "no hello: "+helloErr)
	}
	if docErr != "" {
		warnLine(w, docErr)
		hintLine(w, "Press r to retry the state document, or check the tunnel's link.")
		fmt.Fprintln(w)
		return
	}
	fmt.Fprintln(w, "  "+kv("Kharej", fmt.Sprintf("wattun %s · up %s", orStr(doc.Ver, "?"), scepterUp(up))))
	fmt.Fprintln(w, "  "+kv("Pairing", orStr(doc.PairUUID, "?")+" · "+orStr(doc.PairCaps, "?")))
	if len(doc.Tunnels) == 0 {
		if caps.Has(CapCreate) {
			hintLine(w, "No tunnels on this Kharej yet — pick 'Create a tunnel on Kharej' below.")
		} else {
			hintLine(w, "No tunnels on this Kharej yet; creating one needs the 'create' capability.")
		}
	}
	fmt.Fprintln(w)
}

// ---- the pair-level read views (one fresh RPC each, printed honestly) ----

func scepterStateView(cl ScepterClient) {
	fmt.Fprintln(Stdout)
	Hint("What Kharej reports right now")
	doc, err := scepterFetchDoc(cl)
	if err != nil {
		Warn(err.Error())
		return
	}
	lines := []string{
		KV(12, "Engine", doc.Ver),
		KV(12, "Changes", strconv.FormatUint(doc.StateSeq, 10)),
		KV(12, "Uptime", scepterUp(doc.UptimeS)),
		KV(12, "Pairing", orStr(doc.PairUUID, "?")+" · access "+orStr(doc.PairCaps, "?")),
	}
	for _, r := range doc.Tunnels {
		lines = append(lines, KV(12, "Tunnel", scepterRowDesc(r)))
	}
	Panel(Stdout, "state document", lines...)
}

func scepterHelloView(cl ScepterClient) {
	fmt.Fprintln(Stdout)
	Hint("Kharej's version and what this server may do there")
	res, err := cl.Call("scepter.hello", nil)
	if err != nil {
		Warn("channel: " + err.Error())
		return
	}
	if res.Code != scepterCodeOK {
		scepterCodeErr("scepter.hello", res)
		return
	}
	scepterPrintParams(res.Params)
}

func scepterEventsView(cl ScepterClient, since uint64) {
	fmt.Fprintln(Stdout)
	Hint("What happened on Kharej lately")
	res, err := cl.Call("events.since", map[string]any{"seq": since})
	if err != nil {
		Warn("channel: " + err.Error())
		return
	}
	if res.Code != scepterCodeOK {
		scepterCodeErr("events.since", res)
		return
	}
	events, _ := res.Params["events"].([]any)
	if len(events) == 0 {
		Say("  " + GRY + "no events since " + strconv.FormatUint(since, 10) + RST)
	}
	rows := make([]scepterEvRow, 0, len(events))
	for _, e := range events {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := m["type"].(string)
		rows = append(rows, scepterEvRow{
			seq: scepterU64(m["seq"]), typ: typ,
			ts: int64(scepterU64(m["ts"])), detail: scepterDetailStr(m["detail"]),
		})
	}
	// newest first: the reader cares about what just happened; the engine's
	// ring answers oldest-first
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	scepterTimeline(Stdout, rows)
}

// scepterEvRow is one timeline node: the event's seq, type, timestamp and the
// rendered detail — every field straight from the engine's ring.
type scepterEvRow struct {
	seq    uint64
	typ    string
	ts     int64
	detail string
}

// scepterEvColor pins the timeline's node palette (owner directive
// 2026-11-23): up green, down/deleted red, a carrier rotate saffron, the
// update family cyan, everything else grey — a colour only ever says what the
// event's own type word already says.
func scepterEvColor(typ string) string {
	switch {
	case typ == "tunnel_up" || typ == "scepter_up":
		return GRN
	case typ == "tunnel_down" || typ == "scepter_down" || typ == "tunnel_deleted":
		return RED
	case typ == "carrier_switched":
		return SAF
	case strings.HasPrefix(typ, "update_"):
		return CYN
	}
	return GRY
}

// scepterTimeline renders the events as a vertical timeline: a gradient spine
// down the left (▎, the ramp top at the newest node), one coloured node (●)
// per event, newest at top. Under anim each row drops in staggered (~40 ms,
// capped so a long tail lands within ~0.5 s); anim off and NI print the same
// rows as one static list, byte-stable.
func scepterTimeline(w io.Writer, rows []scepterEvRow) {
	n := len(rows)
	for i, e := range rows {
		if i > 0 && UseAnim && IsTTY && !NonInteractive && i <= 12 {
			time.Sleep(40 * time.Millisecond) // the drop-in stagger, capped
		}
		t := 0.0
		if n > 1 {
			t = float64(i) / float64(n-1)
		}
		line := fmt.Sprintf("%s▎%s %s●%s %s%-6s%s %s", GradRGB(t), RST, scepterEvColor(e.typ),
			RST, GRY, strconv.FormatUint(e.seq, 10), RST, e.typ)
		if e.ts > 0 {
			line += " " + GRY + time.Unix(e.ts, 0).Format("15:04:05") + RST
		}
		if e.detail != "" {
			line += "  " + e.detail
		}
		fmt.Fprintln(w, "  "+line)
	}
}

// scepterDetailStr renders an event's detail map as sorted k=v pairs.
func scepterDetailStr(d any) string {
	m, ok := d.(map[string]any)
	if !ok || len(m) == 0 {
		return ""
	}
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	parts := make([]string, 0, len(ks))
	for _, k := range ks {
		parts = append(parts, k+"="+fmt.Sprintf("%v", m[k]))
	}
	return strings.Join(parts, " ")
}

// ======================================================================================
// The create wizard (plan B.3): the existing prompts become intent builders.
// ======================================================================================

// scepterCreateArgs builds the tunnel.create intent (plan B.1's shape): name,
// carrier, ports, params, base_seq, ttl_s — plus the command id the binary
// lifts for idempotent retries.
func scepterCreateArgs(name, carrier, ports string, params map[string]string, baseSeq uint64, id string) map[string]any {
	args := map[string]any{
		"id": id, "carrier": carrier, "ports": ports,
		"base_seq": baseSeq, "ttl_s": scepterTTLDefault,
	}
	if name != "" {
		args["name"] = name // Kharej suggests one when absent
	}
	if len(params) > 0 {
		args["params"] = params
	}
	return args
}

// scepterRemoteNameSuggest mirrors Kharej's own suggest_name (tunnel,
// tunnel-2, tunnel-3 …) against the state document's tunnel list, so the
// wizard's default is free on Kharej.
func scepterRemoteNameSuggest(rows []scepterTunRow) string {
	taken := map[string]bool{}
	for _, r := range rows {
		taken[r.Name] = true
	}
	for i := 1; i < 1000; i++ {
		n := "tunnel"
		if i > 1 {
			n = fmt.Sprintf("tunnel-%d", i)
		}
		if !taken[n] {
			return n
		}
	}
	return "tunnel"
}

// scepterAskParams prompts for one carrier's params: the listen bind (when the
// carrier binds one), the URL path (http shapes) and the SNI (TLS shapes).
// The wizard uses it for the initial build and after a carrier_needs re-pick —
// a re-pick must rebuild the params for the NEW carrier (a stale path/sni from
// the old shape would land on Kharej verbatim; round-2 finding, 2026-11-22).
// The defaults keep a re-pick continuous: the old listen stays pre-filled, the
// path gets a fresh random and the SNI starts empty. False = the user backed out.
func scepterAskParams(cr, listenDef, pathDef, sniDef string) (map[string]string, bool) {
	params := map[string]string{}
	if carrierWriteListen(cr) && listenDef != "-" { // "-": a reverse tunnel binds nothing on Kharej
		if !AskOK("Listen port on Kharej (empty = carrier default)", listenDef, vPortOpt) {
			return nil, false
		}
		if ReplyV != "" {
			params["listen"] = ":" + ReplyV // all-interfaces bind, the yml's ":PORT" form
		}
	}
	switch cr {
	case "ws", "wss", "h2", "h2c", "grpc":
		if !AskOK("URL path", pathDef, vPath) {
			return nil, false
		}
		params["path"] = ReplyV
	}
	switch cr {
	case "tls", "wss", "h2", "grpc":
		if v := Ask("SNI (empty = none)", sniDef); v != "" {
			params["sni"] = v
		}
	}
	return params, true
}

// scepterCreateParams asks the shape params of a remote create. On a reverse pair (Kharej reaches this server
// only by dialing it, the owner's filtered route) the new tunnel is reverse too: Kharej dials this server's
// address at a port picked here, so the token Kharej answers needs no Kharej address (Handoff 4 R4).
func scepterCreateParams(pair, cr, listenDef string) (map[string]string, bool) {
	if Cfg(pair, "reverse") != "true" {
		return scepterAskParams(cr, listenDef, p2RandPath(), "")
	}
	host := scepterPeerHost(pair)
	if strings.Contains(cr, "+") || !IsRpool(cr) || host == "" {
		Warn("This Kharej reaches this server only in reverse: pick one of tcp, tls, ws, wss, h2, h2c, grpc, udp.")
		return nil, false
	}
	params, ok := scepterAskParams(cr, "-", p2RandPath(), "")
	if !ok {
		return nil, false
	}
	proto := p2Rproto(cr)
	def := 27443
	for def < 65000 && listenBlocked(proto, def) {
		def++
	}
	if !AskOK("Port on this server that Kharej dials", strconv.Itoa(def), vPort) {
		return nil, false
	}
	params["reverse"] = "true"
	params["peer"] = net.JoinHostPort(host, ReplyV)
	return params, true
}

func scepterWizardCreate(n string, cl ScepterClient, base scepterDoc) {
	baseSeq := base.StateSeq
	Page("New tunnel on Kharej and here", n)
	Hint("Kharej checks the request, starts the tunnel and answers; then this server")
	Hint("sets up its own side of the tunnel, with no token to copy.")
	fmt.Fprintln(Stdout)
	name := scepterRemoteNameSuggest(base.Tunnels)
	if !AskOK("Tunnel name", name, vScepterName) {
		return
	}
	name = ReplyV
	head := func(w io.Writer) {
		Title(w, "New tunnel on Kharej and here", n)
	}
	// auto: Kharej opens every carrier it can and this server tests them, the same plan the panel creates; a
	// reverse pair cannot, since Kharej dials one carrier back here
	cr := pickCarrier(Cfg(n, "reverse") != "true", head)
	if cr == "" {
		return
	}
	params := map[string]string{}
	if cr != "auto" {
		var pok bool
		if params, pok = scepterCreateParams(n, cr, ""); !pok {
			return
		}
	}
	// Deliberately not asked here: reverse direction, FEC, bonding and the F19
	// shaped knobs — edit them on the tunnel page (tunnel.edit) once the tunnel
	// exists, like the local advanced menu does.
	fmt.Fprintln(Stdout)
	if !AskOK("Forwarded ports (e.g. 443, 8443:443/udp, 2000-2010)", "", vScepterPorts) {
		return
	}
	pstr := ReplyV
	var sum wizSummary
	sum.add("Name", name+" (on Kharej "+n+")")
	sum.add("Carrier", cr)
	ks := make([]string, 0, len(params))
	for k := range params {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		sum.add(k, params[k])
	}
	sum.add("Ports", pstr)
	Box(Stdout, "Summary", sum...)
	fmt.Fprintln(Stdout)
	if !Confirm("Create it on Kharej now?", true) {
		Warn("Cancelled.")
		return
	}
	for {
		res, ok := scepterRun(cl, "tunnel.create", func(seq uint64, id string) map[string]any {
			return scepterCreateArgs(name, cr, pstr, params, seq, id)
		}, baseSeq)
		if !ok {
			return // transport gave up; nothing decided
		}
		switch res.Code {
		case scepterCodeNameTaken:
			if !AskOK("Tunnel name (that one is taken on Kharej)", scepterRemoteNameSuggest(base.Tunnels), vScepterName) {
				return
			}
			name = ReplyV
			continue
		case scepterCodePortBusy:
			// port_busy is always a BIND port (the intent's params["listen"] or
			// the carrier default — round-2 finding, 2026-11-22): re-ask the
			// LISTEN prompt and rebuild params with the new bind; the forwarded
			// ports (and any shape params) stay. The old re-ask of the ports
			// string resent the same listen and looped forever.
			if !carrierWriteListen(cr) {
				Warn("Kharej's own port for " + cr + " is busy — pick a different carrier or free the port there.")
				return
			}
			if !AskOK("Listen port on Kharej (that one is busy; empty = carrier default)", "", vPortOpt) {
				return
			}
			delete(params, "listen")
			if ReplyV != "" {
				params["listen"] = ":" + ReplyV // all-interfaces bind, the yml's ":PORT" form
			}
			continue
		case scepterCodeCarrierNeeds:
			// rebuild the params for the NEW carrier, keeping only the listen
			// bind if the user re-confirms it — the old shape's path/sni must
			// not ride into a carrier that reads none (round-2 finding)
			ncr := pickCarrier(false, head)
			if ncr == "" {
				return
			}
			np, pok := scepterCreateParams(n, ncr, strings.TrimPrefix(params["listen"], ":"))
			if !pok {
				return
			}
			cr, params = ncr, np
			continue
		case scepterCodeBad:
			// a rejected name or ports string: re-ask whichever it was
			if _, isName := res.Params["name"]; isName {
				if !AskOK("Tunnel name (Kharej refused it)", name, vScepterName) {
					return
				}
				name = ReplyV
				continue
			}
			if _, isPorts := res.Params["ports"]; isPorts {
				if !AskOK("Ports (Kharej refused them)", pstr, vScepterPorts) {
					return
				}
				pstr = ReplyV
				continue
			}
			return // a refused param key: the hint already said which
		}
		// an answered code the wizard does not recover from (denied, rate,
		// internal…) was printed by scepterRun with its code and hint — it
		// must never fall through to the "created" line (round-3 finding:
		// the same gate the key menu, ports and preset paths got)
		if res.Code != scepterCodeOK {
			return
		}
		scepterShowCreated(n, res.Params, params)
		return
	}
}

// scepterShowCreated reports a created tunnel and sets up its Iran side on
// this server (Handoff 4 R4): the token goes straight into the Iran wizard,
// and is printed only when the user asks for it (to set the Iran side up on
// another server) or when this server cannot build one.
func scepterShowCreated(pair string, p map[string]any, params map[string]string) {
	name, _ := p["name"].(string)
	Ok("Tunnel '" + orStr(name, "?") + "' created on Kharej.")
	if c, _ := p["carrier"].(string); c != "" {
		Say("  " + kv("Carrier", c))
	}
	if _, moved := p["state"]; moved {
		Hint("Kharej changed while the tunnel was being made; press r to refresh.")
	}
	tok := scepterCreatedToken(pair, p, params)
	if tok == "" {
		Warn("This server cannot build the Iran side by itself (no single carrier port, or no Kharej address).")
		Hint("Take the token from Kharej's console (Tunnels, show token) and paste it in New tunnel.")
		return
	}
	fmt.Fprintln(Stdout)
	if Confirm("Set up this tunnel's Iran side on this server now?", true) {
		local := name
		if local == "" || fileExists(filepath.Join(P.Conf, local+".yml")) {
			local = suggestName("iran")
		}
		if wizardIranWith(tok, local) {
			return
		}
		Warn("The Iran side was not set up.")
	}
	if Confirm("Show the token (to set the Iran side up on another server)?", false) {
		scepterShowToken(tok)
	}
}

// scepterCreatedToken is the Iran token of a created tunnel: Kharej's own
// when it knew its public address, else built here from this pair's Kharej
// host, the carrier port Kharej bound and the shape params. "" when it
// cannot be built (a bond's several ports, no host, an older Kharej).
func scepterCreatedToken(pair string, p map[string]any, params map[string]string) string {
	if tok, _ := p["token"].(string); tok != "" {
		return tok
	}
	host := scepterPeerHost(pair)
	if Cfg(pair, "reverse") == "true" {
		host = "" // a reverse pair's peer is this server's own address, not Kharej's
	}
	cr, _ := p["carrier"].(string)
	key, _ := p["key"].(string)
	if host == "" || cr == "" || key == "" {
		return ""
	}
	peer := host
	if port, ok := p["listen_port"].(float64); ok && port > 0 {
		peer = net.JoinHostPort(host, strconv.Itoa(int(port)))
	} else if carrierWriteListen(cr) {
		return ""
	}
	allow, _ := p["allow"].(string)
	return MakeToken(cr, peer, key, params["path"], params["sni"], "", allow, "", "")
}

// ======================================================================================
// The remote tunnel page: one tunnel of the paired Kharej.
// ======================================================================================

func scepterTunnelPage(pair string, cl ScepterClient, caps ScepterCaps, name string) {
	sel := 0
	var row scepterTunRow
	var cursor uint64
	var stateSeq uint64
	gone := func() bool {
		Page("Kharej server", pair)
		Warn("Tunnel '" + name + "' is no longer in the state document (deleted on Kharej?).")
		Pause()
		return false
	}
	refresh := func() bool { // one state.get per action, never per tick
		doc, err := scepterFetchDoc(cl)
		if err != nil {
			Page("Kharej server", pair)
			Warn(err.Error())
			Pause()
			return false
		}
		cursor = doc.Cursor
		stateSeq = doc.StateSeq
		for _, r := range doc.Tunnels {
			if r.Name == name {
				row = r
				return true
			}
		}
		return gone()
	}
	if !refresh() {
		return
	}
	curTw := NewTween(float64(cursor)) // the cursor settles across refreshes (anim off snaps)
	for {
		items := scepterTunnelItems(row, caps)
		head := func(w io.Writer) {
			scepterTunnelHead(w, pair, row, uint64(curTw.Step(float64(cursor))), caps)
		}
		i, k := Choose(head, items, &sel, []string{"⏎", "run", "s", "stats", "l", "logs",
			"c", "carrier", "u", "up/down", "esc", "back"}, time.Second)
		switch {
		case i >= 0:
			k = items[i].Key
		case k == "tick" || k == "move":
			continue
		case k == "eof":
			return
		}
		ran := true
		switch k {
		case "s":
			scepterTunnelStats(cl, name)
			Pause()
		case "l":
			scepterTunnelLogs(cl, name)
			Pause()
		case "c": // plan C.1: carrier.change on Kharej, then the local follow
			ran = scepterRemoteCarrierChange(pair, cl, caps, name, stateSeq)
			Pause()
		case "p":
			// base_seq is the STATE version the intent is built on, never the
			// event cursor (round-2 finding, 2026-11-22: the cursor moves on
			// every event, so a cursor-built intent answered stale each time)
			ran = scepterRemotePorts(cl, name, row.Ports, stateSeq)
		case "k":
			ran = scepterRemoteKeyMenu(pair, cl, name, row, stateSeq)
		case "z":
			ran = scepterRemotePreset(cl, name, stateSeq)
		case "q":
			ran = scepterRemoteLimits(cl, name)
		case "f":
			ran = scepterRemoteLimitsReset(cl, name)
		case "m":
			ran = scepterRemoteMute(cl, name, row)
		case "t":
			ran = scepterRemoteKeyrotate(pair, cl, name, stateSeq)
		case "r":
			ran = scepterRemoteUnit(cl, name, "restart")
		case "u":
			action := "start"
			if row.State == "active" {
				action = "stop"
			}
			ran = scepterRemoteUnit(cl, name, action)
		case "d":
			if scepterRemoteDelete(cl, name) {
				return // the page's subject is gone
			}
			ran = false
		case "0", "esc":
			return
		default:
			ran = false
		}
		if ran && !refresh() {
			return
		}
	}
}

// scepterTunnelItems: the actions of one remote tunnel. Reads need the manage
// tier (D4: manage covers stats/logs), so a tunnel-only credential sees an
// empty list and the head's hint says why. carrier.mute belongs to bonded
// tunnels only (a lone carrier is the tunnel).
func scepterTunnelItems(row scepterTunRow, caps ScepterCaps) []Item {
	if !caps.Has(CapManage) {
		return nil
	}
	run := "Start"
	if row.State == "active" {
		run = "Stop"
	}
	items := []Item{
		{Key: "s", Label: "Stats", Desc: "live /stats numbers of the remote unit"},
		{Key: "l", Label: "Logs", Desc: "the tunnel's last log lines on Kharej"},
		{Key: "c", Label: "Carrier", Desc: "switch it on both sides (rolls back if the link fails)"},
		{Key: "p", Label: "Ports", Desc: "edit the forwarded ports (restarts the unit)"},
		{Key: "k", Label: "Config keys", Desc: "per-key prompts for the common keys (restarts the unit)"},
		{Key: "z", Label: "Preset", Desc: "pick a ready-made setting (rolls back on failure)"},
		{Key: "q", Label: "Limits", Desc: "per-port rate and quota (hot-reloads, no restart)"},
		{Key: "f", Label: "Reset quotas", Desc: "the usage counters restart at 0"},
	}
	if strings.Contains(row.Carrier, "+") {
		items = append(items, Item{Key: "m", Label: "Mute a carrier",
			Desc: "drop one leg of this bond (or bring it back)"})
	}
	items = append(items,
		Item{Key: "t", Label: "Rotate key", Desc: "new key on Kharej; this server switches to it by itself"},
		Item{Key: "r", Label: "Restart", Desc: "restart the remote unit (drops connections)"},
		Item{Key: "u", Label: run, Desc: "start or stop the remote unit"},
		Item{Key: "d", Label: RED + "Delete" + RST, Desc: "stop it; files move to .bak on Kharej (types the name)"},
	)
	return items
}

func scepterTunnelHead(w io.Writer, pair string, row scepterTunRow, cursor uint64, caps ScepterCaps) {
	col, dot, txt := scepterStateCell(row)
	Title(w, row.Name, "on Kharej "+pair+"  "+col+dot+" "+txt+RST)
	GradBand(w, uiW())
	fmt.Fprintln(w, "  "+kv("Carrier", orStr(row.Carrier, "?")))
	if row.Ports != "" {
		fmt.Fprintln(w, "  "+kv("Ports", row.Ports))
	}
	if row.Metrics != "" {
		fmt.Fprintln(w, "  "+kv("Metrics", row.Metrics+" (on Kharej)"))
	}
	if !caps.Has(CapManage) {
		// scepterTunnelItems returned an empty action list for this tier; say why
		// instead of stranding the reader on a headless page.
		hintLine(w, "Stats, logs and edits need the 'manage' capability on the pairing line.")
	}
	fmt.Fprintln(w)
}

// ---- the tunnel actions ----

// scepterStatRow is one formatted tunnel.stats row; unknown keys print raw
// below them, so nothing the engine answers is hidden.
var scepterStatRows = []struct {
	key, lab string
	fmt      func(any) string
}{
	{"alive", "Alive", scepterFmtBool},
	{"streams", "Streams", scepterFmtInt},
	{"rate_bps", "Rate", func(v any) string { return Rate(scepterF64(v)) }},
	{"srtt_ms", "SRTT", scepterFmtMs},
	{"min_rtt_ms", "Min RTT", scepterFmtMs},
	{"loss_pct", "Loss", scepterFmtPct},
	{"bytes_in", "In", func(v any) string { return Human(scepterF64(v)) }},
	{"bytes_out", "Out", func(v any) string { return Human(scepterF64(v)) }},
	{"retrans", "Retrans", scepterFmtInt},
	{"pkts_in", "Pkts in", scepterFmtInt},
	{"pkts_out", "Pkts out", scepterFmtInt},
}

func scepterF64(v any) float64 {
	if n, ok := v.(float64); ok {
		return n
	}
	return 0
}

func scepterFmtBool(v any) string {
	b, _ := v.(bool)
	if b {
		return "yes"
	}
	return "no"
}

func scepterFmtInt(v any) string {
	if f, ok := v.(float64); ok {
		return strconv.FormatInt(int64(f), 10)
	}
	return fmt.Sprintf("%v", v)
}

func scepterFmtMs(v any) string {
	return fmt.Sprintf("%.1f ms", scepterF64(v))
}

func scepterFmtPct(v any) string {
	return fmt.Sprintf("%.1f %%", scepterF64(v))
}

// scepterStatSample is one Stats view's honest readings: the engine's own
// rate_bps and srtt_ms counters as answered (each sample is one real RPC
// reading, never smoothed or fabricated — the monitor's chartSample rule).
type scepterStatSample struct {
	T          time.Time
	Rate, RTTT float64
}

// scepterStatHist is the per-tunnel ring behind the mini chart (the monitor's
// chartHist pattern, separate so the two never alias). Built only from Stats
// views: repeated views are the sampling.
var scepterStatHist = map[string][]scepterStatSample{}

// scepterStatCap bounds the ring: 120 Stats views per tunnel, in-memory only.
const scepterStatCap = 120

func scepterStatPush(name string, at time.Time, rate, rtt float64) {
	s := append(scepterStatHist[name], scepterStatSample{T: at, Rate: rate, RTTT: rtt})
	if len(s) > scepterStatCap {
		s = s[len(s)-scepterStatCap:]
	}
	scepterStatHist[name] = s
}

// scepterMiniChart renders the compact two-row rate history of one remote
// tunnel under its stats: one braille row of rate_bps (the ramp; cyan at
// tier 8), one thin grey srtt trace — the monitor's RateChart in miniature.
// Honesty rule: fewer than two samples prints the placeholder, never an
// invented shape.
func scepterMiniChart(w io.Writer, name string) {
	s := scepterStatHist[name]
	if len(s) < 2 {
		fmt.Fprintf(w, "  %sno rate history yet (%d/2 stats views) — the mini chart builds from repeated Stats reads%s\n",
			GRY, len(s), RST)
		return
	}
	cols := uiW() - 8
	if cols < 8 {
		cols = 8
	}
	show := len(s)
	if show > cols*2 {
		show = cols * 2
	}
	rates := make([]float64, show)
	rtts := make([]float64, show)
	for i := 0; i < show; i++ {
		rates[i], rtts[i] = s[len(s)-show+i].Rate, s[len(s)-show+i].RTTT
	}
	rmax, rttmax := chartMax(rates), chartMax(rtts)
	if rmax <= 0 {
		rmax = 1 // all-flat honest baseline
	}
	if rttmax <= 0 {
		rttmax = 1
	}
	for _, row := range brailleGrid(rates, rmax, 1, true) {
		paintChartGrid(w, "  rate ", string(row), false)
	}
	for _, row := range brailleGrid(rtts, rttmax, 1, false) {
		if ColorTier == 0 {
			fmt.Fprintf(w, "  rtt  %s\n", string(row))
		} else {
			fmt.Fprintf(w, "  %srtt  %s%s\n", GRY, string(row), RST)
		}
	}
	last := s[len(s)-1]
	fmt.Fprintf(w, "  %snow %s/s · srtt %.0f ms · avg %s/s over %d view(s)%s\n",
		GRY, Rate(last.Rate), last.RTTT, Rate(chartMean(rates)), show, RST)
}

func scepterTunnelStats(cl ScepterClient, name string) {
	fmt.Fprintln(Stdout)
	Hint("Live numbers of the tunnel on Kharej")
	res, ok := scepterAct(cl, "tunnel.stats", map[string]any{"name": name})
	if !ok {
		return
	}
	seen := map[string]bool{}
	for _, r := range scepterStatRows {
		if v, present := res.Params[r.key]; present {
			Say("  " + kv(r.lab, r.fmt(v)))
			seen[r.key] = true
		}
	}
	ks := make([]string, 0, len(res.Params))
	for k := range res.Params {
		if !seen[k] {
			ks = append(ks, k)
		}
	}
	sort.Strings(ks)
	for _, k := range ks {
		Say("  " + kv(k, fmt.Sprintf("%v", res.Params[k])))
	}
	// the mini chart's ring only grows on answers that actually carry the
	// rate counter — a rateless answer must not fabricate a zero sample
	if _, present := res.Params["rate_bps"]; present {
		scepterStatPush(name, time.Now(), scepterF64(res.Params["rate_bps"]), scepterF64(res.Params["srtt_ms"]))
	}
	fmt.Fprintln(Stdout)
	scepterMiniChart(Stdout, name)
}

// scepterTunnelLogs prints the chunked log tail. The engine caps tail at 1000;
// the screen clamps the DRAW to the last 40 lines so a full tail stays one
// page, and says how many were cut.
func scepterTunnelLogs(cl ScepterClient, name string) {
	fmt.Fprintln(Stdout)
	Hint("The tunnel's last log lines on Kharej")
	res, ok := scepterAct(cl, "tunnel.logs", map[string]any{"name": name, "tail": 100})
	if !ok {
		return
	}
	lines, _ := res.Params["logs"].([]any)
	vals := make([]string, 0, len(lines))
	for _, l := range lines {
		if s, ok := l.(string); ok {
			vals = append(vals, s)
		}
	}
	const show = 40
	cut := 0
	if len(vals) > show {
		cut = len(vals) - show
		vals = vals[cut:]
	}
	for _, l := range vals {
		Say("  " + GRY + l + RST)
	}
	if cut > 0 {
		Hint(fmt.Sprintf("%d older line(s) not shown.", cut))
	}
}

func scepterRemotePorts(cl ScepterClient, name, cur string, baseSeq uint64) bool {
	Page("Remote ports", name)
	GradBand(Stdout, uiW())
	Hint("The forwarded ports (the ports: allowlist). Kharej restarts the unit to")
	Hint("apply; the previous config stays as NAME.yml.bak there.")
	fmt.Fprintln(Stdout)
	if !AskOK("Ports (e.g. 443, 8443:443/udp, 2000-2010)", cur, vScepterPorts) {
		return false
	}
	pstr := ReplyV
	fmt.Fprintln(Stdout)
	res, ok := scepterRun(cl, "tunnel.edit", func(seq uint64, id string) map[string]any {
		return map[string]any{"id": id, "name": name, "ports": pstr,
			"base_seq": seq, "ttl_s": scepterTTLDefault}
	}, baseSeq)
	// only an OK gets the success line — an answered rejection was printed by
	// scepterRun with its code and hint (round-3 finding)
	if ok && res.Code == scepterCodeOK {
		Ok("Ports applied on Kharej.")
	}
	Pause()
	return ok
}

// ======================================================================================
// The remote config-key menu (wave-2 upgrade of the raw "set/drop one key"
// flow): the local Advanced / Anti-censor rows rebuilt as tunnel.edit intents
// — the same validators, the same unset words, the same pickers. The channel
// cannot read the remote values (no config-read command in the RPC), so every
// prompt starts at the engine's default and an unset word drops the key;
// Kharej's apply-or-rollback is the real gate (D3).
// ======================================================================================

// scepterKeyPatch is one key row's outcome: what tunnel.edit sets and drops.
type scepterKeyPatch struct {
	set  map[string]string
	drop []string
}

// scepterKeyRow is one row of the remote key menu. ask == nil is a grey row:
// the management RPC has no command for it yet.
type scepterKeyRow struct {
	hk, key, label, hint string
	ask                  func(car string) (scepterKeyPatch, bool)
}

// scepterKeyAskSet is the common prompt: one value, validator v; an unset word
// (empty, -, 0, default — whatever the validator accepted) drops the key.
func scepterKeyAskSet(key, label string, v func(string) bool) (scepterKeyPatch, bool) {
	if !AskOK(label+" (empty or - = the engine's default)", "", v) {
		return scepterKeyPatch{}, false
	}
	if unsetWord(ReplyV) {
		return scepterKeyPatch{drop: []string{key}}, true
	}
	return scepterKeyPatch{set: map[string]string{key: ReplyV}}, true
}

// scepterKeyAskOnOff is the toggle prompt the local pages flip: on sets
// "true", off drops the key (the engine default).
func scepterKeyAskOnOff(key, label, sub string) (scepterKeyPatch, bool) {
	v := pickValue(label, sub, []acOpt{{"on", ""}, {"off", "the engine default"}}, "", "", "", nil)
	switch v {
	case "":
		return scepterKeyPatch{}, false
	case "off":
		return scepterKeyPatch{drop: []string{key}}, true
	}
	return scepterKeyPatch{set: map[string]string{key: "true"}}, true
}

// scepterTwinReverse reports whether the remote tunnel's local twin runs
// reverse. The state document's row carries no direction flag, so reverse is
// detected from the local twin (the scepterFollowLocal identification: same
// name, this server, dialing the pair's host); with no twin the direct
// validators run — Kharej's own re-check is the real gate. The validators
// need it because the engine refuses sessions > 1 and the sum/seqsum fake
// modes on a reverse tunnel: offering them only buys an apply-rollback.
func scepterTwinReverse(pair, name string) bool {
	host := scepterPeerHost(pair)
	if host == "" || !fileExists(filepath.Join(P.Conf, name+".yml")) || Role(name) != "Iran" ||
		scepterPeerHost(name) != host {
		return false
	}
	return IsReverse(name)
}

// scepterFakeModes is the remote desync-mode picker's list. On a reverse
// tunnel the engine refuses sum and seqsum (checksum markers can kill the
// flow — the local page's rule, anticensor.go), so they are omitted instead
// of offered as a guaranteed rollback.
func scepterFakeModes(rev bool) []acOpt {
	var opts []acOpt
	for _, m := range strings.Fields(acAllModes) {
		if rev && (m == "sum" || m == "seqsum") {
			continue
		}
		opts = append(opts, acOpt{m, fakeModeDesc(m)})
	}
	return opts
}

// scepterKeyRows: the menu, grouped Performance, Shaping & DPI, Safety, State —
// the Advanced page's groups. The fake-* and dialer keys act when the remote
// tunnel dials (reverse); allow-clients/bind when it listens. rev is the local
// twin's direction (scepterTwinReverse).
func scepterKeyRows(car string, rev bool) []scepterKeyRow {
	return []scepterKeyRow{
		{"m", "max-mbps", "Speed limit", "MB/s per direction, per session", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("max-mbps", "Speed ceiling in MB/s", vMbpsAdv)
		}},
		{"s", "sessions", "Sessions", "1-16 (one udp/tcp/tls/ws/h2/h2c/grpc carrier, no reverse)", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("sessions", fmt.Sprintf("Sessions 1-%d", engMaxSessions),
				func(s string) bool { return vSessions(s, car, rev) })
		}},
		{"c", "conns", "Conns", "1-64 per pool", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("conns", fmt.Sprintf("Conns 1-%d", engMaxConns), vConns)
		}},
		{"u", "mtu", "MTU", "256 to the carrier's max", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("mtu", fmt.Sprintf("MTU %d-%d for '%s'", engMTUMin, mtuMaxFor(car), car),
				func(s string) bool { return vMTU(s, car) })
		}},
		{"b", "batch", "Batching", "recvmmsg/sendmmsg, icmp/udp (on, off, default)", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("batch", "Batching (on, off, default)", func(s string) bool {
				if s == "on" || s == "off" || s == "default" || s == "-" || s == "" {
					return true
				}
				Err("Use on, off or default.")
				return false
			})
		}},
		{"e", "win-max", "Window max", "per-stream receive window cap, MB (4-64; empty = auto)", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("win-max", "Stream receive window cap in MB (4-64)", vWinMax)
		}},
		{"h", "udp-hop", "UDP hop", "new UDP source port every N packets (2-1000; empty = off)", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("udp-hop", "Packets per source port", vUDPHop)
		}},
		{"L", "loss-ceiling", "Loss ceiling", "also cuts the rate on loss spikes (default: delay only)", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskOnOff("loss-ceiling", "Loss ceiling", "")
		}},
		{"f", "fec", "FEC", "adaptive XOR parity (off, auto)", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("fec", "FEC: off or auto", vFec)
		}},
		{"o", "fec-on-loss", "FEC on loss", "% above which parity starts (remote default off-loss 0.5)", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("fec-on-loss", "FEC on-loss percent (above 0.5%)",
				func(s string) bool { return vFecOn(s, 0.5) })
		}},
		{"x", "fec-off-loss", "FEC off loss", "% below which parity stops (remote default on-loss 2)", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("fec-off-loss", "FEC off-loss percent (below 2%)",
				func(s string) bool { return vFecOff(s, 2) })
		}},
		{"p", "shape-data", "Shape data", "pad stream packets, 0-25 % of stream bytes", func(string) (scepterKeyPatch, bool) {
			if !AskOK("shape-data percent (0..25; empty = off)", "", vShapeData) {
				return scepterKeyPatch{}, false
			}
			if unsetWord(ReplyV) || ReplyV == "0.0" {
				return scepterKeyPatch{drop: []string{"shape-data"}}, true
			}
			return scepterKeyPatch{set: map[string]string{"shape-data": ReplyV}}, true
		}},
		{"n", "noise", "Noise", "idle filler: off, low, med, custom", func(string) (scepterKeyPatch, bool) {
			m := pickValue("Idle noise", "per session", []acOpt{{"off", ""}, {"low", "~11 MB a day"},
				{"med", "~88 MB a day"}, {"custom", "set bytes per second"}}, "", "", "", nil)
			switch m {
			case "":
				return scepterKeyPatch{}, false
			case "off":
				return scepterKeyPatch{drop: []string{"noise", "noise-bps"}}, true
			case "low", "med":
				return scepterKeyPatch{set: map[string]string{"noise": m}, drop: []string{"noise-bps"}}, true
			}
			if !AskOK("Noise filler bytes/second (64..1000000)", "1024", vNoiseBps) {
				return scepterKeyPatch{}, false
			}
			return scepterKeyPatch{set: map[string]string{"noise": "custom", "noise-bps": ReplyV}}, true
		}},
		{"B", "noise-bps", "Noise B/s", "custom filler budget, 64..1000000 bytes/second", func(string) (scepterKeyPatch, bool) {
			if !AskOK("Noise filler bytes/second (64..1000000)", "", vNoiseBps) {
				return scepterKeyPatch{}, false
			}
			return scepterKeyPatch{set: map[string]string{"noise-bps": ReplyV, "noise": "custom"}}, true
		}},
		{"w", "noise-window", "Noise window", "local-clock HH:MM-HH:MM (empty = all day)", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("noise-window", "Noise window HH:MM-HH:MM", vNoiseWindow)
		}},
		{"1", "fake-sni", "Fake SNI", "decoy TLS hello the filter allows (dialer side)", func(string) (scepterKeyPatch, bool) {
			v := pickSNIPreset("mci.ir")
			switch v {
			case "":
				return scepterKeyPatch{}, false
			case "off", "0":
				return scepterKeyPatch{drop: []string{"fake-sni", "fake-mode", "fake-ttl"}}, true
			}
			// the remote fake-mode stays whatever it is (the engine defaults to
			// seq); desync itself is tuned on the next two rows
			return scepterKeyPatch{set: map[string]string{"fake-sni": v}}, true
		}},
		{"2", "fake-mode", "Desync mode", "how the decoy hello is made unusable (sum/seqsum never on reverse)", func(string) (scepterKeyPatch, bool) {
			v := pickValue("Desync mode", "how the decoy hello is made unusable for the real server",
				scepterFakeModes(rev), "seq", "NI_FAKEMODE", "", nil)
			if v != "" && !vFakeMode(v) {
				return scepterKeyPatch{}, false
			}
			if v == "" {
				return scepterKeyPatch{}, false
			}
			p := scepterKeyPatch{set: map[string]string{"fake-mode": v}}
			if v != "ttl" {
				p.drop = []string{"fake-ttl"} // the local page drops it with the mode
			}
			return p, true
		}},
		{"3", "fake-ttl", "Fake TTL", "hop count for the ttl desync mode (1-255; empty = calibrate)", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskSet("fake-ttl", "Fake TTL (hop count)", vFakeTTL)
		}},
		{"g", "governor", "Governor", "hold ICMP volume under the path's reroute ceiling", func(string) (scepterKeyPatch, bool) {
			return scepterKeyAskOnOff("governor", "Governor", "")
		}},
		{"4", "ech", "ECH", "Encrypted Client Hello (dialer, tls/wss/h2/grpc)", func(string) (scepterKeyPatch, bool) {
			v := pickEch("ladder")
			switch v {
			case "":
				return scepterKeyPatch{}, false
			case "off":
				return scepterKeyPatch{drop: []string{"ech"}}, true
			}
			return scepterKeyPatch{set: map[string]string{"ech": v}}, true
		}},
		{"5", "dns-listen", "DNS forwarder", "answers DNS through the tunnel (dialer side)", func(string) (scepterKeyPatch, bool) {
			v := pickDNSListen("off")
			switch v {
			case "":
				return scepterKeyPatch{}, false
			case "off", "0":
				return scepterKeyPatch{drop: []string{"dns-listen"}}, true
			}
			return scepterKeyPatch{set: map[string]string{"dns-listen": v}}, true
		}},
		{"6", "src-ip", "Source IP", "outbound source address (dialer side; typed — Kharej's NICs are not visible here)", func(string) (scepterKeyPatch, bool) {
			if !AskOK("Source IPv4/IPv6 (off = the route picks)", "", vSrcIP) {
				return scepterKeyPatch{}, false
			}
			switch strings.ToLower(ReplyV) {
			case "", "0", "off":
				return scepterKeyPatch{drop: []string{"src-ip"}}, true
			}
			return scepterKeyPatch{set: map[string]string{"src-ip": ReplyV}}, true
		}},
		{"a", "allow-clients", "Allow clients", "source IPs/CIDRs that may open a session (empty = any)", func(string) (scepterKeyPatch, bool) {
			if allowClientsCDNRisk(car, "") {
				Hint("Behind a CDN the source is the proxy: this list cannot match; skip it.")
			}
			return scepterKeyAskSet("allow-clients", "Allowed client addresses/CIDRs", vAllowClients)
		}},
		{"d", "bind", "Bind", "the address the remote listener binds (empty = 0.0.0.0)", func(string) (scepterKeyPatch, bool) {
			if !AskOK("Bind address", "", vBind) {
				return scepterKeyPatch{}, false
			}
			if ReplyV == "0.0.0.0" {
				return scepterKeyPatch{drop: []string{"bind"}}, true
			}
			return scepterKeyPatch{set: map[string]string{"bind": ReplyV}}, true
		}},
		{"v", "state-save", "State save", "seconds between quota/total saves (0 = shutdown only)", func(string) (scepterKeyPatch, bool) {
			// "0" is a real value here (save on shutdown only), not an unset
			// word — the local Advanced page excludes it from the unset words
			// the same way (advanced.go's state-save row, round-3 finding:
			// scepterKeyAskSet's unsetWord would drop it instead)
			if !AskOK("State save interval in seconds (0 = shutdown only)", "", vStateSave) {
				return scepterKeyPatch{}, false
			}
			if ReplyV == "" || ReplyV == "-" || ReplyV == "default" {
				return scepterKeyPatch{drop: []string{"state-save"}}, true
			}
			return scepterKeyPatch{set: map[string]string{"state-save": ReplyV}}, true
		}},
		{"7", "state-dir", "State dir", "where the remote unit keeps its state files", nil},
		{"8", "port-offset", "Port offset", "adds to every client listen port (0 = off)", func(string) (scepterKeyPatch, bool) {
			// a plain flag: the standard prompt sets it, like "Other key" could
			// already — the row only lied about needing a future command
			// (round-3 finding)
			return scepterKeyAskSet("port-offset", "Port offset in whole ports (0 = off)", func(s string) bool {
				if unsetWord(s) || intIn(s, 0, 65535) {
					return true
				}
				Err("Enter the port offset as a whole number, at most 65535 (0 = off).")
				return false
			})
		}},
		{"*", "", "Other key", "set or drop any one config key the menu does not list", func(string) (scepterKeyPatch, bool) {
			if !AskOK("Config key (a flag name, e.g. tcp-mimic)", "", vScepterKey) {
				return scepterKeyPatch{}, false
			}
			key := ReplyV
			if !AskOK("Value for "+key+" (empty or - = drop the key)", "", func(s string) bool {
				if s == "" || s == "-" {
					return true
				}
				return vScepterValue(s)
			}) {
				return scepterKeyPatch{}, false
			}
			if unsetWord(ReplyV) {
				return scepterKeyPatch{drop: []string{key}}, true
			}
			return scepterKeyPatch{set: map[string]string{key: ReplyV}}, true
		}},
	}
}

// scepterEditArgs builds tunnel.edit {id, name, set?, drop?, base_seq, ttl_s}.
func scepterEditArgs(name string, patch scepterKeyPatch, baseSeq uint64, id string) map[string]any {
	args := map[string]any{"id": id, "name": name, "base_seq": baseSeq, "ttl_s": scepterTTLDefault}
	if len(patch.set) > 0 {
		args["set"] = patch.set
	}
	if len(patch.drop) > 0 {
		args["drop"] = patch.drop
	}
	return args
}

// scepterRemoteKeyMenu is the remote tunnel page's per-key config menu
// (the tunnel page's "k"). One edit per pick; the menu stays open, and a
// successful edit refetches the state so the next intent is built on the new
// seq instead of answering stale.
// scepterOffDesc renders a disabled row's grey caption with a one-time grey
// pulse: for the first ~600 ms of the menu's life the caption's brightness
// toggles with the shimmer frames (so the row reads as switched off, not
// merely dim), then it settles steady. Anim off is always the steady grey —
// byte-stable.
func scepterOffDesc(txt string, opened time.Time) string {
	if UseAnim && animNow().Sub(opened) < 600*time.Millisecond && shimmerFrame() == 1 {
		return BOLD + GRY + txt + RST
	}
	return GRY + txt + RST
}

func scepterRemoteKeyMenu(pair string, cl ScepterClient, name string, row scepterTunRow, baseSeq uint64) bool {
	sel := 0
	changed := false
	rev := scepterTwinReverse(pair, name)
	opened := animNow()
	for {
		rows := scepterKeyRows(row.Carrier, rev)
		items := make([]Item, len(rows))
		for i, r := range rows {
			desc := r.hint
			if r.ask == nil {
				desc = scepterOffDesc("needs an engine command", opened)
			}
			label := r.label
			if r.key != "" {
				label += "  " + GRY + r.key + RST
			}
			items[i] = Item{Key: r.hk, Label: label, Desc: desc, Off: r.ask == nil}
		}
		head := func(w io.Writer) {
			Title(w, "Settings of "+name, "on Kharej")
			GradBand(w, uiW())
			hintLine(w, "The channel cannot read the remote values: a prompt starts at the engine's default,")
			hintLine(w, "an unset word drops the key, and every edit restarts the remote unit (with rollback).")
			fmt.Fprintln(w)
		}
		i, k := Choose(head, items, &sel, []string{"⏎", "edit", "esc", "back"}, time.Second)
		switch {
		case i >= 0:
		case k == "tick" || k == "move":
			continue
		case k == "esc" || k == "q" || k == "0" || k == "eof":
			return changed
		default:
			continue
		}
		r := rows[i]
		if r.ask == nil {
			fmt.Fprintln(Stdout)
			Hint("'" + r.key + "' needs an engine command — a future wattun edits it over the RPC.")
			Pause()
			continue
		}
		patch, pok := r.ask(row.Carrier)
		if !pok || (len(patch.set) == 0 && len(patch.drop) == 0) {
			continue // backed out, or a picker cancelled
		}
		fmt.Fprintln(Stdout)
		res, ok := scepterRun(cl, "tunnel.edit", func(seq uint64, id string) map[string]any {
			return scepterEditArgs(name, patch, seq, id)
		}, baseSeq)
		if !ok {
			continue // the transport retry was declined
		}
		if res.Code == scepterCodeOK {
			changed = true
			Ok("Key applied on Kharej — the unit restarts to apply.")
			if doc, err := scepterFetchDoc(cl); err == nil {
				baseSeq = doc.StateSeq // the next edit is built on the moved state
			}
		}
		// a rejection was printed by scepterRun with its code and hint; the
		// menu stays open so the value can be corrected
	}
}

// scepterPresetRow is one preset.list row: the engine-owned catalog, the same
// list the panel will see.
type scepterPresetRow struct{ Name, Desc string }

// scepterParsePresets parses preset.list's {presets:[{name,desc}]}; an answer
// without a usable list is not trusted (the caller falls back), a row without
// a name is skipped — nothing is invented around it.
func scepterParsePresets(p map[string]any) []scepterPresetRow {
	list, ok := p["presets"].([]any)
	if !ok {
		return nil
	}
	var out []scepterPresetRow
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		var r scepterPresetRow
		r.Name, _ = m["name"].(string)
		r.Desc, _ = m["desc"].(string)
		if r.Name != "" {
			out = append(out, r)
		}
	}
	return out
}

// scepterRemotePreset applies one engine preset (the tunnel page's "z").
// preset.list is asked first: the full catalog the engine owns. An old peer
// answers unknown_cmd (or anything that is not a catalog) and the built-in
// stealth/plain menu takes over — both shapes go through the edit path, so a
// unit that refuses the new config rolls back on Kharej.
func scepterRemotePreset(cl ScepterClient, name string, baseSeq uint64) bool {
	res, err := cl.Call("preset.list", nil)
	if err == nil && res.Code == scepterCodeOK {
		if rows := scepterParsePresets(res.Params); len(rows) > 0 {
			return scepterRemotePresetCatalog(cl, name, baseSeq, rows)
		}
	}
	// an unknown command or a catalog-less answer is the old peer's shape:
	// fall through to the built-in pair, silently (preset.apply below says
	// its own honest code if the channel is really dead)
	return scepterRemotePresetPlain(cl, name, baseSeq)
}

// scepterRemotePresetCatalog picks one preset from preset.list's answer.
func scepterRemotePresetCatalog(cl ScepterClient, name string, baseSeq uint64, rows []scepterPresetRow) bool {
	sel := 0
	items := make([]Item, len(rows))
	for i, r := range rows {
		items[i] = Item{Label: r.Name, Desc: r.Desc}
	}
	head := func(w io.Writer) {
		Title(w, "Preset", name+" · on Kharej")
		GradBand(w, uiW())
		hintLine(w, "The engine's own catalog, applied through the edit path (the unit")
		hintLine(w, "restarts; one that refuses the new config rolls back on Kharej).")
		fmt.Fprintln(w)
	}
	for {
		i, k := Choose(head, items, &sel, []string{"⏎", "apply", "esc", "back"}, time.Second)
		switch {
		case i >= 0:
		case k == "tick" || k == "move":
			continue
		default:
			return false
		}
		fmt.Fprintln(Stdout)
		if !Confirm("Apply preset '"+rows[i].Name+"' on Kharej?", true) {
			Warn("Cancelled.")
			Pause()
			return false
		}
		fmt.Fprintln(Stdout)
		res, ok := scepterRun(cl, "preset.apply", func(seq uint64, id string) map[string]any {
			return map[string]any{"id": id, "name": name, "preset": rows[i].Name,
				"base_seq": seq, "ttl_s": scepterTTLDefault}
		}, baseSeq)
		// only an OK gets the success line — an answered rejection was printed
		// by scepterRun with its code and hint (round-3 finding)
		if ok && res.Code == scepterCodeOK {
			Ok("Preset '" + rows[i].Name + "' applied on Kharej.")
		}
		Pause()
		return ok
	}
}

// scepterRemotePresetPlain is the old-peer menu: the two built-in names.
func scepterRemotePresetPlain(cl ScepterClient, name string, baseSeq uint64) bool {
	Page("Remote preset", name)
	GradBand(Stdout, uiW())
	Hint("This Kharej has no preset list yet (update it to wattun 3.5.0), so the")
	Hint("built-in pair: stealth pads stream packets and sends idle filler while quiet;")
	Hint("plain removes both again. Applied through the edit path, so a unit that refuses")
	Hint("the new config rolls back on Kharej.")
	fmt.Fprintln(Stdout)
	MenuLine(Stdout, "s", "stealth", "p", "plain", "0", "cancel")
	fmt.Fprintf(Stdout, "  %s▸%s ", CYN, RST)
	k, _, ok := KeyRead(0)
	if !ok || k == "0" || k == "esc" {
		return false
	}
	preset := ""
	switch k {
	case "s":
		preset = "stealth"
	case "p":
		preset = "plain"
	default:
		Hint("Press s, p or 0.")
		Pause()
		return false
	}
	fmt.Fprintln(Stdout)
	res, ok := scepterRun(cl, "preset.apply", func(seq uint64, id string) map[string]any {
		return map[string]any{"id": id, "name": name, "preset": preset,
			"base_seq": seq, "ttl_s": scepterTTLDefault}
	}, baseSeq)
	// only an OK gets the success line — an answered rejection was printed by
	// scepterRun with its code and hint (round-3 finding)
	if ok && res.Code == scepterCodeOK {
		Ok("Preset '" + preset + "' applied on Kharej.")
	}
	Pause()
	return ok
}

// scepterRemoteLimits edits the hot-reloaded limits: list. Items are separated
// by commas (the grammar itself is space-separated); empty input clears every
// limit — the engine's limits: [] semantics, sent as an explicit empty list.
func scepterRemoteLimits(cl ScepterClient, name string) bool {
	Page("Remote limits", name)
	GradBand(Stdout, uiW())
	Hint("Per-port items: PORT [rate=SIZE] [quota=SIZE] [period=day|week|month]")
	Hint("e.g. 443 rate=10MB quota=100GB period=month — comma-separated. Empty input")
	Hint("clears every limit. Hot-reloads within 3 s, no restart.")
	fmt.Fprintln(Stdout)
	if !AskOK("Limit items (empty clears all)", "", vScepterLimits) {
		return false
	}
	var items []string
	if ReplyV != "" {
		for _, it := range strings.Split(ReplyV, ",") {
			items = append(items, strings.TrimSpace(it))
		}
	} else {
		items = []string{} // an explicit empty list: limits.set's "clear all"
	}
	fmt.Fprintln(Stdout)
	_, ok := scepterAct(cl, "limits.set", map[string]any{"name": name, "limits": items})
	if ok {
		Ok(fmt.Sprintf("Limits applied on Kharej (%d item(s), hot-reloaded).", len(items)))
	}
	Pause()
	return ok
}

// scepterRemoteLimitsReset resets the remote tunnel's quota counters
// (limits.reset). The limits themselves stay; only the used amounts restart
// at 0, so the confirm defaults to no.
func scepterRemoteLimitsReset(cl ScepterClient, name string) bool {
	fmt.Fprintln(Stdout)
	if !Confirm("Reset every quota counter of '"+name+"' on Kharej? The ports keep their limits; the used amounts restart at 0.", false) {
		return false
	}
	_, ok := scepterAct(cl, "limits.reset", map[string]any{"name": name})
	if ok {
		Ok("Quota counters reset on Kharej.")
	}
	Pause()
	return ok
}

// scepterRemoteMute mutes or unmutes one carrier leg of a bonded remote tunnel
// (carrier.mute {name, carrier, mute}). Only a bond can mute: a lone carrier
// IS the tunnel, and muting it would just kill the link. No base_seq: the
// contract's mute is runtime bond state, not a config edit.
func scepterRemoteMute(cl ScepterClient, name string, row scepterTunRow) bool {
	legs := strings.Split(row.Carrier, "+")
	if len(legs) < 2 {
		Warn("'" + orStr(row.Carrier, "?") + "' is not a bond — there is no second path to mute.")
		Pause()
		return false
	}
	Page("Mute a carrier", name+" · "+row.Carrier)
	GradBand(Stdout, uiW())
	Hint("Muting drops one leg of the bond for this tunnel; the remaining legs carry")
	Hint("the traffic (bond.go's PathChooser). Unmute brings it back. No restart.")
	fmt.Fprintln(Stdout)
	sel := 0
	items := make([]Item, len(legs))
	for i, l := range legs {
		items[i] = Item{Label: l, Desc: "bond leg " + strconv.Itoa(i+1)}
	}
	head := func(w io.Writer) { Title(w, "Mute a carrier", name+" · "+row.Carrier) }
	for {
		i, k := Choose(head, items, &sel, []string{"⏎", "pick", "esc", "back"}, time.Second)
		switch {
		case i >= 0:
			leg := legs[i]
			fmt.Fprintln(Stdout)
			MenuLine(Stdout, "m", "mute "+leg, "u", "unmute "+leg, "0", "cancel")
			fmt.Fprintf(Stdout, "  %s▸%s ", CYN, RST)
			mk, _, ok := KeyRead(0)
			if !ok || mk == "0" || mk == "esc" {
				return false
			}
			mute := false
			switch mk {
			case "m":
				mute = true
			case "u":
			default:
				Hint("Press m, u or 0.")
				Pause()
				continue
			}
			fmt.Fprintln(Stdout)
			res, ok := scepterAct(cl, "carrier.mute", map[string]any{"name": name, "carrier": leg, "mute": mute})
			if !ok {
				Pause()
				return false
			}
			muted, _ := res.Params["muted"].(bool)
			verb := "unmuted"
			if muted {
				verb = "muted"
			}
			Ok("Leg " + leg + " " + verb + " on Kharej.")
			Pause()
			return true
		case k == "tick" || k == "move":
			continue
		default:
			return false
		}
	}
}

// scepterRemoteKeyrotate rotates the remote tunnel's PSK (tunnel.keyrotate).
// The answer carries the new token for the tunnel's Iran side: when the twin
// is the local tunnel, its key and token files are rewritten at once, with
// the old field-10 pair capability carried over (F7: the field must survive
// byte-for-byte, or a token-bootstrap pairing silently drops). Otherwise the
// token is shown and may be saved to a file. The unit restarts on Kharej;
// the twin needs a restart to dial with the new key.
//
// The twin is identified by the wave-2 follow rule (scepterFollowLocal): a
// same-named local tunnel alone proves nothing — two paired Kharej can both
// have a remote of this name, and a key rewrite of the wrong tunnel breaks it
// with no link check to catch it (a carrier change at least reverts on a dead
// link; a rewritten key does not). So the name match counts only when the
// local yml dials the pair's own host; anything else goes through the pick
// screen of tunnels that do, and when nothing matches (or the pick is
// declined — a peerless pair has no verifiable candidate at all) the token is
// handed out instead of rewriting anything (round-3 finding: the old
// `host == ""` arm rewrote any same-named tunnel silently).
func scepterRemoteKeyrotate(pair string, cl ScepterClient, name string, baseSeq uint64) bool {
	Page("Rotate key", name+" · on Kharej "+pair)
	GradBand(Stdout, uiW())
	Warn("Kharej makes a new key and restarts the tunnel. This server switches to it")
	Warn("by itself; any other Iran server on this tunnel needs the new token.")
	fmt.Fprintln(Stdout)
	if !Confirm("Rotate the key of '"+name+"' now?", false) {
		Warn("Cancelled.")
		return false
	}
	fmt.Fprintln(Stdout)
	res, ok := scepterRun(cl, "tunnel.keyrotate", func(seq uint64, id string) map[string]any {
		return map[string]any{"id": id, "name": name, "base_seq": seq, "ttl_s": scepterTTLDefault}
	}, baseSeq)
	if !ok {
		return false
	}
	if res.Code != scepterCodeOK {
		return false // the rejection was printed by scepterRun; nothing was rotated
	}
	tok, _ := res.Params["token"].(string)
	if tok == "" {
		Warn("Kharej answered OK but carried no token — read it on Kharej's console and paste it on the Iran side.")
		Pause()
		return true
	}
	host := scepterPeerHost(pair)
	local := name
	if !fileExists(filepath.Join(P.Conf, local+".yml")) || Role(local) != "Iran" ||
		host == "" || scepterPeerHost(local) != host {
		local = pickTunnel("Which local tunnel is '"+name+"'s Iran side?",
			"it dials "+orStr(host, "this pair's Kharej")+" — its key and token are rewritten",
			func(n string) bool { return Role(n) == "Iran" && host != "" && scepterPeerHost(n) == host })
		if local == "" {
			scepterTokenHandoff(name, tok)
			return true
		}
	}
	carried, err := scepterRotateLocalToken(local, tok)
	if err != nil {
		Err("Rewriting " + local + " failed: " + err.Error())
		scepterShowToken(tok)
	} else {
		// honest about the carry: the pair field is only "carried over" when
		// the rewrite merged the old token's field in (round-3 finding — the
		// old line claimed it even with no old token at all)
		if carried {
			Ok("'" + local + "' here now uses the new key (Kharej management access kept).")
		} else {
			Ok("'" + local + "' here now uses the new key.")
		}
		scepterRotMark(local)
		if scepterRestartAndCheck(local) {
			Ok(local + " is connected on the new key.")
		} else {
			Hint("Kharej is on the new key; " + local + " has not connected with it yet — check its tunnel page.")
		}
		if Confirm("Show the new token (for another Iran server on this tunnel)?", false) {
			scepterShowToken(tok)
		}
	}
	Pause()
	return true
}

// scepterTokenHandoff shows a rotated token that was NOT rewritten into a
// local twin: the honest why, then the optional save. A bare file name lands
// in the conf dir next to the tunnel's files, not in whatever the CWD is
// (round-3 finding: the dead `filepath.Dir(s) == ""` check never ran, and a
// bare name wrote into the process's working directory).
func scepterTokenHandoff(name, tok string) {
	scepterShowToken(tok)
	Hint("No local tunnel here serves '" + name + "' (matched by name AND the pair's")
	Hint("host, or picked from the ones that do): the token goes to the tunnel's")
	Hint("Iran side — paste it, or rewrite its key file with the token's key.")
	fmt.Fprintln(Stdout)
	if !AskOK("Save the token to a file (empty = don't save)", "", func(s string) bool {
		if s == "" {
			return true
		}
		if strings.ContainsAny(s, "\n\r") {
			Err("Give a one-line file path.")
			return false
		}
		return true
	}) {
		Pause()
		return
	}
	if ReplyV != "" {
		path := ReplyV
		if filepath.Dir(path) == "." {
			path = filepath.Join(P.Conf, path)
		}
		if err := atomicWrite(path, []byte(tok+"\n"), 0o600); err != nil {
			Err("Writing the token failed: " + err.Error())
		} else {
			Ok("Token saved: " + path + " (0600).")
		}
	}
	Pause()
}

// scepterRotateLocalToken rewrites the local twin's key and token with the
// rotated token's contents. The twin dials with the KEY file, so that is the
// load-bearing write; the token rides for a future re-paste. The old field-10
// pair capability is carried into the new token when the rotation dropped it
// (F7, 2026-11-22): losing the field would silently unpair the twin. carried
// says the merge happened — the success line only claims the carry then.
func scepterRotateLocalToken(local, tok string) (bool, error) {
	nt, err := ReadToken(tok)
	if err != nil {
		return false, fmt.Errorf("the rotated token does not parse: %v", err)
	}
	carried := false
	if raw, rerr := os.ReadFile(filepath.Join(P.Conf, local+".token")); rerr == nil {
		if t, terr := ReadToken(strings.TrimSpace(string(raw))); terr == nil && t.Pair != "" && nt.Pair == "" {
			tok = MakeToken(nt.Carrier, nt.Peer, nt.Key, nt.Path, nt.SNI, nt.Icmp, nt.Ports, nt.Rev, nt.Auto, t.Pair)
			carried = true
		}
	}
	if err := atomicWrite(filepath.Join(P.Conf, local+".key"), []byte(nt.Key+"\n"), 0o600); err != nil {
		return false, err
	}
	return carried, atomicWrite(filepath.Join(P.Conf, local+".token"), []byte(tok+"\n"), 0o600)
}

// scepterShowToken prints a token the way p2ShowToken does (secret, one line).
func scepterShowToken(tok string) {
	fmt.Fprintln(Stdout)
	fmt.Fprintf(Stdout, "  %sNew token for this tunnel's Iran side%s (contains the secret; share privately):\n", BOLD, RST)
	fmt.Fprintf(Stdout, "  %s%s%s\n", BOLD+YEL, tok, RST)
}

// scepterRotAt remembers the rotations this process performed per local tunnel
// (the "restart pending" marker in ScepterPairStatus). In-memory only: after a
// manager restart the marker is gone, the tunnel still works.
var (
	scepterRotMu sync.Mutex
	scepterRotBy = map[string]time.Time{}
)

// scepterCacheMaxAge bounds the in-memory per-tunnel caches (rotations, pair
// statuses): renamed or deleted tunnels would otherwise keep their entries
// forever in a long-running manager. 24 h past an entry's write it is dropped
// — far past the 30 min marker window and the 60 s status TTL it serves.
const scepterCacheMaxAge = 24 * time.Hour

func scepterRotMark(local string) {
	scepterRotMu.Lock()
	for n, at := range scepterRotBy {
		if time.Since(at) > scepterCacheMaxAge {
			delete(scepterRotBy, n)
		}
	}
	scepterRotBy[local] = time.Now()
	scepterRotMu.Unlock()
}

// scepterRotSuffix is the rotation part of the local tunnel page's pair
// status: "key rotated 14:03 — restart to apply" while the marker is fresh
// (30 min), "" otherwise.
func scepterRotSuffix(local string) string {
	scepterRotMu.Lock()
	at, ok := scepterRotBy[local]
	scepterRotMu.Unlock()
	if !ok || time.Since(at) > 30*time.Minute {
		return ""
	}
	return fmt.Sprintf(" · %skey rotated %s — restart to apply%s", YEL, at.Format("15:04"), RST)
}

// scepterStatusEntry is one cached pair status; scepterStatusTTL bounds how
// often a header may shell out (a redraw loop must not RPC per tick — the
// fleet's round-2 lesson).
type scepterStatusEntry struct {
	txt string
	at  time.Time
}

var (
	scepterStatusMu  sync.Mutex
	scepterStatusBy  = map[string]scepterStatusEntry{}
	scepterStatusTTL = 60 * time.Second
)

// ScepterPairStatus is the local tunnel page's pair/rotate status line (the
// tunnels lane appends it in tunnelHead, next to PairedBadge): engine version,
// capability tier and state seq from the pair's hello (state document as the
// fallback), "unreachable: why" when the pair does not answer, "" when the
// tunnel is not paired. Cached for scepterStatusTTL — one RPC per minute per
// tunnel page, never per redraw.
func ScepterPairStatus(name string) string {
	if !IsPaired(name) {
		return ""
	}
	scepterStatusMu.Lock()
	e, ok := scepterStatusBy[name]
	scepterStatusMu.Unlock()
	if ok && time.Since(e.at) < scepterStatusTTL {
		return e.txt + scepterRotSuffix(name)
	}
	txt := scepterStatusFetch(name)
	scepterStatusMu.Lock()
	for n, e := range scepterStatusBy {
		if time.Since(e.at) > scepterCacheMaxAge {
			delete(scepterStatusBy, n) // a renamed/deleted tunnel's entry must not live forever
		}
	}
	scepterStatusBy[name] = scepterStatusEntry{txt: txt, at: time.Now()}
	scepterStatusMu.Unlock()
	return txt + scepterRotSuffix(name)
}

// scepterStatusFetch asks the pair for the status line: hello first (ver, caps,
// state_seq), the state document as the fallback when hello says nothing.
var scepterStatusFetch = func(name string) string {
	cl, err := scepterDial(name)
	if err != nil {
		return "pair unreachable"
	}
	helloErr := ""
	var hello map[string]any
	if h, e := cl.Call("scepter.hello", nil); e != nil {
		helloErr = e.Error()
	} else if h.Code != scepterCodeOK {
		helloErr = scepterCodeHint(h.Code, h.Params)
	} else {
		hello = h.Params
	}
	if v, _ := hello["ver"].(string); v != "" {
		s := "Kharej " + v + " · " + orStr(scepterCapsOf(hello).Labels(), "?")
		if seq := scepterU64(hello["state_seq"]); seq > 0 {
			s += fmt.Sprintf(" · seq %d", seq)
		}
		return s
	}
	doc, err := scepterFetchDoc(cl)
	if err != nil {
		return "pair unreachable: " + orStr(helloErr, "no answer")
	}
	return fmt.Sprintf("Kharej %s · seq %d", orStr(doc.Ver, "?"), doc.StateSeq)
}

// ScepterKharejView is the local tunnel page's "Kharej view →" jump (the
// tunnels lane wires the deck row): it opens the remote tunnel page of the
// twin — the same-named tunnel on this pair's Kharej. With no same-named
// remote tunnel the pair screen opens instead (the honest "which one?" list).
// False when nothing was shown (unpaired, or the channel refused).
func ScepterKharejView(name string) bool {
	ch := scepterChannelFor(name)
	if ch == "" {
		return false
	}
	cl, err := scepterDial(ch)
	if err != nil {
		Page("Kharej server", name)
		GradBand(Stdout, uiW())
		Warn(err.Error())
		Hint("Fix the pairing first (Kharej server, a); that screen lists every paired Kharej.")
		Pause()
		return false
	}
	helloErr := ""
	var hello map[string]any
	if h, e := cl.Call("scepter.hello", nil); e != nil {
		helloErr = e.Error()
	} else if h.Code != scepterCodeOK {
		helloErr = fmt.Sprintf("Kharej refused this server (code %d)", h.Code)
	} else {
		hello = h.Params
	}
	caps := scepterPairCaps(ch, hello, helloErr)
	doc, derr := scepterFetchDoc(cl)
	if derr != nil {
		Page("Kharej server", name)
		GradBand(Stdout, uiW())
		Warn(derr.Error())
		Hint("Kharej did not answer; try again when the tunnel is connected.")
		Pause()
		return false
	}
	for _, r := range doc.Tunnels {
		if r.Name == name {
			scepterTunnelPage(ch, cl, caps, r.Name)
			return true
		}
	}
	scepterPairScreen(ch) // no same-named remote tunnel: pick from the list
	return true
}

// scepterRemoteUnit runs tunnel.start|stop|restart and reports the state the
// unit actually reached (the ops verified it before answering). Start defaults
// to yes; stop and restart drop connections, so they default to no.
func scepterRemoteUnit(cl ScepterClient, name, action string) bool {
	fmt.Fprintln(Stdout)
	if !Confirm(strings.ToUpper(action[:1])+action[1:]+" '"+name+"' on Kharej?", action == "start") {
		return false
	}
	res, ok := scepterAct(cl, "tunnel."+action, map[string]any{"name": name})
	if ok {
		state, _ := res.Params["state"].(string)
		Ok(strings.ToUpper(action[:1]) + action[1:] + " done — unit is " + orStr(state, "changed") + ".")
	}
	Pause()
	return ok
}

// scepterRemoteDelete: a destructive op repeats the name back (the RPC takes
// confirm:"name"); Kharej keeps everything as .bak, reversible there.
func scepterRemoteDelete(cl ScepterClient, name string) bool {
	Page("Delete remote tunnel", name)
	GradBand(Stdout, uiW()) // every screen carries the band (round-3 cosmetic)
	fmt.Fprintln(Stdout)
	Warn("The tunnel stops and its files move to .bak on Kharej (reversible there).")
	fmt.Fprintln(Stdout)
	if !AskOK("Type '"+name+"' to confirm", "", func(s string) bool {
		if s != name {
			Err("The name does not match.")
			return false
		}
		return true
	}) {
		return false
	}
	fmt.Fprintln(Stdout)
	res, ok := scepterAct(cl, "tunnel.delete", map[string]any{"name": name, "confirm": name})
	if ok {
		if b, _ := res.Params["backup"].(string); b != "" {
			Ok("Deleted. Backup on Kharej: " + b)
		} else {
			Ok("Deleted.")
		}
	}
	Pause()
	return ok
}

// ======================================================================================
// Validators for the intent fields (they print their own reason, like every
// AskOK validator here).
// ======================================================================================

// vScepterName: the remote tunnel-name rule — the engine's ValidScepterName
// shape, the manager's v_name without the local file check (the name lands on
// Kharej, not here).
func vScepterName(s string) bool {
	// the "-r" ban mirrors the engine's ValidScepterName (companion_of would hide a tunnel named
	// <x>-r whenever x is an auto Kharej tunnel — wave-1 finding F12)
	if regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`).MatchString(s) && !strings.HasSuffix(s, "-r") {
		return true
	}
	Err("Use 1-32 letters, digits, - or _ (a name may not end in -r).")
	return false
}

// vScepterKey: a config key is a flag name (lowercase letters, digits, -).
func vScepterKey(s string) bool {
	if regexp.MustCompile(`^[a-z0-9-]{1,40}$`).MatchString(s) {
		return true
	}
	Err("Use a config key (lowercase flag name, e.g. max-mbps).")
	return false
}

// vScepterValue: any non-empty one-line value.
func vScepterValue(s string) bool {
	if s != "" && !strings.ContainsAny(s, "\n\r") {
		return true
	}
	Err("Give a value.")
	return false
}

// vScepterPortItem validates one ports item in the engine's parsePortItem
// grammar: L[:T][/tcp|/udp], each side a port or an a-b range, equal counts
// when both sides are ranges.
func vScepterPortItem(item string) bool {
	s := item
	if p, ok := strings.CutSuffix(s, "/udp"); ok {
		s = p
	} else if p, ok := strings.CutSuffix(s, "/tcp"); ok {
		s = p
	}
	l, t, mapped := strings.Cut(s, ":")
	rangeOf := func(x string) (int, int, bool) {
		x = strings.TrimSpace(x)
		a, b := x, x
		if i := strings.Index(x, "-"); i > 0 {
			a, b = x[:i], x[i+1:]
		}
		p1, err1 := strconv.Atoi(a)
		p2, err2 := strconv.Atoi(b)
		if err1 != nil || err2 != nil || p1 < 1 || p1 > 65535 || p2 < 1 || p2 > 65535 || p1 > p2 {
			return 0, 0, false
		}
		return p1, p2, true
	}
	l1, l2, ok := rangeOf(l)
	if !ok {
		return false
	}
	if !mapped {
		return true
	}
	t1, t2, ok := rangeOf(t)
	if !ok || t2-t1 != l2-l1 {
		return false
	}
	return true
}

// vScepterPorts validates the create/edit ports string — the shape the engine
// parses (parsePortItem grammar, ranges included); empty is refused because a
// create without ports forwards nothing.
func vScepterPorts(s string) bool {
	if strings.TrimSpace(s) == "" {
		Err("Give at least one port, e.g. 443 or 8443:443/udp.")
		return false
	}
	for _, item := range strings.Split(s, ",") {
		if !vScepterPortItem(strings.TrimSpace(item)) {
			Err(fmt.Sprintf("%q is not a port item (443, 8443:443/udp, 2000-2010; ranges with -).", item))
			return false
		}
	}
	return true
}

// vScepterLimits validates a comma-separated limits.set item list; empty is
// the explicit "clear all". The grammar is the engine's parseLimitItem (a bare
// port parses there too; period= demands a quota=).
func vScepterLimits(s string) bool {
	if strings.TrimSpace(s) == "" {
		return true
	}
	for _, item := range strings.Split(s, ",") {
		it := strings.TrimSpace(item)
		if it == "" {
			Err("Empty limit item.")
			return false
		}
		f := strings.Fields(it)
		p, err := strconv.Atoi(f[0])
		if err != nil || p < 1 || p > 65535 {
			Err(fmt.Sprintf("%q: the item starts with the port (443 rate=10MB).", it))
			return false
		}
		quota := false
		for _, kvv := range f[1:] {
			k, v, ok := strings.Cut(kvv, "=")
			if !ok {
				Err(fmt.Sprintf("%q: want rate=SIZE, quota=SIZE or period=day|week|month.", it))
				return false
			}
			switch k {
			case "period":
				if v != "day" && v != "week" && v != "month" {
					Err(fmt.Sprintf("%q: period is day, week or month.", it))
					return false
				}
			case "rate", "quota":
				if v == "" {
					Err(fmt.Sprintf("%q: %s needs a size.", it, k))
					return false
				}
				if k == "quota" {
					quota = true
				}
			default:
				Err(fmt.Sprintf("%q: unknown limit key %q.", it, k))
				return false
			}
		}
		if strings.Contains(" "+strings.Join(f[1:], " ")+" ", " period=") && !quota {
			Err(fmt.Sprintf("%q: period= needs a quota=SIZE.", it))
			return false
		}
	}
	return true
}

// pairedIranTunnels: the paired tunnels this server dials as Iran (a Kharej's own token carries the pair field
// too, so IsPaired alone would list the Kharej side).
// fleetPairs is one paired tunnel per Kharej host, a link or explicit pair before a legacy tunnel (4.0.0 pairs
// every old tunnel, so a Kharej with ten tunnels would otherwise fill the fleet with ten rows).
func fleetPairs() []string {
	var out []string
	at := map[string]int{}
	for _, n := range pairedTunnels() {
		h := PairHost(n)
		if h == "" || Cfg(n, "reverse") == "true" {
			out = append(out, n) // no host to group by (a reverse tunnel names this server)
			continue
		}
		i, seen := at[h]
		switch {
		case !seen:
			at[h] = len(out)
			out = append(out, n)
		case !ExplicitPaired(out[i]) && ExplicitPaired(n):
			out[i] = n
		}
	}
	return out
}

func pairedIranTunnels() []string {
	var out []string
	for _, n := range pairedTunnels() {
		if Role(n) == "Iran" {
			out = append(out, n)
		}
	}
	return out
}

// scepterNewBoth is New tunnel's first choice on a paired Iran (Handoff 4 R7): one wizard makes the tunnel on
// Kharej and its Iran side here, with no token to copy.
func scepterNewBoth(pairs []string) {
	n := pairs[0]
	if len(pairs) > 1 {
		items := make([]Item, len(pairs))
		for i, p := range pairs {
			items[i] = Item{Label: pairLabel(p)}
		}
		sel := 0
		ClearScreen()
		for n = ""; n == ""; {
			i, k := Choose(func(w io.Writer) { Title(w, "Which Kharej?", "the tunnel is made there and here") }, items, &sel, []string{"⏎", "choose", "esc", "back"}, 0)
			if i >= 0 {
				n = pairs[i]
			} else if k == "esc" || k == "q" || k == "eof" {
				return
			}
		}
	}
	cl, err := scepterDial(n)
	if err != nil {
		Warn(err.Error())
		Pause()
		return
	}
	doc, err := scepterFetchDoc(cl)
	if err != nil {
		Warn(err.Error())
		Pause()
		return
	}
	scepterWizardCreate(n, cl, doc)
	Pause()
}

// scepterChannelFor is the paired tunnel whose channel reaches name's Kharej: name itself when it is paired,
// else a paired direct Iran tunnel dialing the same host (a tunnel made by "On Kharej and here" carries no
// pairing of its own, Handoff 4 R7). "" = no channel; an explicit pairing: false stays off.
func scepterChannelFor(name string) string {
	if ExplicitPaired(name) {
		return name
	}
	self := ""
	if IsPaired(name) { // legacy (4.0.0): its own channel works, but an explicit pair to the same host is known to answer
		self = name
	}
	host := scepterPeerHost(name)
	if host == "" || Role(name) != "Iran" || Cfg(name, "pairing") == "false" {
		return self
	}
	rev := Cfg(name, "reverse") == "true"
	var revPairs []string
	for _, p := range pairedIranTunnels() {
		if p == name || !ExplicitPaired(p) {
			continue
		}
		switch {
		case IsLink(p) && !rev && linkHost(p) == host: // a link names its Kharej in its token, whatever carrier it uses
			return p
		case IsLink(p) || Cfg(p, "reverse") == "true":
			revPairs = append(revPairs, p)
		case !rev && scepterPeerHost(p) == host:
			return p
		}
	}
	// a reverse tunnel's peer is this server's own address, so it names no Kharej: only a single reverse pair
	// is unambiguous
	if rev && len(revPairs) == 1 {
		return revPairs[0]
	}
	return self
}
