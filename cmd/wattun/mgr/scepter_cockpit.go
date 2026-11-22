// Scepter cockpit screens (3.5.0, plan B.3): the write side of the pairing
// plane on Iran. Three surfaces live here:
//
//   - the fleet view of pairs (scepter-fleet): one row per paired Iran tunnel
//     with the remote state of its Kharej;
//   - the pair screen (wattun-manager scepter NAME when paired): the remote
//     tunnel list of that Kharej plus the create wizard;
//   - the remote tunnel pages: state, stats, logs, edit/delete, unit actions —
//     every row and every answer comes from the RPC, never fabricated.
//
// The wizard prompts reuse the phase-A builders (pickCarrier, AskOK, vPort);
// they become intent builders producing a tunnel.create args map. Client-side
// capability gating is UX only — Kharej re-checks every command (D3).

package mgr

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func init() {
	Register("scepter_fleet", func(args ...string) int {
		scepterFleet()
		return 0
	})
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
		return scepterDoc{}, fmt.Errorf("state.get answered code %d: %s", res.Code, scepterCodeHint(res.Code, res.Params))
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

// scepterNewID mints one command id; retries of the SAME intent reuse it (the
// server journal answers at-most-once), a rebuilt intent gets a fresh one.
func scepterNewID() string {
	return fmt.Sprintf("mgr%d-%d", time.Now().UnixNano(), scepterIDSeq.Add(1))
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
		res, err := cl.Call(cmd, argsf(cur, id))
		if err != nil {
			Warn("channel: " + err.Error())
			if !Confirm("Retry the same intent (same command id — an applied one replays from the journal)?", true) {
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
		if !Confirm(fmt.Sprintf("Rebuild on the fresh state (seq %d) and retry?", fresh.StateSeq), true) {
			return res, true
		}
		cur, id = fresh.StateSeq, scepterNewID()
	}
}

// scepterAct runs one command that has no base_seq (unit ops, delete) and
// prints the honest outcome; true when Kharej answered OK.
func scepterAct(cl ScepterClient, cmd string, args map[string]any) (ScepterResult, bool) {
	res, err := cl.Call(cmd, args)
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

// pairedTunnels lists the visible Iran tunnels carrying `pairing: true` — the
// fleet. Hidden helpers are never pairs (a companion carries no pairing line).
func pairedTunnels() []string {
	var out []string
	for _, n := range Tunnels() {
		if IsPaired(n) {
			out = append(out, n)
		}
	}
	return out
}

func scepterFleet() {
	for {
		names := pairedTunnels()
		if len(names) == 0 {
			Page("Scepter fleet", "no pairs yet")
			fmt.Fprintln(Stdout)
			Hint("Pair a Kharej once: its install.sh prints a watp1: line; on the Iran tunnel run")
			Hint(P.Self + " scepter NAME and press a to attach it.")
			Pause()
			return
		}
		type pairRow struct {
			doc scepterDoc
			err string
		}
		rows := make([]pairRow, len(names))
		for i, n := range names { // one state.get per pair; a pair that cannot answer says so
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
		items := make([]Item, len(names))
		for i, r := range rows {
			desc := ""
			if r.err != "" {
				desc = YEL + "unreachable: " + r.err + RST
			} else {
				desc = fmt.Sprintf("%s · seq %d · %d tunnel(s) · up %s", r.doc.Ver, r.doc.StateSeq,
					len(r.doc.Tunnels), scepterUp(r.doc.UptimeS))
			}
			items[i] = Item{Label: names[i], Desc: desc}
		}
		sel := 0
		head := func(w io.Writer) {
			Title(w, "Scepter fleet", fmt.Sprintf("%d pair(s) · Iran cockpit", len(names)))
			hintLine(w, "One row per paired tunnel; the state is live from its Kharej.")
			fmt.Fprintln(w)
		}
		i, k := Choose(head, items, &sel, []string{"⏎", "open", "r", "refresh", "esc", "back"}, time.Second)
		switch {
		case i >= 0:
			scepterScreen(names[i])
		case k == "tick" || k == "move":
			continue
		case k == "r":
			continue
		case k == "eof":
			return
		default:
			return
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
		Page("Scepter", n)
		Warn(err.Error())
		Pause()
		return
	}
	// One hello per entry: version and capabilities gate the write items
	// (client-side UX; Kharej re-checks). A failed hello keeps the reads.
	caps := ScepterCaps(0)
	helloErr := ""
	if h, e := cl.Call("scepter.hello", nil); e != nil {
		helloErr = e.Error()
	} else if h.Code != scepterCodeOK {
		helloErr = fmt.Sprintf("scepter.hello answered code %d", h.Code)
	} else {
		caps = scepterCapsOf(h.Params)
	}
	refetch := func() (scepterDoc, string) {
		doc, err := scepterFetchDoc(cl)
		if err != nil {
			return scepterDoc{}, err.Error()
		}
		return doc, ""
	}
	doc, docErr := refetch()
	sel := 0
	for {
		items, rows := scepterPairItems(doc, docErr, caps)
		head := func(w io.Writer) { scepterPairHead(w, n, doc, docErr, caps, helloErr) }
		i, k := Choose(head, items, &sel, []string{"⏎", "open", "n", "create", "t", "test",
			"a", "auto", "s", "state", "e", "events", "h", "hello", "r", "refresh", "esc", "back"}, time.Second)
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
		case "s":
			scepterStateView(cl)
			Pause()
			doc, docErr = refetch()
		case "e":
			scepterEventsView(cl, doc.Cursor)
			Pause()
			doc, docErr = refetch()
		case "h":
			scepterHelloView(cl)
			Pause()
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
		items = append(items, Item{Key: "n", Label: "Create a tunnel on Kharej", Desc: "the wizard drives tunnel.create"})
	}
	if caps.Has(CapManage) {
		items = append(items,
			Item{Key: "t", Label: "Probe carrier test", Desc: "open a probe on Kharej, measure it from here, close it"},
			Item{Key: "a", Label: "Fleet auto-test", Desc: "rank what Kharej can serve (auto.test), apply a row"},
		)
	}
	items = append(items,
		Item{Key: "s", Label: "State document", Desc: "seq, uptime, tunnels — the pair's whole state"},
		Item{Key: "e", Label: "Events", Desc: "what changed since the last cursor"},
		Item{Key: "h", Label: "Hello", Desc: "versions and capabilities of the pair"},
	)
	return items, rows
}

func scepterPairHead(w io.Writer, n string, doc scepterDoc, docErr string, caps ScepterCaps, helloErr string) {
	Title(w, n, "Iran cockpit · caps "+orStr(caps.Labels(), "none"))
	if helloErr != "" {
		warnLine(w, "no hello: "+helloErr)
	}
	if docErr != "" {
		warnLine(w, docErr)
		fmt.Fprintln(w)
		return
	}
	fmt.Fprintln(w, "  "+kv("Kharej", fmt.Sprintf("%s · seq %d · up %s · cursor %d",
		doc.Ver, doc.StateSeq, scepterUp(doc.UptimeS), doc.Cursor)))
	fmt.Fprintln(w, "  "+kv("Pairing", orStr(doc.PairUUID, "?")+" · "+orStr(doc.PairCaps, "?")))
	if len(doc.Tunnels) == 0 {
		hintLine(w, "No tunnels on this Kharej yet.")
	}
	fmt.Fprintln(w)
}

// ---- the pair-level read views (one fresh RPC each, printed honestly) ----

func scepterStateView(cl ScepterClient) {
	fmt.Fprintln(Stdout)
	Hint("state.get — the versioned state document of the pair")
	doc, err := scepterFetchDoc(cl)
	if err != nil {
		Warn(err.Error())
		return
	}
	Say("  " + kv("Engine", doc.Ver))
	Say("  " + kv("State seq", strconv.FormatUint(doc.StateSeq, 10)))
	Say("  " + kv("Uptime", scepterUp(doc.UptimeS)))
	Say("  " + kv("Event cursor", strconv.FormatUint(doc.Cursor, 10)))
	Say("  " + kv("Pairing", orStr(doc.PairUUID, "?")+" · caps "+orStr(doc.PairCaps, "?")))
	for _, r := range doc.Tunnels {
		Say("  " + kv("Tunnel", scepterRowDesc(r)))
	}
}

func scepterHelloView(cl ScepterClient) {
	fmt.Fprintln(Stdout)
	Hint("scepter.hello — versions and capabilities of the pair")
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
	Hint(fmt.Sprintf("events.since %d — what changed on Kharej", since))
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
	for _, e := range events {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := m["type"].(string)
		line := fmt.Sprintf("  %s%-6s%s %s", GRY, strconv.FormatUint(scepterU64(m["seq"]), 10), RST, typ)
		if ts := int64(scepterU64(m["ts"])); ts > 0 {
			line += " " + GRY + time.Unix(ts, 0).Format("15:04:05") + RST
		}
		if d := scepterDetailStr(m["detail"]); d != "" {
			line += "  " + d
		}
		Say(line)
	}
	if c := scepterU64(res.Params["cursor"]); c > since {
		Hint(fmt.Sprintf("cursor is now %d", c))
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

func scepterWizardCreate(n string, cl ScepterClient, base scepterDoc) {
	baseSeq := base.StateSeq
	Page("Create tunnel on Kharej", n+" · built on seq "+strconv.FormatUint(baseSeq, 10))
	Hint("Kharej validates, writes the files, starts the unit and reports; the key")
	Hint("and the Iran token come back inside the encrypted channel.")
	fmt.Fprintln(Stdout)
	name := scepterRemoteNameSuggest(base.Tunnels)
	if !AskOK("Tunnel name", name, vScepterName) {
		return
	}
	name = ReplyV
	head := func(w io.Writer) {
		Title(w, "Create tunnel on Kharej", n+" · built on seq "+strconv.FormatUint(baseSeq, 10))
	}
	cr := pickCarrier(false, head)
	if cr == "" {
		return
	}
	params := map[string]string{}
	if carrierWriteListen(cr) {
		if !AskOK("Listen port on Kharej (empty = carrier default)", "", vPortOpt) {
			return
		}
		if ReplyV != "" {
			params["listen"] = ":" + ReplyV // all-interfaces bind, the yml's ":PORT" form
		}
	}
	switch cr {
	case "ws", "wss", "h2", "h2c", "grpc":
		if !AskOK("URL path", p2RandPath(), vPath) {
			return
		}
		params["path"] = ReplyV
	}
	switch cr {
	case "tls", "wss", "h2", "grpc":
		if v := Ask("SNI (empty = none)", ""); v != "" {
			params["sni"] = v
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
	sum.add("Base seq", strconv.FormatUint(baseSeq, 10))
	Box(Stdout, "Intent", sum...)
	fmt.Fprintln(Stdout)
	if !Confirm("Send tunnel.create?", true) {
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
			if !AskOK("Ports (the remote listen port collides — forwarded ports)", pstr, vScepterPorts) {
				return
			}
			pstr = ReplyV
			continue
		case scepterCodeCarrierNeeds:
			cr = pickCarrier(false, head)
			if cr == "" {
				return
			}
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
		scepterShowCreated(res.Params)
		return
	}
}

// scepterShowCreated reports a created tunnel: what Kharej answered, the Iran
// token when the carrier is client-facing, and the base_seq tail when the
// state moved under the intent.
func scepterShowCreated(p map[string]any) {
	name, _ := p["name"].(string)
	Ok("Tunnel '" + orStr(name, "?") + "' created on Kharej.")
	if c, _ := p["carrier"].(string); c != "" {
		Say("  " + kv("Carrier", c))
	}
	if m, _ := p["metrics"].(string); m != "" {
		Say("  " + kv("Metrics", m+" (on Kharej)"))
	}
	if k, _ := p["key"].(string); k != "" {
		Say("  " + kv("Key", k))
	}
	if tok, _ := p["token"].(string); tok != "" {
		fmt.Fprintln(Stdout)
		fmt.Fprintf(Stdout, "  %sToken for this tunnel's Iran side%s (contains the secret; share privately):\n", BOLD, RST)
		fmt.Fprintf(Stdout, "  %s%s%s\n", BOLD+YEL, tok, RST)
	}
	if _, moved := p["state"]; moved {
		Hint("The state moved while the create ran (the answer carries the fresh document); press r to refresh.")
	}
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
		Page("Scepter", pair)
		Warn("Tunnel '" + name + "' is no longer in the state document (deleted on Kharej?).")
		Pause()
		return false
	}
	refresh := func() bool { // one state.get per action, never per tick
		doc, err := scepterFetchDoc(cl)
		if err != nil {
			Page("Scepter", pair)
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
	for {
		items := scepterTunnelItems(row, caps)
		head := func(w io.Writer) { scepterTunnelHead(w, pair, row, cursor) }
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
			ran = scepterRemotePorts(cl, name, row.Ports, cursor)
		case "k":
			ran = scepterRemoteKey(cl, name, cursor)
		case "z":
			ran = scepterRemotePreset(cl, name, cursor)
		case "q":
			ran = scepterRemoteLimits(cl, name)
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
// empty list and the head's hint says why.
func scepterTunnelItems(row scepterTunRow, caps ScepterCaps) []Item {
	if !caps.Has(CapManage) {
		return nil
	}
	run := "Start"
	if row.State == "active" {
		run = "Stop"
	}
	return []Item{
		{Key: "s", Label: "Stats", Desc: "live /stats numbers of the remote unit"},
		{Key: "l", Label: "Logs", Desc: "remote journal tail (chunked)"},
		{Key: "c", Label: "Carrier", Desc: "switch it (carrier.change rolls back; this side follows)"},
		{Key: "p", Label: "Ports", Desc: "edit the forwarded ports (restarts the unit)"},
		{Key: "k", Label: "Config key", Desc: "set or drop one config key (restarts the unit)"},
		{Key: "z", Label: "Preset", Desc: "stealth / plain, via preset.apply (rolls back on failure)"},
		{Key: "q", Label: "Limits", Desc: "per-port rate and quota (hot-reloads, no restart)"},
		{Key: "r", Label: "Restart", Desc: "restart the remote unit (drops connections)"},
		{Key: "u", Label: run, Desc: "start or stop the remote unit"},
		{Key: "d", Label: RED + "Delete" + RST, Desc: "stop it; files move to .bak on Kharej (types the name)"},
	}
}

func scepterTunnelHead(w io.Writer, pair string, row scepterTunRow, cursor uint64) {
	col, dot, txt := scepterStateCell(row)
	Title(w, row.Name, "on Kharej "+pair+"  "+col+dot+" "+txt+RST)
	fmt.Fprintln(w, "  "+kv("Carrier", orStr(row.Carrier, "?")))
	if row.Ports != "" {
		fmt.Fprintln(w, "  "+kv("Ports", row.Ports))
	}
	if row.Metrics != "" {
		fmt.Fprintln(w, "  "+kv("Metrics", row.Metrics+" (on Kharej)"))
	}
	fmt.Fprintln(w, "  "+kv("Event cursor", strconv.FormatUint(cursor, 10)))
	if cursor == 0 {
		hintLine(w, "The events cursor rides the state document; press e on the pair screen to read events.")
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

func scepterTunnelStats(cl ScepterClient, name string) {
	fmt.Fprintln(Stdout)
	Hint("tunnel.stats — live numbers of the remote unit")
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
}

// scepterTunnelLogs prints the chunked log tail. The engine caps tail at 1000;
// the screen clamps the DRAW to the last 40 lines so a full tail stays one
// page, and says how many were cut.
func scepterTunnelLogs(cl ScepterClient, name string) {
	fmt.Fprintln(Stdout)
	Hint("tunnel.logs — the remote unit's last log lines")
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
	Hint("The forwarded ports (the ports: allowlist). Kharej restarts the unit to")
	Hint("apply; the previous config stays as NAME.yml.bak there.")
	fmt.Fprintln(Stdout)
	if !AskOK("Ports (e.g. 443, 8443:443/udp, 2000-2010)", cur, vScepterPorts) {
		return false
	}
	pstr := ReplyV
	fmt.Fprintln(Stdout)
	_, ok := scepterRun(cl, "tunnel.edit", func(seq uint64, id string) map[string]any {
		return map[string]any{"id": id, "name": name, "ports": pstr,
			"base_seq": seq, "ttl_s": scepterTTLDefault}
	}, baseSeq)
	if ok {
		Ok("Ports applied on Kharej.")
	}
	Pause()
	return ok
}

func scepterRemoteKey(cl ScepterClient, name string, baseSeq uint64) bool {
	Page("Remote config", name)
	Hint("Set or drop one config key (a flag name, e.g. max-mbps). Kharej")
	Hint("restarts the unit to apply; an unknown key is refused with its reason.")
	fmt.Fprintln(Stdout)
	MenuLine(Stdout, "s", "set a key", "d", "drop a key", "0", "cancel")
	fmt.Fprintf(Stdout, "  %s▸%s ", CYN, RST)
	k, _, ok := KeyRead(0)
	if !ok || k == "0" || k == "esc" {
		return false
	}
	if k != "s" && k != "d" {
		Hint("Press s, d or 0.")
		Pause()
		return false
	}
	fmt.Fprintln(Stdout)
	if !AskOK("Config key", "", vScepterKey) {
		return false
	}
	key := ReplyV
	var patch func(uint64, string) map[string]any
	if k == "s" {
		if !AskOK("Value for "+key, "", vScepterValue) {
			return false
		}
		val := ReplyV
		patch = func(seq uint64, id string) map[string]any {
			return map[string]any{"id": id, "name": name, "set": map[string]string{key: val},
				"base_seq": seq, "ttl_s": scepterTTLDefault}
		}
	} else {
		patch = func(seq uint64, id string) map[string]any {
			return map[string]any{"id": id, "name": name, "drop": []string{key},
				"base_seq": seq, "ttl_s": scepterTTLDefault}
		}
	}
	fmt.Fprintln(Stdout)
	_, ok = scepterRun(cl, "tunnel.edit", patch, baseSeq)
	if ok {
		Ok("Key applied on Kharej.")
	}
	Pause()
	return ok
}

// scepterRemotePreset applies one engine-owned preset (the same catalog the
// panel will see) through the edit path.
func scepterRemotePreset(cl ScepterClient, name string, baseSeq uint64) bool {
	Page("Remote preset", name)
	Hint("stealth: pad stream packets and send idle filler while quiet (3.3.0 knobs).")
	Hint("plain: remove both again. Applied through the edit path, so a unit that")
	Hint("refuses the new config rolls back on Kharej.")
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
	_, ok = scepterRun(cl, "preset.apply", func(seq uint64, id string) map[string]any {
		return map[string]any{"id": id, "name": name, "preset": preset,
			"base_seq": seq, "ttl_s": scepterTTLDefault}
	}, baseSeq)
	if ok {
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
	if regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`).MatchString(s) {
		return true
	}
	Err("Use 1-32 letters, digits, - or _.")
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
