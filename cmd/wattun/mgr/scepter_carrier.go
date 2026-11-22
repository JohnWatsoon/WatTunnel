// Scepter carrier work from the cockpit (3.5.0, plan C.1/C.2). Three flows
// live here, all riding the phase-C RPC (docs/TECHNICAL.md, "remote testing
// and carrier change"; both ends need 3.5.0):
//
//   - the remote carrier test (pair screen): test.open a probe listener of a
//     picked shape on Kharej, measure it from THIS server with the tunnel's
//     existing throw-away client machinery (the atProbe shape), then
//     test.close; the probe also expires on its own at the ttl, and Kharej
//     rate-limits the openings (3 at once, then 1 per 30 s);
//   - the carrier change (remote tunnel page): carrier.change lets Kharej
//     apply, link-check and roll itself back; after its OK this side follows
//     (the Iran-side restart contract): rewrite the local tunnel, restart it,
//     run the link check — reverted when the link stays dead;
//   - the fleet auto-test (pair screen): auto.test triggers the ranking run
//     (async — auto.rows is polled), the ranked table is shown and a row is
//     applied through auto.apply, which routes into the same local follow.
//
// Never fabricated: every number comes from a real measurement or an RPC
// answer; a failed shape says why. Client-side capability gating is UX only —
// Kharej re-checks every command (D3).

package mgr

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// ======================================================================================
// RPC arg shapes and answer parsers (pure; the tests pin them against the
// engine's strictly-typed arg readers in wat/scepter.go).
// ======================================================================================

// scepterTestOpenArgs builds test.open {carrier, ttl, id}. ttl 0 = the engine's
// default (300); the id is lifted by -scepter-call into the command id, so a
// transport retry replays from the journal instead of opening a second probe.
func scepterTestOpenArgs(carrier string, ttl int, id string) map[string]any {
	args := map[string]any{"carrier": carrier, "id": id}
	if ttl > 0 {
		args["ttl"] = ttl
	}
	return args
}

// scepterProbeInfo is the test.open answer: everything a throw-away client
// needs to dial the probe (id, carrier, port, key, ttl; path/metrics when the
// shape has them). JSON numbers arrive as float64.
type scepterProbeInfo struct {
	ID, Carrier, Key, Path, Metrics string
	Port, TTL                       int
}

// scepterParseProbe parses the answer; a missing id, port or key is an error,
// never a half-filled struct that looks dialable.
func scepterParseProbe(p map[string]any) (scepterProbeInfo, error) {
	var pr scepterProbeInfo
	if p == nil {
		return pr, fmt.Errorf("empty test.open answer")
	}
	pr.ID, _ = p["id"].(string)
	pr.Carrier, _ = p["carrier"].(string)
	pr.Key, _ = p["key"].(string)
	pr.Path, _ = p["path"].(string)
	pr.Metrics, _ = p["metrics"].(string)
	pr.Port = int(scepterU64(p["port"]))
	pr.TTL = int(scepterU64(p["ttl"]))
	if pr.ID == "" || pr.Port <= 0 || pr.Key == "" {
		return pr, fmt.Errorf("test.open answer lacks id, port or key")
	}
	return pr, nil
}

// scepterCarrierChangeArgs builds carrier.change {name, carrier, params?,
// base_seq, ttl_s, id}. The carrier never rides inside params — the engine
// refuses the duplicate (the args carrier is authoritative).
func scepterCarrierChangeArgs(name, carrier string, params map[string]string, baseSeq uint64, id string) map[string]any {
	args := map[string]any{"id": id, "name": name, "carrier": carrier,
		"base_seq": baseSeq, "ttl_s": scepterTTLDefault}
	if len(params) > 0 {
		args["params"] = params
	}
	return args
}

// scepterAutoTestArgs builds auto.test {mode?, id}; mode "" = the engine's
// plain catalog (udp, tcp, ws, h2c).
func scepterAutoTestArgs(mode, id string) map[string]any {
	args := map[string]any{"id": id}
	if mode != "" {
		args["mode"] = mode
	}
	return args
}

// scepterAutoApplyArgs builds auto.apply {name, row, base_seq, ttl_s, id};
// row is 1-based, exactly the rank the auto.rows table shows.
func scepterAutoApplyArgs(name string, row int, baseSeq uint64, id string) map[string]any {
	return map[string]any{"id": id, "name": name, "row": row,
		"base_seq": baseSeq, "ttl_s": scepterTTLDefault}
}

// scepterAutoRow is one ranked row of the auto.rows table; rank is the number
// auto.apply names. A failed row carries why and no rate.
type scepterAutoRow struct {
	Rank     int
	Carrier  string
	Port     int
	OK       bool
	DownMbps float64
	Why      string
}

// scepterAutoTable is the auto.rows answer: the stored table of the last (or
// running) fleet run. Rows fill in only when the run reports done.
type scepterAutoTable struct {
	Run, Mode string
	Done      bool
	OK        int
	Rows      []scepterAutoRow
}

// scepterParseAutoRows parses the table; an answer without a rows list is an
// error (an empty list is a valid "nothing measured yet").
func scepterParseAutoRows(p map[string]any) (scepterAutoTable, error) {
	var t scepterAutoTable
	if p == nil {
		return t, fmt.Errorf("empty auto.rows answer")
	}
	t.Run, _ = p["run"].(string)
	t.Mode, _ = p["mode"].(string)
	t.Done, _ = p["done"].(bool)
	t.OK = int(scepterU64(p["ok"]))
	list, ok := p["rows"].([]any)
	if !ok {
		return t, fmt.Errorf("auto.rows answer has no rows list")
	}
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		var r scepterAutoRow
		r.Rank = int(scepterU64(m["rank"]))
		r.Carrier, _ = m["carrier"].(string)
		r.Port = int(scepterU64(m["port"]))
		r.OK, _ = m["ok"].(bool)
		r.DownMbps = scepterF64(m["down_mbps"])
		r.Why, _ = m["why"].(string)
		t.Rows = append(t.Rows, r)
	}
	return t, nil
}

// ======================================================================================
// The local follow: the Iran-side restart contract. After carrier.change (or
// auto.apply) answers OK, the local tunnel is rewritten, restarted and
// link-checked; a dead link offers the revert.
// ======================================================================================

// scepterPeerHost is the Kharej address this tunnel dials (probe tests and the
// follow dial it); "" when the config has no peer.
func scepterPeerHost(name string) string {
	peer := Cfg(name, "peer")
	if peer == "" {
		return ""
	}
	host, _ := SplitHP(peer)
	return host
}

// scepterLocalSave is one config key's pre-change value: set=false marks a key
// that was absent (the restore unsets it instead of writing an empty value).
type scepterLocalSave struct {
	key, val string
	set      bool
}

// scepterSaveLocal reads the keys a carrier change touches, before touching them.
func scepterSaveLocal(name string, keys ...string) []scepterLocalSave {
	saved := make([]scepterLocalSave, 0, len(keys))
	for _, k := range keys {
		v := Cfg(name, k)
		saved = append(saved, scepterLocalSave{key: k, val: v, set: v != ""})
	}
	return saved
}

// scepterRestoreLocal writes back what scepterSaveLocal read: atomic like every
// SetValue, and a formerly-absent key is unset rather than emptied.
func scepterRestoreLocal(name string, saved []scepterLocalSave) error {
	for _, s := range saved {
		var err error
		if s.set {
			err = SetValue(name, s.key, s.val)
		} else {
			err = UnsetValue(name, s.key)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// scepterApplyLocalCarrier mirrors a carrier.change on the local yml: the
// carrier itself, the peer port from the response's listen (listen is Kharej's
// bind — what Iran dials), and every param that was sent except listen, so
// both sides hold exactly the same keys. A 0 listenPort (raw carriers bind no
// port) leaves the peer alone.
func scepterApplyLocalCarrier(name, carrier string, params map[string]string, listenPort int) error {
	if err := SetValue(name, "carrier", carrier); err != nil {
		return err
	}
	if listenPort > 0 {
		if host := scepterPeerHost(name); host != "" {
			if err := SetValue(name, "peer", JoinHP(host, strconv.Itoa(listenPort))); err != nil {
				return err
			}
		}
	}
	ks := make([]string, 0, len(params))
	for k := range params {
		if k != "listen" { // Kharej-side bind; the local twin dials it, it does not bind it
			ks = append(ks, k)
		}
	}
	sort.Strings(ks)
	for _, k := range ks {
		if err := SetValue(name, k, params[k]); err != nil {
			return err
		}
	}
	return nil
}

// The local machine seams: restart and the link verdict. The live forms are
// the systemctl restart and the honest /stats alive wait; the tests stub both.
var (
	scepterRestartTunnel = func(name string) error { return Restart(Unit(name)) }
	scepterWaitAlive     = func(name string, secs int) bool {
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		for {
			if s, err := statsOf(name); err == nil && get(s, "alive") == "true" {
				return true
			}
			if time.Now().After(deadline) {
				return false
			}
			time.Sleep(time.Second)
		}
	}
)

// scepterRestartAndCheck restarts the local unit and waits for the link —
// the pass-traffic verdict of the restart contract, never assumed.
func scepterRestartAndCheck(name string) bool {
	if err := scepterRestartTunnel(name); err != nil {
		Err("Restart failed: " + err.Error())
		Hint("Run: systemctl restart " + Unit(name))
		return false
	}
	if !scepterWaitAlive(name, 15) {
		Err("No link within 15 s on '" + name + "'.")
		return false
	}
	return true
}

// scepterFollowLocal runs the LOCAL half of a remote carrier change (the
// Iran-side restart contract, docs/TECHNICAL.md): rewrite the local tunnel
// that serves the changed remote one, restart it, let the link check decide.
// Kharej has already switched when this runs and does not roll back for a
// local failure — the revert here restores only the previous local values
// (undoing Kharej's side means running carrier.change back, per the doc).
// True when the local side ended up serving, or when there was no local side
// to change (nothing was touched, nothing to revert).
//
// The follower is identified by its PEER, not by name: a same-named local
// tunnel proves nothing — two paired Kharej can both have a remote "web", and
// rewriting the wrong one redirects it to the wrong host (round-2 finding,
// 2026-11-22). The auto same-name path only fires when the local yml dials the
// pair's own host; anything else goes through the pick screen, which lists
// only tunnels dialing that host and states it.
func scepterFollowLocal(pair, remote, carrier string, params map[string]string, listenPort int) bool {
	host := scepterPeerHost(pair)
	local := remote
	if !fileExists(filepath.Join(P.Conf, local+".yml")) || Role(local) != "Iran" ||
		(host != "" && scepterPeerHost(local) != host) {
		// The cockpit may serve remote tunnels whose Iran side lives on another
		// server or under another name: ask which local tunnel follows, esc = none.
		local = pickTunnel("Follow the change locally",
			"the local tunnel that dials "+orStr(host, "this pair's Kharej")+" (now "+carrier+")",
			func(n string) bool { return Role(n) == "Iran" && (host == "" || scepterPeerHost(n) == host) })
		if local == "" {
			Warn("No local tunnel changed — Kharej's '" + remote + "' is on " + carrier + ".")
			Hint("Its Iran side lives elsewhere or under another name; point it at the new shape there.")
			return true
		}
	}
	saved := scepterSaveLocal(local, "carrier", "peer", "path", "sni")
	if err := scepterApplyLocalCarrier(local, carrier, params, listenPort); err != nil {
		Err("Rewriting " + local + ".yml failed: " + err.Error())
		Hint("Kharej's '" + remote + "' is on " + carrier + "; fix the file by hand or change it back there.")
		return false
	}
	fmt.Fprintln(Stdout)
	Hint("Restarting " + Unit(local) + " — the Iran side follows the change…")
	if !scepterRestartAndCheck(local) {
		Hint("Kharej's '" + remote + "' stays on " + carrier + " — run carrier.change back to undo it there.")
		if Confirm("Revert "+local+" to its previous settings and restart?", true) {
			if err := scepterRestoreLocal(local, saved); err != nil {
				Err("Revert write failed: " + err.Error())
				return false
			}
			if err := scepterRestartTunnel(local); err != nil {
				Err("Revert restart failed: " + err.Error())
				Hint("Run: systemctl restart " + Unit(local))
				return false
			}
			Ok("Reverted — " + local + " is back on " + orStr(Cfg(local, "carrier"), "?") + ".")
			if !scepterWaitAlive(local, 15) {
				// the verdict is separate from the revert: the restore is done
				// either way, and a dead link on the old carrier is a fact to show
				Hint("The restored config does not link either — check the tunnel page for why.")
			}
		}
		return false
	}
	Ok("Link is up — " + local + " follows on " + carrier + ".")
	return true
}

// ======================================================================================
// The remote carrier test (pair screen): test.open → measure → test.close.
// ======================================================================================

// scepterProbeShapes: the shapes a probe listener can serve — one carrier, no
// bonds, no raw sockets; a probe must be a thing a throw-away client can dial
// from Iran (docs/TECHNICAL.md).
var scepterProbeShapes = []struct{ name, desc string }{
	{"udp", "fastest and lowest latency, if UDP passes"},
	{"tcp", "plain TCP, if TCP passes"},
	{"tls", "TCP that looks like a normal HTTPS site"},
	{"ws", "WebSocket without TLS"},
	{"wss", "WebSocket over TLS; works behind a CDN"},
	{"h2", "HTTP/2"},
	{"h2c", "HTTP/2 without TLS"},
	{"grpc", "gRPC, for CDNs that allow it"},
}

// pickProbeCarrier: the probe shape list — a cut of pickCarrier holding only
// the shapes test.open can serve a listener for.
func pickProbeCarrier(head func(io.Writer)) string {
	items := make([]Item, len(scepterProbeShapes))
	for i, s := range scepterProbeShapes {
		items[i] = Item{Label: s.name, Desc: s.desc}
	}
	sel := 0
	for {
		i, k := Choose(head, items, &sel, []string{"⏎", "pick", "1-9", "quick pick", "esc", "cancel"}, 0)
		switch {
		case i >= 0:
			return scepterProbeShapes[i].name
		case k == "esc" || k == "q" || k == "eof":
			return ""
		}
	}
}

// vPortOpt is vPort with an explicit empty = "leave it": the carrier-change
// prompt keeps Kharej's current bind, and the create wizard's "empty = carrier
// default" wants the same (vPort itself refuses empty, which stranded that
// default).
func vPortOpt(s string) bool {
	if s == "" {
		return true
	}
	return vPort(s)
}

// vProbeTTL: the probe lifetime, pre-clamped to the engine's bounds (10..3600;
// empty = the engine's 300 default). The engine clamps again either way.
func vProbeTTL(s string) bool {
	if s == "" {
		return true
	}
	if !isDigits(s) {
		Err("Seconds, digits only.")
		return false
	}
	if n := atoi(s); n < 10 || n > 3600 {
		Err("The engine clamps the ttl to 10..3600 s.")
		return false
	}
	return true
}

// probeSpeedtest runs the probe client's down speed test — 4 MB over 4
// streams, the same measurement the engine's own probe core runs.
func probeSpeedtest(mp int) (float64, bool, string) {
	resp, err := httpClient.Get(speedtestURLStreams(fmt.Sprintf("127.0.0.1:%d", mp), "down", 4, 4))
	if err != nil {
		return 0, false, "speedtest: " + err.Error()
	}
	defer resp.Body.Close()
	var r speedtestResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return 0, false, "speedtest: " + err.Error()
	}
	if !r.OK {
		return 0, false, "speedtest failed: " + orStr(r.Error, "unknown error")
	}
	return r.MBPerS, true, ""
}

// scepterProbeMeasureLive drives the LOCAL half of a remote probe test with
// the tunnel's existing test machinery (the atProbe shape: spawnClient
// adapter, /stats alive wait, one down speedtest). The throw-away client dials
// the probe listener on Kharej's public address with the probe's own one-time
// key (delivered inside the session AEAD).
func scepterProbeMeasureLive(pair string, pr scepterProbeInfo) (float64, bool, string) {
	host := scepterPeerHost(pair)
	if host == "" {
		return 0, false, "no peer address in " + pair + ".yml"
	}
	mp := envFreeMetricsPort()
	dmap, ok := atFreePort(mp+1, map[int]bool{mp: true})
	if !ok {
		return 0, false, "no free test port"
	}
	args := []string{
		"-mode", "client", "-carrier", pr.Carrier, "-key", pr.Key,
		"-peer", net.JoinHostPort(host, strconv.Itoa(pr.Port)),
	}
	if pr.Path != "" { // the answer carries the shared default path for the http shapes
		args = append(args, "-path", pr.Path)
	}
	// the engine refuses a client without any -map: a loopback-only dummy
	// mapping publishes nothing (the atProbe shape)
	args = append(args, "-map", fmt.Sprintf("%d:1@127.0.0.1", dmap),
		"-metrics", "127.0.0.1:"+strconv.Itoa(mp))
	proc, err := envSpawnClient(args, "")
	if err != nil {
		return 0, false, "client spawn: " + err.Error()
	}
	defer proc.Kill()
	if !atWaitAlive(mp, 15) {
		return 0, false, "no link in 15 s"
	}
	return probeSpeedtest(mp)
}

// scepterProbeMeasure is the seam the screen calls; the tests stub it (the
// live form spawns the real throw-away client).
var scepterProbeMeasure = scepterProbeMeasureLive

// scepterProbeTest runs one remote carrier test on the pair (plan C.1). The
// probe is closed after the answer either way; a close that fails says the ttl
// expiry covers it. // shortcut: one measurement per probe — reopen for
// another; the probe rate limit (3 at once, 1 per 30 s) is the ceiling
func scepterProbeTest(pair string, cl ScepterClient, caps ScepterCaps) {
	if !caps.Has(CapManage) {
		Warn("The probe test needs the 'manage' capability on the pairing line.")
		return
	}
	Page("Probe carrier test", pair)
	Hint("Opens a probe listener on Kharej for one shape, measures it from here with")
	Hint("a throw-away client, closes it. Probes are rate-limited per pair (3 at once,")
	Hint("then 1 per 30 s) and expire on their own at the ttl.")
	host := scepterPeerHost(pair)
	if host == "" {
		fmt.Fprintln(Stdout)
		Err("No peer address in " + pair + ".yml — the probe test dials Kharej from here.")
		return
	}
	if IsReverse(pair) { // honest heads-up, not a refusal: some reverse paths still dial fine
		Warn("This tunnel is reverse — a probe dialed from here may not reach Kharej.")
	}
	head := func(w io.Writer) { Title(w, "Probe carrier test", pair+" · dials "+host+" · test.open") }
	cr := pickProbeCarrier(head)
	if cr == "" {
		return
	}
	if !AskOK("Probe ttl seconds (empty = 300; the engine clamps 10..3600)", "", vProbeTTL) {
		return
	}
	ttl := 0
	if ReplyV != "" {
		ttl = atoi(ReplyV)
	}
	fmt.Fprintln(Stdout)
	Hint("test.open " + cr + " — Kharej writes a throw-away server unit and reports what to dial.")
	res, ok := scepterAct(cl, "test.open", scepterTestOpenArgs(cr, ttl, scepterNewID()))
	if !ok {
		return
	}
	pr, err := scepterParseProbe(res.Params)
	if err != nil {
		Warn(err.Error())
		return
	}
	Say("  " + kv("Probe", pr.ID+" · "+pr.Carrier+" :"+strconv.Itoa(pr.Port)+" on Kharej · ttl "+strconv.Itoa(pr.TTL)+"s"))
	if pr.Path != "" {
		Say("  " + kv("Path", pr.Path))
	}
	fmt.Fprintln(Stdout)
	down, okM, why := scepterProbeMeasure(pair, pr)
	if okM {
		Ok(fmt.Sprintf("Link up · down %.1f MB/s (%.0f Mbps, 4 MB, 4 streams)", down, down*8))
	} else {
		Err("Probe test failed: " + why)
	}
	fmt.Fprintln(Stdout)
	// "probe", not "id": the -scepter-call CLI lifts a top-level args["id"] as the command id and
	// deletes it, so the probe id would never reach the engine (lane H finding, fixed 2026-11-22).
	if _, okC := scepterAct(cl, "test.close", map[string]any{"probe": pr.ID}); okC {
		Ok("Probe closed — nothing was left on Kharej.")
	} else {
		Hint(fmt.Sprintf("The probe expires on its own at ttl %d s.", pr.TTL))
	}
}

// ======================================================================================
// The carrier change (remote tunnel page): carrier.change → the local follow.
// ======================================================================================

// scepterRemoteCarrierChange drives carrier.change on remote tunnel NAME and
// then the local follow (the Iran-side restart contract). Needs the manage
// capability (Kharej re-checks; the gate here is UX only).
func scepterRemoteCarrierChange(pair string, cl ScepterClient, caps ScepterCaps, name string, baseSeq uint64) bool {
	if !caps.Has(CapManage) {
		Warn("Changing the carrier needs the 'manage' capability on the pairing line.")
		return false
	}
	head := func(w io.Writer) { Title(w, "Carrier of "+name, "on Kharej "+pair+" · carrier.change") }
	Page("Carrier change", name+" · on Kharej "+pair)
	Hint("Kharej patches its yml, restarts the unit and link-checks the new shape;")
	Hint("a failure rolls Kharej back before the answer. After an OK this tunnel")
	Hint("follows: rewrite, restart, link check — reverted if the link stays dead.")
	fmt.Fprintln(Stdout)
	cr := pickCarrier(false, head)
	if cr == "" {
		return false
	}
	params := map[string]string{}
	if carrierWriteListen(cr) {
		if !AskOK("Listen port on Kharej (empty = keep the current bind)", "", vPortOpt) {
			return false
		}
		if ReplyV != "" {
			params["listen"] = ":" + ReplyV // all-interfaces bind, the yml's ":PORT" form
		}
	}
	switch cr {
	case "ws", "wss", "h2", "h2c", "grpc":
		// the same-named local tunnel's path keeps the change continuous; a
		// fresh path is the default when there is no local twin to read
		if !AskOK("URL path", orStr(Cfg(name, "path"), p2RandPath()), vPath) {
			return false
		}
		params["path"] = ReplyV
	}
	switch cr {
	case "tls", "wss", "h2", "grpc":
		if v := Ask("SNI (empty = none)", Cfg(name, "sni")); v != "" {
			params["sni"] = v
		}
	}
	var sum wizSummary
	sum.add("Tunnel", name+" (on Kharej "+pair+")")
	sum.add("Carrier", cr)
	ks := make([]string, 0, len(params))
	for k := range params {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		sum.add(k, params[k])
	}
	sum.add("Base seq", strconv.FormatUint(baseSeq, 10))
	Box(Stdout, "Intent", sum...)
	fmt.Fprintln(Stdout)
	if !Confirm("Send carrier.change?", true) {
		Warn("Cancelled.")
		return false
	}
	res, ok := scepterRun(cl, "carrier.change", func(seq uint64, id string) map[string]any {
		return scepterCarrierChangeArgs(name, cr, params, seq, id)
	}, baseSeq)
	if !ok || res.Code != scepterCodeOK {
		return false // scepterRun printed the outcome; Kharej rolled itself back if it tried
	}
	newCar, _ := res.Params["carrier"].(string)
	if newCar == "" {
		newCar = cr
	}
	lp := int(scepterU64(res.Params["listen"]))
	Ok("Kharej switched '" + name + "' to " + newCar + " (its link check passed).")
	return scepterFollowLocal(pair, name, newCar, params, lp)
}

// ======================================================================================
// The fleet auto-test (pair screen): auto.test → poll auto.rows → apply a row.
// ======================================================================================

// scepterFleetAuto triggers a fleet ranking run on the pair and opens the
// ranked table. The run is async (about a minute); a second trigger while one
// runs answers already_running, which is surfaced, not an error.
func scepterFleetAuto(pair string, cl ScepterClient, caps ScepterCaps, doc scepterDoc) {
	if !caps.Has(CapManage) {
		Warn("The fleet auto-test needs the 'manage' capability on the pairing line.")
		return
	}
	Page("Fleet auto-test", pair+" · what Kharej can serve")
	Hint("Kharej opens one probe per shape, measures what it can SERVE and ranks the")
	Hint("table (plain: udp tcp ws h2c · tls adds tls wss h2 grpc). The DPI verdict")
	Hint("stays here: probe-test the winner from Iran. A run takes about a minute;")
	Hint("rate-limited per pair: 2 at once, then 1 per 60 s.")
	fmt.Fprintln(Stdout)
	MenuLine(Stdout, "p", "plain shapes", "t", "tls shapes too", "0", "cancel")
	fmt.Fprintf(Stdout, "  %s▸%s ", CYN, RST)
	k, _, ok := KeyRead(0)
	if !ok || k == "0" || k == "esc" {
		return
	}
	mode := ""
	switch k {
	case "t":
		mode = "tls"
	case "p":
	default:
		Hint("Press p, t or 0.")
		Pause()
		return
	}
	fmt.Fprintln(Stdout)
	res, ok := scepterAct(cl, "auto.test", scepterAutoTestArgs(mode, scepterNewID()))
	if !ok {
		return
	}
	run, _ := res.Params["run"].(string)
	if b, _ := res.Params["already_running"].(bool); b {
		Warn("Run " + orStr(run, "?") + " is already going — showing its table.")
	} else {
		Ok(fmt.Sprintf("Run %s started (%d shape(s), about a minute).",
			orStr(run, "?"), int(scepterU64(res.Params["shapes"]))))
	}
	scepterAutoWait(cl)
	scepterAutoRowsView(pair, cl, caps, doc)
}

// scepterAutoWait polls auto.rows until the run reports done; esc or q skips
// the wait (the table view shows the partial state anyway).
func scepterAutoWait(cl ScepterClient) {
	fmt.Fprintln(Stdout)
	Hint("Polling auto.rows — esc to skip the wait.")
	for i := 0; i < 150; i++ { // 150 x 2 s: a run takes ~1 min; the ceiling bounds a wedged channel
		res, err := cl.Call("auto.rows", nil)
		if err != nil {
			Warn("channel: " + err.Error())
			return
		}
		if res.Code != scepterCodeOK {
			scepterCodeErr("auto.rows", res)
			return
		}
		t, err := scepterParseAutoRows(res.Params)
		if err != nil {
			Warn(err.Error())
			return
		}
		if t.Done {
			return
		}
		Say("  " + GRY + fmt.Sprintf("run %s in progress (%s shapes)…", orStr(t.Run, "?"), orStr(t.Mode, "?")) + RST)
		k, _, ok := KeyRead(2 * time.Second)
		if !ok || k == "esc" || k == "q" {
			return
		}
	}
	Warn("Still running after 5 min — the table view shows the state so far.")
}

// scepterAutoRowsView shows the ranked table and applies a picked row through
// auto.apply + the local follow; r re-reads the table while the run fills it.
func scepterAutoRowsView(pair string, cl ScepterClient, caps ScepterCaps, doc scepterDoc) {
	sel := 0
	var t scepterAutoTable
	fetch := func() bool {
		res, err := cl.Call("auto.rows", nil)
		if err != nil {
			Warn("channel: " + err.Error())
			return false
		}
		if res.Code != scepterCodeOK {
			scepterCodeErr("auto.rows", res)
			return false
		}
		t, err = scepterParseAutoRows(res.Params)
		if err != nil {
			Warn(err.Error())
			return false
		}
		return true
	}
	if !fetch() {
		Pause()
		return
	}
	for {
		items := make([]Item, len(t.Rows))
		for i, r := range t.Rows {
			desc := fmt.Sprintf("port %d · %.1f MB/s down", r.Port, r.DownMbps)
			if !r.OK {
				desc = "failed: " + orStr(r.Why, "no reason")
			}
			items[i] = Item{Label: fmt.Sprintf("%d · %s", r.Rank, r.Carrier), Desc: desc}
		}
		head := func(w io.Writer) { scepterAutoHead(w, pair, t, len(doc.Tunnels)) }
		i, k := Choose(head, items, &sel, []string{"⏎", "apply", "r", "refresh", "esc", "back"}, time.Second)
		switch {
		case i >= 0 && i < len(t.Rows):
			scepterAutoApplyRow(pair, cl, doc, t.Rows[i])
			fetch() // the table may have moved under the apply
		case k == "tick" || k == "move":
			continue
		case k == "r":
			if !fetch() {
				return
			}
		case k == "eof":
			return
		default:
			return
		}
	}
}

// scepterAutoHead draws the table header: the run, its progress and the honest
// "no rows yet" when the run has not filled the table.
func scepterAutoHead(w io.Writer, pair string, t scepterAutoTable, tunnels int) {
	Title(w, "Fleet auto-test", pair+" · run "+orStr(t.Run, "?")+" · "+orStr(t.Mode, "plain"))
	status := "done"
	if !t.Done {
		status = "in progress"
	}
	fmt.Fprintln(w, "  "+kv("Table", fmt.Sprintf("%s · %d/%d shape(s) served", status, t.OK, len(t.Rows))))
	if len(t.Rows) == 0 {
		hintLine(w, "No rows yet — the run fills the table as shapes are measured.")
	}
	if tunnels == 0 {
		hintLine(w, "No tunnels on this Kharej to apply a row to (create one first).")
	}
	fmt.Fprintln(w)
}

// scepterAutoApplyRow pushes one ranked row through auto.apply (Kharej's
// carrier.change path: link check + rollback there) and then the local follow.
// A failed row applies only on an explicit no — the rank order puts failures
// last for a reason.
func scepterAutoApplyRow(pair string, cl ScepterClient, doc scepterDoc, r scepterAutoRow) {
	if !r.OK && !Confirm(fmt.Sprintf("Row %d failed (%s) — apply it anyway?", r.Rank, orStr(r.Why, "no reason")), false) {
		return
	}
	def := ""
	if len(doc.Tunnels) == 1 {
		def = doc.Tunnels[0].Name // the common one-tunnel fleet: no typing
	}
	fmt.Fprintln(Stdout)
	if !AskOK("Apply to remote tunnel", def, vScepterName) {
		return
	}
	name := ReplyV
	fmt.Fprintln(Stdout)
	res, ok := scepterRun(cl, "auto.apply", func(seq uint64, id string) map[string]any {
		return scepterAutoApplyArgs(name, r.Rank, seq, id)
	}, doc.StateSeq)
	if !ok || res.Code != scepterCodeOK {
		return // printed
	}
	carrier, _ := res.Params["carrier"].(string)
	if carrier == "" {
		carrier = r.Carrier // the ops echo the carrier; the row is the fallback
	}
	lp := int(scepterU64(res.Params["listen"]))
	Ok(fmt.Sprintf("Row %d applied on Kharej: '%s' is on %s (its link check passed).", r.Rank, name, carrier))
	scepterFollowLocal(pair, name, carrier, nil, lp)
}
