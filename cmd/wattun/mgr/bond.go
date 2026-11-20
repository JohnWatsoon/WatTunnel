package mgr

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Bonds: the Bonding screen, and bond auto-retest (F10), which re-tests the carriers of a
// bond on a schedule and adds one back when it works again. The retest setting lives in
// the NAME.bondretest sidecar, never in NAME.yml: the engine rejects unknown keys.

func init() {
	Register("bond_retest_job", func(a ...string) int { return b2rc(bondRetestJob(arg(a, 0))) })
	Register("bonding_menu", func(a ...string) int { bondingMenu(arg(a, 0)); return 0 })
}

const bondRetestBudgetMB = 20 // traffic budget of one run, .manager.conf key bondretest-budget

func isBond(c string) bool { return strings.Contains(c, "+") }

// bondRetestVisible: the setting belongs on a bonded Iran client.
func bondRetestVisible(role, car string) bool { return role == "Iran" && isBond(car) }

// bondRetestOK normalizes a schedule: off, 30m, 1h, 6h or daily-offpeak ("" = refused).
func bondRetestOK(v string) string {
	switch strings.ToLower(v) {
	case "off", "0", "none", "never":
		return "off"
	case "30m", "30min", "half-hour":
		return "30m"
	case "1h", "60m", "hourly":
		return "1h"
	case "6h", "360m":
		return "6h"
	case "daily-offpeak", "daily", "offpeak", "off-peak":
		return "daily-offpeak"
	}
	return ""
}

func bondRetestGet(n string) string {
	v := strings.TrimSpace(strings.SplitN(mustRead(filepath.Join(P.Conf, n+".bondretest")), "\n", 2)[0])
	return orStr(bondRetestOK(orStr(v, "off")), "off")
}

// bondRetestTimer: the [Timer] lines of a schedule.
func bondRetestTimer(v string) string {
	if v == "daily-offpeak" {
		return "OnCalendar=*-*-* 04:15:00\nRandomizedDelaySec=300\nPersistent=true\n"
	}
	every := map[string]string{"30m": "30min", "1h": "1h", "6h": "6h"}[v]
	return "OnBootSec=5min\nOnUnitActiveSec=" + every + "\nRandomizedDelaySec=60\nPersistent=true\n"
}

func bondRetestUnit(n string) string { return P.Prefix + "-bondretest-" + n }

func bondRetestEnable(n, v string) bool {
	u, ud := bondRetestUnit(n), unitDir()
	desc := ""
	if P.Sandbox {
		desc = " (sandbox " + P.Prefix + ")"
	}
	svc := "[Unit]\nDescription=WatTunnel bond carrier re-test for " + n + desc + "\n[Service]\nType=oneshot\n" +
		unitEnvLines() + "ExecStart=" + P.Mgr + " bond-retest " + n + " --yes\n"
	tmr := "[Unit]\nDescription=WatTunnel bond carrier re-test for " + n + " (" + v + ")\n[Timer]\n" +
		bondRetestTimer(v) + "[Install]\nWantedBy=timers.target\n"
	if os.WriteFile(filepath.Join(ud, u+".service"), []byte(svc), 0o644) != nil ||
		os.WriteFile(filepath.Join(ud, u+".timer"), []byte(tmr), 0o644) != nil {
		return false
	}
	return systemctlOK("daemon-reload") && systemctlOK("enable", "--now", u+".timer")
}

func bondRetestDisable(n string) {
	u := bondRetestUnit(n)
	if !fileExists(filepath.Join(unitDir(), u+".timer")) {
		return
	}
	_ = systemctlErr("disable", "--now", u+".timer")
	_ = os.Remove(filepath.Join(unitDir(), u+".service"))
	_ = os.Remove(filepath.Join(unitDir(), u+".timer"))
	_ = systemctlErr("daemon-reload")
}

func bondRetestSet(n, v string) bool {
	if v = bondRetestOK(v); v == "" {
		Err("Use off, 30m, 1h, 6h or daily-offpeak.")
		return false
	}
	if !bondRetestVisible(Role(n), Cfg(n, "carrier")) {
		Err("Bond auto-retest applies to a bonded tunnel on Iran (carrier list with '+'), not '" + n + "'.")
		return false
	}
	if atomicWrite(filepath.Join(P.Conf, n+".bondretest"), []byte(v+"\n"), 0o600) != nil {
		Err("Could not write " + filepath.Join(P.Conf, n+".bondretest") + ".")
		return false
	}
	if v == "off" {
		bondRetestDisable(n)
		Ok("Bond auto-retest off for '" + n + "'.")
	} else if bondRetestEnable(n, v) {
		Ok("Bond auto-retest for '" + n + "': " + v + ".")
	} else {
		Err("Could not install the bond-retest timer.")
		return false
	}
	return true
}

// ---- the retest job ----

func bondFailGet(n string) string {
	v := strings.TrimSpace(strings.SplitN(mustRead(filepath.Join(P.Conf, n+".bondfail")), "\n", 2)[0])
	if v == "none" {
		v = ""
	}
	return strings.TrimSuffix(v, ",")
}

func bondFailSet(n, v string) {
	_ = atomicWrite(filepath.Join(P.Conf, n+".bondfail"), []byte(orStr(v, "none")+"\n"), 0o600)
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '+' })
}

// bondFailNext: the carriers the next run retries. Only carriers outside the bond are kept
// (a bond leg is probed on every run anyway): this run's failures, then old ones it did not test.
func bondFailNext(old, car, tested, failing string) string {
	in := func(list []string, x string) bool {
		for _, y := range list {
			if y == x {
				return true
			}
		}
		return false
	}
	cars, ts, fs := splitList(car), splitList(tested), splitList(failing)
	var out []string
	for _, x := range ts {
		if !in(cars, x) && in(fs, x) {
			out = append(out, x)
		}
	}
	for _, x := range splitList(old) {
		if !in(cars, x) && !in(ts, x) && !in(out, x) {
			out = append(out, x)
		}
	}
	return strings.Join(out, ",")
}

// bondWorth: a working carrier joins when no leg works, or when it reaches 10 % of the best leg.
func bondWorth(score, best float64) bool { return score > 0 && (best <= 0 || score >= best*0.1) }

// bondBudgetFit: how many candidates fit a budget (1 MB each way per candidate).
func bondBudgetFit(n, budget int) int { return min(n, max(budget/2, 1)) }

// bondCandidatesPlan: "carrier peer" pairs for every planned carrier the bond lacks. icmp has
// no listen port and uses the bare peer; shaped carriers and portless entries are skipped
// (the engine refuses a shaped leg in a bond).
func bondCandidatesPlan(cur, pd, addr, sni string) [][2]string {
	have := " " + strings.ReplaceAll(cur, "+", " ") + " "
	var out [][2]string
	if !strings.Contains(have, " icmp ") && !strings.Contains(addr, ":") {
		out = append(out, [2]string{"icmp", addr})
	}
	for _, x := range strings.Split(pd, ",") {
		c, p := strings.SplitN(x, ":", 2)[0], x[strings.LastIndex(x, ":")+1:]
		if c == "" || strings.Contains(have, " "+c+" ") || IsShapedCarrier(c) || !isDigits(p) || atoi(p) < 1 || atoi(p) > 65535 {
			continue
		}
		h := addr
		if sni != "" && (c == "ws" || c == "wss" || c == "grpc") {
			h = sni
		}
		out = append(out, [2]string{c, JoinHP(h, p)})
	}
	return out
}

// bondPeerFor: the address a throw-away probe of carrier c dials (peer-<c>, the auto plan, else peer).
func bondPeerFor(n, c string) string {
	if p := Cfg(n, "peer-"+c); p != "" {
		return p
	}
	addr := Cfg(n, "peer")
	if t, err := readAutoTok(n); err == nil && t.Auto != "" {
		if p := planPort(planPart(t.Auto, "d"), c); p != "" && c != "icmp" {
			return JoinHP(t.Peer, p)
		}
		addr = t.Peer
	}
	return addr
}

// bondRetestJob probes the bond's carriers plus the last failures and adds one that works now.
// A bond leg is never removed here.
func bondRetestJob(n string) bool {
	log := func(s string) { envLogger("wattun-bondretest", n+s) }
	if !cfgFileExists(n) {
		Err("No tunnel named '" + n + "'.")
		return false
	}
	if Role(n) != "Iran" {
		Err("Bond auto-retest runs on Iran (the side that dials the bond), not on Kharej.")
		return false
	}
	cur := Cfg(n, "carrier")
	if !isBond(cur) {
		Err("'" + n + "' is not bonded (carrier '" + cur + "' has no '+'); nothing to re-test.")
		return false
	}
	if IsReverse(n) {
		Err("Bond auto-retest does not support a reverse bond: Kharej is the dialing side there.")
		return false
	}
	legs := strings.Split(cur, "+")
	prev, sni := bondFailGet(n), Cfg(n, "sni")
	var curPairs, candPairs [][2]string
	for _, c := range legs {
		curPairs = append(curPairs, [2]string{c, bondPeerFor(n, c)})
	}
	if t, err := readAutoTok(n); err == nil && t.Auto != "" {
		candPairs = bondCandidatesPlan(cur, planPart(t.Auto, "d"), t.Peer, sni)
	}
	have := func(c string) bool {
		for _, p := range append(append([][2]string{}, curPairs...), candPairs...) {
			if p[0] == c {
				return true
			}
		}
		return false
	}
	for _, c := range splitList(prev) {
		if !have(c) {
			candPairs = append(candPairs, [2]string{c, bondPeerFor(n, c)})
		}
	}
	pairs := append(append([][2]string{}, curPairs...), candPairs...)
	budget := atoi(ConfGet("bondretest-budget", ""))
	if budget <= 0 {
		budget = bondRetestBudgetMB
	}
	nfit := bondBudgetFit(len(pairs), budget)
	if nfit < len(pairs) && len(curPairs) >= nfit && len(candPairs) > 0 {
		if nfit >= 2 { // one leg sets the bar, then the candidates, then the other legs
			pairs = append(append(append([][2]string{}, curPairs[0]), candPairs...), curPairs[1:]...)
		} else {
			pairs = append(append([][2]string{}, candPairs...), curPairs...)
		}
	}
	if nfit < len(pairs) {
		log(fmt.Sprintf(": traffic budget %d MB, probing %d of %d carriers", budget, nfit, len(pairs)))
	}
	// probes are throw-away clients with this tunnel's key and settings: the live bond is untouched
	key := strings.TrimSpace(mustRead(filepath.Join(P.Conf, n+".key")))
	kd, err := atPrep(key)
	if err != nil {
		Err("Could not prepare the test directory.")
		return false
	}
	defer kd.cleanup()
	atKeyFile, atTok = kd.dir+"/key", Token{Path: orStr(Cfg(n, "path"), "/wat"), Icmp: Cfg(n, "icmp-type")}
	defer func() { atKeyFile = "" }()
	atQuiet, atMB, atStop, atSkip, atAct = true, 1, false, "", ""
	av, ar = nil, nil
	fp, ech, frag, fs, fm := Cfg(n, "fp"), Cfg(n, "ech"), Cfg(n, "tls-frag"), Cfg(n, "fake-sni"), Cfg(n, "fake-mode")
	isLeg := func(c string) bool {
		for _, l := range legs {
			if l == c {
				return true
			}
		}
		return false
	}
	best, total := 0.0, 0
	var added, failed, tested []string
	candPeer := map[string]string{}
	for i, p := range pairs {
		if i >= nfit {
			break
		}
		c, peer := p[0], p[1]
		candPeer[c] = peer
		if IsPool(c) {
			avAdd(c, c, "d", peer, "", sni, fp, ech, frag, fs, fm, "")
		} else {
			avAdd(c, c, "d", peer, "", "", "", "", "", "", "", "")
		}
		k := len(av) - 1
		atProbe(k, 8)
		tested = append(tested, c)
		total += 2 * atMB
		r := ar[k]
		switch {
		case isLeg(c) && r.OK: // a bond leg: never removed, only its speed sets the bar for a new path
			best = max(best, atScore(k))
			log(fmt.Sprintf("/%s (in the bond): %.1f down / %.1f up MB/s", c, r.Down, r.Up))
		case isLeg(c):
			log("/" + c + " (in the bond): failed, " + r.Why + "; it stays in the bond")
		case r.OK && bondWorth(atScore(k), best):
			added = append(added, c)
			log(fmt.Sprintf("/%s works now: %.1f down / %.1f up MB/s, adding it to the bond", c, r.Down, r.Up))
		case r.OK:
			log("/" + c + " works but is too slow next to the bond; not adding it")
		default:
			failed = append(failed, c)
			log("/" + c + " failed: " + r.Why)
		}
	}
	if len(added) > 0 {
		nw := cur + "+" + strings.Join(added, "+")
		ok := VCarrierList(nw) // never write/restart into a carrier list the engine refuses
		for _, a := range added {
			ok = ok && carrierOkHere(a)
		}
		if !ok {
			log(": '" + nw + "' is not a carrier list this engine can run; keeping the bond unchanged")
			added = nil
		} else {
			for _, a := range added {
				if candPeer[a] != "" {
					SetValue(n, "peer-"+a, candPeer[a])
				}
			}
			SetValue(n, "carrier", nw)
			log(": adding " + strings.Join(added, " ") + " to the bond (" + cur + " -> " + nw + "), restarting the tunnel")
			_ = Restart(Unit(n))
			Ok("Added " + strings.Join(added, " ") + " to '" + n + "' (bond now " + nw + "). The tunnel restarted.")
		}
	}
	if len(added) == 0 {
		msg := "No carrier to add: the bond keeps its legs"
		if prev != "" {
			msg += " (still failing: " + prev + ")"
		}
		Ok(msg + ".")
	}
	nf := bondFailNext(prev, cur, strings.Join(tested, " "), strings.Join(failed, " "))
	bondFailSet(n, nf)
	if nf != "" {
		log(": retrying next run: " + nf)
	}
	log(fmt.Sprintf(": probed %s (%d MB of test traffic)", strings.Join(tested, " "), total))
	return true
}

// ---- the Bonding screen ----

func bondingMenu(n string) {
	r := Role(n)
	tok, terr := readAutoTok(n)
	isAuto := r == "Iran" && terr == nil && tok.Auto != ""
	sel := 0
	ClearScreen()
	for {
		cr := Cfg(n, "carrier")
		ti := tinfo(n)
		brVis := bondRetestVisible(r, cr)
		items := []Item{{Key: "m", Label: "Bond mode", Desc: orStr(Cfg(n, "bond-mode"), "balanced")}}
		acts := []string{"mode"}
		if brVis {
			items = append(items, Item{Key: "r", Label: "Auto-retest", Desc: bondRetestGet(n) + GRY + " · re-test blocked paths" + RST})
			acts = append(acts, "retest")
		}
		items = append(items,
			Item{Key: "t", Label: "Mute or unmute a path"},
			Item{Key: "a", Label: "Add a carrier", Desc: "auto tunnels on Iran"},
			Item{Key: "d", Label: "Remove a carrier", Desc: "auto tunnels on Iran"})
		acts = append(acts, "mute", "add", "del")
		i, k := Choose(func(w io.Writer) { Title(w, "Bonding", n+" · "+cr); bondPaths(w, ti) }, items, &sel,
			[]string{"⏎", "change", "esc", "back"}, 2*time.Second)
		if i < 0 {
			if k == "esc" || k == "q" || k == "eof" {
				return
			}
			continue // tick: redraw the live path table
		}
		fmt.Fprintln(Stdout)
		restart := func(q string) {
			if Confirm(q, true) {
				step("Restarting "+Unit(n), func() bool { return Restart(Unit(n)) == nil })
			}
		}
		switch acts[i] {
		case "retest":
			Hint("Re-tests every leg plus the last failures; never removes a working leg. A carrier that works again is added only when it reaches 10 % of the best working leg.")
			if AskOK("Re-test: off, 30m, 1h, 6h or daily-offpeak", bondRetestGet(n), func(s string) bool {
				if bondRetestOK(s) == "" {
					Err("Use off, 30m, 1h, 6h or daily-offpeak.")
					return false
				}
				return true
			}) {
				bondRetestSet(n, ReplyV)
			}
		case "mute":
			if len(ti.Cars) == 0 {
				Hint("No path data: the tunnel is stopped or has one carrier.")
				break
			}
			names := make([]Item, len(ti.Cars))
			for j, c := range ti.Cars {
				st := "up"
				if c.Muted == "true" {
					st = "muted"
				} else if c.Alive != "true" {
					st = "down"
				}
				names[j] = Item{Label: c.Name, Desc: st}
			}
			ps := 0
			ClearScreen()
			j, _ := Choose(func(w io.Writer) { Title(w, "Mute or unmute", n) }, names, &ps, []string{"⏎", "toggle", "esc", "back"}, 0)
			if j >= 0 {
				want := "mute"
				if ti.Cars[j].Muted == "true" {
					want = "unmute"
				}
				carrierToggle(want, n, ti.Cars[j].Name)
			}
		case "mode":
			modes := []Item{
				{Label: "balanced", Desc: "weighted round-robin by path capacity"},
				{Label: "active-backup", Desc: "all on the primary path, fast cutover to the next"},
				{Label: "replicate", Desc: "datagrams on every path, for zero loss"},
			}
			ms := 0
			ClearScreen()
			j, _ := Choose(func(w io.Writer) { Title(w, "Bond mode", n) }, modes, &ms, []string{"⏎", "set", "esc", "back"}, 0)
			if j < 0 {
				continue
			}
			SetValue(n, "bond-mode", modes[j].Label)
			Ok("Set bond-mode: " + modes[j].Label)
			restart("Restart '" + n + "' to apply the mode?")
		case "add":
			if !isAuto {
				Warn("Adding a carrier here is for auto tunnels on Iran: the plan already made Kharej listen on every type.")
				Hint("A hand-made bond needs peer-<carrier> and listen-<carrier> in Advanced YAML (tunnel page, o).")
				Hint("To get a bond the easy way: make an auto tunnel on Kharej, then join the tested types on Iran (tunnel page, m).")
				break
			}
			pd := planPart(tok.Auto, "d")
			if !AskOK("Carrier to add (in the plan: "+orStr(pd, "none")+")", "tls", func(s string) bool { return s != "" }) {
				continue
			}
			nc := ReplyV
			switch {
			case !CarrierOK(nc):
				Err("Unknown carrier '" + nc + "' (use icmp, udp, tcp, tls, ws, wss, h2, h2c, grpc, gre, ipip or an F19 shape).")
			case IsShapedCarrier(nc):
				Err("F19 shaped carriers are single-carrier only (the engine refuses a shaped leg in a '+'-bond).")
			case strings.Contains("+"+cr+"+", "+"+nc+"+"):
				Warn("Carrier '" + nc + "' is already in carrier list '" + cr + "'.")
			case nc == "icmp":
				if strings.Contains(tok.Peer, ":") && !isIPv4(tok.Peer) {
					Err("icmp requires an IPv4/hostname peer.")
					break
				}
				SetValue(n, "peer-icmp", tok.Peer)
				SetValue(n, "carrier", cr+"+icmp")
				Ok("Updated carrier: " + Cfg(n, "carrier"))
				restart("Restart '" + n + "' to apply the new bond?")
			default:
				p := planPort(pd, nc)
				if p == "" {
					Err("Carrier '" + nc + "' is not in this tunnel's auto plan, so Kharej does not listen for it.")
					break
				}
				SetValue(n, "peer-"+nc, JoinHP(tok.Peer, p))
				SetValue(n, "carrier", cr+"+"+nc)
				Ok("Updated carrier: " + Cfg(n, "carrier"))
				if !IsPool(nc) && Cfg(n, "fake-sni")+Cfg(n, "pool-rotate")+Cfg(n, "pool-rotate-bytes") != "" {
					Warn("The " + nc + " leg carries no fake-SNI or rotation: only tcp/tls/ws/wss/h2/h2c/grpc legs are disguised.")
				}
				restart("Restart '" + n + "' to apply the new bond?")
			}
		case "del":
			if !isAuto {
				Warn("Removing a carrier here is for auto tunnels on Iran; for a hand-made bond edit the YAML (tunnel page, o).")
				break
			}
			legs := strings.Split(cr, "+")
			if len(legs) < 2 {
				Err("Cannot remove the only carrier.")
				break
			}
			li := make([]Item, len(legs))
			for j, l := range legs {
				li[j] = Item{Label: l}
			}
			ls := 0
			ClearScreen()
			j, _ := Choose(func(w io.Writer) { Title(w, "Remove a carrier", n+" · "+cr) }, li, &ls, []string{"⏎", "remove", "esc", "back"}, 0)
			if j < 0 {
				continue
			}
			rc := legs[j]
			SetValue(n, "carrier", strings.Join(append(legs[:j:j], legs[j+1:]...), "+"))
			UnsetValue(n, "peer-"+rc)
			Ok("Updated carrier: " + Cfg(n, "carrier"))
			restart("Restart '" + n + "' to apply?")
		}
		Pause()
		ClearScreen()
	}
}

// bondPaths draws the live per-path table of a bond.
func bondPaths(w io.Writer, ti *tunnelInfo) {
	if len(ti.Cars) == 0 {
		hintLine(w, "No path data: the tunnel is stopped or has one carrier.")
		fmt.Fprintln(w)
		return
	}
	fmt.Fprintf(w, "  %s%-12s %-8s %8s %7s %6s%s\n", GRY, "path", "state", "rtt", "loss", "share", RST)
	for _, c := range ti.Cars {
		col, dot, st := GRN, "●", "up"
		if c.Muted == "true" {
			col, dot, st = GRY, "○", "muted"
		} else if c.Alive != "true" {
			col, dot, st = RED, "○", "down"
		}
		fmt.Fprintf(w, "  %-12s %s%s %-6s%s %5.0f ms %6.1f%% %5.0f%%\n", c.Name, col, dot, st, RST,
			parseF(c.RTT), parseF(c.Loss)*100, parseF(c.Share)*100)
	}
	fmt.Fprintln(w)
}
