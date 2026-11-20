// Port of the anti-censor carrier matrix: ac_matrix_cmd / ac_matrix / ac_matrix_apply
// / ac_load plus the at_* probe helpers it uses (at_prep, at_start, at_wait, at_probe,
// at_measure, at_curl, at_kill, at_busy/at_idle/at_print, at_rank, at_table,
// at_peak_update, at_probe_mb, auto_refine). The flow is the bash's: build the variant
// list from the running tunnel, probe each with a throw-away client on a free metrics
// port, rank, re-measure the top 3 bigger, then offer to apply the best (restart via
// systemd).

package mgr

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- constants (verbatim from the bash) ----

const acSNIS = "mci.ir,irancell.ir,tci.ir,divar.ir" // curated allowlisted SNIs
const acModes = "seq seqsum sum ttl rst synrst paws"

// AC_ALLMODES (H6): the single mode list shared by the validator and the matrix.

const removed_atScreenMBStart = 8
const removed_atScreenCapMB = 16
const atFinalMBMin = 20
const removed_atFinalMBMax = 40

// ac_mode_ok(): 1 when the installed wattun knows the mode.
func acModeOK(mode, binVer string) bool {
	switch mode {
	case "seq", "sum", "ttl":
		return true
	case "seqsum":
		return verGE(binVer, "2.8.0")
	case "rst":
		return verGE(binVer, "2.9.0")
	case "split", "hlen0", "fakeip", "synrst", "ff":
		return verGE(binVer, "2.10.5")
	case "paws":
		return verGE(binVer, "3.0.2")
	}
	return false
}

// ver_ge(): $1 >= $2, dotted versions.
func verGE(a, b string) bool {
	pa, pb := verParts(a), verParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return true
}

func verParts(v string) [3]int {
	var p [3]int
	for i, s := range strings.SplitN(v, ".", 3) {
		p[i], _ = strconv.Atoi(s)
	}
	return p
}

// binVer: `wattun -version` (empty when unknown) — one shared helper lives in
// BinVersion (sysd.go); this var stays so tests can pin the version.
var binVer = func() string { return BinVersion() }

// wattunBin: the engine binary path from P1's path set ($WAT_BIN honoured there).
func wattunBin() string {
	if P.Bin != "" {
		return P.Bin
	}
	return "/usr/local/bin/wattun"
}

// at_probe_mb(): start 8, x4 until >= min-secs at that rate, capped.
func atProbeMB(rate float64, minSecs float64, cap int) int {
	mb := atScreenMBStart
	if cap < atScreenMBStart {
		cap = atScreenMBStart
	}
	if rate <= 0 {
		return mb
	}
	for mb < cap && float64(mb)/rate < minSecs {
		mb *= 4
	}
	if mb > cap {
		mb = cap
	}
	return mb
}

// ---- variants (av_add / av_key / av_anti) ----

type variant struct {
	Label, Car, Kind, Peer, Port, SNI, FP, ECH, Frag, FS, FM, X string
}

func avAnti(v variant) bool {
	return v.Kind == "d" && (v.FS != "" || v.FP != "" || v.ECH != "" || v.Frag != "")
}

func avKey(v variant) string {
	if strings.Contains(v.Car, "+") {
		if v.Kind == "r" {
			return "bond/r"
		}
		return "bond"
	}
	k := v.Car + "/" + v.Kind
	if avHop(v) != "" {
		k += "/hop"
	}
	if avAnti(v) {
		k += "/" + v.FS + "-" + v.FM + "-" + v.FP + "-" + v.ECH + "-" + v.Frag
	}
	return k
}

// ac_matrix variant list, in the bash's exact order (0..5).
func matrixPlan(n, car, peer, sni, binVer string, cfg func(string) string, fallback bool) []variant {
	var vs []variant
	add := func(label, car, kind, peer, port, sni, fp, ech, frag, fs, fm string) {
		vs = append(vs, variant{label, car, kind, peer, port, sni, fp, ech, frag, fs, fm, ""})
	}
	legs := []string{car}
	bond := false
	if strings.Contains(car, "+") {
		bond = true
		legs = legs[:0]
		for _, l := range strings.Split(car, "+") {
			if IsPool(l) {
				legs = append(legs, l)
			}
		}
	}
	snis := strings.Split(acSNIS, ",")
	first := snis[0]
	rest := snis[1:]
	tlsLeg := ""
	for _, leg := range legs {
		tag := ""
		if bond {
			tag = leg + " "
		}
		lpeer := peer
		if bond {
			if p := cfg("peer-" + leg); p != "" {
				lpeer = p
			}
		}
		if lpeer == "" {
			continue
		}
		// 0. baseline: this leg as the tunnel runs now (no desync)
		add(tag+"base (no desync)", leg, "d", lpeer, "", sni, "", "", "", "", "")
		// 1. every fake-mode for the first curated SNI
		for _, fm := range strings.Fields(acModes) {
			if !acModeOK(fm, binVer) {
				continue
			}
			add(tag+"desync "+first+" → "+fm, leg, "d", lpeer, "", sni, "", "", "", first, fm)
		}
		// 2. rst against every other curated SNI
		if acModeOK("rst", binVer) {
			for _, fs := range rest {
				if fs == "" {
					continue
				}
				add(tag+"desync "+fs+" → rst", leg, "d", lpeer, "", sni, "", "", "", fs, "rst")
			}
		}
		// 2b. the Cloudflare edge name with rst/synrst
		for _, fm := range []string{"rst", "synrst"} {
			if !acModeOK(fm, binVer) {
				continue
			}
			add(tag+"desync www.cloudflare.com → "+fm, leg, "d", lpeer, "", sni, "", "", "", "www.cloudflare.com", fm)
		}
		if tlsLeg == "" {
			switch leg {
			case "tls", "wss", "h2", "grpc":
				tlsLeg = leg
			}
		}
	}
	// 3. ECH ladder (TLS carriers only)
	if tlsLeg != "" && cfg("ech") == "" && verGE(binVer, "2.9.0") {
		tag, lpeer := "", peer
		if bond {
			tag = tlsLeg + " "
			if p := cfg("peer-" + tlsLeg); p != "" {
				lpeer = p
			}
		}
		if lpeer != "" {
			add(tag+"ech ladder (no desync)", tlsLeg, "d", lpeer, "", sni, "chrome", "auto", "", "", "")
		}
	}
	// 4. auto mode
	if len(legs) > 0 && verGE(binVer, "2.9.0") {
		leg, tag, lpeer := legs[0], "", peer
		if bond {
			tag = leg + " "
			if p := cfg("peer-" + leg); p != "" {
				lpeer = p
			}
		}
		if lpeer != "" {
			add(tag+"desync auto-probe", leg, "d", lpeer, "", sni, "", "", "", first, "auto")
		}
	}
	// 5. native ICMP fallback (emergency ladder)
	if fallback && car != "icmp" && peer != "" {
		icmpPeer := peer
		if i := strings.LastIndex(icmpPeer, ":"); i >= 0 {
			icmpPeer = icmpPeer[:i]
		}
		add("fallback ICMP echo", "icmp", "d", icmpPeer, "", "", "", "", "", "", "")
	}
	return vs
}

// ---- results (AR_*) and ranking (at_rank, speed policy + anti-censor 0.92 penalty) ----

type result struct {
	OK            bool
	Down, Up, RTT float64
	Why           string
}

func atRank(vs []variant, rs []result, policy string) []int {
	type row struct {
		k1, k2 float64
		i      int
	}
	var rows []row
	for i := range vs {
		if !rs[i].OK {
			continue
		}
		pen := 1.0
		if avAnti(vs[i]) {
			pen = 0.92 // an anti-censor variant must beat the plain type by 8 %
		}
		switch policy {
		case "latency":
			rows = append(rows, row{rs[i].RTT, rs[i].Down + rs[i].Up, i})
		case "direct":
			dp := 0.0
			switch vs[i].Car {
			case "tcp", "tls", "udp", "icmp":
				if vs[i].Kind == "d" {
					dp = 1
				}
			}
			rows = append(rows, row{dp, rs[i].Down + rs[i].Up, i})
		default: // bond|speed
			rows = append(rows, row{(rs[i].Down + rs[i].Up) * pen, rs[i].RTT, i})
		}
	}
	sort.SliceStable(rows, func(a, b int) bool {
		if policy == "latency" {
			if rows[a].k1 != rows[b].k1 {
				return rows[a].k1 < rows[b].k1
			}
			return rows[a].k2 > rows[b].k2
		}
		if policy == "direct" {
			if rows[a].k1 != rows[b].k1 {
				return rows[a].k1 > rows[b].k1
			}
			if rows[a].k2 != rows[b].k2 {
				return rows[a].k2 > rows[b].k2
			}
			return rows[a].i < rows[b].i
		}
		if rows[a].k1 != rows[b].k1 {
			return rows[a].k1 > rows[b].k1
		}
		if rows[a].k2 != rows[b].k2 {
			return rows[a].k2 < rows[b].k2
		}
		return rows[a].i < rows[b].i
	})
	out := make([]int, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.i)
	}
	return out
}

// at_lbl(): truncated with .. when longer than max.
func atLbl(s string, max int) string {
	if len(s) > max {
		return s[:max-2] + ".."
	}
	return s
}

// ---- probe runtime (at_prep/at_start/at_wait/at_measure/at_kill) ----

type matrixRun struct {
	dir string // temp dir with the key file (at_prep)
	pid *exec.Cmd
}

func atPrep(key string) (*matrixRun, error) {
	dir, err := os.MkdirTemp("", "wattun-matrix-*")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(dir+"/key", []byte(key+"\n"), 0o600); err != nil {
		return nil, err
	}
	return &matrixRun{dir: dir}, nil
}

func (m *matrixRun) cleanup() {
	if m.pid != nil && m.pid.Process != nil {
		_ = m.pid.Process.Kill()
	}
	_ = os.RemoveAll(m.dir)
}

// at_free_port(): first free TCP port from 20500 (bind check).
func atFreePort(start int, exclude map[int]bool) (int, bool) {
	for p := start; p < 21000; p++ {
		if exclude[p] {
			continue
		}
		c, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			c.Close()
			return p, true
		}
	}
	return 0, false
}

// at_alive(): /stats alive on the probe's metrics port.
func atAlive(mp int) bool {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/stats", mp))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var st map[string]any
	if json.NewDecoder(resp.Body).Decode(&st) != nil {
		return false
	}
	return get(st, "alive") == "true"
}

// at_start(): the throw-away client of variant i (no published -map besides the dummy).
func (m *matrixRun) atStart(i int, vs []variant, mp, dmap int, tPath, tIcmp string) error {
	v := vs[i]
	a := []string{"-mode", "client", "-carrier", v.Car, "-key-file", m.dir + "/key",
		"-peer", v.Peer, "-metrics", fmt.Sprintf("127.0.0.1:%d", mp)}
	hasWS, hasICMP := false, false
	for _, c := range strings.Split(v.Car, "+") {
		switch c {
		case "ws", "wss", "h2", "h2c", "grpc":
			hasWS = true
		case "icmp":
			hasICMP = true
		}
	}
	if hasWS {
		p := tPath
		if p == "" {
			p = "/wat"
		}
		a = append(a, "-path", p)
	}
	if hasICMP && tIcmp != "" {
		a = append(a, "-icmp-type", tIcmp)
	}
	if v.SNI != "" {
		a = append(a, "-sni", v.SNI, "-host", v.SNI)
	}
	if v.FP != "" {
		a = append(a, "-fp", v.FP)
	}
	if v.ECH != "" {
		a = append(a, "-ech", v.ECH)
	}
	if v.Frag != "" && v.Frag != "0" {
		a = append(a, "-tls-frag", v.Frag)
	}
	if v.FS != "" {
		a = append(a, "-fake-sni", v.FS)
		if v.FM != "" {
			a = append(a, "-fake-mode", v.FM)
		}
	}
	a = append(a, "-map", fmt.Sprintf("%d:1@127.0.0.1", dmap))
	cmd := exec.Command(wattunBin(), a...)
	cmd.Stdout, _ = os.Create(m.dir + fmt.Sprintf("/client.%d.log", i))
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	m.pid = cmd
	return nil
}

func (m *matrixRun) atKill() {
	if m.pid != nil && m.pid.Process != nil {
		_ = m.pid.Process.Kill()
		_, _ = m.pid.Process.Wait()
	}
	m.pid = nil
}

// at_wait(): poll alive until the deadline.
func (m *matrixRun) atWait(mp int, secs int) bool {
	end := time.Now().Add(time.Duration(secs) * time.Second)
	for time.Now().Before(end) {
		if atAlive(mp) {
			return true
		}
		if m.pid != nil && m.pid.Process != nil && m.pid.ProcessState != nil && m.pid.ProcessState.Exited() {
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// at_measure(): down then up speed test on the running probe client.
func (m *matrixRun) atMeasure(mp, mb int) (result, string) {
	var r result
	for _, dir := range []string{"down", "up"} {
		c := &http.Client{Timeout: time.Duration(max20(mb*2)) * time.Second}
		resp, err := c.Get(speedtestURL(fmt.Sprintf("127.0.0.1:%d", mp), dir, mb))
		if err != nil {
			return r, "speed test failed/stalled"
		}
		var sr speedtestResult
		err = json.NewDecoder(resp.Body).Decode(&sr)
		resp.Body.Close()
		if err != nil || !sr.OK {
			return r, "speed test failed/stalled"
		}
		if dir == "down" {
			r.Down = sr.MBPerS
		} else {
			r.Up = sr.MBPerS
		}
	}
	// rtt from the probe's /stats
	c := &http.Client{Timeout: 2 * time.Second}
	if resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/stats", mp)); err == nil {
		var st map[string]any
		if json.NewDecoder(resp.Body).Decode(&st) == nil {
			r.RTT = getFFlat(st, "rtt_ms", "srtt_ms")
		}
		resp.Body.Close()
	}
	r.OK = true
	return r, ""
}

func max20(v int) int {
	if v > 20 {
		return v
	}
	return 20
}

// ---- the screen: ac_matrix_cmd ----

// MatrixCmd: port of ac_matrix_cmd(). Probes are real only when startProbes is true;
// the plan/rank/table path is pure so tests pin the order and layout.
func MatrixCmd(name string, w io.Writer, startProbes bool) bool {
	n := name
	if roleName(n) != "Iran" {
		errLine(w, fmt.Sprintf("'%s' is not an Iran tunnel (the matrix runs client-side).", n))
		return false
	}
	if IsReverse(n) {
		errLine(w, fmt.Sprintf("'%s' is a reverse tunnel; the desync matrix needs a normal Iran tunnel.", n))
		return false
	}
	cr := p1Cfg(n, "carrier")
	if !IsPoolList(cr) {
		if cr == "icmp" {
			errLine(w, "The desync kit does not attach to the icmp carrier (its camouflage is the ICMP shape itself).")
			hintLine(w, "For icmp the resilience knob is the volume governor: wattun-manager blackout "+n+"  # or tunnel page -> o -> k")
			if p1Cfg(n, "governor") == "true" {
				hintLine(w, "The governor is already ON for '"+n+"'.")
			}
		} else {
			errLine(w, fmt.Sprintf("Carrier '%s' has no anti-censorship layer (only tcp, tls, ws, wss, h2, h2c, grpc, alone or bonded).", cr))
		}
		return false
	}
	// ac_load(): key/peer from the running tunnel
	kf := p1Cfg(n, "key-file")
	if !fileReadable(kf) {
		kf = "/etc/wattun/" + n + ".key"
	}
	tCarrier, tPeer, tPath, tSNI, tIcmp := p1Cfg(n, "carrier"), p1Cfg(n, "peer"), p1Cfg(n, "path"), p1Cfg(n, "sni"), p1Cfg(n, "icmp-type")
	if tSNI == "" {
		tSNI = p1Cfg(n, "host")
	}
	tKey := ""
	if b, err := os.ReadFile(kf); err == nil {
		tKey = strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
	}
	if tKey == "" || tPeer == "" {
		errLine(w, fmt.Sprintf("Cannot read the key/peer of '%s'.", n))
		return false
	}
	bv := binVer()
	if !verGE(bv, "2.7.0") {
		errLine(w, "The desync matrix needs wattun 2.7.0 or newer (run: wattun-manager update).")
		return false
	}
	pageHeader(w, "Anti-censor matrix", fmt.Sprintf("%s (%s)", n, cr))
	hintLine(w, "Probing local desync/ECH combinations · live tunnel untouched")
	fmt.Fprintln(w)

	cfgFn := func(key string) string { return p1Cfg(n, key) }
	vs := matrixPlan(n, tCarrier, tPeer, tSNI, bv, cfgFn, false)
	rs := make([]result, len(vs))
	atMB := atScreenMBStart
	if startProbes {
		m, err := atPrep(tKey)
		if err != nil {
			errLine(w, "Could not prepare the test.")
			return false
		}
		defer m.cleanup()
		secHdr(w, "Matrix", fmt.Sprintf("%d combinations", len(vs)))
		for i := range vs {
			r, _ := m.probeOne(i, vs, atMB, tPath, tIcmp)
			rs[i] = r
			atPrint(w, i, vs, rs, atMB)
		}
		// auto_refine: re-measure the top 3 with 16 streams and a sustained run
		rank := atRank(vs, rs, "speed")
		var top []int
		for _, i := range rank {
			if len(top) == 3 {
				break
			}
			top = append(top, i)
		}
		if len(top) > 0 {
			secHdr(w, fmt.Sprintf("Confirming top %d", len(top)), "16 streams")
			for _, i := range top {
				rate := rs[i].Down
				if rs[i].Up > rate {
					rate = rs[i].Up
				}
				mb := atProbeMB(rate, 1.5, atFinalMBMax)
				if mb < atFinalMBMin {
					mb = atFinalMBMin
				}
				r, _ := m.probeOne(i, vs, mb, tPath, tIcmp)
				if r.OK {
					rs[i] = r // a failed re-measure keeps the screening numbers
				}
			}
		}
	}
	rank := atRank(vs, rs, "speed")
	atTable(w, vs, rs, rank, atMB, 0)
	if len(rank) == 0 {
		fmt.Fprintln(w)
		errLine(w, "Nothing connects (even baseline failed — likely L3/IP block)")
		hintLine(w, " · Switch carrier ([m]), use CDN (cdn-tune), or wait out blackout")
		return false
	}
	best := rank[0]
	fmt.Fprintln(w)
	okLine(w, fmt.Sprintf("Best: %s (%.1f/%.1f MB/s)", vs[best].Label, rs[best].Down, rs[best].Up))
	cur := fmt.Sprintf("fs=%s fm=%s", p1Cfg(n, "fake-sni"), p1Cfg(n, "fake-mode"))
	want := fmt.Sprintf("fs=%s fm=%s", vs[best].FS, vs[best].FM)
	if p1Cfg(n, "fake-ttl") != "" {
		cur += " ttl=" + p1Cfg(n, "fake-ttl")
	}
	if vs[best].ECH != "" {
		cur += " ech=" + p1Cfg(n, "ech")
		want += " ech=" + vs[best].ECH
	}
	if cur == want {
		okLine(w, "The running tunnel already uses this combination; nothing to change.")
		return true
	}
	if p1Confirm(fmt.Sprintf("Apply '%s' to '%s'? (restarts the tunnel, open connections drop)", vs[best].Label, n), true) {
		// ac_matrix_apply: the desync keys go through the config writer, the unit restarts
		applyMatrixVariant(n, vs[best])
		if strings.Contains(cr, "+") {
			hintLine(w, fmt.Sprintf("The fake-SNI and mode now apply to every pool leg of '%s'.", cr))
		}
	} else {
		warnLine(w, "No change.")
	}
	return true
}

// probeOne: at_probe for one direct variant — free ports, start, wait 8 s, measure, kill.
func (m *matrixRun) probeOne(i int, vs []variant, mb int, tPath, tIcmp string) (result, string) {
	mp, ok := atFreePort(20500, nil)
	if !ok {
		return result{}, "no free test port"
	}
	dmap, ok := atFreePort(mp+1, map[int]bool{mp: true})
	if !ok {
		return result{}, "no free test port"
	}
	if err := m.atStart(i, vs, mp, dmap, tPath, tIcmp); err != nil {
		return result{}, "no free test port"
	}
	if !m.atWait(mp, 8) {
		m.atKill()
		return result{}, "no link in 8 s"
	}
	r, why := m.atMeasure(mp, mb)
	m.atKill()
	return r, why
}

// applyMatrixVariant: the config writes of ac_matrix_apply — desync keys via P1's
// atomic SetValue/UnsetValue (the matrix probes always run ttl auto-calibration).
func applyMatrixVariant(n string, v variant) {
	if v.FS != "" {
		_ = SetValue(n, "fake-sni", v.FS)
		_ = SetValue(n, "fake-mode", fmDefault(v.FM))
	} else {
		_ = UnsetValue(n, "fake-sni")
		_ = UnsetValue(n, "fake-mode")
	}
	_ = UnsetValue(n, "fake-ttl")
	if v.ECH != "" {
		_ = SetValue(n, "ech", v.ECH)
	}
	_ = p1Systemctl("restart", Unit(n))
}

// at_print(): one result line, ✓/✗ with the bash's columns.
func atPrint(w io.Writer, i int, vs []variant, rs []result, mb int) {
	if rs[i].OK {
		pk := rs[i].Down
		if rs[i].Up > pk {
			pk = rs[i].Up
		}
		fmt.Fprintf(w, "  %s✓%s %-24s %s%6.1f%s ↓  %6.1f ↑  %4.0f ms  %s\n",
			GRN, RST, atLbl(vs[i].Label, 24), BOLD, rs[i].Down, RST, rs[i].Up, rs[i].RTT, tbar(pk, 10, 10))
	} else {
		fmt.Fprintf(w, "  %s✗%s %-24s %s%s%s\n", RED, RST, atLbl(vs[i].Label, 24), GRY, rs[i].Why, RST)
	}
}

// at_table(): the ranked results box (wide form, BOXW >= 66).
func atTable(w io.Writer, vs []variant, rs []result, rank []int, mb, secs int) {
	peak := 10.0
	for _, i := range rank {
		if pk := maxF(rs[i].Down, rs[i].Up); pk > peak {
			peak = pk
		}
	}
	fmt.Fprintln(w)
	title := fmt.Sprintf("Results · %d working", len(rank))
	if secs > 0 {
		title += fmt.Sprintf(" · %d s", secs)
	}
	boxTop(w, title)
	if len(rank) > 0 {
		hdr := fmt.Sprintf("%s %2s  %-22s %6s %6s %6s%s", GRY, "#", "Carrier", "Down", "Up", "RTT", RST)
		boxRow(w, hdr)
		for k, i := range rank {
			pk := maxF(rs[i].Down, rs[i].Up)
			bar := "  " + tbarC(pk, peak, 10)
			line := fmt.Sprintf("%2d  %-22s %6.1f %6.1f %4.0fms", k+1, atLbl(vs[i].Label, 22), rs[i].Down, rs[i].Up, rs[i].RTT)
			if k == 0 {
				boxRow(w, BOLD+CYN+"▸"+line+RST+bar+"  "+CYN+"★"+RST)
			} else {
				boxRow(w, " "+line+bar)
			}
		}
	}
	hasFail := false
	for i := range vs {
		if !rs[i].OK && rs[i].Why != "skipped" {
			hasFail = true
			break
		}
	}
	if hasFail {
		if len(rank) > 0 {
			boxMid(w)
		}
		for i := range vs {
			if rs[i].OK || rs[i].Why == "skipped" {
				continue
			}
			boxRow(w, fmt.Sprintf("  %s✗%s  %-22s %s%s%s", RED, RST, atLbl(vs[i].Label, 22), GRY, atLbl(rs[i].Why, boxW-30), RST))
		}
	}
	boxBot(w)
	hintLine(w, fmt.Sprintf("%d MB/probe · %d s", mb, secs))
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// the engine defaults fake-mode to seq when the key is absent
func fmDefault(fm string) string {
	if fm == "" {
		return "seq"
	}
	return fm
}

func fileReadable(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}
