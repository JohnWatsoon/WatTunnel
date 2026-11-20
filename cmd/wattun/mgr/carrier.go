package mgr

import (
	"io"
	"path/filepath"
)

// findCarrier tests which carriers and modes get through for one Iran tunnel:
// an auto tunnel re-runs its auto test, any other runs the anti-censor matrix.
func findCarrier() {
	n := pickTunnel("Find a carrier", "tests every way through the filter and keeps the best",
		func(n string) bool { return Role(n) == "Iran" })
	if n == "" {
		return
	}
	ClearScreen()
	if fileExists(filepath.Join(P.Conf, n+".auto")) {
		dispatch("auto_test_cmd", n)
	} else {
		dispatch("ac_matrix_cmd", n)
	}
	Pause()
}

// blackoutKit groups the blackout tools for one tunnel.
func blackoutKit() {
	n := pickTunnel("Blackout kit", "get ready before a filter tightens, act when it does", nil)
	if n == "" {
		return
	}
	items := []Item{
		{Key: "a", Label: "Arm", Desc: "prepare this side now (Kharej: extra listeners; Iran: fast failover)"},
		{Key: "s", Label: "Switch on", Desc: "fake-SNI with an allowlisted name or an operator preset"},
		{Key: "c", Label: "Check readiness", Desc: "capabilities, sysctls, ports, DNS relay"},
		{Key: "t", Label: "Test the link", Desc: "is the tunnel up with its current settings"},
	}
	routes := []string{"arm_blackout_cmd", "blackout_cmd", "audit_blackout_cmd", "anticensor_test"}
	sel := 0
	for {
		ClearScreen()
		i, k := Choose(func(w io.Writer) { Title(w, "Blackout kit", n+" · "+Role(n)) }, items, &sel,
			[]string{"⏎", "run", "esc", "back"}, 0)
		if i >= 0 {
			ClearScreen()
			dispatch(routes[i], n)
			Pause()
			continue
		}
		if k == "esc" || k == "q" || k == "eof" {
			return
		}
	}
}
