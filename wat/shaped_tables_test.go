package wat

// audit H5 (2026-11-04): one source of truth across the two shaped-carrier tables. The engine is authoritative;
// the manager copy (wattun-manager) and the docs table must agree name-for-name, port-for-port and MTU-for-MTU.
// The test skips outside a repo checkout (manager/docs files absent) so the module stays usable as a library.
//
// If this fails after a deliberate engine change, update wattun-manager (shaped_udp_port/shaped_udp_mtu/
// shaped_raw_mtu) and docs/TECHNICAL.md in the same commit — that is exactly the drift the audit found.

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func shapedManagerFunc(t *testing.T, src, fn string) string {
	t.Helper()
	start := strings.Index(src, "\n"+fn+"() {")
	if start < 0 {
		t.Fatalf("wattun-manager: %s() not found", fn)
	}
	body := src[start:]
	if end := strings.Index(body, "\n}"); end >= 0 {
		body = body[:end]
	}
	return body
}

// shapedCaseValues parses the case lines inside one manager table function.
// It understands both `name) echo 5555 ;;` and grouped `a|b) echo 5555 ;;` / `a|b) m=1392 ;;`.
func shapedCaseValues(t *testing.T, src, fn, action string) map[string]int {
	t.Helper()
	body := shapedManagerFunc(t, src, fn)
	re := regexp.MustCompile(`([a-z0-9|-]+)\)\s+` + action + `(\d+)`)
	out := map[string]int{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("%s: bad value %q", fn, m[2])
		}
		for _, name := range strings.Split(m[1], "|") {
			out[name] = n
		}
	}
	return out
}

func TestShapedCarrierTablesMatchManager(t *testing.T) {
	mgr, err := os.ReadFile("../wattun-manager")
	if err != nil {
		t.Skipf("no repo checkout (%v); table consistency is checked in CI", err)
	}
	src := string(mgr)
	ports := shapedCaseValues(t, src, "shaped_udp_port", "echo ")
	udpMTU := shapedCaseValues(t, src, "shaped_udp_mtu", "m=")
	rawMTU := shapedCaseValues(t, src, "shaped_raw_mtu", "m=")

	for _, sh := range udpShapeTable {
		if got := UDPShapePort(sh.name); got != ports[sh.name] {
			t.Errorf("%s: engine conventional port %d, manager %d", sh.name, got, ports[sh.name])
		}
		if want, got := sh.mtu(), udpMTU[sh.name]; want != got {
			t.Errorf("%s: engine MTU ceiling %d, manager %d", sh.name, want, got)
		}
	}
	if len(ports) != len(udpShapeTable) || len(udpMTU) != len(udpShapeTable) {
		t.Errorf("manager UDP tables list %d ports / %d MTUs, engine ships %d shapes",
			len(ports), len(udpMTU), len(udpShapeTable))
	}
	for _, name := range []string{"sit", "6to4", "xfrm-ipsec", "etherip", "l2tpv3"} {
		s, ok := rawShapeByName(name)
		if !ok {
			t.Fatalf("engine lost raw shape %q", name)
		}
		if want, got := rawShapeMTU(s), rawMTU[name]; want != got {
			t.Errorf("%s: engine raw MTU ceiling %d, manager %d", name, want, got)
		}
	}
	if len(rawMTU) != 5 {
		t.Errorf("manager raw table lists %d shapes, engine ships 5", len(rawMTU))
	}

	// The docs table must at least name every shipped carrier, otherwise the sync is one-sided.
	if docs, err := os.ReadFile("../docs/TECHNICAL.md"); err == nil {
		for _, sh := range udpShapeTable {
			if !strings.Contains(string(docs), sh.name) {
				t.Errorf("docs/TECHNICAL.md does not mention shaped carrier %q", sh.name)
			}
		}
		for _, name := range []string{"sit", "6to4", "xfrm-ipsec", "etherip", "l2tpv3"} {
			if !strings.Contains(string(docs), name) {
				t.Errorf("docs/TECHNICAL.md does not mention raw shaped carrier %q", name)
			}
		}
	}
}
