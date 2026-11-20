package mgr

import "testing"

func TestAdvancedValidators(t *testing.T) {
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"sessions 4 tcp", vSessions("4", "tcp", false)},
		{"sessions 0", vSessions("0", "icmp", false)},
		{"!sessions 4 bond", !vSessions("4", "tcp+tls", false)},
		{"!sessions 2 reverse", !vSessions("2", "tcp", true)},
		{"!sessions 17", !vSessions("17", "tcp", false)},
		{"conns 64", vConns("64")}, {"!conns 65", !vConns("65")},
		{"mtu pool 9000", vMTU("9000", "tcp")}, {"!mtu icmp 1500", !vMTU("1500", "icmp")},
		{"!mtu bond 1401", !vMTU("1401", "tcp+udp")}, {"!mtu sit 1361", !vMTU("1361", "sit")},
		{"winmax 4", vWinMax("4")}, {"!winmax 65", !vWinMax("65")},
		{"fecon 2>0.5", vFecOn("2", 0.5)}, {"!fecon 0.4<0.5", !vFecOn("0.4", 0.5)}, {"!fecon 51", !vFecOn("51", 0.5)},
		{"fecoff 0", vFecOff("0", 2)}, {"!fecoff 2", !vFecOff("2", 2)},
		{"statedir", vStateDir("/run/wattun")}, {"!statedir rel", !vStateDir("run/wattun")}, {"!statedir ..", !vStateDir("/run/../etc")},
		{"statesave 0", vStateSave("0")}, {"!statesave big", !vStateSave("2592001")},
		{"shape 25", vShapeData("25")}, {"!shape 26", !vShapeData("26")},
		{"noisebps", vNoiseBps("64")}, {"!noisebps", !vNoiseBps("63")},
		{"window", vNoiseWindow("22:00-06:00")}, {"!window same", !vNoiseWindow("02:00-02:00")}, {"!window 24", !vNoiseWindow("24:00-02:00")},
		{"allow", vAllowClients("1.2.3.4, 10.0.0.0/8 2001:db8::/32")}, {"!allow", !vAllowClients("1.2.3.4/33")},
		{"!allow mapped", !vAllowClients("::ffff:0:0/80")},
		{"cdn risk sni", allowClientsCDNRisk("tcp", "a.io")}, {"cdn risk wss", allowClientsCDNRisk("tcp+wss", "")},
		{"!cdn risk", !allowClientsCDNRisk("tcp+udp", "")},
	} {
		if !c.ok {
			t.Error(c.name)
		}
	}
}
