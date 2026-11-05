package wat

// F19 (3.3.0) shaped-carrier name lists, exported so cmd/wattun accepts exactly the shapes the engine ships instead
// of keeping a second copy that can go stale (audit L6/F15). Each call returns a fresh slice; the tables stay private.

// RawShapedCarrierNames returns the phase-1 raw-tier carrier names in rawShape table order.
func RawShapedCarrierNames() []string {
	out := make([]string, len(rawShapeNames))
	copy(out, rawShapeNames[:])
	return out
}

// UDPShapedCarrierNames returns the phase-2 UDP carrier names in udpShapeTable order.
func UDPShapedCarrierNames() []string {
	out := make([]string, len(udpShapeTable))
	for i := range udpShapeTable {
		out[i] = udpShapeTable[i].name
	}
	return out
}
