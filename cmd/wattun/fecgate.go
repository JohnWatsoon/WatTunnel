package main

// F11 (3.3.0): -fec-on-loss/-fec-off-loss are percentages on the command line and fractions in wat.Config. The band
// is validated once at startup here, so a typo cannot silently disable the loss gate (off above on) or open it at a
// loss that never happens.

import (
	"fmt"
	"math"
)

// fecGatePct validates the two loss-gate thresholds (percent, as on the command line) and converts them to the
// fractions wat.Config takes. Bounds: 0 <= off < on <= 50; 50 % is far above the 0.2-2 % random loss of the target
// path (and everything above 50 is not loss any more but a dead link), so a larger "on" value would leave parity off
// forever.
func fecGatePct(onPct, offPct float64) (on, off float64, err error) {
	// M12: NaN/Inf pass every range comparison (all comparisons with NaN are false), so reject them explicitly.
	if math.IsNaN(onPct) || math.IsInf(onPct, 0) || onPct <= 0 || onPct > 50 {
		return 0, 0, fmt.Errorf("-fec-on-loss must be above 0 and at most 50 (percent), got %g", onPct)
	}
	if math.IsNaN(offPct) || math.IsInf(offPct, 0) || offPct < 0 || offPct >= onPct {
		return 0, 0, fmt.Errorf("-fec-off-loss must be 0 or more and below -fec-on-loss (%g), got %g", onPct, offPct)
	}
	return onPct / 100, offPct / 100, nil
}
