package wat

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// spray port-range parsing, shared by every platform so a config file validates the same everywhere.

// ParseSprayPorts parses the spray carrier's port spec: "lo-hi" is an explicit range, a single
// "port" means port..port+999 (the field-proven 41000 default spans 41000-41999, PLAN-carriers.md
// 2026-11-20). Both ends must derive the same range from the same base or the server's BPF filter
// drops the client's datagrams.
func ParseSprayPorts(s string) (lo, hi int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, errors.New("empty spray port spec")
	}
	ls, hs, isRange := strings.Cut(s, "-")
	if lo, err = strconv.Atoi(strings.TrimSpace(ls)); err != nil || lo < 1 || lo > 65535 {
		return 0, 0, fmt.Errorf("bad spray port %q", s)
	}
	if !isRange {
		hi = lo + 999 // single base port: the default 1000-wide span
	} else if hi, err = strconv.Atoi(strings.TrimSpace(hs)); err != nil {
		return 0, 0, fmt.Errorf("bad spray port range %q", s)
	}
	if hi < lo || hi > 65535 {
		return 0, 0, fmt.Errorf("bad spray port range %q", s)
	}
	return lo, hi, nil
}
