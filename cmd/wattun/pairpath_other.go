//go:build !linux

package main

// Windows dev checkout (see AGENTS.md): there is no /etc/wattun, so a config-less run keeps the pairing file in
// the working directory. Linux production uses /etc/wattun/.pairing (pairpath_linux.go); the unit's readable
// tree decides, hence the build-tag split instead of a runtime check.

// pairingFilePath is where -pair writes and every later start reads. cfgPath set (a config run): next to the
// config; no config: the current directory on this platform.
func pairingFilePath(cfgPath string) string {
	if cfgPath != "" {
		return dirOf(cfgPath) + "/.pairing"
	}
	return ".pairing"
}
