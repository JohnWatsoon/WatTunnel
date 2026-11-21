package main

// Production pairing file location (3.5.0): /etc/wattun/.pairing, like the tunnel configs — readable by the
// systemd unit (ProtectHome=yes keeps /root out, so the file must live under /etc/wattun).

// pairingFilePath is where -pair writes and every later start reads. cfgPath set (a config run): next to the
// config, so a dev or multi-instance setup keeps pairings separate; no config: the production default.
func pairingFilePath(cfgPath string) string {
	if cfgPath != "" {
		return dirOf(cfgPath) + "/.pairing"
	}
	return "/etc/wattun/.pairing"
}
