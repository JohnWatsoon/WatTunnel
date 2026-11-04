package main

// W10 (3.3.0): the server-side client allowlist, -allow-clients / -allow-clients-file. The list is handed to
// wat.Config.AllowClients and checked in wat.Server before a session is admitted (wat/server.go sourceAllowed), so it
// never touches an established session and costs nothing per packet once a session exists.
//
// Format: IPv4/IPv6 addresses (one host) or CIDR prefixes, separated by comma, space or newline. A bare address is
// kept as its /32 or /128. Entries are masked, so a non-network prefix such as 10.1.2.3/8 also matches its block.
// -allow-clients-file replaces -allow-clients (like -allow-file overrides -allow-ports) and is read once at startup:
// there is no hot reload, a change needs a restart (the same as every other server-side admission setting).

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path"
	"strings"
)

func isClientSeparator(r rune) bool {
	return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

// parseClientAllow parses one -allow-clients list (the flag value or the file contents).
func parseClientAllow(txt string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(txt, isClientSeparator) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IPv4/IPv6 address or CIDR prefix", f)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// clientAllowList resolves -allow-clients / -allow-clients-file into the prefixes wat.Server enforces; both empty
// returns nil (no filter, today's behavior). An empty result from a set flag or file is an error: a typo or an empty
// file must not silently allow every client.
func clientAllowList(flagVal, file string) ([]netip.Prefix, error) {
	if flagVal == "" && file == "" {
		return nil, nil
	}
	txt := flagVal
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("-allow-clients-file: %w", err)
		}
		txt = string(b)
	}
	ps, err := parseClientAllow(txt)
	if err != nil {
		return nil, fmt.Errorf("-allow-clients: %w", err)
	}
	if len(ps) == 0 {
		return nil, errors.New("-allow-clients: no entries (remove the flag to allow every source)")
	}
	return ps, nil
}

// allowClientsDir is the one directory -allow-clients-file may live in (M4): the systemd unit runs with
// ProtectHome=yes, so a list under /root or /home would pass manager validation and then fail at startup. /etc/wattun
// is the unit's config directory and is readable.
const allowClientsDir = "/etc/wattun"

// allowClientsFileUnderEtc reports whether p is inside allowClientsDir. Paths are cleaned with slash semantics after
// normalising backslashes, so a Windows-style or volume-qualified path does not pass (production is Linux and the
// systemd unit is what matters).
func allowClientsFileUnderEtc(p string) bool {
	s := path.Clean(strings.ReplaceAll(p, `\`, "/"))
	return s == allowClientsDir || strings.HasPrefix(s, allowClientsDir+"/")
}

// allowClientsCDN names the CDN/proxy carrier or -sni that makes -allow-clients meaningless ("" = a direct carrier).
// With one of these the server sees the CDN edge's address, not the client's, so a source list would reject every real
// client (M11); cmd/wattun makes the combination a startup error.
func allowClientsCDN(names []string, sni string) string {
	if sni != "" {
		return "-sni"
	}
	for _, n := range names {
		switch n {
		case "ws", "wss", "h2", "h2c", "grpc":
			return "the " + n + " carrier"
		}
	}
	return ""
}
