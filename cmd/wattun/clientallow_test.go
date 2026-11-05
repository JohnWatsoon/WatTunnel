package main

// W10 (3.3.0): the -allow-clients/-allow-clients-file parser. The server hands the result to wat.Config.AllowClients;
// a bad or empty entry must be a clear startup error, never a silently open or closed list.

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestParseClientAllow(t *testing.T) {
	for _, c := range []struct {
		name    string
		in      string
		want    []netip.Prefix
		wantErr bool
	}{
		{"address", "192.0.2.7", []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32")}, false},
		{"cidr", "10.0.0.0/8", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, false},
		{"host bits masked", "10.1.2.3/8", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, false},
		{"ipv6", "2001:db8::5", []netip.Prefix{netip.MustParsePrefix("2001:db8::5/128")}, false},
		{"ipv4-mapped", "::ffff:198.51.100.4", []netip.Prefix{netip.MustParsePrefix("198.51.100.4/32")}, false},
		// M3 (audit 2026-11-04): a 4-in-6 CIDR is stored as its IPv4 form, because sources are unmapped.
		{"ipv4-mapped cidr", "::ffff:203.0.113.0/120", []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, false},
		{"ipv4-mapped cidr host bits", "::ffff:203.0.113.7/120", []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, false},
		{"ipv4-mapped cidr shorter than /96", "::ffff:203.0.113.0/64", nil, true},
		{"comma and space", "192.0.2.7, 10.0.0.0/8 2001:db8::/32", []netip.Prefix{
			netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32"),
		}, false},
		{"newlines and tabs", "192.0.2.7\n\t10.0.0.0/8\r\n", []netip.Prefix{
			netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("10.0.0.0/8"),
		}, false},
		{"empty", "", nil, false},
		{"blank lines", "\n \t\n", nil, false},
		{"hostname", "example.com", nil, true},
		{"bad port", "192.0.2.7:80", nil, true},
		{"bad cidr", "10.0.0.0/33", nil, true},
		{"bad mask", "10.0.0.0/8/8", nil, true},
		{"one bad entry fails all", "192.0.2.7 nope", nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseClientAllow(c.in)
			if (err != nil) != c.wantErr {
				t.Fatalf("parseClientAllow(%q) err = %v, wantErr %v", c.in, err, c.wantErr)
			}
			if len(got) != len(c.want) {
				t.Fatalf("parseClientAllow(%q) = %v, want %v", c.in, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("parseClientAllow(%q)[%d] = %v, want %v", c.in, i, got[i], c.want[i])
				}
			}
		})
	}
}

// M3 (audit 2026-11-04): wat.Server unmaps every source before netip.Prefix.Contains, which requires equal address
// bit lengths. A mapped CIDR stored as-is matched nothing and silently locked every client out.
func TestParseClientAllowMappedCIDR(t *testing.T) {
	for _, c := range []struct {
		in    string
		match netip.Addr
		want  bool
	}{
		{"::ffff:203.0.113.0/120", netip.MustParseAddr("203.0.113.4"), true},
		{"203.0.113.0/24", netip.MustParseAddr("203.0.113.4"), true},
		{"::ffff:203.0.113.7/120", netip.MustParseAddr("203.0.113.4"), true}, // host bits still masked
		{"::ffff:198.51.100.0/120", netip.MustParseAddr("203.0.113.4"), false},
	} {
		ps, err := parseClientAllow(c.in)
		if err != nil {
			t.Fatalf("parseClientAllow(%q): %v", c.in, err)
		}
		if len(ps) != 1 {
			t.Fatalf("parseClientAllow(%q) = %v, want one prefix", c.in, ps)
		}
		if got := ps[0].Contains(c.match); got != c.want {
			t.Errorf("parseClientAllow(%q)[0] = %v, Contains(%v) = %v, want %v", c.in, ps[0], c.match, got, c.want)
		}
	}
}

func TestClientAllowList(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	file := write("good.txt", "192.0.2.7\n10.0.0.0/8\n")
	empty := write("empty.txt", "\n")
	bad := write("bad.txt", "192.0.2.7\nnot-an-ip\n")
	for _, c := range []struct {
		name string
		flag string
		file string
		want int // prefix count; -1 = error
	}{
		{"flag only", "192.0.2.7,10.0.0.0/8", "", 2},
		{"file only", "", file, 2},
		{"file replaces the flag", "198.51.100.0/24", file, 2}, // the file's entries, not the flag's
		{"nothing set", "", "", 0},
		{"empty flag", "", "", 0},
		{"missing file", "", filepath.Join(dir, "nope.txt"), -1},
		{"empty file", "", empty, -1},
		{"bad entry in file", "", bad, -1},
		{"bad flag", "nope", "", -1},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := clientAllowList(c.flag, c.file)
			if c.want < 0 {
				if err == nil {
					t.Fatalf("clientAllowList(%q, %q) accepted an invalid list", c.flag, c.file)
				}
				return
			}
			if err != nil {
				t.Fatalf("clientAllowList(%q, %q): %v", c.flag, c.file, err)
			}
			if len(got) != c.want {
				t.Fatalf("clientAllowList(%q, %q) = %v, want %d prefixes", c.flag, c.file, got, c.want)
			}
		})
	}
	// An empty file must not silently mean "allow everyone": it is a configuration error (see clientAllowList).
	if ps, err := clientAllowList("", empty); err == nil && len(ps) == 0 {
		t.Fatal("an empty -allow-clients-file must fail, not allow every client")
	}
}

// M4 (audit 2026-11-04): -allow-clients-file must live under /etc/wattun (the unit's ProtectHome=yes hides /root and
// /home). Slash-cleaned comparison, no Windows-volume escape.
func TestAllowClientsFileUnderEtc(t *testing.T) {
	for _, c := range []struct {
		path string
		want bool
	}{
		{"/etc/wattun/clients.txt", true},
		{"/etc/wattun/sub/list", true},
		{"/etc/wattun/./clients.txt", true},
		{"/etc/wattun/../wattun.txt", false},
		{"\\etc\\wattun\\clients.txt", true},
		{"/root/clients.txt", false},
		{"/home/op/clients.txt", false},
		{"/etc/wattunx/clients.txt", false},
		{"etc/wattun/clients.txt", false},
		{"C:/etc/wattun/clients.txt", false},
		{"", false},
	} {
		if got := allowClientsFileUnderEtc(c.path); got != c.want {
			t.Errorf("allowClientsFileUnderEtc(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// M11 (audit 2026-11-04): a CDN/proxy carrier or -sni makes -allow-clients a guaranteed lock-out; it is named for the
// startup error instead of being warned about and applied.
func TestAllowClientsCDN(t *testing.T) {
	for _, c := range []struct {
		names []string
		sni   string
		want  string
	}{
		{[]string{"udp"}, "", ""},
		{[]string{"tcp"}, "", ""},
		{[]string{"gre"}, "", ""},
		{[]string{"sit"}, "", ""},
		{[]string{"ws"}, "", "the ws carrier"},
		{[]string{"wss"}, "", "the wss carrier"},
		{[]string{"h2"}, "", "the h2 carrier"},
		{[]string{"h2c"}, "", "the h2c carrier"},
		{[]string{"grpc"}, "", "the grpc carrier"},
		{[]string{"tcp"}, "cdn.example", "-sni"},
		{[]string{"icmp", "tcp", "grpc"}, "", "the grpc carrier"},
	} {
		if got := allowClientsCDN(c.names, c.sni); got != c.want {
			t.Errorf("allowClientsCDN(%v, %q) = %q, want %q", c.names, c.sni, got, c.want)
		}
	}
}
