// wattun: TCP port forwarding over ICMP echo with its own transport (see ../../README.md).
//
//	server:  wattun -mode server -key SECRET
//	client:    wattun -mode client -key SECRET -peer 203.0.113.10 -map 20030:20030
//
// -map is listenPort:serverPort[,...]; the server connects each stream to 127.0.0.1:serverPort.
// -config FILE.yml supplies flags (command-line flags win) and a hot-reloaded `ports:` list; -reverse swaps which
// side dials the pool carriers (see config.go and wat/carrier_reverse.go) and which side sends the ICMP requests.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	rdebug "runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

var carrierNames = []string{"icmp", "udp", "tcp", "tls", "ws", "wss", "h2", "h2c", "grpc", "gre", "ipip"}

// rawIPCarrier: the carriers on a raw IP socket, which take a bare IP and run one session.
var rawIPCarrier = map[string]bool{"icmp": true, "gre": true, "ipip": true}

var validCarrier = map[string]bool{
	"icmp": true, "udp": true, "tcp": true, "tls": true, "ws": true, "wss": true, "h2": true, "h2c": true, "grpc": true, "gre": true, "ipip": true,
	"fortress": true,
}

var poolCarriers = map[string]bool{"tcp": true, "tls": true, "ws": true, "wss": true, "h2": true, "h2c": true, "grpc": true}

func main() {
	runManager()
	// GOGC 200 (2.4.0-2.4.5) saved little CPU but let a busy CDN tunnel's heap reach ~1.75x its live size: Iran sat at
	// 1 GB Sys for ~400 MB live, with GC at under 0.1 % CPU (field 2026-10-12). The Go default (100) is used again;
	// GOGC / GOMEMLIMIT still override it.
	mode := flag.String("mode", "", "client|server")
	key := flag.String("key", "", "pre-shared key")
	keyFile := flag.String("key-file", "", "read the key from a file")
	peer := flag.String("peer", "", "client: server IP; the pool carriers (tcp|tls|ws|wss|h2|h2c|grpc) take host:port and may list several, comma separated, which the pool connections spread over (client only, 2.2.0)")
	maps := flag.String("map", "", "client: listenPort:serverPort[,...]")
	udpMaps := flag.String("udp", "", "client: UDP forwarding, PORT or listenPort:serverPort[@bind][,...] (both ends need wattun >= 1.2.0)")
	udpIdle := flag.Duration("udp-idle", 60*time.Second, "UDP flows with no traffic for this long are closed")
	bind := flag.String("bind", "0.0.0.0", "client: listen address")
	offset := flag.Int("port-offset", 0, "client: add this to every listen port (second slot)")
	lanes := flag.Int("lanes", 4, "client: ICMP identifiers to stripe over")
	keepSlow := flag.String("keep-slow", "", "pool carriers: on = never close a pool connection for delivering below its share, off = always run that check, empty = the default (on for reverse and direct tcp|tls, off for ws|wss|h2|h2c|grpc through a CDN); on suits a direct HTTP carrier on a route that cuts flows, where the check can retire the connection that was about to recover (3.0.0)")
	batch := flag.String("batch", "", "icmp|udp: recvmmsg/sendmmsg batching, on|off (empty = the carrier default: on for icmp, off for udp); the same switch as WAT_BATCH, which this flag overrides (3.0.0)")
	maxMB := flag.Float64("max-mbps", 0, "pace ceiling, MB/s per direction, per session (0 = the carrier default: 16 for a lone icmp carrier, 1250 (10 Gbit, i.e. no practical cap) otherwise; in a bond only the icmp path is held to 16 (3.2.0, before: the whole bond); 2.4.18, before: 200; 2.3.0, before: 16 for all)")
	slackMs := flag.Int("slack-ms", 8, "tolerated RTT growth before slowing down, ms")
	metrics := flag.String("metrics", "", "serve JSON stats on this address (e.g. 127.0.0.1:19700)")
	allowLo := flag.Int("allow-min", 1, "server: lowest target port a client may ask for")
	allowHi := flag.Int("allow-max", 65535, "server: highest target port")
	allowList := flag.String("allow-ports", "", "server: comma list of target ports clients may reach (overrides allow-min/max)")
	allowFile := flag.String("allow-file", "", "server: file with the allowed target ports (comma/space/newline separated), re-read when it changes; overrides -allow-ports")
	debug := flag.Bool("debug", false, "log every stream open/close")
	version := flag.Bool("version", false, "print the version and exit")
	fecMode := flag.String("fec", "off", "off|auto: adaptive XOR parity after bursts of small packets (cuts tail latency on lossy links; both ends need 1.7.0 and -fec auto)")
	hedge := flag.Bool("hedge", false, "send small young packets twice (extra packets, helps lossy tails)")
	lossCeil := flag.Bool("loss-ceiling", false, "pacer: also cut the rate when loss jumps far above its learned baseline (opt-in; default: delay only)")
	governor := flag.Bool("governor", false, "pacer, ICMP paths: learn the path's volume ceiling from the reroute signature (a sudden base-RTT jump after sustained bulk) and hold the rate under it (opt-in; replaces hand-tuned max-mbps on routes where ICMP above ~30 MB/s total triggers a reroute inside Iran; 2.9.0)")
	tlsSmallCH := flag.Bool("tls-small-ch", false, "client, tls|wss|h2|grpc: keep the ClientHello small (skip the post-quantum hybrid key share; ~250 B instead of ~1.5 KB). Some DPIs drop large hellos outright (measured 2026-10-22 on a live Iranian path)")
	hdrMask := flag.Bool("hdr-mask", true, "mask the session id and packet number at the start of every packet, so no byte of a packet is constant or counts up (3.0.0; an older peer is detected and answered in the plain form; false sends the plain header)")
	tcpMimic := flag.Bool("tcp-mimic", true, "tcp carrier: open every connection with a TLS ClientHello-shaped hello (SNI -fake-sni, default www.cloudflare.com) that carries the authentication, and mask the 2-byte frame lengths, so the stream starts like TLS and has no plain structure (3.0.0; both ends; an older peer is detected and answered with the plain 8-byte pool id after a few seconds; false sends the plain id)")
	udpDNS := flag.Bool("udp-dns", false, "udp carrier: start every datagram with a DNS message header and question, so a filter that lets only DNS-looking UDP through (measured: UDP to port 53 passes, everything else is cut after 3 datagrams) passes the tunnel; use with port 53 on the server. Both ends must set it; an older peer cannot read it (3.0.0)")
	shape := flag.Bool("shape", true, "randomize idle traffic: pad small packets (acks, keepalives, key exchange) to random sizes and jitter the keepalive interval around -ping-every (3.0.0; wire-compatible with older peers)")
	pingEvery := flag.Int("ping-every", 2, "idle keepalive interval, seconds (raise on paths whose filter rate-limits steady periodic packets into a penalty box: live 2026-10-22 saw 30 echo req/min collapse to 95% loss until a ~5 min cooldown; both ends use their own value)")
	dnsUpstream := flag.String("dns-relay-upstream", "8.8.8.8:53", "Kharej recursive resolver used by the internal DNS relay (port 53, -ech ladder); empty = 8.8.8.8:53")
	icmpType := flag.String("icmp-type", "echo", "icmp carrier: echo|timestamp|info|mask - the ICMP request type the client sends (the server answers with the matching reply: 8/0, 13/14, 15/16, 17/18); both ends must use the same")
	carrier := flag.String("carrier", "icmp", "icmp|udp|tcp|tls|ws|wss|h2|h2c|grpc|gre|ipip (gre/ipip: IP protocol 47/4 on a raw socket, root and Linux, -peer is a bare IP like icmp, 3.2.0 on both ends; all but icmp/gre/ipip: client dials -peer host:port, server listens on -listen; h2 through Cloudflare: not supported, use grpc or wss); join several with '+' (icmp+udp+tcp) to bond them into ONE session that survives any one being blocked; then -peer / -listen are the defaults and -peer-NAME / -listen-NAME (e.g. -peer-udp, -listen-tcp, also keys in the config file) override them per carrier")
	udpListen := flag.String("listen", ":4443", "server, udp carrier: address to listen on")
	conns := flag.Int("conns", 0, "client, tcp/tls carrier: connections in the pool (0 = auto-tuned from host hardware: 8 on lean VPS, 16 on 2-CPU/2GB+, 24-32 on 4+ cores)")
	poolRotate := flag.String("pool-rotate", "0", "client, pool carriers (tcp|tls|ws|wss|h2|grpc): recycle each healthy pool connection after this long, so no flow shows a months-stable lifetime; accepts 30m, 4h or seconds; jittered +/-40% per connection so the redials never line up; 0 = off (2.8.0; a -reverse server dials too, so it honours it since 3.0.2)")
	poolRotateBytes := flag.String("pool-rotate-bytes", "0", "client, pool carriers, with -pool-rotate or alone: also recycle each healthy pool connection after this many bytes handed to its socket (500MB, 4GB, 300k; 1MB = 1e6); jittered +/-25% like the time axis; whichever limit hits first recycles (2.8.1; a -reverse server honours it since 3.0.2)")
	tcpCC := flag.String("tcp-cc", wat.PoolTCPCC, "tcp|tls|ws|wss|h2|h2c|grpc: TCP congestion control set on every pool socket, Linux (bbr ignores random loss, the kernel default cubic halves the window on it; 'system' keeps the kernel default; 2.4.18, before: system)")
	nSess := flag.Int("sessions", 0, "client: independent sessions to the server (0 = auto-tuned from host CPU, 1-16), each with its own -conns pool, pacer and session id; new TCP streams go to the least loaded live one, UDP flows stick to one, /speedtest uses all; udp|tcp|tls|ws|wss|h2|h2c|grpc only (not icmp, bonded carriers or -reverse); each counts against the server's 32-session limit (client only, 2.3.0; server unchanged)")
	tlsCert := flag.String("tls-cert", "", "server, tls carrier: certificate file (empty = self-signed in memory)")
	tlsKey := flag.String("tls-key", "", "server, tls carrier: private key file")
	sni := flag.String("sni", "", "client, tls carrier: server name sent in the ClientHello")
	tlsPin := flag.String("tls-pin", "", "client, tls carrier: hex sha256 of the server certificate to require")
	mtu := flag.Int("mtu", 0, "datagram size cap incl. header/tag, 256-1400 (tcp|tls|ws|wss|h2|h2c|grpc: up to 16384) (0 = the carrier default: 640 icmp, 1400 udp, 4096 tcp-based)")
	memBudget := flag.Int("mem-budget", 0, "MB of stream buffers (send data and grown receive windows) the whole process may hold before every stream shrinks to small buffers (0 = an eighth of the RAM) (3.2.0: one fast client took a server to 2 GB)")
	winMax := flag.Int("win-max", 0, "both ends: cap the per-stream receive window in MB, clamped to 4-64 (0 = auto-tuned from host RAM: 4 on lean VPS, 16 on 2-4GB, 32-64 on high-perf VPS) (3.0.3). Windows are receiver-driven, so this bounds what the PEER's sender buffers per stream. Set it explicitly to override auto-tuning")
	path := flag.String("path", "/wat", "client/server, ws|wss|h2|h2c|grpc carrier: URL path (grpc: service name, requests go to <path>/Tun)")
	tlsFP := flag.String("fp", "go", "client (also a -reverse server), tls|wss|h2|grpc carriers: TLS ClientHello fingerprint go|chrome|firefox|safari|edge|random; go is the standard library's (client only, 2.2.0; server unchanged)")
	echMode := flag.String("ech", "off", "client, tls|wss|h2|grpc carriers: Encrypted Client Hello: off|auto|ladder|<base64 ECHConfigList>; auto reads the HTTPS DNS record of the SNI/host name over DNS-over-HTTPS (1.1.1.1, 1.0.0.1, 8.8.8.8, 9.9.9.9 raced in parallel; the last good config is kept if they all fail); ladder = auto plus a second rung for hijacked networks (2.9.0): when every direct DoH server fails, the query goes through the tunnel's built-in DNS relay (server target port 53, the speed-test pattern), so a wss+ECH tunnel bootstraps on an ICMP-only route; both ends need 2.9.0 (old server: the relay port is just a failed local dial, the ladder falls back to no ECH)")
	echCache := flag.String("ech-cache", "", "client, with -ech auto: file keeping the last good ECH config across restarts, used at once on start while DoH refreshes in the background (2.2.3; empty = off)")
	tlsFrag := flag.Int("tls-frag", 0, "client, tls|wss|h2|grpc carriers: split the TLS ClientHello into N-byte TCP segments, 0 = off, -1 = mid-SNI split (client only, 2.2.0; server unchanged)")
	fakeSNI := flag.String("fake-sni", "", "dialer (client, or server when -reverse), tcp|tls|wss|h2|grpc carriers: track every outgoing TCP handshake on the wire and inject a fake TLS ClientHello carrying this allowlisted SNI right after it, so the DPI classifies the flow as TLS to an allowed site; the peer never sees the fake (raw socket, Linux, like the ICMP carrier; 2.6.0; server when -reverse 2.10.12)")
	fakeMode := flag.String("fake-mode", "seq", "client, with -fake-sni: seq = wrong sequence number, the server drops the fake as an old duplicate (default); ttl = small TTL, the fake dies at the censor's hop (needs -fake-ttl N or 0 = calibrate it from the server's replies); sum = valid window, bad TCP checksum, the server's kernel drops the fake (fails behind NATs that validate checksums); seqsum = both markers per connection, ~1 ms apart (experimental, 2.8.0); rst = in-window RST with a damaged TCP checksum: stateful middleboxes clear the flow, the server kernel drops the packet before reading the flags (2.9.0); split = the fake hello cut across -fake-split segments so no single packet carries the SNI (2.10.5); hlen0 = F&F-style empty TLS record (length 0) that makes a stateful parser latch and stop reading the flow (2.10.5); fakeip = a checksum-valid SYN + hello to -fake-ip (a whitelisted CDN edge) so destination-IP allowlists classify the flow as CDN traffic (2.10.5); synrst = in-window SYN|RST with a damaged checksum, clears flow tables harder than rst (2.10.5); paws = in-window fake hello with a valid checksum and a TCP timestamp 2^30 behind the real one: the server kernel drops it (RFC 7323 PAWS) while DPIs that verify checksums and windows accept it; needs timestamps on the connection, otherwise it sends the seq marker (3.0.2); all = seq + sum + hlen0 markers ~1 ms apart (2.10.5); ff = the Irancell F&F record plan for the fake hello (a zero-length record + 104-byte record + 1-byte records, cut across -fake-split (default 11) segments), the shape the owner's channel reports working at full speed (2.10.6); auto = run a one-time startup probe (2.9.0): two throwaway markers next to a throwaway connection tell which marker class the filter tolerates, and the mode is picked from that (logs the verdict; also in /stats as filter_profile)")
	fakeIP := flag.String("fake-ip", "", "client, -fake-mode fakeip: IPv4 or IPv6 address the fake SYN+hello is addressed to, so a destination-IP allowlist files the flow as CDN traffic; must match -peer's family, else the default for that family is used instead (empty = 104.16.0.1 for an IPv4 peer, 2606:4700::6810:1 for an IPv6 one, both Cloudflare edges; IPv6 support since 2.10.9)")
	fakeSplit := flag.Int("fake-split", 0, "client, -fake-mode split: how many TCP segments the fake ClientHello is cut into (0 = 3, or 2..16)")
	fakeTTL := flag.Int("fake-ttl", 0, "client, with -fake-sni -fake-mode ttl: hop count of the fake packet, 1 more than the distance to the censor's DPI box, 1 less than the distance to the server; 0 = calibrate from the server's replies (unused by the seq, sum and seqsum modes)")
	host := flag.String("host", "", "client, ws|wss|h2|h2c|grpc carrier: Host header / authority (default: -peer)")
	plain := flag.Bool("plain", false, "grpc carrier: cleartext h2c instead of TLS (behind a proxy that terminates TLS)")
	reverse := flag.Bool("reverse", false, "tcp|tls|ws|wss|h2|h2c|grpc carriers: the client listens on -listen and the server dials -peer; icmp carrier: the server sends the requests to -peer (the client's IP) and the client answers with replies (both ends need wattun >= 2.0.0 and -reverse); udp carrier: the client binds -listen and never sends first, the server punches datagrams to -peer (the client's address) and the client answers to the source of the latest one (3.0.0, both ends)")
	srcIP := flag.String("src-ip", "", "client: outbound source IP address for carriers (or per-carrier -src-ip-NAME)")
	dnsListen := flag.String("dns-listen", "", "client: local address to listen for DNS queries (e.g. 127.0.0.1:53 or 127.0.0.1:5353) and forward them via the tunnel's DNS relay (2.9.0)")
	pathProbeMax := flag.Duration("path-probe-max", 0, "client, bonded carriers: maximum probe backoff for dead paths (default 30s; blackout mode: 6s)")
	bondMode := flag.String("bond-mode", "balanced", "client/server, bonded carriers: balanced|active-backup|replicate (default: balanced)")
	peerBy, listenBy, srcIPBy := map[string]*string{}, map[string]*string{}, map[string]*string{}
	for _, c := range carrierNames {
		peerBy[c] = flag.String("peer-"+c, "", "client, bonded carriers: server address of the "+c+" carrier (default: -peer)")
		srcIPBy[c] = flag.String("src-ip-"+c, "", "client, bonded carriers: source IP address of the "+c+" carrier (default: -src-ip)")
		if c != "icmp" && c != "gre" && c != "ipip" {
			listenBy[c] = flag.String("listen-"+c, "", "server (or -reverse client), bonded carriers: listen address of the "+c+" carrier (default: -listen)")
		}
	}
	cfgPath := flag.String("config", "", "YAML-subset config file: keys are flag names, plus a ports: list (hot-reloaded); command-line flags win")
	var hdrs []string
	flag.Func("header", "client, ws|wss|h2|h2c|grpc carrier: extra request header 'Name: value' (repeatable)", func(v string) error {
		if !strings.Contains(v, ":") {
			return fmt.Errorf("want 'Name: value'")
		}
		hdrs = append(hdrs, v)
		return nil
	})
	flag.Parse()
	if *version {
		fmt.Println("wattun " + wat.Version)
		return
	}
	var fileCfg *fileConfig
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	known := func(k string) bool { return k != "config" && k != "version" && flag.Lookup(k) != nil }
	if *cfgPath != "" {
		b, err := os.ReadFile(*cfgPath)
		if err != nil {
			log.Fatal(err)
		}
		if fileCfg, err = parseConfig(string(b), known); err != nil {
			log.Fatalf("config %s: %v", *cfgPath, err)
		}
		for _, e := range fileCfg.KVs {
			if explicit[e.Key] {
				continue
			}
			if err := flag.Set(e.Key, e.Val); err != nil {
				log.Fatalf("config %s: %s: %v", *cfgPath, e.Key, err)
			}
		}
	}
	debugOn = *debug
	switch *keepSlow {
	case "", "on", "true", "off", "false":
	default:
		log.Fatalf("-keep-slow must be on or off, got %q", *keepSlow)
	}
	switch *batch { // read by the carriers through WAT_BATCH when they are built below (3.0.0)
	case "":
	case "on", "true", "1":
		os.Setenv("WAT_BATCH", "1")
	case "off", "false", "0":
		os.Setenv("WAT_BATCH", "0")
	default:
		log.Fatalf("-batch must be on or off, got %q", *batch)
	}
	if wat.PoolTCPCC = *tcpCC; *tcpCC == "system" || *tcpCC == "" {
		wat.PoolTCPCC = ""
	}
	wat.SetLossCeiling(*lossCeil)
	wat.SetGovernor(*governor)
	if *dnsUpstream != "" {
		u := *dnsUpstream
		if !strings.Contains(u, ":") {
			u += ":53"
		}
		dnsRelayUpstream = u
	}
	if _, _, ok := wat.ICMPTypes(*icmpType); !ok {
		log.Fatalf("-icmp-type must be echo, timestamp, info or mask, got %q", *icmpType)
	}
	if *fecMode != "off" && *fecMode != "auto" {
		log.Fatalf("-fec must be off or auto, got %q", *fecMode)
	}
	if *udpIdle < time.Second { // a shorter idle makes the janitor reap flows mid-burst and UDP silently dies (audit 2026-10-22)
		log.Fatalf("-udp-idle must be at least 1s, got %v", *udpIdle)
	}

	k := []byte(*key)
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
		k = []byte(strings.TrimSpace(string(b)))
	}
	if len(k) == 0 || (*mode != "client" && *mode != "server") {
		fmt.Fprintln(os.Stderr, "usage: wattun -mode client|server -key SECRET [-peer IP -map l:s,...]")
		os.Exit(2)
	}
	server := *mode == "server"
	if *carrier == "fortress" {
		*carrier = "icmp+tcp+tls+wss+udp"
		if v := listenBy["tcp"]; v != nil && *v == "" {
			*v = ":80"
		}
		if v := listenBy["tls"]; v != nil && *v == "" {
			*v = ":443"
		}
		if v := listenBy["wss"]; v != nil && *v == "" {
			*v = ":8443"
		}
		if v := listenBy["udp"]; v != nil && *v == "" {
			*v = ":53"
		}
	}
	names := strings.Split(*carrier, "+")
	seen := map[string]bool{}
	anyPool := false
	for _, n := range names {
		if !validCarrier[n] || seen[n] {
			fmt.Fprintln(os.Stderr, "unknown -carrier (icmp|udp|tcp|tls|ws|wss|h2|h2c|grpc|gre|ipip, joined with + to bond; each at most once)")
			os.Exit(2)
		}
		seen[n] = true
		anyPool = anyPool || poolCarriers[n]
	}
	if *winMax < 0 || *winMax > 64 {
		log.Fatalf("-win-max must be 0 (auto) or 4..64 MB, got %d", *winMax)
	}
	if *pingEvery < 0 || *pingEvery > 60 { // Alive and the server IdleTimeout are 3x this value
		log.Fatalf("-ping-every must be 0..60 seconds, got %d", *pingEvery)
	}
	hp := wat.HostProfile()
	wat.SetMemBudget(int64(*memBudget) << 20)
	if os.Getenv("GOMEMLIMIT") == "" && hp.TotalRAMMB > 0 { // the GC works harder near a third of the RAM instead of letting garbage double the heap (1024 streams: 1.8 GB peak at RAM/2)
		rdebug.SetMemoryLimit(int64(hp.TotalRAMMB) << 20 / 3)
	}
	if *conns <= 0 {
		*conns = hp.DefaultPoolConns
	}
	if *nSess <= 0 {
		if !server && !*reverse && len(names) == 1 && !rawIPCarrier[names[0]] {
			*nSess = hp.DefaultSessions
		} else {
			*nSess = 1
		}
	}
	if *reverse && !anyPool && !seen["icmp"] && !seen["udp"] {
		fmt.Fprintf(os.Stderr, "-reverse needs icmp, udp or a connection-pool carrier (tcp|tls|ws|wss|h2|h2c|grpc), not %q\n", *carrier)
		os.Exit(2)
	}
	if *nSess != 1 && !server {
		switch {
		case *nSess < 1 || *nSess > maxSessions:
			fmt.Fprintf(os.Stderr, "-sessions must be 1..%d, got %d\n", maxSessions, *nSess)
			os.Exit(2)
		case len(names) > 1 || rawIPCarrier[names[0]]:
			fmt.Fprintf(os.Stderr, "-sessions > 1 works with one udp|tcp|tls|ws|wss|h2|h2c|grpc carrier, not %q\n", *carrier)
			os.Exit(2)
		case *reverse:
			fmt.Fprintln(os.Stderr, "-sessions > 1 does not work with -reverse (the server dials one pool)")
			os.Exit(2)
		}
	}
	if *reverse && *fakeSNI != "" && (*fakeMode == "sum" || *fakeMode == "seqsum") { // 3.0.0
		fmt.Fprintf(os.Stderr, "-fake-mode %s does not work with -reverse: checksum markers need a middlebox that drops the damaged segment; on an open reverse path the peer can take it and the tunnel dies. Use rst or synrst.\n", *fakeMode)
		os.Exit(2)
	}
	// -fake-sni implies -tls-small-ch (2.10.11: large post-quantum hellos were dropped on a live path), unless the
	// operator set -tls-small-ch explicitly, so -tls-small-ch=false now turns the full hello back on (3.0.0).
	smallCHSet := false
	flag.Visit(func(f *flag.Flag) { smallCHSet = smallCHSet || f.Name == "tls-small-ch" })
	smallCH := *tlsSmallCH || *fakeSNI != "" && !smallCHSet
	if *maxMB <= 0 { // carrier default: the ICMP path keeps its measured 16 MB/s, the others are not capped by it
		*maxMB = 1250 // 10 Gbit: no practical cap (2.4.18, before: 200)
		if len(names) == 1 && seen["icmp"] {
			*maxMB = 16 // in a bond only the icmp path is capped (wat.ICMPPathBps), not the session (3.2.0)
		}
	}
	// -ech ladder (2.9.0): the DoH-through-the-tunnel hook needs the sessions, which are built after the
	// pools; the hook reads through a pointer that newTunnel sets (a nil/nil'd tunnel errors per query).
	var tunRef atomic.Pointer[tunnel]
	ladderHook := func(query []byte) ([]byte, error) { return dialDNSRelay(tunRef.Load(), query) }
	if _, err := wat.NormFingerprint(*tlsFP); err != nil {
		log.Fatal(err)
	}
	if _, _, err := wat.ParseECHFlag(*echMode); err != nil {
		log.Fatal(err)
	}
	if *tlsFrag < -1 || *tlsFrag > 1<<14 {
		log.Fatalf("-tls-frag must be -1..16384 (-1 = mid-SNI split), got %d", *tlsFrag)
	}
	rotateD, err := time.ParseDuration(*poolRotate)
	if err != nil || rotateD < 0 {
		log.Fatalf("-pool-rotate must be a duration (30m, 4h, 90s) or 0, got %q", *poolRotate)
	}
	rotateB, err := parseSize(*poolRotateBytes)
	if err != nil {
		log.Fatalf("-pool-rotate-bytes must be a byte count (500MB, 4G) or 0, got %q", *poolRotateBytes)
	}
	// getDesync returns or lazily creates the fake-SNI layer for a peer.
	var desyncMu sync.Mutex
	desyncByPeer := map[string]*wat.Desync{}
	desyncNone := map[string]bool{} // peers the probe found unfiltered: no fake-SNI at all
	getDesync := func(peer, carrier string) (*wat.Desync, error) {
		if *fakeSNI == "" {
			return nil, nil
		}
		wat.SetNote(log.Printf) // a failed raw send must be heard: the real SNI would go out unprotected
		desyncMu.Lock()
		defer desyncMu.Unlock()
		if d := desyncByPeer[peer]; d != nil || desyncNone[peer] {
			return d, nil
		}
		mode := *fakeMode
		if mode == "auto" { // measure the route once at startup, pick the mode from the verdict (3.0.0: by acked bytes)
			mode = wat.ProbeFakeMode(wat.DesyncConfig{SNI: *fakeSNI, TTL: *fakeTTL}, peer, carrier,
				wat.ProbeName(carrier, *sni, *host, peer), *path, log.Printf)
			if mode == "none" {
				desyncNone[peer] = true
				return nil, nil
			}
		}
		d, err := wat.NewDesync(wat.DesyncConfig{SNI: *fakeSNI, Mode: mode, TTL: *fakeTTL, FakeIP: *fakeIP, Split: *fakeSplit}, peer)
		if err != nil {
			return nil, err
		}
		desyncByPeer[peer] = d
		return d, nil
	}
	pick := func(by map[string]*string, def, c string) string {
		if v := by[c]; v != nil && *v != "" {
			return *v
		}
		return def
	}
	var tlsPools []*wat.TCPPoolClient // dialing pool clients, for the tls_fp / ech stats
	// build opens one carrier; the single-carrier case is exactly the old code path.
	build := func(carrier string) (pio wat.PacketIO, raw wat.RawIO) {
		peer, listen := pick(peerBy, *peer, carrier), pick(listenBy, *udpListen, carrier)
		src := pick(srcIPBy, *srcIP, carrier)
		var srcNetIP net.IP
		if src != "" {
			srcNetIP = net.ParseIP(src)
			if srcNetIP == nil {
				log.Fatalf("%s carrier: invalid -src-ip %q", carrier, src)
			}
		}
		if (rawIPCarrier[carrier] || carrier == "udp") && strings.Contains(peer, ",") {
			log.Fatalf("%s carrier: -peer takes exactly one address, got %q (several comma separated addresses work with tcp|tls|ws|wss|h2|h2c|grpc)", carrier, peer)
		}
		lis := server != (*reverse && poolCarriers[carrier]) // which side listens: the server, or the client when -reverse
		var ps *wat.TCPPoolServer
		var pc *wat.TCPPoolClient
		var err error
		switch carrier {
		case "icmp":
			var ic *wat.ICMPIO
			if srcNetIP != nil {
				ic, err = wat.NewICMPIOSource(server, *reverse, peer, srcNetIP.String(), k, *icmpType)
			} else if !*reverse {
				ic, err = wat.NewICMPIOType(server, peer, k, *icmpType)
			} else if ic, err = wat.NewICMPIOReverse(server, true, peer, k, *icmpType); err == nil && server {
				if peer == "" {
					log.Printf("reverse icmp: no -peer (the client's IP) set, so this server only answers; set it so the client's replies are always solicited")
				}
				ic.Knock(*lanes, 5*time.Second)
			}
			if err != nil {
				log.Fatalf("icmp socket: %v", err)
			}
			pio, raw = ic, ic
		case "gre", "ipip":
			if *reverse {
				log.Fatalf("%s carrier: -reverse is not supported (use icmp, udp or a pool carrier)", carrier)
			}
			r, err := wat.NewRawIPIO(carrier == "gre", server, peer, src, k)
			if err != nil {
				log.Fatalf("%s socket: %v", carrier, err)
			}
			pio, raw = r, r
		case "udp":
			if *reverse && server { // 3.0.0: the server punches towards the client, which never sends first
				raw, err = wat.NewUDPReverseServer(listen, peer, k)
			} else if *reverse {
				pio, err = wat.NewUDPReverseListener(listen, k)
			} else if server {
				raw, err = wat.NewUDPServer(listen)
			} else if srcNetIP != nil {
				pio, err = wat.NewUDPClientAddr(peer, &net.UDPAddr{IP: srcNetIP})
			} else {
				pio, err = wat.NewUDPClient(peer)
			}
			if err != nil {
				log.Fatalf("udp socket: %v", err)
			}
			if *udpDNS {
				for _, x := range []any{pio, raw} {
					if d, ok := x.(interface{ SetDNS(bool) }); ok {
						d.SetDNS(true)
					}
				}
			}
		case "tcp":
			if lis {
				ps, err = wat.NewTCPPoolServer(listen)
			} else {
				var opt wat.TCPClientOptions
				if srcNetIP != nil {
					opt.LocalAddr = &net.TCPAddr{IP: srcNetIP}
				}
				d, derr := getDesync(peer, carrier)
				if derr != nil {
					log.Fatalf("fake-sni: %v", derr)
				}
				if d != nil {
					opt.DialHook = func(ctx context.Context, slot int, inner func(context.Context, int) (net.Conn, error)) (net.Conn, error) {
						c, err := inner(ctx, slot)
						if err != nil {
							return nil, err
						}
						return d.Wrap(c)
					}
				}
				pc, err = wat.NewTCPPoolClientOptions(peer, *conns, opt)
			}
			if err != nil {
				log.Fatalf("tcp carrier: %v", err)
			}
		case "tls":
			if lis {
				ps, err = wat.NewTLSPoolServer(listen, *tlsCert, *tlsKey)
			} else {
				var pin []byte
				if *tlsPin != "" {
					if pin, err = hex.DecodeString(strings.ReplaceAll(*tlsPin, ":", "")); err != nil || len(pin) != 32 {
						log.Fatalf("-tls-pin must be 64 hex chars (sha256)")
					}
				}
				d, derr := getDesync(peer, carrier)
				if derr != nil {
					log.Fatalf("fake-sni: %v", derr)
				}
				tlsOpts := wat.TLSClientOptions{ServerName: *sni, PinSHA256: pin, NoPQ: smallCH,
					Fingerprint: *tlsFP, ECH: *echMode, ECHCache: *echCache, Frag: *tlsFrag, Logf: log.Printf,
					ECHLadder: ladderHook}
				if srcNetIP != nil {
					tlsOpts.LocalAddr = &net.TCPAddr{IP: srcNetIP}
				}
				if d != nil {
					tlsOpts.DialHook = d.Wrap
				}
				pc, err = wat.NewTLSPoolClient(peer, *conns, tlsOpts)
			}
			if err != nil {
				log.Fatalf("tls carrier: %v", err)
			}
		case "ws", "wss", "h2", "h2c", "grpc":
			secure := carrier == "wss" || carrier == "h2" || carrier == "grpc" && !*plain
			if lis {
				so := wat.HTTPServerOptions{Path: *path, Secure: secure, CertFile: *tlsCert, KeyFile: *tlsKey}
				switch carrier {
				case "ws", "wss":
					ps, err = wat.NewWSPoolServer(listen, so)
				case "grpc":
					ps, err = wat.NewGRPCPoolServer(listen, so)
				default:
					ps, err = wat.NewH2PoolServer(listen, so)
				}
			} else {
				co := wat.HTTPClientOptions{Path: *path, Host: *host, Secure: secure, Headers: map[string]string{}}
				co.TLS.ServerName = *sni
				co.TLS.NoPQ = smallCH
				co.TLS.Fingerprint, co.TLS.ECH, co.TLS.Frag, co.TLS.Logf = *tlsFP, *echMode, *tlsFrag, log.Printf
				co.TLS.ECHCache = *echCache
				co.TLS.ECHLadder = ladderHook
				if srcNetIP != nil {
					co.TLS.LocalAddr = &net.TCPAddr{IP: srcNetIP}
				}
				d, derr := getDesync(peer, carrier)
				if derr != nil {
					log.Fatalf("fake-sni: %v", derr)
				}
				if d != nil {
					co.DialHook = d.Wrap
					co.TLS.DialHook = d.Wrap
				}
				if *tlsPin != "" {
					if co.TLS.PinSHA256, err = hex.DecodeString(strings.ReplaceAll(*tlsPin, ":", "")); err != nil || len(co.TLS.PinSHA256) != 32 {
						log.Fatalf("-tls-pin must be 64 hex chars (sha256)")
					}
				}
				for _, h := range hdrs {
					k, v, _ := strings.Cut(h, ":")
					co.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
				switch carrier {
				case "ws", "wss":
					pc, err = wat.NewWSPoolClient(peer, *conns, co)
				case "grpc":
					pc, err = wat.NewGRPCPoolClient(peer, *conns, co)
				default:
					pc, err = wat.NewH2PoolClient(peer, *conns, co)
				}
			}
			if err != nil {
				log.Fatalf("%s carrier: %v", carrier, err)
			}
		}
		if pc != nil {
			tlsPools = append(tlsPools, pc)
			if rotateD > 0 || rotateB > 0 { // churn (2.8.0/2.8.1, 3.0.2): any dialer pool (normal client or reverse server)
				pc.SetRotate(rotateD, rotateB)
			}
		}
		if carrier == "tcp" && *tcpMimic { // 3.0.0: TLS-shaped hello and masked frame lengths on a raw tcp pool
			if ps != nil {
				ps.SetObfs(k)
			}
			if pc != nil {
				pc.SetObfs(k, *fakeSNI)
			}
		}
		keep := len(names) == 1 && (*reverse || carrier == "tcp" || carrier == "tls") // direct path (Config.Direct)
		switch *keepSlow {
		case "on", "true":
			keep = true
		case "off", "false":
			keep = false
		}
		if keep {
			if pc != nil {
				pc.SetKeepSlow(true)
			}
			if ps != nil {
				ps.SetKeepSlow(true)
			}
		}
		switch { // pool carriers: who listens and who dials is independent of the session role
		case ps != nil && server:
			raw = ps
		case ps != nil:
			pio = wat.NewReverseListenIO(ps)
		case pc != nil && !server:
			pio = pc
		case pc != nil:
			pc.SetMaxBackoff(30 * time.Second) // the client may be listening on another carrier only
			pc.SetDialLog(carrier+" reverse dial", log.Printf)
			raw = wat.NewReverseDialRaw(pc)
		}
		return
	}
	var pio wat.PacketIO
	var raw wat.RawIO
	var tm wat.PathTimings
	if *pathProbeMax > 0 {
		tm.ProbeMax = *pathProbeMax
	}
	tm.Mode = *bondMode
	if len(names) == 1 {
		pio, raw = build(names[0])
	} else { // bonded: one session over all of them
		var kids []wat.PacketIO
		var raws []wat.RawIO
		var lanesPer []int
		for _, n := range names {
			p, r := build(n)
			kids, raws = append(kids, p), append(raws, r)
			lanesPer = append(lanesPer, 1)
			if n == "icmp" {
				lanesPer[len(lanesPer)-1] = *lanes
			}
		}
		var err error
		if server {
			raw = wat.NewMultiRaw(names, raws)
		} else if pio, err = wat.NewBondIO(kids, wat.BondOptions{Names: names, Lanes: lanesPer, Timings: tm, Mode: *bondMode}); err != nil {
			log.Fatal(err)
		}
	}
	cfg := wat.Config{
		Server: server, Key: k, Paths: *lanes, MaxBps: *maxMB * 1e6, Slack: time.Duration(*slackMs) * time.Millisecond,
		PingEvery: time.Duration(*pingEvery) * time.Second, NoMask: !*hdrMask, NoShape: !*shape,
		Logf: log.Printf, Hedge: *hedge, FEC: *fecMode == "auto", MaxPayload: *mtu, Bond: tm,
		WinMax: uint64(*winMax) << 20,
		// no CDN can sit in a reverse pool (Kharej dials Iran's IP) or in front of raw tcp/tls: TCP paces (2.4.18)
		Direct: allReliableDirect(names, *reverse),
	}
	var tun *tunnel
	var srv *wat.Server
	if server {
		if *nSess != 1 {
			log.Printf("-sessions is a client option, ignored on the server")
		}
		srv = wat.NewServer(cfg, raw)
		revEngine := wat.NewReviveEngine(k, func(action uint8, src net.Addr) {
			log.Printf("emergency revive: action 0x%02x signal from %s", action, src)
			switch action {
			case wat.ReviveReloadListeners:
				log.Printf("emergency revive: cycling listeners")
			case wat.ReviveReverseCompanion:
				log.Printf("emergency revive: reverse companion trigger from %s", src)
			case wat.ReviveFlushRateLimits:
				log.Printf("emergency revive: flushing rate limits")
			}
		})
		srv.SetRevive(revEngine)
	} else {
		pios := []wat.PacketIO{pio}
		for k := 1; k < *nSess; k++ { // -sessions: more independent carriers to the same peer(s)
			var p wat.PacketIO
			var err error
			switch c := pio.(type) {
			case *wat.TCPPoolClient: // same TLS engine and edge health, own connections; the next slots continue the edge rotation
				p, err = c.Clone(k * max(*conns, 1))
			case *wat.UDPClient:
				var uc *wat.UDPClient
				if uc, err = wat.NewUDPClient(pick(peerBy, *peer, "udp")); err == nil {
					uc.SetDNS(*udpDNS)
					p = uc
				}
			default:
				err = fmt.Errorf("-sessions > 1 is not supported on this carrier")
			}
			if err != nil {
				log.Fatalf("session %d: %v", k+1, err)
			}
			pios = append(pios, p)
		}
		var list []*wat.Session
		for _, p := range pios {
			s, err := wat.NewSession(cfg, p)
			if err != nil {
				log.Fatal(err)
			}
			list = append(list, s)
		}
		tun = newTunnel(list)
		tunRef.Store(tun) // -ech ladder's DoH hook (2.9.0)
		if *dnsListen != "" {
			dnsCloser, err := startDNSListener(*dnsListen, func() *tunnel { return tunRef.Load() }, log.Printf)
			if err != nil {
				log.Fatalf("dns-listen %s: %v", *dnsListen, err)
			}
			defer dnsCloser.Close()
		}
	}
	stats := func() wat.Stats {
		if srv != nil {
			return srv.Stats()
		}
		return tun.stats()
	}
	// A server counts as alive only while a client was heard in the last 10 s, like a client does: a session that is
	// still in the table but silent (every pool conn blackholed) is not alive (3.0.1).
	alive := func() bool {
		return srv != nil && srv.Sessions() > 0 && time.Since(srv.LastRecv()) < 10*time.Second || tun != nil && tun.alive()
	}
	// rxAge: ms since the last authenticated packet from the peer (server: from any client), -1 if none yet.
	rxAge := func() int64 {
		var t time.Time
		if srv != nil {
			t = srv.LastRecv()
		} else {
			t = tun.lastRecv()
		}
		if t.IsZero() {
			return -1
		}
		return time.Since(t).Milliseconds()
	}
	carrierStats := func() []wat.CarrierStat {
		if srv != nil {
			return srv.CarrierStats()
		}
		return tun.list[0].CarrierStats() // bonded carriers run one session
	}
	side = "c"
	if server {
		side = "s"
	}
	if *cfgPath != "" {
		portReg.loadQuota(*cfgPath + ".quota.json")
		portReg.loadTotals(*cfgPath+".totals.json", func() (uint64, uint64) { st := stats(); return st.BytesIn, st.BytesOut })
	}
	if fileCfg != nil {
		portReg.applyLimits(fileCfg.Limits)
	}
	go portReg.run()
	log.Printf("wattun %s up (ident base %d, lanes %d, max %.0f MB/s; host: %d CPU, %d MB RAM, %s tier, conns %d, sessions %d)",
		*mode, wat.IdentBase(k), *lanes, *maxMB, hp.NumCPU, hp.TotalRAMMB, hp.Tier, *conns, *nSess)
	if tun != nil && len(tun.list) > 1 {
		log.Printf("%d sessions (new streams go to the least loaded live one)", len(tun.list))
	}
	if len(names) > 1 {
		log.Printf("bonded carriers: %s", strings.Join(names, " + "))
	}

	if *metrics != "" {
		fixed, changed := loopbackMetricsAddr(*metrics)
		if changed {
			log.Printf("metrics: %s is not a loopback address; serving on %s instead (it exposes stats, pprof and /speedtest)", *metrics, fixed)
		}
		*metrics = fixed
		if _, p, err := net.SplitHostPort(fixed); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				metricsPort.Store(int32(n))
			}
		}
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/ports", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(portReg.snapshot(side))
			})
			mux.HandleFunc("/quota/reset", quotaResetHandler)
			mux.HandleFunc("/carrier/toggle", func(w http.ResponseWriter, r *http.Request) {
				pStr := r.URL.Query().Get("path")
				cName := r.URL.Query().Get("carrier")
				idx := -1
				if pStr != "" {
					if n, err := strconv.Atoi(pStr); err == nil {
						idx = n
					}
				} else if cName != "" {
					for i, n := range names {
						if n == cName {
							idx = i
							break
						}
					}
				}
				if idx < 0 || idx >= len(names) {
					http.Error(w, "invalid path or carrier", http.StatusBadRequest)
					return
				}
				muted := false
				if pm, ok := pio.(wat.PathMuter); ok {
					muted = pm.ToggleMute(idx)
				} else if srv != nil {
					muted = srv.ToggleMute(idx)
				} else {
					http.Error(w, "carrier muting not supported on this tunnel", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"path":%d,"carrier":%q,"muted":%t}`+"\n", idx, names[idx], muted)
			})
			if tun != nil {
				mux.HandleFunc("/speedtest", speedTestHandler(tun))
			}
			mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
				st := stats()
				inTot, outTot := portReg.sessionTotals(st.BytesIn, st.BytesOut)
				out := map[string]any{
					"bytes_in_total": inTot, "bytes_out_total": outTot,
					"pkts_out": st.PktsOut, "pkts_in": st.PktsIn, "bytes_out": st.BytesOut, "bytes_in": st.BytesIn,
					"fec_sent": st.FecSent, "fec_recovered": st.FecRecovered, "retrans": st.Retrans, "send_errors": st.Dropped, "ack_late": st.AckLate, "dup_recv": st.RxDup, "rx_too_old": st.RxTooOld, "rate_bps": st.RateBps,
					"ceiling_bps": st.CeilingBps, "loss_pct": st.LossPct,
					"srtt_ms": float64(st.SRTT) / 1e6, "min_rtt_ms": float64(st.MinRTT) / 1e6,
					"streams": st.Streams, "inflight": st.Inflight, "alive": alive(), "last_rx_age_ms": rxAge(), "version": wat.Version, "draining": srv != nil && srv.Draining(),
					"sessions": func() int {
						if srv != nil {
							return srv.Sessions()
						}
						return len(tun.list)
					}(),
					"dgram_sent": st.DgramSent, "dgram_recv": st.DgramRecv, "dgram_dropped_queue": st.DgramDropQueue,
					"dgram_dropped_size": st.DgramDropSize, "dgram_dropped_rx": st.DgramDropRx, "dgram_fragmented": st.DgramFragmented, "dgram_reassembled": st.DgramReassembled, "dgram_flows": udpFlowsActive.Load(),
					"dgram_rejected": udpRejected.Load(), "dgram_flow_cap_drops": udpFlowCapDrop.Load(), "pool_slow_closed": wat.PoolSlowKills(), "pool_conn_deaths": wat.PoolConnDeaths(), "pool_drops": wat.PoolDrops(), "tcp_cc": wat.PoolTCPCCInUse(), "pool_conns": wat.PoolConnStats(),
					"filter_profile": wat.FilterProfileNow(), // fake-mode auto's startup verdict (2.9.0)
					"raw_send_fails": wat.RawSendFails(),     // fake-SNI fires that never left the host (2.10.9)
				}
				out["cc"] = map[string]any{ // pacer diagnostics (2.4.10): what held the sender back, and why it slowed
					"ticks": st.CC.Ticks, "tok_limited": st.CC.TokLimited, "cwnd_limited": st.CC.CwndLimited,
					"app_limited": st.CC.AppLimited, "loss_cuts": st.CC.LossCuts, "delay_cuts": st.CC.DelayCuts,
					"deep_trips": st.CC.DeepTrips, "pool_full": st.CC.PoolFull, "lost": st.CC.Lost, "spurious": st.CC.Spurious,
					"floor_bps": st.FloorBps, "cwnd": st.Cwnd, "loss_time_ms": st.LossTime.Milliseconds(),
					"pto_ms": st.PTO.Milliseconds(), "loss_timer_x": st.RelLossMul, "win_blocked": st.WinBlocked,
				}
				out["ports"] = portReg.snapshot(side)
				var edges []wat.EdgeStat
				for _, p := range tlsPools { // dialing pools: per-address health, and the client-side TLS state
					edges = append(edges, p.Edges()...)
					if _, ok := out["tls_mode"]; ok {
						continue
					}
					if fp, mode, ech, ok := p.TLSInfo(); ok {
						out["tls_fp"], out["tls_mode"], out["ech"] = fp, mode, ech
					}
				}
				if len(edges) > 0 {
					out["edges"] = edges
				}
				if len(names) > 1 {
					out["carriers"] = carrierStats()
				}
				if srv != nil {
					out["clients"] = clientsJSON(srv.Clients())
				} else {
					out["sessions_up"] = tun.up()
					if len(tun.list) > 1 {
						out["session_list"] = tun.sessionList()
					}
				}
				json.NewEncoder(w).Encode(out)
			})
			log.Println(http.ListenAndServe(*metrics, mux))
		}()
	}
	go func() {
		var last wat.Stats
		var lw linkWatch
		for range time.Tick(10 * time.Second) {
			st := stats()
			if !server {
				if note := lw.tick(10*time.Second, st.PktsIn, st.PktsOut-last.PktsOut, alive()); note != "" {
					log.Print(note)
				}
			}
			if st.PktsIn == last.PktsIn && st.PktsOut == last.PktsOut && st.Streams == 0 {
				continue
			}
			log.Printf("stats: streams=%d rate=%.1fMB/s srtt=%v min=%v out=%d in=%d retrans=%d errs=%d ceiling=%.1fMB/s loss=%.1f%%", st.Streams, st.RateBps/1e6,
				st.SRTT.Round(time.Millisecond), st.MinRTT.Round(time.Millisecond), st.PktsOut-last.PktsOut, st.PktsIn-last.PktsIn, st.Retrans-last.Retrans, st.Dropped-last.Dropped, st.CeilingBps/1e6, st.LossPct)
			last = st
		}
	}()

	if server {
		var al *allow
		if fileCfg != nil && fileCfg.PortsSet { // the config's ports replace -allow-file / -allow-ports
			al = newAllow("", "")
			al.setPorts(fileCfg.tcpPorts())
			al.setUDPPorts(fileCfg.udpPorts())
		} else {
			al = newAllow(*allowList, *allowFile)
		}
		if *cfgPath != "" {
			w := &cfgWatcher{path: *cfgPath, known: known, skip: func(k string) bool { return explicit[k] }, interval: 3 * time.Second,
				onPorts: func(c *fileConfig) []error {
					if !c.PortsSet { // ports: removed: fall back to -allow-ports/-allow-file, not an empty list
						al.reset(*allowList)
						return nil
					}
					al.setPorts(c.tcpPorts())
					al.setUDPPorts(c.udpPorts())
					return nil
				},
				onLimits: func(c *fileConfig) { portReg.applyLimits(c.Limits) }}
			w.start(fileCfg)
			go w.run()
		}
		go func() {
			for s := range srv.New {
				go serve(s, *allowLo, *allowHi, al)
				go serveDgrams(s, *allowLo, *allowHi, al, *udpIdle)
			}
		}()
		usr := make(chan os.Signal, 1)
		if drainSignal != nil {
			signal.Notify(usr, drainSignal)
			go func() { // SIGUSR1: stop taking new client sessions, exit once the current ones are gone (handover)
				<-usr
				srv.Drain()
				log.Printf("draining: no new sessions; %d active", srv.Sessions())
				for range time.Tick(2 * time.Second) {
					if srv.Sessions() == 0 {
						log.Printf("drained, exiting")
						portReg.save() // the handover exit skips the signal path's save (audit 2026-10-21)
						os.Exit(0)
					}
				}
			}()
		}
	} else {
		cfgPorts := fileCfg != nil && fileCfg.PortsSet
		if *maps != "" || !cfgPorts && *udpMaps == "" { // without -map and without ports: keep the old "bad -map entry" failure
			for _, m := range strings.Split(*maps, ",") {
				bindAddr := *bind
				if at := strings.Index(m, "@"); at >= 0 { // 18999:18999@127.0.0.1 keeps a port private
					bindAddr = strings.TrimSpace(m[at+1:])
					m = m[:at]
				}
				f := strings.Split(strings.TrimSpace(m), ":")
				if len(f) != 2 {
					log.Fatalf("bad -map entry %q", m)
				}
				lp, e1 := strconv.Atoi(f[0])
				sp, e2 := strconv.Atoi(f[1])
				if e1 != nil || e2 != nil || lp < 1 || lp > 65535 || sp < 1 || sp > 65535 {
					// range too: uint16(target) would silently wrap 70000->4464 and route 0 to the speed test
					log.Fatalf("bad -map entry %q", m)
				}
				addr := net.JoinHostPort(bindAddr, strconv.Itoa(lp+*offset))
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					log.Fatalf("listen %s: %v", addr, err)
				}
				log.Printf("forwarding %s -> server :%d", addr, sp)
				ps := portReg.get("c", lp+*offset)
				go acceptLoop(ln, func(c net.Conn) { forward(tun, c, sp, ps) })
			}
		}
		dc := newDgramClient(tun, *udpIdle)
		for _, m := range strings.Split(*udpMaps, ",") {
			if strings.TrimSpace(m) == "" {
				continue
			}
			addr, target, err := parseUDPMap(strings.TrimSpace(m), *bind, *offset)
			if err != nil {
				log.Fatal(err)
			}
			if _, err := dc.listen(addr, target); err != nil {
				log.Fatalf("listen udp %s: %v", addr, err)
			}
			log.Printf("forwarding udp %s -> server :%d", addr, target)
		}
		if *cfgPath != "" { // config ports: public port N -> server port N, added and removed live
			uls := newUDPListeners(func(p, t int) (*udpListener, error) {
				addr := net.JoinHostPort(*bind, strconv.Itoa(p+*offset))
				l, err := dc.listen(addr, t)
				if err == nil {
					log.Printf("forwarding udp %s -> server :%d", addr, t)
				}
				return l, err
			})
			ls := newListeners(func(p, t int) (net.Listener, error) {
				addr := net.JoinHostPort(*bind, strconv.Itoa(p+*offset))
				ln, err := net.Listen("tcp", addr)
				if err == nil {
					log.Printf("forwarding %s -> server :%d", addr, t)
					ps := portReg.get("c", p+*offset)
					go acceptLoop(ln, func(c net.Conn) { forward(tun, c, t, ps) })
				}
				return ln, err
			})
			if cfgPorts {
				if errs := ls.apply(fileCfg.tcpMaps()); len(errs) > 0 {
					log.Fatal(errs[0])
				}
				if errs := uls.apply(fileCfg.udpMaps()); len(errs) > 0 {
					log.Fatal(errs[0])
				}
			}
			w := &cfgWatcher{path: *cfgPath, known: known, skip: func(k string) bool { return explicit[k] }, interval: 3 * time.Second,
				onLimits: func(c *fileConfig) { portReg.applyLimits(c.Limits) },
				onPorts: func(c *fileConfig) []error {
					var errs []error
					for _, e := range append(ls.apply(c.tcpMaps()), uls.apply(c.udpMaps())...) {
						errs = append(errs, e)
						log.Print(e)
					}
					return errs
				}}
			w.start(fileCfg)
			go w.run()
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	portReg.save()
	if srv != nil {
		srv.Close()
	} else {
		tun.Close()
	}
}

// acceptLoop runs handle for every connection until the listener is closed.
func acceptLoop(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go handle(c)
	}
}

// forward opens a stream to server port target on the least loaded live session and bridges c to it.
func forward(tun *tunnel, c net.Conn, target int, ps *portStat) {
	if !ps.track(c) { // quota used up
		c.Close()
		return
	}
	defer ps.untrack(c)
	sess := tun.pick()
	if !sess.Alive() { // tunnel is down (pick prefers a live session): fail fast so the client retries elsewhere
		ps.errs.Add(1)
		c.Close()
		return
	}
	st, err := sess.OpenStream()
	if err != nil {
		ps.errs.Add(1)
		c.Close()
		return
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(target))
	st.SetGroup(uint32(target)) // fair queuing: one port's heavy streams share the link with the others
	if _, err := st.Write(hdr[:]); err != nil {
		ps.errs.Add(1)
		c.Close()
		return
	}
	dbg("client conn %s -> stream opened", c.RemoteAddr())
	bridge(c, st, fmt.Sprintf("client %s", c.RemoteAddr()), ps, false)
}

// listeners is the live set of public client ports opened from the config's ports list. Closing a listener stops
// new connections only; connections already bridged keep running.
type listeners struct {
	mu     sync.Mutex
	active map[portMap]net.Listener
	open   func(listen, target int) (net.Listener, error)
}

func newListeners(open func(listen, target int) (net.Listener, error)) *listeners {
	return &listeners{active: map[portMap]net.Listener{}, open: open}
}

// apply makes the open listeners equal to want; a changed target for the same listen port is a close + reopen.
// Failures are returned and retried by the next apply.
func (l *listeners) apply(want []portMap) []error {
	l.mu.Lock()
	defer l.mu.Unlock()
	set := map[portMap]bool{}
	for _, m := range want {
		set[m] = true
	}
	for m, ln := range l.active { // close first so a re-targeted listen port can be rebound
		if !set[m] {
			ln.Close()
			delete(l.active, m)
			log.Printf("stopped listening on port %d (-> %d)", m.Listen, m.Target)
		}
	}
	var errs []error
	for _, m := range want {
		if l.active[m] == nil {
			ln, err := l.open(m.Listen, m.Target)
			if err != nil {
				errs = append(errs, fmt.Errorf("listen port %d: %v", m.Listen, err))
				continue
			}
			l.active[m] = ln
		}
	}
	return errs
}

// has reports whether listen port p is open.
func (l *listeners) has(p int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for m := range l.active {
		if m.Listen == p {
			return true
		}
	}
	return false
}

// target returns the target of the open listener on listen port p (0 if none).
func (l *listeners) target(p int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for m := range l.active {
		if m.Listen == p {
			return m.Target
		}
	}
	return 0
}

// metricsPort is the port of the local metrics server (0 when off). The server never forwards a stream to it,
// whatever the allowlist says: it exposes stats, pprof and /speedtest.
var metricsPort atomic.Int32

func isMetricsPort(port int) bool {
	m := int(metricsPort.Load())
	return m != 0 && port == m
}

// loopbackMetricsAddr returns addr unchanged when its host is a loopback IP or "localhost"; otherwise (empty,
// 0.0.0.0, ::, a LAN address, a name) it returns 127.0.0.1:<port> and changed=true.
func loopbackMetricsAddr(addr string) (string, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if p := strings.TrimPrefix(addr, ":"); p != "" && !strings.Contains(p, ":") {
			return "127.0.0.1:" + p, true
		}
		return addr, false // unparseable: let ListenAndServe report it
	}
	if strings.EqualFold(host, "localhost") {
		return addr, false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return addr, false
	}
	return net.JoinHostPort("127.0.0.1", port), true
}

func serve(sess *wat.Session, lo, hi int, al *allow) {
	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		go func() {
			var hdr [2]byte
			if _, err := io.ReadFull(st, hdr[:]); err != nil {
				st.Reset()
				return
			}
			port := int(binary.BigEndian.Uint16(hdr[:]))
			if port == speedTestPort { // built-in speed test, never a local service
				serveSpeedTest(st)
				return
			}
			if isMetricsPort(port) { // the metrics server exposes stats, pprof and /quota/reset: never forward to it
				st.Reset()
				return
			}
			if port == dnsRelayPort && al.relayFor(port, lo, hi) { // built-in DNS relay for -ech ladder (2.9.0)
				serveDNSRelay(st)
				return
			}
			if !al.ok(port, lo, hi) {
				st.Reset()
				return
			}
			st.SetGroup(uint32(port))
			ps := portReg.get("s", port)
			c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
			if err != nil {
				ps.errs.Add(1)
				st.Reset()
				return
			}
			if !ps.track(c) {
				c.Close()
				st.Reset()
				return
			}
			defer ps.untrack(c)
			dbg("server stream -> %d dialed", port)
			bridge(c, st, fmt.Sprintf("server :%d", port), ps, true)
		}()
	}
}

// allow is the set of target ports a client may reach. With a file it is re-read whenever the file changes, so
// adding or removing a port never restarts the server (a restart would cut every client session).
type allow struct {
	mu    sync.RWMutex
	ports map[int]bool
	udp   map[int]bool // udp target ports: `N/udp` entries in the config ports list, -allow-ports or -allow-file
	file  string
	mtime time.Time
	size  int64 // allow-file size, checked next to mtime (a same-granularity rewrite changes size)
	cfg   bool  // ports come from the config file: authoritative, even when empty
}

func parsePorts(txt string) map[int]bool {
	m := map[int]bool{}
	for _, f := range strings.FieldsFunc(txt, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }) {
		if p, err := strconv.Atoi(f); err == nil && p > 0 && p < 65536 {
			m[p] = true
		}
	}
	return m
}

func isPortSep(r rune) bool {
	return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r'
}

// parseUDPPorts collects the `N/udp` tokens of a ports list (parsePorts skips them).
func parseUDPPorts(txt string) map[int]bool {
	m := map[int]bool{}
	for _, f := range strings.FieldsFunc(txt, isPortSep) {
		if s, ok := strings.CutSuffix(f, "/udp"); ok {
			if p, err := strconv.Atoi(s); err == nil && p > 0 && p < 65536 {
				m[p] = true
			}
		}
	}
	return m
}

// reset reinstalls list as the allowlist, undoing an authoritative config ports: list. A running
// allow-file poller resumes applying the file on its next tick (reload skips only while a.cfg).
func (a *allow) reset(list string) {
	m, um := parsePorts(list), parseUDPPorts(list)
	a.mu.Lock()
	a.ports, a.udp, a.cfg = m, um, false
	a.mu.Unlock()
	log.Printf("allowed target ports: %d", len(m))
}

func newAllow(list, file string) *allow {
	a := &allow{ports: parsePorts(list), udp: parseUDPPorts(list), file: file}
	if file != "" {
		a.reload()
		go func() {
			for range time.Tick(3 * time.Second) {
				a.reload()
			}
		}()
	}
	return a
}

func (a *allow) reload() {
	st, err := os.Stat(a.file)
	// mtime alone misses a rewrite landing inside the filesystem's timestamp granularity; size catches it
	if err != nil || (st.ModTime().Equal(a.mtime) && st.Size() == a.size) {
		return
	}
	b, err := os.ReadFile(a.file)
	if err != nil {
		return
	}
	m, um := parsePorts(string(b)), parseUDPPorts(string(b))
	a.mu.Lock()
	if a.cfg { // the config's ports: list is authoritative; only note the file mtime, never apply its contents
		a.mtime, a.size = st.ModTime(), st.Size()
		a.mu.Unlock()
		return
	}
	a.ports, a.udp, a.mtime, a.size = m, um, st.ModTime(), st.Size()
	a.mu.Unlock()
	log.Printf("allowed target ports: %d", len(m))
}

// setPorts installs the config file's tcp ports as the (authoritative) allowlist.
func (a *allow) setPorts(ports []int) {
	m := map[int]bool{}
	for _, p := range ports {
		m[p] = true
	}
	a.mu.Lock()
	a.ports, a.cfg = m, true
	a.mu.Unlock()
	log.Printf("allowed target ports: %d", len(m))
}

// setUDPPorts installs the config file's udp ports (call after setPorts, which marks the list authoritative).
func (a *allow) setUDPPorts(ports []int) {
	m := map[int]bool{}
	for _, p := range ports {
		m[p] = true
	}
	a.mu.Lock()
	a.udp = m
	a.mu.Unlock()
	log.Printf("allowed udp target ports: %d", len(m))
}

// udpOK is ok for datagram flows: with any allowlist only listed /udp ports pass (a tcp-only list allows no udp).
func (a *allow) udpOK(port, lo, hi int) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.file != "" || a.cfg || len(a.ports) > 0 || len(a.udp) > 0 {
		return a.udp[port]
	}
	return port >= lo && port <= hi
}

func (a *allow) ok(port, lo, hi int) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.file != "" || a.cfg || len(a.ports) > 0 { // a file is authoritative, even when empty
		return a.ports[port]
	}
	return port >= lo && port <= hi
}

// relayFor: the built-in DNS relay owns target 53 unless an explicit allowlist forwards it to a real local
// resolver. The default 1-65535 range does not count as explicit — otherwise the ladder's relay rung (2.9.0)
// is dead on every default-config server, because 53 then dials a local resolver that is usually not there.
// A narrowed -allow-min/-allow-max range is explicit (audit 2026-10-22): the operator picked what to forward.
func (a *allow) relayFor(port, lo, hi int) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.file != "" || a.cfg || len(a.ports) > 0 {
		return !a.ports[port]
	}
	if lo != 1 || hi != 65535 {
		return !(port >= lo && port <= hi)
	}
	return true
}

var debugOn bool

func dbg(f string, a ...any) {
	if debugOn {
		log.Printf(f, a...)
	}
}

// side is "c" or "s" for the process (stats key); set before any traffic.
var side = "c"

// bridge pipes c <-> st counting into ps; server = c is the target service, so c->st is the "down" direction.
func bridge(c net.Conn, st *wat.Stream, tag string, ps *portStat, server bool) {
	t0 := time.Now()
	var up, down int64
	var upErr, downErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := ps.copy(st, c, !server)
		up, upErr = n, err
		if err != nil {
			ps.errs.Add(1)
			st.Reset()
			return
		}
		st.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		n, err := ps.copy(c, st, server)
		down, downErr = n, err
		if tc, ok := c.(*net.TCPConn); ok && err == nil {
			tc.CloseWrite()
		} else if err != nil {
			c.Close()
		}
	}()
	wg.Wait()
	c.Close()
	st.CloseRead() // local conn is gone: drop any unread data so the stream reaps instead of lingering (no local TCP behind it)
	dbg("%s done in %v: tcp->stream %d B (%v), stream->tcp %d B (%v)", tag, time.Since(t0).Round(time.Millisecond), up, upErr, down, downErr)
}

type clientJSON struct {
	IP      string `json:"ip"`
	Carrier string `json:"carrier"`
	AgeMS   int64  `json:"age_ms"`
}

// clientsJSON is the /stats "clients" list (server only): one row per live client session.
func clientsJSON(list []wat.ClientInfo) []clientJSON {
	out := make([]clientJSON, 0, len(list))
	for _, c := range list {
		out = append(out, clientJSON{c.IP, c.Carrier, c.Age.Milliseconds()})
	}
	return out
}

func allReliableDirect(names []string, reverse bool) bool {
	if len(names) == 0 {
		return false
	}
	for _, n := range names {
		if reverse {
			if !poolCarriers[n] {
				return false
			}
		} else {
			if n != "tcp" && n != "tls" {
				return false
			}
		}
	}
	return true
}
