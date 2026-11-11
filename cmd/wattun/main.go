// wattun: TCP port forwarding over ICMP echo with its own transport (see ../../README.md).
//
//	server:  wattun -mode server -key SECRET -allow-ports 20030
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
	"net/netip"
	"net/url"
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

// nameSet turns a carrier name list into the lookup maps below.
func nameSet(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// carrierNames is every -carrier name in a stable order (base carriers first, then the F19 shaped tables). The shaped
// names come from wat, not a copy, so a shape the engine ships cannot stay rejected here (audit L6/F15).
var carrierNames = append(append([]string{
	"icmp", "udp", "tcp", "tls", "ws", "wss", "h2", "h2c", "grpc", "gre", "ipip",
}, wat.RawShapedCarrierNames()...), wat.UDPShapedCarrierNames()...)

// rawIPCarrier: the carriers on a raw IP socket, which take a bare IP and run one session.
var rawIPCarrier = nameSet(append([]string{"icmp", "gre", "ipip"}, wat.RawShapedCarrierNames()...))

// shapedUDPCarrier: F19 phase-2 (3.3.0) wattun-internal UDP shapes: the udp carrier with a fixed per-protocol header
// and conventional port. Both ends must run 3.3.0 and pick the same name; they do not talk to the real protocol.
var shapedUDPCarrier = nameSet(wat.UDPShapedCarrierNames())

// shapedRawCarrier: F19 phase-1 raw-tier shaped carriers (Linux + CAP_NET_RAW). D7: shaped carriers, raw or UDP tier,
// are single-carrier in 3.3.0 and are rejected inside a '+' bond.
var shapedRawCarrier = nameSet(wat.RawShapedCarrierNames())

// validCarrier adds the manager's fortress alias on top of every -carrier name.
var validCarrier = func() map[string]bool {
	m := nameSet(carrierNames)
	m["fortress"] = true
	return m
}()

var poolCarriers = map[string]bool{"tcp": true, "tls": true, "ws": true, "wss": true, "h2": true, "h2c": true, "grpc": true}

// carrierNoListen: carriers with no -listen / -listen-NAME (raw sockets bind the whole protocol; icmp is a raw socket
// that only answers). The raw set is exactly rawIPCarrier.
var carrierNoListen = rawIPCarrier

func main() {
	runManager()
	// GOGC 200 (2.4.0-2.4.5) saved little CPU but let a busy CDN tunnel's heap reach ~1.75x its live size: Iran sat at
	// 1 GB Sys for ~400 MB live, with GC at under 0.1 % CPU (field 2026-10-12). The Go default (100) is used again;
	// GOGC / GOMEMLIMIT still override it.
	mode := flag.String("mode", "", "client|server")
	key := flag.String("key", "", "pre-shared key")
	keyFile := flag.String("key-file", "", "read the key from a file")
	peer := flag.String("peer", "", "client: server IP; the pool carriers (tcp|tls|ws|wss|h2|h2c|grpc) take host:port and may list several, comma separated, which the pool connections spread over (client only, 2.2.0); the F19 shaped carriers take the same host:port form, with a bare host using the carrier's conventional port")
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
	allowClients := flag.String("allow-clients", "", "server: comma/space separated IPv4/IPv6 addresses or CIDR prefixes that may open a session; every other source is dropped before admission (empty = every source). Direct carriers only: behind a CDN the source is the proxy, and -reverse is not filtered (3.3.0)")
	allowClientsFile := flag.String("allow-clients-file", "", "server: file with the -allow-clients list (comma/space/newline separated), read at startup; replaces -allow-clients (3.3.0)")
	debug := flag.Bool("debug", false, "log every stream open/close")
	version := flag.Bool("version", false, "print the version and exit")
	fecMode := flag.String("fec", "off", "off|auto: adaptive XOR parity after bursts of small packets, sent only while the measured loss is above -fec-on-loss (cuts tail latency on lossy links; both ends need 1.7.0 and -fec auto; loss gate since 3.3.0)")
	fecOnLoss := flag.Float64("fec-on-loss", 2, "fec auto: start sending parity once the sender's measured loss is above this percent (0.01 = 1 %, at most 50; must be above -fec-off-loss; 3.3.0)")
	fecOffLoss := flag.Float64("fec-off-loss", 0.5, "fec auto: stop sending parity once the measured loss falls below this percent (0 = once open it never closes; below -fec-on-loss; 3.3.0)")
	shapeData := flag.Float64("shape-data", 0, "pad packets that carry stream data to randomized realistic sizes, spending at most this percent of the stream bytes sent (0 = off, at most 25; 3.3.0)")
	noiseMode := flag.String("noise", "off", "idle traffic, off|low|med|custom: while the session has no user data for ~2 keepalives, send non-ack-eliciting filler packets at the matching byte budget (low 128 B/s, med 1024 B/s; custom uses -noise-bps; 3.3.0)")
	noiseBps := flag.Int("noise-bps", 0, "noise, with -noise custom: filler byte budget in bytes/second (64..1000000; 3.3.0)")
	noiseWindow := flag.String("noise-window", "", `noise: local-clock window "HH:MM-HH:MM" (e.g. 02:00-06:00) during which filler may be sent; empty = all day (3.3.0)`)
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
	icmpType := flag.String("icmp-type", "echo", "icmp carrier: echo|timestamp - the ICMP request type the client sends (the server answers with the matching reply: 8/0, 13/14); both ends must use the same. info|mask are accepted, but the Linux kernel does not answer them")
	carrier := flag.String("carrier", "icmp", "icmp|udp|tcp|tls|ws|wss|h2|h2c|grpc|gre|ipip|sit|6to4|xfrm-ipsec|etherip|l2tpv3|fou-gre|gue-ipip|vxlan|geneve|dnscrypt-udp|ntp-direct|openvpn-dco|srtp-direct (gre/ipip: IP protocol 47/4 on a raw socket, root and Linux, -peer is a bare IP like icmp, 3.2.0 on both ends; sit/6to4/xfrm-ipsec/etherip/l2tpv3: F19 raw-tier shaped carriers, IP protocol 41/41/50/97/115 on a raw socket, root and Linux, bare-IP -peer, 3.3.0 on both ends; fou-gre/gue-ipip/vxlan/geneve/dnscrypt-udp/ntp-direct/openvpn-dco/srtp-direct: F19 UDP-shaped carriers, the udp carrier with a fixed per-protocol header and conventional port (5555/6080/4789/6081/443/123/1194/5004, an explicit port wins), client dials -peer host:port, server listens on -listen, 3.3.0 on both ends; F19 shapes are wattun-internal: both ends must use the same name, they do not talk to the real protocol; all but icmp/gre/ipip and the F19 raw shapes: client dials -peer host:port, server listens on -listen; h2 through Cloudflare: not supported, use grpc or wss); join several with '+' (icmp+udp+tcp) to bond them into ONE session that survives any one being blocked; then -peer / -listen are the defaults and -peer-NAME / -listen-NAME (e.g. -peer-udp, -listen-tcp, also keys in the config file) override them per carrier; fortress = alias the manager writes for blackout mode (icmp+tcp+tls+wss+udp on ports 80/443/8443/53)")
	udpListen := flag.String("listen", ":4443", "server, udp carrier: address to listen on (the F19 UDP-shaped carriers listen on their conventional port when this is not set)")
	conns := flag.Int("conns", 0, "client, tcp/tls carrier: connections in the pool (0 = auto-tuned from host hardware: 8 on lean VPS, 16 on 2-CPU/2GB+, 24-32 on 4+ cores)")
	poolRotate := flag.String("pool-rotate", "0", "client, pool carriers (tcp|tls|ws|wss|h2|grpc): recycle each healthy pool connection after this long, so no flow shows a months-stable lifetime; accepts 30m, 4h or seconds; jittered +/-40% per connection so the redials never line up; 0 = off (2.8.0; a -reverse server dials too, so it honours it since 3.0.2)")
	poolRotateBytes := flag.String("pool-rotate-bytes", "0", "client, pool carriers, with -pool-rotate or alone: also recycle each healthy pool connection after this many bytes handed to its socket (500MB, 4GB, 300k; 1MB = 1e6); jittered +/-25% like the time axis; whichever limit hits first recycles (2.8.1; a -reverse server honours it since 3.0.2)")
	tcpCC := flag.String("tcp-cc", wat.PoolTCPCC, "tcp|tls|ws|wss|h2|h2c|grpc: TCP congestion control set on every pool socket, Linux (bbr ignores random loss, the kernel default cubic halves the window on it; 'system' keeps the kernel default; 2.4.18, before: system)")
	nSess := flag.Int("sessions", 0, "client: independent sessions to the server (0 = auto-tuned from host CPU, 1-16), each with its own -conns pool, pacer and session id; new TCP streams go to the least loaded live one, UDP flows stick to one, /speedtest uses all; udp|tcp|tls|ws|wss|h2|h2c|grpc only (not icmp, bonded carriers or -reverse); each counts against the server's -max-sessions limit (client only, 2.3.0; server unchanged)")
	maxSess := flag.Int("max-sessions", 128, "server: sessions admitted at once, 1-4096; every client -sessions slot counts one, and a handover runs two clients (3.3.5, before: fixed 32)")
	maxConns := flag.Int("max-conns", maxPublicConns, "public TCP listeners: connections held at once in total, 1-1000000; one source IP holds at most 1024 or this, whichever is lower (3.3.5, before: fixed 4096)")
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
		if !carrierNoListen[c] {
			listenBy[c] = flag.String("listen-"+c, "", "server (or -reverse client), bonded carriers: listen address of the "+c+" carrier (default: -listen)")
		}
	}
	stateDir := flag.String("state-dir", "", "directory for the quota-usage and lifetime-totals state files (<config>.quota.json, <config>.totals.json); created 0700 when missing, an existing wider mode is tightened; needs -config. Empty = next to the config, the 2.5.0-3.2.x location (3.3.0). Point it at tmpfs (e.g. /run/wattun) to spare the disk: tmpfs loses the counters on reboot")
	stateSave := flag.Int("state-save", 30, "seconds between state-file saves (quota usage and lifetime totals); 0 = only on shutdown, at most 2592000 (30 days; 3.3.0)")
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
	// F19 (3.3.0): which keys the config file set, so a shaped carrier can tell its -listen default (:4443, the udp
	// carrier's) from an operator's explicit choice.
	cfgKeys := map[string]bool{}
	if fileCfg != nil {
		for _, e := range fileCfg.KVs {
			cfgKeys[e.Key] = true
		}
	}
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
	// F8 (3.3.0): the state files stay named after the config; -state-dir only moves them, -state-save sets the
	// periodic write interval (0 = shutdown only).
	stateEvery, err := stateSaveInterval(*stateSave)
	if err != nil {
		log.Fatal(err)
	}
	quotaPath, totalsPath := statePaths(*cfgPath, *stateDir)
	if *stateDir != "" {
		if *cfgPath == "" {
			log.Fatal("-state-dir needs -config: the state files are named after the config file")
		}
		if err := prepareStateDir(*stateDir); err != nil {
			log.Fatalf("-state-dir: %v", err)
		}
		log.Printf("state files in %s", *stateDir)
	}
	fecOn, fecOff, err := fecGatePct(*fecOnLoss, *fecOffLoss)
	if err != nil {
		log.Fatal(err)
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
			fmt.Fprintln(os.Stderr, "unknown -carrier (icmp|udp|tcp|tls|ws|wss|h2|h2c|grpc|gre|ipip|sit|6to4|xfrm-ipsec|etherip|l2tpv3|fou-gre|gue-ipip|vxlan|geneve|dnscrypt-udp|ntp-direct|openvpn-dco|srtp-direct, joined with + to bond; each at most once)")
			os.Exit(2)
		}
		seen[n] = true
		anyPool = anyPool || poolCarriers[n]
	}
	// D7 (3.3.0): shaped carriers are single-carrier. A bond sizes each packet for the path it takes, and each shaped
	// carrier derives its own header (the UDP tier also its own conventional port), so a shaped leg in a bond was
	// untested and could silently use mismatched ports; refuse it here (the manager refuses it too).
	if bad := shapedBondCarrier(names); bad != "" {
		fmt.Fprintf(os.Stderr, "-carrier %q: %s is a shaped carrier and works as a single carrier only in 3.3.0; bond udp|tcp|tls|ws|wss|h2|h2c|grpc or use it alone\n", *carrier, bad)
		os.Exit(2)
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
		if !server && !*reverse && len(names) == 1 && !rawIPCarrier[names[0]] && !shapedUDPCarrier[names[0]] {
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
		case len(names) > 1 || rawIPCarrier[names[0]] || shapedUDPCarrier[names[0]]:
			fmt.Fprintf(os.Stderr, "-sessions > 1 works with one udp|tcp|tls|ws|wss|h2|h2c|grpc carrier, not %q\n", *carrier)
			os.Exit(2)
		case *reverse:
			fmt.Fprintln(os.Stderr, "-sessions > 1 does not work with -reverse (the server dials one pool)")
			os.Exit(2)
		}
	}
	if *maxSess < 1 || *maxSess > 4096 {
		fmt.Fprintf(os.Stderr, "-max-sessions must be 1..4096, got %d\n", *maxSess)
		os.Exit(2)
	}
	if *maxConns < 1 || *maxConns > 1000000 {
		fmt.Fprintf(os.Stderr, "-max-conns must be 1..1000000, got %d\n", *maxConns)
		os.Exit(2)
	}
	publicConns.max, publicConns.maxPer = *maxConns, min(maxPublicPerIP, *maxConns)  // set before any listener starts
	if *reverse && *fakeSNI != "" && (*fakeMode == "sum" || *fakeMode == "seqsum") { // 3.0.0
		fmt.Fprintf(os.Stderr, "-fake-mode %s does not work with -reverse: checksum markers need a middlebox that drops the damaged segment; on an open reverse path the peer can take it and the tunnel dies. Use rst or synrst.\n", *fakeMode)
		os.Exit(2)
	}
	// W10 (3.3.0): server-side client allowlist. The check runs before a session is admitted, on the source address the
	// carrier reports, so it only makes sense where that is the client's own IP. M4: it restricts holders of the
	// PSK/token to these source IPs (AEAD-before-admission already keeps every other source out); the file variant must
	// live under /etc/wattun because the unit runs with ProtectHome=yes. M11: with a CDN/proxy carrier or -sni the
	// server sees the edge's address, so the list would reject every real client: that combination is a startup error.
	// -reverse has no client source to compare, so it is ignored with a warning (the server dials the client).
	var allowClientPrefixes []netip.Prefix
	if *allowClients != "" || *allowClientsFile != "" {
		if !server {
			log.Fatal("-allow-clients is a server option: it filters which clients may open a session")
		}
		// M4 (3.3.0): the unit runs with ProtectHome=yes, so a list under /root or /home would pass manager validation
		// and then fail at startup; require the file under /etc/wattun (the unit's readable tree).
		if *allowClientsFile != "" && !allowClientsFileUnderEtc(*allowClientsFile) {
			log.Fatalf("-allow-clients-file must be under /etc/wattun (the service unit runs with ProtectHome=yes, so a list under /root or /home is not readable); got %q", *allowClientsFile)
		}
		ps, err := clientAllowList(*allowClients, *allowClientsFile)
		if err != nil {
			log.Fatal(err)
		}
		if *reverse {
			log.Printf("warning: -allow-clients is ignored with -reverse: the server dials the client, so a session's source address is not the client's")
		} else if cdn := allowClientsCDN(names, *sni); cdn != "" {
			// M11 (3.3.0): with a CDN/proxy carrier the source the server sees is the edge's address, so a list would
			// reject every real client. That is a guaranteed lock-out, not a warning: refuse it at startup.
			log.Fatalf("-allow-clients cannot be used with %s: the server sees the CDN/proxy address, not the client's, so every real client would be rejected; filter at the proxy or use a direct carrier", cdn)
		} else {
			allowClientPrefixes = ps
			log.Printf("clients allowed from %d prefix(es) (-allow-clients restricts holders of the PSK/token to these source IPs)", len(ps))
		}
	}
	// W7/F13 (3.3.0): opt-in traffic shaping. Both are off by default and validate their own bounds here; nothing is
	// added to the packet path unless the parsed value is non-zero.
	shapeFrac, err := shapeDataPct(*shapeData)
	if err != nil {
		log.Fatal(err)
	}
	noiseBpsVal, err := noiseBudget(*noiseMode, *noiseBps)
	if err != nil {
		log.Fatal(err)
	}
	noiseFrom, noiseTo, err := parseNoiseWindow(*noiseWindow)
	if err != nil {
		log.Fatal(err)
	}
	if noiseBpsVal == 0 && *noiseWindow != "" {
		log.Printf("warning: -noise-window is ignored without -noise")
	}
	if shapeFrac > 0 && len(names) > 1 {
		log.Printf("warning: -shape-data is ignored on bonded carriers: a bond sizes each packet for the path it takes")
	}
	if shapeFrac > 0 {
		log.Printf("shape-data: padding stream-data packets with up to %.0f%% extra bytes", shapeFrac*100)
	}
	if noiseBpsVal > 0 {
		if noiseFrom == 0 && noiseTo == 0 {
			log.Printf("noise: up to %.0f B/s of filler while idle (all day)", noiseBpsVal)
		} else {
			log.Printf("noise: up to %.0f B/s of filler while idle (window %02d:%02d-%02d:%02d)", noiseBpsVal, noiseFrom/60, noiseFrom%60, noiseTo/60, noiseTo%60)
		}
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
		if (rawIPCarrier[carrier] || carrier == "udp" || shapedUDPCarrier[carrier]) && strings.Contains(peer, ",") {
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
		case "sit", "6to4", "xfrm-ipsec", "etherip", "l2tpv3":
			// F19 phase 1 (3.3.0): raw-tier shaped carriers. wattun-internal wire shapes between two 3.3.0 peers
			// (both ends need the same carrier name), not real 6in4/IPsec/EtherIP/L2TPv3; raw sockets are Linux+root.
			if *reverse {
				log.Fatalf("%s carrier: -reverse is not supported (use icmp, udp or a pool carrier)", carrier)
			}
			if !server && peer == "" {
				log.Fatalf("%s carrier: -peer is empty (want the server's bare IP)", carrier)
			}
			r, err := wat.NewShapedRaw(carrier, server, peer, src, k)
			if err != nil {
				log.Fatalf("%s socket: %v", carrier, err)
			}
			pio, raw = r, r
			log.Printf("%s carrier: wattun-internal F19 shape between two 3.3.0 wattun peers, not real %s", carrier, carrierRealName[carrier])
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
		case "fou-gre", "gue-ipip", "vxlan", "geneve", "dnscrypt-udp", "ntp-direct", "openvpn-dco", "srtp-direct":
			// F19 phase 2 (3.3.0): the udp carrier with a fixed per-protocol header in front of every datagram and the
			// protocol's conventional port by default. wattun-internal shapes between two 3.3.0 peers (same name), not
			// real VXLAN/Geneve/GUE/FOu/DNSCrypt/NTP/OpenVPN/SRTP.
			if *reverse {
				log.Fatalf("%s carrier: -reverse is not supported (use udp or icmp for reverse)", carrier)
			}
			shapePort := wat.UDPShapePort(carrier)
			if !server && peer == "" {
				log.Fatalf("%s carrier: -peer is empty (want host[:port])", carrier)
			}
			if peer != "" {
				peer = withDefaultPort(peer, shapePort)
			}
			// -listen defaults to the udp carrier's :4443; a shaped carrier that was not given an explicit address
			// uses its protocol's conventional port instead.
			if !explicit["listen"] && !explicit["listen-"+carrier] && !cfgKeys["listen"] && !cfgKeys["listen-"+carrier] {
				listen = withDefaultPort("", shapePort)
			} else {
				listen = withDefaultPort(listen, shapePort)
			}
			if server {
				raw, err = wat.NewShapedUDPServer(carrier, listen, k)
			} else if srcNetIP != nil {
				pio, err = wat.NewShapedUDPClientAddr(carrier, peer, &net.UDPAddr{IP: srcNetIP}, k)
			} else {
				pio, err = wat.NewShapedUDPClient(carrier, peer, k)
			}
			if err != nil {
				log.Fatalf("%s socket: %v", carrier, err)
			}
			log.Printf("%s carrier: wattun-internal F19 shape between two 3.3.0 wattun peers, not real %s", carrier, carrierRealName[carrier])
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
	// M1/M15 (3.3.0): an explicit -mtu may not exceed the carrier's own payload ceiling (a shaped carrier adds its header
	// inside the 1400 B datagram; NewSession clamps too, for the server's admitted sessions). A profile without a ceiling
	// (icmp) keeps the operator's value.
	maxPayload := *mtu
	if maxPayload > 0 {
		var prof wat.Profile
		if pr, ok := pio.(wat.Profiled); ok {
			prof = pr.Profile()
		} else if pr, ok := raw.(wat.Profiled); ok {
			prof = pr.Profile()
		}
		if v, clamped := clampMaxPayload(maxPayload, prof); clamped {
			log.Printf("-mtu %d is above the payload ceiling of carrier %q (%d B); using %d B", maxPayload, *carrier, v, v)
			maxPayload = v
		}
	}
	cfg := wat.Config{
		Server: server, Key: k, Paths: *lanes, MaxBps: *maxMB * 1e6, Slack: time.Duration(*slackMs) * time.Millisecond,
		PingEvery: time.Duration(*pingEvery) * time.Second, NoMask: !*hdrMask, NoShape: !*shape,
		Logf: log.Printf, Hedge: *hedge, FEC: *fecMode == "auto", FECOnLoss: fecOn, FECOffLoss: fecOff,
		MaxPayload: maxPayload, Bond: tm, AllowClients: allowClientPrefixes,
		ShapeData: shapeFrac, NoiseBps: noiseBpsVal, NoiseFrom: noiseFrom, NoiseTo: noiseTo,
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
		if totalsPath != "" { // needs -config, like the other state files: <config>.pn
			keepPNFloor(strings.TrimSuffix(totalsPath, ".totals.json") + ".pn")
		}
		srv = wat.NewServer(cfg, raw)
		srv.MaxSessions = *maxSess
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
			if h, _, err := net.SplitHostPort(*dnsListen); err == nil && !loopbackHost(h) {
				log.Printf("dns-listen %s is not a loopback address: anyone who can reach it can resolve names through the tunnel (an open resolver); bind it to 127.0.0.1 unless that is intended", *dnsListen)
			}
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
	if quotaPath != "" { // F8: -state-dir/-state-save only move and time these files; their names stay <config>.*
		portReg.loadQuota(quotaPath)
		portReg.loadTotals(totalsPath, func() (uint64, uint64) { st := stats(); return st.BytesIn, st.BytesOut })
	}
	if fileCfg != nil {
		portReg.applyLimits(fileCfg.Limits)
	}
	go portReg.run(stateEvery)
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
			mux.HandleFunc("/debug/pprof/", guard(pprof.Index))
			mux.HandleFunc("/debug/pprof/profile", guard(pprof.Profile))
			mux.HandleFunc("/ports", guard(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(portReg.snapshot(side))
			}))
			mux.HandleFunc("/quota/reset", func(w http.ResponseWriter, r *http.Request) {
				if crossSiteRequest(r) {
					http.Error(w, "cross-site request refused", http.StatusForbidden)
					return
				}
				quotaResetHandler(w, r) // keeps its own loopback + POST checks
			})
			mux.HandleFunc("/carrier/toggle", func(w http.ResponseWriter, r *http.Request) {
				if crossSiteRequest(r) {
					http.Error(w, "cross-site request refused", http.StatusForbidden)
					return
				}
				if r.Method != http.MethodPost { // it changes state: a GET (a link, a prefetch) must not
					w.Header().Set("Allow", http.MethodPost)
					http.Error(w, "POST only", http.StatusMethodNotAllowed)
					return
				}
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
				speedH := speedTestHandler(tun)
				mux.HandleFunc("/speedtest", func(w http.ResponseWriter, r *http.Request) {
					if crossSiteRequest(r) {
						http.Error(w, "cross-site request refused", http.StatusForbidden)
						return
					}
					speedH(w, r)
				})
			}
			mux.HandleFunc("/stats", guard(func(w http.ResponseWriter, r *http.Request) {
				st := stats()
				inTot, outTot := portReg.sessionTotals(st.BytesIn, st.BytesOut)
				out := map[string]any{
					"bytes_in_total": inTot, "bytes_out_total": outTot,
					"pkts_out": st.PktsOut, "pkts_in": st.PktsIn, "bytes_out": st.BytesOut, "bytes_in": st.BytesIn,
					"fec_sent": st.FecSent, "fec_recovered": st.FecRecovered, "fec_state": st.FecState, "shape_data_bytes": st.PadBytes, "noise_sent": st.NoiseSent, "noise_bytes": st.NoiseBytes, "retrans": st.Retrans, "send_errors": st.Dropped, "ack_late": st.AckLate, "dup_recv": st.RxDup, "rx_too_old": st.RxTooOld, "rate_bps": st.RateBps,
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
					"conn_limit_drops": connLimitDrops.Load(), "conns_active": connLimitActive.Load(),
					"filter_profile": wat.FilterProfileNow(), // fake-mode auto's startup verdict (2.9.0)
					"raw_send_fails": wat.RawSendFails(),     // fake-SNI fires that never left the host (2.10.9)
				}
				// Flat aliases for the aggregates: encoding/json sorts the nested carriers/session_list before
				// these keys, and the manager's grep|head -1 parser would otherwise read a nested value (M6).
				for k, v := range statsAliases(st) {
					out[k] = v
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
			}))
			log.Println(http.ListenAndServe(*metrics, mux))
		}()
	}
	go func() {
		var last, prev wat.Stats // last: at the last printed line (its deltas); prev: at the previous tick
		var lw linkWatch
		for range time.Tick(10 * time.Second) {
			st := stats()
			if !server {
				if note := lw.tick(10*time.Second, st.PktsIn, st.PktsOut-prev.PktsOut, alive()); note != "" {
					log.Print(note)
				}
			}
			var nSess int
			if srv != nil {
				nSess = srv.Sessions()
			} else {
				nSess = len(tun.list)
			}
			// M7 (3.3.0): noise filler is never acked and must not keep the quiet-idle stats line alive forever.
			quiet := quietStats(st, prev, nSess)
			prev = st
			if quiet {
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
		// M4: a flag-run server with no explicit allowlist source forwards every 127.0.0.1 port. Warn once and
		// keep the documented default (the operator opts in with -allow-ports or a `ports:` list).
		if (fileCfg == nil || !fileCfg.PortsSet) && *allowList == "" && *allowFile == "" && *allowLo <= 1 && *allowHi >= 65535 {
			log.Printf("warning: server allows every target port 1-65535; set -allow-ports (or ports: in the config) to limit which localhost services a client can reach")
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

// acceptLoop runs handle for every connection until the listener is closed. Public listeners are capped so one
// source cannot take every stream slot; a refused connection is closed right away.
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
		ip := remoteIP(c.RemoteAddr())
		if !publicConns.acquire(ip) {
			connLimitDrops.Add(1)
			c.Close()
			continue
		}
		connLimitActive.Add(1)
		go func() {
			defer func() {
				publicConns.release(ip)
				connLimitActive.Add(-1)
			}()
			handle(c)
		}()
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
	if loopbackHost(host) {
		return addr, false
	}
	return net.JoinHostPort("127.0.0.1", port), true
}

// loopbackHost reports whether host (no port, no brackets) is "localhost" or a loopback IP.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// guard refuses a cross-site browser request before h runs; the metrics server is loopback-bound, but a page
// can still issue a plain GET at 127.0.0.1:port with no preflight.
func guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if crossSiteRequest(r) {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// statsAliases returns the flat aggregate aliases the manager greps out of /stats (see the merge in the handler).
func statsAliases(st wat.Stats) map[string]any {
	return map[string]any{"rtt_ms": float64(st.SRTT) / 1e6, "streams_total": st.Streams}
}

// crossSiteRequest reports whether r was started by a web page on another origin. The metrics server is
// loopback-bound, but a browser page can still issue a plain GET at 127.0.0.1:port with no preflight.
// Browsers send Sec-Fetch-Site (and an Origin header for CORS-relevant requests); curl/the manager send
// neither, so absent headers stay allowed. A Host that is not localhost or a loopback IP is refused too: a
// DNS-rebinding page is same-origin with its own name, which then resolves to 127.0.0.1.
func crossSiteRequest(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	// 0.0.0.0/:: too: curl to a hand-edited "metrics: 0.0.0.0:N" (served on loopback) sends that Host, and a
	// rebinding page always arrives with a name
	if ip := net.ParseIP(host); !loopbackHost(host) && (ip == nil || !ip.IsUnspecified()) {
		return true
	}
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" && s != "none" {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return true // an unparseable Origin cannot be proven to be this host
	}
	return !loopbackHost(u.Hostname())
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

// clampMaxPayload (M1/M15) applies a carrier's payload ceiling to an explicit -mtu. MaxMTU is the hard frame ceiling
// when the carrier sets one (a direct pool allows bigger than its default MTU); otherwise MTU is the ceiling (shaped
// carriers, gre/ipip: their own header comes out of the 1400 B datagram, so an explicit 1400 overflowed the wire). A
// profile with neither (icmp) does not constrain -mtu.
func clampMaxPayload(explicit int, prof wat.Profile) (int, bool) {
	if explicit <= 0 {
		return explicit, false
	}
	ceiling := prof.MaxMTU
	if ceiling <= 0 {
		ceiling = prof.MTU
	}
	if ceiling > 0 && explicit > ceiling {
		return ceiling, true
	}
	return explicit, false
}

// quietStats reports whether the 10 s stats line has nothing to say: no stream is live and the non-noise packets that
// moved since the previous tick (prev) are no more than keepalives. Noise alone is deliberately quiet (M7: with -noise
// an otherwise idle tunnel otherwise logged a "stats:" line every 10 s, ~8.6k lines/day, for traffic that is never
// acked); so are keepalives, which moved PktsIn on every idle but connected tunnel (3.3.5).
func quietStats(st, prev wat.Stats, sessions int) bool {
	const keepalivePkts = 40 // per session per 10 s: an idle udp pair measured ~15 (in+out, both directions' pings and acks)
	moved := st.PktsIn - prev.PktsIn + (st.PktsOut - st.NoiseSent) - (prev.PktsOut - prev.NoiseSent)
	return st.Streams == 0 && moved <= uint64(keepalivePkts*max(sessions, 1))
}

// shapedBondCarrier returns the first shaped carrier in a bonded '+' list ("" when none). D7 (3.3.0): the F19 raw-tier
// and UDP-tier shapes are wattun-internal per-carrier shapes whose headers/ports are sized for one carrier, so they are
// single-carrier in this release.
func shapedBondCarrier(names []string) string {
	if len(names) < 2 { // a single carrier is not a bond (and is exactly how a shaped carrier is meant to be used)
		return ""
	}
	for _, n := range names {
		if shapedRawCarrier[n] || shapedUDPCarrier[n] {
			return n
		}
	}
	return ""
}

// carrierRealName names the protocol each F19 shaped carrier imitates, for the startup "not real ..." line.
var carrierRealName = map[string]string{
	"sit": "6in4", "6to4": "6to4", "xfrm-ipsec": "IPsec/ESP", "etherip": "EtherIP", "l2tpv3": "L2TPv3",
	"fou-gre": "FOu/GRE-in-UDP", "gue-ipip": "GUE", "vxlan": "VXLAN", "geneve": "Geneve",
	"dnscrypt-udp": "DNSCrypt", "ntp-direct": "NTP", "openvpn-dco": "OpenVPN DCO", "srtp-direct": "SRTP",
}

// withDefaultPort fills port into an address that has no explicit one ("" becomes ":port"); an address that already
// carries a port, including a bracketed IPv6 literal, is returned unchanged. F19 UDP-shaped carriers use it so a bare
// host or -listen gets the protocol's conventional port unless the operator chose one.
func withDefaultPort(addr string, port int) string {
	if port <= 0 {
		return addr
	}
	if addr == "" {
		return ":" + strconv.Itoa(port)
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if len(addr) > 2 && addr[0] == '[' && addr[len(addr)-1] == ']' { // a bracketed IPv6 literal without a port
		return net.JoinHostPort(addr[1:len(addr)-1], strconv.Itoa(port))
	}
	if ip := net.ParseIP(addr); ip != nil {
		return net.JoinHostPort(addr, strconv.Itoa(port))
	}
	if strings.Contains(addr, ":") { // an unbracketed IPv6 literal
		return "[" + addr + "]:" + strconv.Itoa(port)
	}
	return net.JoinHostPort(addr, strconv.Itoa(port))
}
