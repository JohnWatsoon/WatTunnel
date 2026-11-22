package mgr

// usageText is usage() VERBATIM from wattun-manager ($SELF substituted at
// print time; $AC_ALLMODES expands to the desync mode list like the bash).
const usageText = `
Usage: $SELF [command]

  (no command)          dashboard: all tunnels; manage one, create, update...
  new [kharej|iran]     create a tunnel (do Kharej FIRST: it makes the token)
  kharej | iran         same as new kharej / new iran
  status | list         one line per tunnel
  monitor               live dashboard (any key exits)
  ports NAME            edit the port mappings of a tunnel
  test NAME             connection doctor + speed test
  speedtest NAME [MB]   speed test only (default 10 MB each way)
  mute NAME PATH        mute one bonded path (PATH = the leg name from /stats, e.g. udp or udp:up)
  unmute NAME PATH      unmute it again; both talk to the running tunnel's metrics server (no root)
  logs NAME             follow the log
  token NAME            print the Kharej token again
  scepter [NAME]        pairing cockpit (Iran; also on the main menu). Setup: paste the
                        Kharej token once — the token carries the pairing credential, so
                        the pair and the cockpit open together (attach with a watp1: line
                        stays for older pairs). Without a name, the fleet of paired Kharej
                        servers with their live remote state; with a name, that pair's
                        cockpit — create tunnels on Kharej (the wizard over the encrypted
                        channel), open its remote tunnels (state, stats, logs, events,
                        ports, limits reset, presets from preset.list, mute, keyrotate),
                        start/stop/restart, edit and delete (per-key prompts walk every
                        change); test carrier shapes remotely (a probe listener on Kharej,
                        measured from this server), switch a remote tunnel's carrier with
                        automatic rollback (this tunnel follows, reverted if its link
                        dies), run/apply the fleet carrier ranking; Operations:
                        update.status/run (Kharej updates its own binary over the channel
                        — the cockpit drops mid-update, the scepter latch revives it on
                        its own, a watchdog rolls back to wattun.prev; full capability),
                        doctor.fetch, backup.export (the config dir as a verified
                        tarball), audit.tail (needs wattun 3.5.0 on both ends; a write
                        needs the pairing's create/manage capability)
  preset NAME [PRESET]  apply built-in anti-censorship preset (rst-fast, mci, irancell, blackout, conservative)
  test-bypass NAME      automated connectivity & filter bypass test for anti-censorship profile
  profile save|list|show|del|apply   resilience profiles: save one tunnel's fake-sni/pool-rotate combination
                        under a name and re-apply it later (profile save NAME [tunnel])
  blackout NAME [SNI|PRESET] turn on resilience: accepts operator preset (rst-fast, mci, irancell, blackout, conservative)
                        or custom allowlisted SNI (e.g. mci.ir), restarts, tests filter bypass.
                        Fine-tuning (mode, ttl, pool-rotate, ech): tunnel page -> o -> k. Linux only.
  arm-blackout NAME     arm Kharej in Fortress mode (multi-carrier listeners, sysctls, firewall)
                        or arm Iran for autonomous failover (silence detection, heal timer)
  audit-blackout NAME   audit blackout readiness (capabilities, sysctls, port conflicts, DNS relay)
  matrix NAME           anti-censor matrix: test EVERY resilience combination (fake-SNI x mode x ECH)
                        from this Iran server with throw-away clients, apply the best that connects.
                        Bonded tunnels: every pool leg is tested. Kharej is never contacted except
                        through the tunnel itself. Linux only.
  reset-traffic NAME    zero the lifetime traffic counters the dashboard shows for a tunnel (restarts it)
  boost [--status|--undo|--yes]  kernel speed boost (BBR, 64MB buffers, FQ)
  iran-firewall [on|off|status]  accept connections on the client ports only from Iranian addresses
  backup [dest.tar.gz]  backup all tunnel configs and keys to archive
  restore <archive.tar.gz> restore tunnel configs and keys from archive
  start-all | stop-all  bulk start or stop all tunnels
  restart-all           restart all tunnels
  auto-optimize         run off-peak carrier re-evaluation for auto tunnels
  auto-test NAME        test every connection type again for an auto Iran tunnel, offer to switch
  auto-ip NAME IP       auto Kharej tunnel: set Iran's IP by hand (creates internal reverse companion)
  bond-retest NAME      bonded Iran tunnel: re-test every leg plus the last failures and add one that works again
  cdn-tune NAME [full]  Iran CDN tunnel (ws/wss/h2/h2c/grpc): find the Cloudflare edges that serve the domain over ECH + TLS settings, apply (needs wattun 2.2.0)
  heal                  restart Iran tunnels whose link is down (used by the timer)
  bundle [amd64|arm64] [OUT.tar.gz]  build a signed offline install/update bundle (e.g. on Kharej for Iran)
  update [--from PATH]  install the latest release (or offline from a verified bundle .tar.gz / directory)
  rollback              go back one version
  delete NAME           stop a tunnel and delete its config, key and token (asks you to type the name)
  uninstall             remove WatTun from this server (asks first)
  help                  this text

Unattended mode (no tty, nothing is asked; --yes turns it on, and so does any --flag when stdin is not a tty;
or NONINTERACTIVE=1). Plain output, errors on stderr, exit code 0 = done, 1 = failed:
  kharej --carrier C --name NAME [--listen PORT] [--path /wat] [--addr HOST] [--udp-dns]
         C = wss|grpc|tcp|tls|ws|h2|h2c|udp|icmp|auto, or one F19 shaped carrier (single carrier only, no + bond):
         sit|6to4|xfrm-ipsec|etherip|l2tpv3 (raw tier: bare-IP peer, Linux + root, no listen port, no reverse) and
         fou-gre|gue-ipip|vxlan|geneve|dnscrypt-udp|ntp-direct|openvpn-dco|srtp-direct (UDP tier: conventional port
         5555/6080/4789/6081/443/123/1194/5004 unless --listen gives one). F19 shapes are wattun-internal: both ends
         need 3.3.0+ and the SAME name, they do not talk to the real protocol.
         [--sni HOST] [--cdn-domain D] [--ports 18999,2000,53/udp] [--max-mbps N] [--extended] --yes
         creates and starts the Kharej tunnel; the last lines are TUNNEL=NAME and TOKEN=wat1:...
         C=auto: the token makes Iran test the standard transports (icmp, udp, tcp/tls/ws/wss/h2/h2c/grpc and
         gre/ipip, which need 3.2.0 on both ends). --extended (needs Kharej 3.3.0) also opens the 13 F19 shaped
         carriers, one hidden single-carrier listener per shape (wattun@NAME-e-<shape>); both ends must run 3.3.0 and
         old Iran ignores them, so their test ports stay open in the background for Iran to probe anytime. Raw tier needs CAP_NET_RAW
         and the cloud firewall to pass IP protocols 41/50/97/115.
         (--addr skips the public-IP detection; --cdn-domain is for auto; --listen/--path/--sni/--max-mbps for the others)
  iran --token TOKEN --map 39901:18999[,8443:443] [--name NAME] [--pick best|bond|N|N,N...] [--test normal|anti|fast|reverse] [--sessions N] [--max-mbps N] --yes
         creates and starts the Iran tunnel. Auto token: runs the test, --pick chooses a row (default best, bond = all
         working direct carriers, 1,3 = join those rows). CDN token: automatic CDN tuning. Ends with LINK=up|down and TUNNEL=NAME; exit 1 if down.
         An extended auto token is tested too; carriers this engine cannot run are skipped with a hint and never written
         into the config.
         --test picks the preset (default normal): normal = direct+CDN+reverse; fast = rst/synrst against
         mci.ir/irancell.ir/cloudflare.com on every direct pool carrier (best row applied); anti = the full
         fake-SNI/fp grid; reverse = only the plan's r= carriers.
         --sessions N writes "sessions: N", 1-16 (only with wattun 2.3.0 or newer and one udp/tcp/tls/ws/wss/h2/h2c/grpc
         carrier: the engine refuses it on icmp/gre/ipip, the F19 shapes, bonds and reverse; otherwise it is ignored with a warning)
         --preset rst-fast|mci|irancell|blackout|conservative applies an operator-tailored anti-censorship preset
          --fake-sni NAME [--fake-mode MODE] [--fake-ttl 0-255] enables the fake-SNI desync on a
          fixed-type token (wattun 2.7.0 or newer; Linux only, needs CAP_NET_RAW; MODE is one of:
          seq | ttl | sum | seqsum | auto | rst | synrst -- older engines accept fewer, the manager refuses a mode the engine would reject;
          --fake-ttl only with --fake-mode ttl)
         [--pool-rotate 90s|30m|4h] [--pool-rotate-bytes 500MB|4G] recycle each healthy pool connection after this
         long / this much traffic (pool-rotate needs wattun 2.8.0, --pool-rotate-bytes 2.8.1; Linux only)
         [--ech off|auto|ladder] Encrypted Client Hello mode (ladder relays DoH via tunnel port 53; 2.9.0+)
         [--governor on|off] ICMP volume pacer against reroute triggers (2.9.0+)
  cdn-tune NAME [full] --yes      apply the best CDN variant without asking
  auto-test NAME --yes            re-test an auto Iran tunnel, switch to --pick (default best) without asking
  delete NAME --yes               delete a tunnel without asking
  uninstall --yes                 uninstall without asking; also deletes the config directory
  Flags also accept --flag=value.

Environment: WAT_NO_ANIM=1 (no animations)  NO_COLOR=1 (no colours)
  WAT_PROXY=https://ghproxy.net/  WAT_CURL_PROXY=socks5h://127.0.0.1:1080  WAT_OFFLINE_DIR=/path/to/bundle
  WAT_ALLOW_UNSIGNED_UPDATE=1 runs install.sh from main without checking the release signature (not recommended)

Sandbox: WAT_PREFIX=wattest wattun-manager ... keeps everything under /etc/wattest, /opt/wattest and wattest@ units.
  Other overrides: WAT_CONF, WAT_BIN, WAT_RUN, WAT_AUTO_RUN (single paths). The first run needs: WAT_PREFIX=wattest wattun-manager update
`
