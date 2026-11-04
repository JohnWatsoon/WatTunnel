# Security policy

## Supported versions

Only the latest release (`3.x` from the
[releases page](https://github.com/JohnWatsoon/WatTunnel/releases)) is supported. Update both servers — old and
new versions are wire-compatible, but a fix only helps the end that runs it.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting (Security tab → "Report a vulnerability"), or contact
[@watxox](https://t.me/watxox) on Telegram. Do not open a public issue.

Please include: the version on each end (`wattun -version`), the carrier, the config with the key and token
removed, and the relevant logs.

## Threat model

This is the baseline for the supported deployment: two Linux VPS (Iran and Kharej), the signed installer, systemd,
and a pre-shared key in a key file. It describes what the shipped code protects and what it does not. Each claim here
is expanded in [docs/TECHNICAL.md](docs/TECHNICAL.md), mainly in
["Security model"](docs/TECHNICAL.md#security-model) and
["Spoofing and shaping, explained"](docs/TECHNICAL.md#spoofing-and-shaping-explained).

### Assets

- **Traffic content on the Iran ↔ Kharej leg** — whatever users send through the forwarded TCP/UDP ports.
- **The pre-shared key (PSK)** — both ends hold it; it is never sent on the wire, and whoever has it can join or
  impersonate the tunnel.
- **The `wat1:` token** — it contains the key (see "What does not exist"), so it is as sensitive as the key.
- **Both hosts** — root access, the key file, the config, `/etc/wattun` state, and the installed binary.
- **User and operator metadata** — the source addresses the Iran listener accepts, forwarded port numbers, and the
  per-port counters and quotas in `/stats`.
- **Availability** — the tunnel staying up on a path that drops most other traffic, and the operator's ability to
  recover it (auto-heal, rollback).

### Adversaries in scope today

- **Passive on-path observer / DPI.** Reads transport headers, packet sizes, timing, and (on TLS carriers) the SNI;
  can block or reset flows. It cannot read the tunnel's payload: the session is encrypted before any carrier sees it.
  What it can still see is listed under "What none of them hide" in
  [Spoofing and shaping](docs/TECHNICAL.md#spoofing-and-shaping-explained).
- **Active prober / scanner.** Sends garbage, replays or plain HTTP to the Kharej listen port or to an HTTP carrier. A
  session is created only when a packet authenticates under the key; everything else is dropped without a reply, and
  the HTTP-family listeners answer a browser request with the stock nginx page, so a scanner finds a web server rather
  than a tunnel banner.
- **Replayer.** A recorded packet replayed later is dropped by the per-session packet-number window; since 3.1.1 a
  captured packet can neither keep a dead session alive nor open a new one.
- **Holder of a leaked token or key file.** Can open a session against Kharej and use the configured allowlist,
  exactly like a legitimate client. There is no second factor and no per-client identity. On a direct carrier,
  `allow-clients` can pin that token to the source IPs you list, which is the only brake on a leaked token.
- **Malicious mirror / tampered download.** Refused: the installer and the manager's self-update verify the binary,
  the manager and their `SHA256SUMS` against an RSA public key baked into both scripts.
- **Compromised endpoint (Iran or Kharej).** Out of scope: root on either host reads plaintext and the key and can
  replace the binary. Nothing in the tunnel prevents that.
- **Browser page reaching the operator endpoints.** The metrics/pprof server is loopback-only and rejects cross-site
  browser requests; a local process that can reach loopback is outside this boundary.

### What exists today

- **Confidentiality and integrity of the tunneled leg.** ChaCha20-Poly1305 per session, under a key derived from the
  PSK and a random 8-byte session id; header masking (`hdr-mask`) on top. Since 2.10.0 every session also runs an
  ephemeral X25519 exchange (forward secrecy), so traffic recorded before a later key-file leak stays unreadable. The
  first RTT of a session is still PSK-only.
- **Replay protection.** A per-session packet-number window, plus an in-memory watermark for retired sessions (a
  server restart starts a new process and therefore a fresh watermark).
- **Authentication before admission.** The server creates a session only for a packet that decrypts under that session
  id's key. Garbage, scans and packets replayed from another key are dropped without a response.
- **Server-side reach.** Kharej dials only `127.0.0.1:<port>`, only for allowlisted target ports
  (`allow-ports`/`allow-file`/`allow-min`/`allow-max`). A flag-run server with no explicit allowlist source
  forwards every local port and logs one warning. On a direct carrier, `allow-clients`/`allow-clients-file` also
  restricts which client source addresses may open a session: it narrows a leaked PSK/token to the listed IPs,
  admission only and fail-closed. It needs the file under `/etc/wattun`, is ignored with `reverse` (warning), and a
  CDN carrier or `-sni` refuses the combination at startup so the operator does not lock every client out. Target
  port 0 is the built-in speed test; port 53 is the built-in
  DNS relay for `ech: ladder` unless an explicit allowlist forwards it to a real local resolver. The metrics port is
  never forwarded.
- **Operator surface.** `metrics` is rewritten to loopback (`127.0.0.1`) even when a public address is configured;
  `/stats`, `/ports`, `/speedtest`, pprof, `/quota/reset` and `/carrier/toggle` live there, and the handlers reject
  cross-site browser requests (curl and the manager send no cross-site headers and are unaffected).
- **Supply chain.** `install.sh` verifies the RSA signature over `SHA256SUMS` and the exact hash of the downloaded
  binary and manager before installing; `wattun-manager update` checks the installer against the signed release before
  running it as root. `WAT_ALLOW_UNSIGNED_MANAGER=1` and `WAT_ALLOW_UNSIGNED_UPDATE=1` are explicit downgrades, off by
  default. The installer keeps the previous binary as `wattun.prev` for rollback.
- **Resource caps (denial-of-service bounds, not isolation).** The server admits 32 sessions per process; a pool holds
  up to 64 connections; a client runs up to 16 sessions; public listeners accept 4096 connections in total and 256 per
  source IP; UDP flows are bounded (4096 per listening port/session); streams have receive-window caps and a
  process-wide memory budget; ports have optional rate limits and quotas.
- **Host hardening from the installer.** The systemd unit runs with `NoNewPrivileges=yes`, a capability bounding set
  of `CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE`, `ProtectSystem=strict` with
  `ReadWritePaths=/etc/wattun /run/wattun`, `RuntimeDirectory=wattun` (mode 0700, preserved across a restart), and
  private tmp/devices.
- **File modes.** The manager creates `/etc/wattun` mode 700 and writes key files mode 600; the token
  (`wat1:` + base64 of carrier, peer, key, path, SNI, ICMP type, allowed ports, reverse, auto plan) is written under
  that directory. `state-dir` (3.3.0) only holds quota and traffic counters (no secrets); the engine creates it 0700.
  The shipped unit supports the tmpfs path `/run/wattun` and keeps it across a service restart; counters there are
  lost on reboot.
- **Shaping is not secrecy.** `shape-data`, `noise` and the 3.3.0 shaped carriers (raw `sit`/`6to4`/`xfrm-ipsec`/
  `etherip`/`l2tpv3`, UDP `fou-gre`/`gue-ipip`/`vxlan`/`geneve`/`dnscrypt-udp`/`ntp-direct`/`openvpn-dco`/
  `srtp-direct`) change only the outer bytes, sizes or timing. They add no encryption, are not interoperable with
  the real protocols they resemble, and do not hide the destination or volume (see
  [Spoofing and shaping](docs/TECHNICAL.md#spoofing-and-shaping-explained)). Padding and noise are real traffic and
  spend bandwidth.

### What does not exist

Listed here so it is not assumed:

- **Per-client identity, accounts or revocation.** All clients of one server use the same PSK. The tunnel cannot tell
  two clients apart, cannot give one client different ports, and cannot revoke one without changing the key for
  everyone. Session ids are random and unauthenticated connection identifiers, not user identities.
- **A token with scopes.** The token **is** the key plus connection details: any holder can connect and use the
  allowlist. Treat it like a password, not like a read-only share link.
- **End-to-end encryption between users and Kharej.** WatTunnel encrypts only the Iran ↔ Kharej leg. Between a user and
  the Iran server, and between Kharej and the local service, the traffic is whatever the forwarded protocol provides —
  run TLS/VLESS/WireGuard inside the tunnel when that matters.
- **Anonymity or concealment of the tunnel's existence.** See [Scope notes](#scope-notes). Hiding options are
  best-effort against a DPI, not a guarantee against a determined classifier, and destination, volume and timing stay
  observable.
- **Tunnel-level impersonation of another tool.** The anti-censor options change packet shape and header bytes; none
  of them makes the tunnel look like a different tunnel end to end (see
  [Spoofing and shaping](docs/TECHNICAL.md#spoofing-and-shaping-explained)).
- **A per-client audit trail.** `/stats` and the per-port counters report totals, not which client did what.
- **Forward secrecy with `WAT_NO_KEX`/`NoKex`.** That is an internal A/B switch that turns the X25519 exchange off;
  never enable it in a shipped config.

### Operator hardening checklist

Go through this on both servers after setup, and again after any change:

- **Key and token hygiene.** Keep the key only in `key-file` (manager-created files are mode 600, `/etc/wattun` mode
  700) — not `-key` on the command line, which `ps` shows. The token contains the key: send it over a private
  channel, never in a group chat or an issue. Rotating the key means updating both ends; there is no partial revoke.
- **Make the allowlist explicit.** Set `allow-ports`/`allow-file` (manager-created tunnels carry a `ports:` list) so
  Kharej forwards only the target ports you run. A flag-run server with no list forwards every `127.0.0.1` port and
  says so once in the log.
- **Optionally restrict client sources.** On a direct carrier, `allow-clients`/`allow-clients-file` pins a leaked
  PSK/token to the listed IPv4/IPv6 addresses or CIDR prefixes; it is checked before a session is created and fails
  closed. Keep the file under `/etc/wattun` (the unit hides `/root` and `/home`). Behind a CDN or with `-sni` the
  engine refuses the combination at startup, and with `reverse` the server dials the client, so the list is ignored
  (warning).
- **Firewall both hosts.** On Iran expose only the public listener ports users need; on Kharej expose only the tunnel
  port(s) to Iran's address. Keep `metrics` on loopback and never publish pprof. Check with `ss -lntup` on both.
- **Close what auto mode opened.** An auto Kharej tunnel listens on every carrier port so Iran's test can reach any of
  them. Since 3.3.0 the heal timer closes what is no longer used once Iran's pick has been stable for `autoprune`
  minutes (`.manager.conf`, default 12, 0 = off); the auto Kharej wizard, `auto-ip` and the next manager run install
  that timer,
  so a Kharej-only server is cleaned up without operator action. By default only the unused reverse companion/watchers
  are closed (`NAME-r`); the direct `carrier:` list is not rewritten, because a bonded Iran client looks like a single
  leg. Full direct narrowing is opt-in: `.manager.conf autoprune-direct=1`, or
  `wattun-manager auto-prune NAME --direct`. A pruned tunnel whose open carriers all stop working for 3 checks is
  reopened in full by the same pass (at most once per `autowiden` minutes, default 10) so it can fail over again — that
  reopens the carrier ports, which is the intended trade-off. Force a close with `wattun-manager auto-narrow NAME`,
  keep every carrier open with `auto-prune NAME --keep-open`, reopen with `auto-widen NAME`. With **extended Auto**
  (opt-in `--extended`, both ends 3.3.0) Kharej additionally listens on one hidden single-carrier unit per shaped
  carrier; the default prune keeps the shape Iran picked and stops the unused ones, and delete/uninstall remove them
  with the parent. Raw-tier extended listeners also need the cloud firewall to pass protocols 41/50/97/115, and an old
  Iran never uses them — so close them with the default prune, `auto-prune NAME --direct` or a manual stop.
- **Keep NTP running on both ends.** The packet-number nonce must never repeat; the forward-secrecy and replay
  guarantees assume the server clock never goes backwards across restarts.
- **Keep the systemd sandbox intact.** The installer writes the unit with the capability bounding set,
  `NoNewPrivileges` and the `Protect*`/`Private*` options above. Re-run the installer after a manual change, or compare
  `/etc/systemd/system/wattun@.service` with the installed copy; do not replace it with a plain root unit.
- **Install only what you verified.** Prefer the release asset or a `git clone` over a third-party mirror; the binary
  and manager are signature-checked, the `install.sh` script you download is trust-on-first-use. Never set
  `WAT_ALLOW_UNSIGNED_MANAGER` or `WAT_ALLOW_UNSIGNED_UPDATE` on a production host.
- **Keep `debug` off** in normal operation; it logs every stream.
- **Update both ends.** Old and new peers interoperate, but a fix helps only a host that runs it; check
  `wattun -version` on both.

## Scope notes

WatTunnel protects the content of the tunnel, not its existence: the server's address, packet volume and timing
stay visible, and it is not an anonymity tool. The full model — key schedule, forward secrecy, what each carrier
adds and what none of it hides — is documented in
[docs/TECHNICAL.md, "Security model"](docs/TECHNICAL.md#security-model) and
[docs/TECHNICAL.md, "Spoofing and shaping, explained"](docs/TECHNICAL.md#spoofing-and-shaping-explained).
