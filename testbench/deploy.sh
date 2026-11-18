#!/bin/sh
# deploy.sh - run the fake-SNI bench on the owner's live pair (Iran client -> Kharej server). This script is for the
# Lead/owner to run; the bench itself never executes it and never touches a VPS. It needs no git state: it builds
# dist/wattun-linux-amd64 with build.sh and copies that binary. It never commits and never pushes.
#
# Assumes `ssh -i KEY root@HOST` works without a password, on both hosts. Every command it runs remotely is:
#   - mkdir -p REMOTE_DIR, scp the binary and a config there
#   - systemd-run --unit=wat-bench-{server,client} --collect ... wattun -config ...
#   - curl 127.0.0.1:METRICS/{stats,speedtest} on the client host (metrics binds loopback only)
# The server listens on SERVER_PORT, the client peers to KHAREJ:SERVER_PORT and exposes its metrics on
# 127.0.0.1:19720 (read over ssh). /speedtest uses wattun's built-in target port 0; no test service is needed.
#
# Usage:
#   testbench/deploy.sh build                   build dist/wattun-linux-amd64 and copy it to both hosts
#   testbench/deploy.sh server                  start/restart the Kharej server
#   testbench/deploy.sh client MODE [SNI]       start/restart the Iran client with -fake-mode MODE
#   testbench/deploy.sh collect MODE [SNI]      read /stats + run /speedtest, print one CSV row (dpi_rule=live)
#   testbench/deploy.sh all [MODES]             for each mode: client, wait alive, collect; prints the CSV
#   testbench/deploy.sh stop                    stop both units on both hosts
#   testbench/deploy.sh logs ROLE               journalctl tail of the server or client unit
#
# Env (the first five are required):
#   SSH_KEY=~/.ssh/id_ed25519        private key path (expand it: sh does not expand ~ inside quotes)
#   IRAN=192.0.2.10              client / Iran host
#   KHAREJ=198.51.100.20              server / Kharej host
#   PSK=...                          shared key, both ends must match
#   SNI=www.example.com              allowlisted SNI the fake ClientHello carries (default)
# Optional:
#   REMOTE_DIR=/root/wat-bench, CARRIER=tcp (tcp|tls|ws|wss|h2|grpc), CONNS=4, SERVER_PORT=38443,
#   CLIENT_MAP=22030:5201, METRICS_PORT=19720, SERVER_METRICS_PORT=19721,
#   MODES="seq ttl sum seqsum rst", SNI_LIST=, LIVE_MB=64, LIVE_WAIT=30, FAKE_TTL= (ttl mode: explicit hop count),
#   SERVER_EXTRA=, CLIENT_EXTRA= (extra config lines, e.g. "-sni example.com")
#
# The CSV row has the same shape as testbench/measure.sh (mode,sni,dpi_rule,mb_per_s_down,mb_per_s_up,alive,retrans),
# with dpi_rule=live: here the real censor on the path decides, so there is no rule profile to vary.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
OUT=${OUT:-$HERE/out}

SSH_KEY=${SSH_KEY:-}
IRAN=${IRAN:?set IRAN=<iran host>}
KHAREJ=${KHAREJ:?set KHAREJ=<kharej host>}
PSK=${PSK:-}
SNI=${SNI:-www.example.com}
REMOTE_DIR=${REMOTE_DIR:-/root/wat-bench}
CARRIER=${CARRIER:-tcp}
CONNS=${CONNS:-4}
SERVER_PORT=${SERVER_PORT:-38443}
CLIENT_MAP=${CLIENT_MAP:-22030:5201}
METRICS_PORT=${METRICS_PORT:-19720}
SERVER_METRICS_PORT=${SERVER_METRICS_PORT:-19721}
MODES=${MODES:-"seq ttl sum seqsum rst"}
SNI_LIST=${SNI_LIST:-"$SNI"}
LIVE_MB=${LIVE_MB:-64}
LIVE_WAIT=${LIVE_WAIT:-30}
FAKE_TTL=${FAKE_TTL:-}
SERVER_EXTRA=${SERVER_EXTRA:-}
CLIENT_EXTRA=${CLIENT_EXTRA:-}

die() { echo "deploy.sh: $*" >&2; exit 1; }
say() { echo "deploy.sh: $*" >&2; }

rsh() { host=$1; shift; ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "root@$host" "$@"; }
rscp() { host=$1; src=$2; dst=$3; scp -q -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$src" "root@$host:$dst"; }

unit() { # unit HOST NAME ROLE - stop NAME if present, then start it from its config
	host=$1
	name=$2
	rsh "$host" "systemctl stop $name 2>/dev/null || true; systemd-run --unit=$name --collect --working-directory=$REMOTE_DIR $REMOTE_DIR/wattun -config $REMOTE_DIR/$name.yml >/dev/null && echo DEPLOY_OK $name" ||
		die "$name did not start on $host (run: testbench/deploy.sh logs $3)"
}

write_server_cfg() {
	[ -n "$PSK" ] || die "PSK is required to write the server config"
	cat >"$OUT/wat-bench-server.yml" <<EOF
mode: server
key: $PSK
carrier: $CARRIER
listen: 0.0.0.0:$SERVER_PORT
metrics: 127.0.0.1:$SERVER_METRICS_PORT
allow-ports: 5201
$SERVER_EXTRA
EOF
}

write_client_cfg() { # write_client_cfg MODE
	[ -n "$PSK" ] || die "PSK is required to write the client config"
	mode=$1
	ttl=""
	[ -n "$FAKE_TTL" ] && ttl="fake-ttl: $FAKE_TTL"
	cat >"$OUT/wat-bench-client.yml" <<EOF
mode: client
key: $PSK
carrier: $CARRIER
peer: $KHAREJ:$SERVER_PORT
conns: $CONNS
map: $CLIENT_MAP
bind: 127.0.0.1
metrics: 127.0.0.1:$METRICS_PORT
fake-sni: $SNI_LIST
fake-mode: $mode
$ttl
$CLIENT_EXTRA
EOF
}

cmd_build() {
	say "building dist/wattun-linux-amd64"
	(cd "$ROOT" && sh build.sh amd64) >&2 || die "build.sh amd64 failed"
	bin=$ROOT/dist/wattun-linux-amd64
	[ -f "$bin" ] || die "no $bin after build"
	for host in "$KHAREJ" "$IRAN"; do
		say "copying binary to $host:$REMOTE_DIR"
		rsh "$host" "mkdir -p $REMOTE_DIR" || die "cannot mkdir on $host"
		rscp "$host" "$bin" "$REMOTE_DIR/wattun" || die "scp to $host failed"
		rsh "$host" "chmod +x $REMOTE_DIR/wattun" || die "chmod on $host failed"
	done
}

cmd_server() {
	write_server_cfg
	rsh "$KHAREJ" "mkdir -p $REMOTE_DIR"
	rscp "$KHAREJ" "$OUT/wat-bench-server.yml" "$REMOTE_DIR/wat-bench-server.yml"
	unit "$KHAREJ" wat-bench-server server
}

cmd_client() { # cmd_client MODE [SNI]
	mode=${1:-seq}
	[ $# -ge 2 ] && { SNI=$2; SNI_LIST=$2; }
	write_client_cfg "$mode"
	rsh "$IRAN" "mkdir -p $REMOTE_DIR"
	rscp "$IRAN" "$OUT/wat-bench-client.yml" "$REMOTE_DIR/wat-bench-client.yml"
	unit "$IRAN" wat-bench-client client
}

wait_alive() {
	i=0
	while [ "$i" -lt "$LIVE_WAIT" ]; do
		if rsh "$IRAN" "curl -s -m 2 http://127.0.0.1:$METRICS_PORT/stats" 2>/dev/null | grep -q '"alive":true'; then
			return 0
		fi
		sleep 1
		i=$((i + 1))
	done
	return 1
}

fetch() { # fetch HOST PORT PATH FILE
	rsh "$1" "curl -s -m 180 'http://127.0.0.1:$2$3'" >"$4" 2>/dev/null || : >"$4"
}

cmd_collect() { # cmd_collect MODE [SNI]
	mode=${1:-seq}
	[ $# -ge 2 ] && { SNI=$2; SNI_LIST=$2; }
	tag=live-$mode
	if wait_alive; then
		fetch "$IRAN" "$METRICS_PORT" "/speedtest?dir=down&mb=$LIVE_MB" "$OUT/$tag-down.json"
		fetch "$IRAN" "$METRICS_PORT" "/speedtest?dir=up&mb=$LIVE_MB" "$OUT/$tag-up.json"
	else
		say "client tunnel is not alive after ${LIVE_WAIT}s; the censor dropped it under mode $mode"
		: >"$OUT/$tag-down.json"
		: >"$OUT/$tag-up.json"
	fi
	fetch "$IRAN" "$METRICS_PORT" "/stats" "$OUT/$tag-stats-client.json"
	fetch "$KHAREJ" "$SERVER_METRICS_PORT" "/stats" "$OUT/$tag-stats-server.json"

	python=
	for p in python3 python; do
		if command -v "$p" >/dev/null 2>&1 && "$p" -c 'pass' >/dev/null 2>&1; then
			python=$p
			break
		fi
	done
	[ -n "$python" ] || die "python3/python not on PATH (parses the JSON)"
	"$python" - "$OUT/$tag-stats-client.json" "$OUT/$tag-down.json" "$OUT/$tag-up.json" "$mode" "$SNI" <<'PY'
import json, sys
statf, downf, upf, mode, sni = sys.argv[1:6]
def load(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}
st, dn, up = load(statf), load(downf), load(upf)
alive = 1 if st.get("alive") is True else 0
try:
    retrans = int(st.get("retrans", -1))
except (TypeError, ValueError):
    retrans = -1
down = float(dn.get("mb_per_s") or 0) if dn.get("ok") else 0.0
ups = float(up.get("mb_per_s") or 0) if up.get("ok") else 0.0
print("%s,%s,live,%.3f,%.3f,%d,%d" % (mode, sni, down, ups, alive, retrans))
PY
}

cmd_all() {
	modes=${1:-$MODES}
	say "server first: deploying wat-bench-server to $KHAREJ"
	cmd_server
	echo "mode,sni,dpi_rule,mb_per_s_down,mb_per_s_up,alive,retrans"
	for mode in $modes; do
		say "mode $mode: deploying wat-bench-client to $IRAN"
		(cmd_client "$mode") || {
			echo "$mode,$SNI,live,0.000,0.000,0,-1"
			continue
		}
		(cmd_collect "$mode") || true
		cmd_stop_client
		sleep 2 # let the server's session slot for the old client expire before the next mode
	done
}

cmd_stop_client() { rsh "$IRAN" "systemctl stop wat-bench-client 2>/dev/null || true"; }

cmd_stop() {
	for host in "$IRAN" "$KHAREJ"; do
		say "stopping wat-bench units on $host"
		rsh "$host" "systemctl stop wat-bench-client wat-bench-server 2>/dev/null || true"
	done
}

cmd_logs() {
	role=${1:-client}
	case $role in
	server) rsh "$KHAREJ" "journalctl -u wat-bench-server -n 80 --no-pager" ;;
	client) rsh "$IRAN" "journalctl -u wat-bench-client -n 80 --no-pager" ;;
	*) die "logs takes client or server" ;;
	esac
}

role=${1:-}
[ -n "$role" ] || { sed -n '2,52p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[ -n "$SSH_KEY" ] || die "SSH_KEY is required (see the header of $0)"
[ -f "$SSH_KEY" ] || die "SSH_KEY $SSH_KEY is not a file"
mkdir -p "$OUT"
shift || true
case $role in
build) cmd_build ;;
server) cmd_server ;;
client) cmd_client "$@" ;;
collect) cmd_collect "$@" ;;
all) cmd_all "$@" ;;
stop) cmd_stop ;;
logs) cmd_logs "$@" ;;
*) die "unknown role $role (build|server|client|collect|all|stop|logs)" ;;
esac
