#!/bin/bash
# bench/pair.sh: measure WatTunnel between two real servers with throw-away instances on spare ports.
#
#   Kharej:  bench/pair.sh server KEYHEX [WATTUN]           # serves tcp/tls/wss/udp and an icmp+tcp bond, 30 min
#   Iran:    bench/pair.sh client KHAREJ_IP KEYHEX [WATTUN]  # runs every case, prints one table
#
# KEYHEX: any shared secret, e.g. `openssl rand -hex 32` (use a fresh one, not a tunnel's key). The live tunnels are
# not touched: ports 15310-15314 and metrics 127.0.0.1:16300-16400 only. Env: MB (default 1000), SECS (adds a
# sustained run of that many seconds per carrier, default 0), SINGLE=1 (one-stream runs, default on).
set -u
role=${1:?server|client}
dir=/tmp/wattun-bench
mkdir -p "$dir"
cd "$dir" || exit 1

if [ "$role" = server ]; then
  key=${2:?key}; bin=${3:-wattun}
  echo "$key" > key
  pkill -f "[w]attun -config $dir/s-" 2>/dev/null
  for c in tcp:15310 tls:15311 wss:15312 udp:15313 icmp+tcp:15314; do
    n=${c%%:*}; p=${c##*:}; f=s-${n/+/-}.yml
    if [ "$n" = icmp+tcp ]; then
      printf 'mode: server\nkey-file: %s/key\ncarrier: icmp+tcp\nlisten-tcp: ":%s"\nmetrics: 127.0.0.1:%s\n' "$dir" "$p" $((p + 1000)) > "$f"
    else
      printf 'mode: server\nkey-file: %s/key\ncarrier: %s\nlisten: ":%s"\nmetrics: 127.0.0.1:%s\n' "$dir" "$n" "$p" $((p + 1000)) > "$f"
    fi
    setsid nohup timeout 1800 "$bin" -config "$dir/$f" > "${f%.yml}.log" 2>&1 < /dev/null &
  done
  sleep 1
  grep -h "server up" s-*.log
  echo "servers run for 30 min (or: pkill -f '[w]attun -config $dir/s-')"
  exit 0
fi

peer=${2:?kharej ip}; key=${3:?key}; bin=${4:-wattun}
MB=${MB:-1000}; SECS=${SECS:-0}; SINGLE=${SINGLE:-1}
echo "$key" > key
m=127.0.0.1:16400

speed() { # dir mb streams -> "MB/s" or "fail"
  curl -s --max-time 120 "http://$m/speedtest?dir=$1&mb=$2&streams=$3" |
    sed -n 's/.*"mb_per_s":\([0-9.]*\).*/\1/p' | awk '{printf "%.0f", $1} END {if (NR == 0) printf "fail"}'
}
peak() { # pid seconds -> "cpu% rssMB" peak over the run, sampled every second
  local pid=$1 n=$2 c r mc=0 mr=0
  for _ in $(seq 1 "$n"); do
    read -r c r < <(ps -o %cpu=,rss= -p "$pid" 2>/dev/null) || break
    c=${c%.*}; [ "${c:-0}" -gt "$mc" ] && mc=$c; [ "${r:-0}" -gt "$mr" ] && mr=$r
    sleep 1
  done
  echo "$mc $((mr / 1024))"
}
run() { # label carrier port [yaml lines...]
  local label=$1 c=$2 p=$3 pid i d s u x1 x2 cpu
  shift 3
  pkill -f "[w]attun -config $dir/c.yml" 2>/dev/null; sleep 0.5
  { printf 'mode: client\nkey-file: %s/key\ncarrier: %s\npeer: %s:%s\nmetrics: %s\nports:\n  - 15999\n' \
      "$dir" "$c" "$peer" "$p" "$m"
    for l in "$@"; do echo "$l"; done; } > c.yml
  "$bin" -config "$dir/c.yml" > c.log 2>&1 &
  pid=$!
  for i in $(seq 1 40); do curl -s "http://$m/stats" | grep -q '"alive":true' && break; sleep 0.5; done
  peak "$pid" 20 > peak.out &
  d=$(speed down "$MB" 16); u=$(speed up $((MB / 2)) 16)
  x1=-; x2=-
  [ "$SINGLE" = 1 ] && { x1=$(speed down $((MB / 4)) 1); x2=$(speed up $((MB / 4)) 1); }
  wait $!
  read -r cpu s < peak.out
  local sus=-
  [ "$SECS" -gt 0 ] && sus=$(speed down $((SECS * 250)) 16)
  printf '%-22s %8s %8s %8s %8s %9s %6s%% %6sMB\n' "$label" "$d" "$u" "$x1" "$x2" "$sus" "$cpu" "$s"
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

"$bin" -version
printf '%-22s %8s %8s %8s %8s %9s %7s %8s\n' case "down" "up" "1s-down" "1s-up" "sustained" "cpu" "rss"
run "tcp" tcp 15310
run "tcp 8 sessions" tcp 15310 "sessions: 8"
run "tls" tls 15311
run "wss" wss 15312
run "udp" udp 15313
run "tcp to icmp+tcp srv" tcp 15314
echo "MB/s per direction, 16 streams (1s = one stream); cpu/rss: client peak over the first 20 s"
