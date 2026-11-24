#!/usr/bin/env bash
# WatTunnel installer.
#   bash <(curl -fsSL https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
# Options:
#   --version vX.Y.Z   install that release instead of the latest
#   --force            reinstall even when the same version is already installed
#   --uninstall        stop every tunnel and remove WatTun (asks before deleting /etc/wattun)
# Environment:
#   WAT_PROXY=https://ghproxy.net/   prefix for every GitHub URL (when github.com is blocked). Trust-on-first-use:
#                                    a mirror could change the installer script itself. The release binary and
#                                    manager are RSA-verified against the signed SHA256SUMS when it ships them.
#   WAT_CURL_PROXY=socks5h://...     HTTP/SOCKS5 proxy passed to curl -x for GitHub downloads and tag resolution
#   WAT_OFFLINE_DIR=/path/to/dir     directory containing an unpacked offline release bundle (binary + SHA256SUMS*)
#   WAT_ALLOW_UNSIGNED_MANAGER=1     install wattun-manager from raw.githubusercontent for a release that does not
#                                    ship it (unsigned; only if you trust the source)
#   WAT_REPO=owner/name              fork to install from
#   WAT_SIG_PUB=/path/to/pub.pem     another release-signing public key (forks)
#   WAT_SKIP_CHECKSUM=1              install a local dist/ binary that has no .sha256 file
#   WAT_NO_ANIM=1                    no animations (also automatic when output is not a terminal)
#   NO_COLOR=1                       no colours
# Installs: /usr/local/bin/wattun, /usr/local/bin/wattun-manager, /etc/systemd/system/wattun@.service, /etc/wattun/
set -uo pipefail
shopt -s extglob

REPO=${WAT_REPO:-JohnWatsoon/WatTunnel}
PROXY=${WAT_PROXY:-}
BIN=${WAT_BIN:-/usr/local/bin/wattun}
MGR=${WAT_MGR:-/usr/local/bin/wattun-manager}
UNIT=${WAT_UNIT:-/etc/systemd/system/wattun@.service}
CONF=${WAT_CONF:-/etc/wattun}
VERSION=latest
FORCE=0
MODE=install
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo /nonexistent)
# Local files (dist/ build, offline bundle, wattun-manager) are used only when this script sits in a real checkout or
# unpacked release, or when wattun-manager update --from points WAT_OFFLINE_DIR at a verified local directory.
if [ -n "${WAT_OFFLINE_DIR:-}" ]; then
  [ "$WAT_OFFLINE_DIR" = "/" ] || WAT_OFFLINE_DIR=${WAT_OFFLINE_DIR%/}
fi
if [ -n "${WAT_OFFLINE_DIR:-}" ] && [ -d "$WAT_OFFLINE_DIR" ]; then HERE=$WAT_OFFLINE_DIR
elif [ "${WAT_FROM_MANAGER:-0}" = 1 ] || [ ! -f "$HERE/install.sh" ]; then HERE=/nonexistent; fi

case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in *UTF-8*|*utf8*) ;; *) export LC_ALL=C.UTF-8 2>/dev/null || true ;; esac

# ======================================================================================
#  Terminal UI: graphite + cyan accent, kite mark, reveal, checklist & rounded cards
# ======================================================================================
IS_TTY=0; [ -t 1 ] && IS_TTY=1
USE_COLOR=0
if [ "${WAT_FORCE_COLOR:-0}" = 1 ] || { [ "$IS_TTY" = 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; }; then USE_COLOR=1; fi
NCOL=8
if [ "$USE_COLOR" = 1 ]; then
  NCOL=$(tput colors 2>/dev/null || echo 8)
  case "${TERM:-}" in *256color*) NCOL=256 ;; esac
  case "$NCOL" in ''|*[!0-9]*) NCOL=8 ;; esac
  RST=$'\e[0m'; BOLD=$'\e[1m'; RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; GRY=$'\e[90m'
  if [ "$NCOL" -ge 256 ]; then CYN=$'\e[38;5;45m'; else CYN=$'\e[36m'; fi
else
  RST=''; BOLD=''; RED=''; GRN=''; YEL=''; CYN=''; GRY=''
fi
ANIM=0
if [ "$IS_TTY" = 1 ] && [ "${WAT_NO_ANIM:-0}" != 1 ]; then ANIM=1; fi

SPIN_PID=''
TMP=''
TERM_COLS=80
BOXW=74
term_cols() {
  local c=${COLUMNS:-}
  if [ -z "$c" ] && [ "$IS_TTY" = 1 ]; then c=$(tput cols 2>/dev/null || echo 80); fi
  case "$c" in ''|*[!0-9]*) c=80 ;; esac
  [ "$c" -lt 30 ] && c=30
  TERM_COLS=$c
}
box_w() {
  term_cols
  local w=$((TERM_COLS - 4))
  [ "$w" -gt 74 ] && w=74
  [ "$w" -lt 42 ] && w=42
  BOXW=$w
}
cur_hide() { [ "$IS_TTY" = 1 ] && [ "$ANIM" = 1 ] && printf '\e[?25l'; return 0; }
cur_show() { [ "$IS_TTY" = 1 ] && printf '\e[?25h'; return 0; }
kill_spin() {
  if [ -n "$SPIN_PID" ]; then kill "$SPIN_PID" 2>/dev/null; wait "$SPIN_PID" 2>/dev/null; SPIN_PID=''; fi
  return 0
}
cleanup() { kill_spin; cur_show; [ -n "$TMP" ] && rm -rf "$TMP"; return 0; }
trap cleanup EXIT
trap 'cleanup; printf "\n"; exit 130' INT
trap 'cleanup; exit 143' TERM HUP

rep() { local s; printf -v s '%*s' "$2" ''; printf '%s' "${s// /$1}"; }
VLEN=0
vlen() { local s=${1//$'\e'\[*([0-9;?])[a-zA-Z]/}; VLEN=${#s}; }
strip_ansi() { printf '%s' "${1//$'\e'\[*([0-9;?])[a-zA-Z]/}"; }
fit_plain() { # text max -> truncated plain text
  local s=$1 m=$2
  [ "$m" -le 0 ] && { printf ''; return 0; }
  if [ "${#s}" -le "$m" ]; then printf '%s' "$s"
  elif [ "$m" -eq 1 ]; then printf '%s' "${s:0:1}"
  else printf '%s…' "${s:0:$((m-1))}"; fi
}
ok()   { printf '  %s✔%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$RST" "$*"; }
err()  { printf '  %s✘%s %s\n' "$RED" "$RST" "$*"; }
hint() { printf '  %s%s%s\n' "$GRY" "$*" "$RST"; }
die()  { cur_show; err "$*"; exit 1; }
hr()   { box_w; printf '  %s%s%s\n' "$GRY" "$(rep ─ "$BOXW")" "$RST"; }
key_label() { printf '%s[%s]%s' "$CYN" "$1" "$RST"; }

# Signature mark: 7-col geometric kite + 43-col WATTUN block wordmark (54 cols total with 2-space indent)
WATTUN_KITE=(
  '   ╱╲  '
  '  ╱──╲ '
  ' ╱ ╲╱  '
)
WATTUN_WORD=(
  '██   ██  ▄██▄  ██████ ██████ ██  ██ ██▄  ██'
  '██ █ ██ ██▄▄██   ██     ██   ██  ██ ██▀█▄██'
  ' ▀█▀█▀  ██  ██   ██     ██   ▀████▀ ██  ▀██'
)
META_TELEGRAM='@WatxDev'

banner_frame() { # k0 k1 k2 wcol show_side side_gap clr
  local k=("$1" "$2" "$3") wc=$4 show_side=$5 gap=$6 clr=${7:-0} i sp pfx=''
  local side=("WatTunnel" "github.com/JohnWatsoon" "t.me/${META_TELEGRAM#@}")
  sp=$(rep ' ' "$gap")
  [ "$clr" = 1 ] && pfx=$'\r\e[K'
  for i in 0 1 2; do
    if [ "$show_side" = 1 ]; then
      printf '%s  %s%s%s  %s%s%s%s%s%s%s\n' "$pfx" \
        "$CYN" "${k[$i]}" "$RST" "$wc" "${WATTUN_WORD[$i]}" "$RST" "$sp" "$GRY" "${side[$i]}" "$RST"
    else
      printf '%s  %s%s%s  %s%s%s\n' "$pfx" \
        "$CYN" "${k[$i]}" "$RST" "$wc" "${WATTUN_WORD[$i]}" "$RST"
    fi
  done
}

banner() { # [1 = 0.35s packet-pulse reveal] : adapts to >=80, 78-79, 56-77, and <56 cols
  local anim=${1:-0} show_side=0 gap=2
  term_cols
  if [ "$TERM_COLS" -lt 56 ]; then
    printf '  %s◇%s %sWatTunnel%s %s· %s%s\n' "$CYN" "$RST" "$BOLD" "$RST" "$GRY" "github.com/JohnWatsoon" "$RST"
    return 0
  fi
  if [ "$TERM_COLS" -ge 80 ]; then show_side=1; gap=2
  elif [ "$TERM_COLS" -ge 78 ]; then show_side=1; gap=1; fi

  if [ "$anim" = 1 ]; then
    cur_hide
    banner_frame '      ┃' ' ╺▸   ┃' '╱     ┃' "$GRY" 0 "$gap" 1
    sleep 0.08
    printf '\e[3A'
    banner_frame '      ┃' '   ╺━▸┃' '╱     ┃' "$GRY" 0 "$gap" 1
    sleep 0.08
    printf '\e[3A'
    banner_frame '      ┃' '    ╺━╋' '╱     ┃' "$BOLD" 0 "$gap" 1
    sleep 0.08
    printf '\e[3A'
    banner_frame "${WATTUN_KITE[0]}" "${WATTUN_KITE[1]}" "${WATTUN_KITE[2]}" "$BOLD" "$show_side" "$gap" 1
    sleep 0.08
    cur_show
  else
    banner_frame "${WATTUN_KITE[0]}" "${WATTUN_KITE[1]}" "${WATTUN_KITE[2]}" "$BOLD" "$show_side" "$gap" 0
  fi
  [ "$show_side" = 1 ] || printf '  %sgithub.com/JohnWatsoon · t.me/%s%s\n' "$GRY" "${META_TELEGRAM#@}" "$RST"
  return 0
}

page() { # title [subtitle] : renders in-flow without wiping scrollback (\e[3J)
  echo
  if [ "$ANIM" = 1 ]; then banner 1; else banner 0; fi
  echo
  printf '  %s%s%s%s\n' "$BOLD" "$1" "$RST" "${2:+  ${GRY}$2${RST}}"
  hr; echo
}

step_diagram() {
  term_cols
  if [ "$TERM_COLS" -ge 68 ]; then
    printf '  %s[1] Kharej%s %s(outside)  ─── wat1: token ───►%s  %s[2] Iran%s %s(inside)%s\n' \
      "$CYN" "$RST" "$GRY" "$RST" "$BOLD" "$RST" "$GRY" "$RST"
    printf '      %sruns service                              users connect here%s\n' "$GRY" "$RST"
  else
    printf '  %s[1] Kharej%s %s(outside) · runs service%s\n' "$CYN" "$RST" "$GRY" "$RST"
    printf '    %s─── wat1: token ───►%s  %s[2] Iran%s %s(inside) · users connect%s\n' "$GRY" "$RST" "$BOLD" "$RST" "$GRY" "$RST"
  fi
}

# ---- step checklist: bounded single-line rows, live download progress, deferred warnings ----
SPIN_FR=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
CL_LABELS=(); CL_N=0; DETAIL=''; ERRMSG=''; WARNINGS=()
dl_total_bytes() {
  [ -f "$TMP/hdr" ] || { echo 0; return 0; }
  awk 'tolower($1) == "content-length:" { v=$2 } END { gsub(/[^0-9]/, "", v); print v + 0 }' "$TMP/hdr" 2>/dev/null || echo 0
}
dl_cur_bytes() {
  [ -f "$1" ] || { echo 0; return 0; }
  stat -c %s "$1" 2>/dev/null || wc -c <"$1" 2>/dev/null || echo 0
}
dl_gauge() { # cur tot width -> "━━━━━━────"
  local c=$1 m=$2 w=${3:-10} f
  [ "$m" -gt 0 ] || m=1; [ "$c" -gt "$m" ] && c=$m
  f=$(( c * w / m ))
  if [ "$USE_COLOR" = 1 ]; then
    printf '%s%s%s%s%s' "$CYN" "$(rep ━ "$f")" "$GRY" "$(rep ─ $((w-f)))" "$RST"
  else
    printf '%s%s' "$(rep '#' "$f")" "$(rep '-' $((w-f)))"
  fi
}
cl_row() { # idx text : rewrite checklist row idx in place
  local up=$((CL_N - $1))
  printf '\e[%dA\r\e[K%s\e[%dB\r' "$up" "$2" "$up"
}
cl_init() {
  local l
  CL_LABELS=("$@"); CL_N=$#
  [ "$ANIM" = 1 ] || return 0
  for l in "$@"; do printf '  %s·%s %s%-15s%s\n' "$GRY" "$RST" "$GRY" "$l" "$RST"; done
}
cl_start() { # idx
  [ "$ANIM" = 1 ] || return 0
  term_cols
  local idx=$1 label=${CL_LABELS[$1]} max_d=$((TERM_COLS - 22))
  cur_hide
  (
    local i=0 t0=$SECONDS up=$((CL_N - idx)) el extra cur tot pct g cur_mb tot_mb
    while :; do
      el=$((SECONDS - t0)); extra=''
      if [ "$idx" -eq 1 ] && [ -f "$TMP/wattun" ]; then
        cur=$(dl_cur_bytes "$TMP/wattun")
        tot=$(dl_total_bytes)
        if [ "$tot" -gt 0 ] && [ "$cur" -gt 0 ]; then
          pct=$((cur * 100 / tot)); [ "$pct" -gt 100 ] && pct=100
          cur_mb=$(awk -v b="$cur" 'BEGIN{printf "%.1f", b/1048576}')
          tot_mb=$(awk -v b="$tot" 'BEGIN{printf "%.1f", b/1048576}')
          if [ "$max_d" -ge 28 ]; then
            g=$(dl_gauge "$cur" "$tot" 10)
            extra=$(printf '%s  %s%3d%%  %s / %s MB%s' "$g" "$GRY" "$pct" "$cur_mb" "$tot_mb" "$RST")
          else
            extra=$(printf '%s%3d%% (%s MB)%s' "$GRY" "$pct" "$cur_mb" "$RST")
          fi
        elif [ "$cur" -gt 0 ]; then
          cur_mb=$(awk -v b="$cur" 'BEGIN{printf "%.1f", b/1048576}')
          extra="${GRY}${cur_mb} MB${RST}"
        fi
      fi
      if [ -z "$extra" ] && [ "$el" -ge 1 ]; then
        extra="${GRY}${el}s${RST}"
      fi
      printf '\e[%dA\r\e[K  %s%s%s %-15s %s\e[%dB\r' "$up" "$CYN" "${SPIN_FR[$i]}" "$RST" "$label" "$extra" "$up"
      i=$(( (i+1) % 10 )); sleep 0.1
    done
  ) &
  SPIN_PID=$!
}
cl_end() { # idx rc
  local idx=$1 rc=$2 label=${CL_LABELS[$1]} line det='' max_d
  kill_spin
  term_cols
  max_d=$((TERM_COLS - 22))
  if [ -n "$DETAIL" ] && [ "$max_d" -gt 4 ]; then
    det=$(fit_plain "$DETAIL" "$max_d")
  fi
  if [ "$rc" -eq 0 ]; then line=$(printf '  %s✔%s %-15s %s' "$GRN" "$RST" "$label" "${det:+$GRY$det$RST}")
  elif [ "$rc" -eq 2 ]; then line=$(printf '  %s–%s %-15s %s' "$GRY" "$RST" "$label" "${det:+$GRY$det$RST}")
  else line=$(printf '  %s✘%s %-15s %s' "$RED" "$RST" "$label" "${det:+$GRY$det$RST}"); fi
  if [ "$ANIM" = 1 ]; then cl_row "$idx" "$line"; cur_show; else printf '%s\n' "$line"; fi
}
run_step() { # idx fn : rc 0 ok, 2 skipped (fn returns 2), 3 interactive recovery hook, else abort
  local idx=$1 rc; DETAIL=''; ERRMSG=''
  cl_start "$idx"
  "$2"; rc=$?
  if [ "$rc" -eq 3 ]; then
    DETAIL="unreachable"
    cl_end "$idx" 1
    return 3
  fi
  cl_end "$idx" "$rc"
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then echo; die "${ERRMSG:-step failed}"; fi
  return 0
}

box() { # title lines... (rounded corners, dynamic width, vlen-safe truncation)
  local w t=$1 l pad t_fit t_len d_len; shift
  box_w; w=$BOXW
  t_fit=$(fit_plain "$t" $((w - 6)))
  t_len=${#t_fit}
  d_len=$((w - t_len - 3)); [ "$d_len" -lt 1 ] && d_len=1
  printf '  %s╭─ %s%s%s %s╮%s\n' "$GRY" "$RST$BOLD" "$t_fit" "$RST$GRY" "$(rep ─ "$d_len")" "$RST"
  for l in "$@"; do
    vlen "$l"
    if [ "$VLEN" -gt $((w - 2)) ]; then
      l=$(strip_ansi "$l")
      l=$(fit_plain "$l" $((w - 2)))
      VLEN=${#l}
    fi
    pad=$((w - 2 - VLEN)); [ "$pad" -lt 0 ] && pad=0
    printf '  %s│%s %s%*s %s│%s\n' "$GRY" "$RST" "$l" "$pad" '' "$GRY" "$RST"
  done
  printf '  %s╰%s╯%s\n' "$GRY" "$(rep ─ "$w")" "$RST"
}

usage() {
  cat <<'EOF'
WatTunnel installer
Usage: bash install.sh [options]

Options:
  --version vX.Y.Z   Install that specific release instead of the latest
  --force            Reinstall even when the same version is already installed
  --uninstall        Stop all tunnels and remove WatTun from this server
  -h, --help         Show this help screen

Environment:
  WAT_PROXY=https://ghproxy.net/   Proxy prefix for GitHub downloads (when github.com is filtered; trust-on-first-use)
  WAT_CURL_PROXY=socks5h://...     HTTP/SOCKS5 proxy passed to curl -x for GitHub downloads and tag resolution
  WAT_OFFLINE_DIR=/path/to/dir     Directory containing an unpacked offline release bundle
  WAT_ALLOW_UNSIGNED_MANAGER=1     Install wattun-manager from raw.githubusercontent when the release does not ship it
  WAT_REPO=owner/name              Fork or repository to install from (default: JohnWatsoon/WatTunnel)
  WAT_SIG_PUB=/path/to/pub.pem     Alternative release-signing public key (for custom forks)
  WAT_SKIP_CHECKSUM=1              Install local dist/ binary without a checksum file
  WAT_NO_ANIM=1                    Disable animations and spinners
  NO_COLOR=1                       Disable colored ANSI formatting
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || die "--version needs a value (example: --version v2.10.2)"; VERSION=$2; shift 2 ;;
    --force) FORCE=1; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

save_side() { # kharej|iran : the manager reads it so it never asks again (key "side" in its settings file)
  mkdir -p "$CONF"; touch "$CONF/.manager.conf"; chmod 600 "$CONF/.manager.conf"
  sed -i '/^side=/d' "$CONF/.manager.conf"; echo "side=$1" >>"$CONF/.manager.conf"
}
tunnel_list() { local f b; for f in "$CONF"/*.yml; do [ -e "$f" ] || continue; b=${f##*/}; echo "${b%.yml}"; done; }

# ======================================================================================
#  Uninstall
# ======================================================================================
uninstall() {
  local list=() n u a
  while IFS= read -r n; do [ -n "$n" ] && list+=("$n"); done < <(tunnel_list)
  page "Uninstall WatTunnel"
  if [ "${#list[@]}" -gt 0 ]; then
    echo "  These tunnels will be stopped and deleted:"
    echo
    for n in "${list[@]}"; do
      u="${GRY}stopped${RST}"; systemctl is-active -q "wattun@$n" 2>/dev/null && u="${GRN}running${RST}"
      printf '    %-18s %s\n' "$n" "$u"
    done
    echo
  else
    hint "No tunnels configured."
    echo
  fi
  if [ "${WAT_YES:-0}" != 1 ] && [ -t 0 ]; then
    printf '  %s?%s Stop all tunnel services and remove WatTun? %s[y/N]%s ' "$CYN" "$RST" "$GRY" "$RST"
    IFS= read -rsn1 a || a=n; echo
    case "$a" in y|Y) ;; *) warn "Uninstall cancelled. Nothing was changed."; exit 0 ;; esac
  fi
  echo
  ok "Stopped and disabled the tunnel units"
  for u in $(systemctl list-units --all --plain --no-legend 'wattun@*' 2>/dev/null | awk '{print $1}'); do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
  done
  systemctl disable --now wattun-heal.timer >/dev/null 2>&1 || true
  systemctl disable --now wattun-auto-optimize.timer >/dev/null 2>&1 || true
  systemctl disable --now wattun-panel.service >/dev/null 2>&1 || true

  ok "Removed the unit files"
  rm -f "$UNIT" /etc/systemd/system/wattun-heal.service /etc/systemd/system/wattun-heal.timer /etc/systemd/system/wattun-auto-optimize.service /etc/systemd/system/wattun-auto-optimize.timer /etc/systemd/system/wattun-panel.service
  systemctl daemon-reload

  ok "Removed $BIN and $MGR"
  rm -f "$BIN" "$BIN.prev" "$BIN.new" "$MGR" "$MGR.new"

  if [ -d "$CONF" ]; then
    echo
    if [ "${WAT_PURGE:-}" = 1 ]; then a=y
    elif [ -t 0 ]; then
      printf '  %s?%s Delete configuration directory %s (tunnel configs, keys, tokens)? %s[y/N]%s ' "$CYN" "$RST" "$CONF" "$GRY" "$RST"
      IFS= read -rsn1 a || a=n; echo
    else a=n; fi
    case "$a" in
      y|Y) rm -rf "$CONF"; ok "Deleted $CONF" ;;
      *) hint "Kept $CONF (configs and keys). Delete it by hand if you want." ;;
    esac
  fi
  echo
  ok "WatTun is uninstalled."
}
if [ "$MODE" = uninstall ]; then uninstall; exit 0; fi

# ======================================================================================
#  Pre-flight Environment Detection & Validation
# ======================================================================================
detect_env() {
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported CPU architecture $(uname -m) (amd64 and arm64 supported only)" ;;
  esac
  NAME=wattun-linux-$ARCH

  OS_DISTRO="Linux"
  if [ -f /etc/os-release ]; then
    OS_DISTRO=$(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}/\1/p' /etc/os-release | head -n1)
  elif [ -f /etc/redhat-release ]; then
    OS_DISTRO=$(head -n1 /etc/redhat-release)
  elif [ -f /etc/debian_version ]; then
    OS_DISTRO="Debian $(cat /etc/debian_version)"
  fi
  [ -n "$OS_DISTRO" ] || OS_DISTRO="$(uname -s) $(uname -r)"

  RAM_TOTAL="$(awk '/MemTotal/{printf "%.1f GB", $2/1048576}' /proc/meminfo 2>/dev/null || free -m 2>/dev/null | awk '/Mem:/{printf "%.1f GB", $2/1024}' || echo "-")"
  SYSTEMD_VER="systemd $(systemctl --version 2>/dev/null | awk 'NR==1{print $2}')"
  [ "$SYSTEMD_VER" = "systemd " ] && SYSTEMD_VER="systemd (active)"
}
detect_env

if [ "$(id -u)" -ne 0 ]; then
  if [ -f "$HERE/install.sh" ]; then die "Administrator privileges required. Run as root: sudo bash install.sh"
  else die "Administrator privileges required. Run as root: sudo bash <(curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh)"; fi
fi
command -v systemctl >/dev/null || die "systemd is required to manage WatTun tunnel services"

CURL_RETRY_ALL=0
if command -v curl >/dev/null 2>&1 && curl --help all 2>&1 | grep -q -- '--retry-all-errors'; then
  CURL_RETRY_ALL=1
fi

NEW=''; OLD=''
fetch() { # url dest [hdr_file]
  local px=() ra=() hd=()
  [ -n "${WAT_CURL_PROXY:-}" ] && px=(-x "$WAT_CURL_PROXY")
  [ "$CURL_RETRY_ALL" = 1 ] && ra=(--retry-all-errors)
  [ -n "${3:-}" ] && hd=(-D "$3")
  if command -v curl >/dev/null; then
    curl -fsSL ${px[@]+"${px[@]}"} ${hd[@]+"${hd[@]}"} --retry 4 ${ra[@]+"${ra[@]}"} --connect-timeout 10 --max-time 300 -o "$2" "$PROXY$1"
  elif command -v wget >/dev/null; then
    wget -q -T 20 -t 4 -O "$2" "$PROXY$1"
  else
    return 127
  fi
}

resolve_tag() {
  local u px=()
  [ "$VERSION" = latest ] || { TAG=$VERSION; return 0; }
  command -v curl >/dev/null || return 1
  [ -n "${WAT_CURL_PROXY:-}" ] && px=(-x "$WAT_CURL_PROXY")
  u=$(curl -fsSL ${px[@]+"${px[@]}"} -o /dev/null -w '%{url_effective}' --connect-timeout 15 --max-time 30 "${PROXY}https://github.com/$REPO/releases/latest" 2>/dev/null) || return 1
  u=${u%/}; u=${u##*/}
  [[ "$u" =~ ^v[0-9]+\.[0-9]+ ]] || return 1
  TAG=$u
}
TAG=''; PREV_WARN=0; MGR_FROM_REL=0; FROM_DIST=0; LOCAL_SIG=0; DL_BASE=''
human_size() { awk -v b="$1" 'BEGIN{printf "%.1f MB", b/1048576}'; }

SIG_PUB=$(cat <<'PEM'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0j+yK26CzKRD+am5rQZJ
v8zChkZ5HuwQ4uBtj2mKfFRG8mrj7XN3iW60QEj7Le/fAYtk4hHvqsxb6Xhxw303
+rFCBxKr+mwc3GOB/zVh/fzNqN2pXzKCT+mSKiaDfwUmCizKFNUUCCnhNVpEx9hl
A4B4n5iBgxW0G/ks4hOujx6teaKUN44+cZNgPshPSQ5KdiqQBi0rFCiSAKBCh1vL
j07u5S/mvU8L8u9M6sUzST0mXcGw9WKQmAiIOCqAwLiyV1RtDodgaCIxLPJ93Qo/
uK4DzYX3Ker8lW6MRKXgX3fAVXoyj/ZaE3oh1ZibVefAy6w7qB74JvQPv4nFvS/Y
VJXpxiHiqE/YMdHbS9eCQnqjHVKmGWvBVPo/IlUiJFbl8nIEFZVij32Cp8A4awO2
IORyD7iC8bA7AZHruzVfiUtrYA5XhBTRJplqws8kM0Ig4sLrws0HPOY4xOBRtSVh
vgY6Qw/EWglth/K24PEC8AiuJYIRRkn/Kq+SBIRu8qVrAgMBAAE=
-----END PUBLIC KEY-----
PEM
)
[ -n "${WAT_SIG_PUB:-}" ] && SIG_PUB=$(cat "$WAT_SIG_PUB")

apply_proxy_input() { # classify mirror URL prefix vs curl -x proxy (handles IPv6, credentials, custom-port HTTPS mirrors)
  local v=${1:-}
  PROXY=''; WAT_CURL_PROXY=''
  case "$v" in
    socks4://*|socks4a://*|socks5://*|socks5h://*)
      WAT_CURL_PROXY=$v; PROXY='' ;;
    http://*)
      if [[ "$v" =~ ^http://([^/]*@)?(\[[0-9a-fA-F:]+\]|[^/:]+):[0-9]{1,5}/?$ ]]; then
        WAT_CURL_PROXY=${v%/}; PROXY=''
      else
        PROXY="${v%/}/"
      fi ;;
    https://*)
      if [[ "$v" =~ ^https://[^/]*@ ]] || [[ "$v" =~ ^https://(127\.|localhost|\[::1\])(:[0-9]{1,5})?/?$ ]]; then
        WAT_CURL_PROXY=${v%/}; PROXY=''
      else
        PROXY="${v%/}/"
      fi ;;
    *)
      if [[ "$v" =~ ^(\[[0-9a-fA-F:]+\]|[^/:]+):[0-9]{1,5}$ ]]; then
        WAT_CURL_PROXY=$v; PROXY=''
      else
        PROXY="${v%/}/"
      fi ;;
  esac
}

unpack_offline_bundle() { # path -> sets HERE on success, else ERRMSG + rc 1
  local src=$1 dst="$TMP/offline" d
  [ "$src" = "/" ] || src=${src%/}
  if [ -d "$src" ]; then
    if [ -f "$src/$NAME" ] || [ -f "$src/dist/$NAME" ]; then
      HERE=$(cd "$src" 2>/dev/null && pwd) || HERE=$src
      return 0
    fi
    ERRMSG="no $NAME found in directory '$src'"
    return 1
  fi
  if [ -f "$src" ]; then
    command -v tar >/dev/null 2>&1 || { ERRMSG="tar is required to unpack '$src'"; return 1; }
    if tar -tf "$src" 2>/dev/null | grep -qE '(^/|(^|/)\.\.(/|$))'; then
      ERRMSG="refusing archive '$src' with unsafe paths"
      return 1
    fi
    rm -rf "$dst" && mkdir -p "$dst" || { ERRMSG="cannot create $dst"; return 1; }
    if tar -xzf "$src" -C "$dst" 2>/dev/null || tar -xf "$src" -C "$dst" 2>/dev/null; then
      if [ -f "$dst/$NAME" ] || [ -f "$dst/dist/$NAME" ]; then HERE=$dst; return 0; fi
      for d in "$dst"/*; do
        [ -d "$d" ] || continue
        if [ -f "$d/$NAME" ] || [ -f "$d/dist/$NAME" ]; then HERE=$d; return 0; fi
      done
    fi
    ERRMSG="could not unpack valid WatTunnel bundle from '$src'"
    return 1
  fi
  ERRMSG="path not found: $src"
  return 1
}

# ======================================================================================
#  6-Stage Installation Pipeline
# ======================================================================================

# Stage 1: Architecture & Host Verification
step_stage1_verify_env() {
  command -v curl >/dev/null || command -v wget >/dev/null || [ -f "$HERE/dist/$NAME" ] || [ -f "$HERE/$NAME" ] || { ERRMSG="curl or wget is required to retrieve WatTunnel"; return 1; }
  mkdir -p "$TMP" || { ERRMSG="cannot create temporary working directory"; return 1; }
  DETAIL="linux/$ARCH · $OS_DISTRO · $RAM_TOTAL · $SYSTEMD_VER"
}

# Stage 2: Binary & Manager Retrieval
step_stage2_retrieve_payload() {
  local base ldir=''
  if [ -f "$HERE/dist/$NAME" ]; then ldir="$HERE/dist"
  elif [ -f "$HERE/$NAME" ]; then ldir="$HERE"; fi
  if [ -n "$ldir" ]; then
    cp "$ldir/$NAME" "$TMP/wattun" || { ERRMSG="cannot read $ldir/$NAME"; return 1; }
    if [ -f "$ldir/SHA256SUMS" ] && [ -f "$ldir/SHA256SUMS.sig" ]; then
      cp "$ldir/SHA256SUMS" "$TMP/SHA256SUMS" && cp "$ldir/SHA256SUMS.sig" "$TMP/SHA256SUMS.sig"
      LOCAL_SIG=1
      awk -v n="$NAME" '$2 == n { print $1; exit }' "$ldir/SHA256SUMS" >"$TMP/sum"
      [ -s "$TMP/sum" ] || rm -f "$TMP/sum"
      DETAIL="offline bundle (${ldir##*/}), $(human_size "$(stat -c %s "$TMP/wattun")")"
    else
      [ -f "$ldir/$NAME.sha256" ] && cp "$ldir/$NAME.sha256" "$TMP/sum"
      FROM_DIST=1
      DETAIL="local build (${ldir##*/})"
    fi
  elif [ -f "$HERE/go.mod" ] && command -v go >/dev/null; then
    (cd "$HERE" && timeout 900 sh build.sh "$ARCH") >"$TMP/build.log" 2>&1 || { ERRMSG="source build failed (see: sh build.sh)"; return 1; }
    cp "$HERE/dist/$NAME" "$TMP/wattun"; cp "$HERE/dist/$NAME.sha256" "$TMP/sum"
    FROM_DIST=1
    DETAIL="compiled from source"
  else
    resolve_tag || TAG=''
    if [ -n "$TAG" ]; then base="https://github.com/$REPO/releases/download/$TAG"
    else base="https://github.com/$REPO/releases/latest/download"; fi
    DL_BASE=$base
    rm -f "$TMP/wattun" "$TMP/hdr"
    if fetch "$base/$NAME" "$TMP/wattun" "$TMP/hdr"; then
      fetch "$base/$NAME.sha256" "$TMP/sum" || { ERRMSG="could not download checksum file"; return 1; }
      DETAIL="release ${TAG:-latest} · $(human_size "$(stat -c %s "$TMP/wattun")")"
    else
      ERRMSG="could not reach github.com (use an offline bundle via 'wattun bundle $ARCH' on Kharej, or set WAT_PROXY / WAT_CURL_PROXY)"
      return 3
    fi
  fi

  # Retrieve manager payload. Prefer $ldir/wattun-manager so signed dist/ copies win over working-tree edits.
  # raw.githubusercontent is only an opt-in fallback for releases that predate the asset, never through a proxy.
  if [ -n "$ldir" ] && [ -f "$ldir/wattun-manager" ]; then
    cp "$ldir/wattun-manager" "$TMP/mgr"
    [ "$LOCAL_SIG" = 1 ] && MGR_FROM_REL=1
  elif [ -f "$HERE/wattun-manager" ]; then
    cp "$HERE/wattun-manager" "$TMP/mgr"
    [ "$LOCAL_SIG" = 1 ] && MGR_FROM_REL=1
  elif [ -f "$HERE/dist/wattun-manager" ]; then
    cp "$HERE/dist/wattun-manager" "$TMP/mgr"
    [ "$LOCAL_SIG" = 1 ] && MGR_FROM_REL=1
  elif [ -n "$DL_BASE" ] && fetch "$DL_BASE/wattun-manager" "$TMP/mgr"; then
    MGR_FROM_REL=1
  elif [ "${WAT_ALLOW_UNSIGNED_MANAGER:-0}" != 1 ]; then
    ERRMSG="this release does not ship a signed wattun-manager; refusing to install an unsigned copy (set WAT_ALLOW_UNSIGNED_MANAGER=1 only if you trust the source)"; return 1
  elif fetch "https://raw.githubusercontent.com/$REPO/${WAT_MGR_REF:-main}/wattun-manager" "$TMP/mgr"; then
    [ -n "$PROXY" ] && { ERRMSG="this release does not ship wattun-manager; refusing to fetch it unsigned through WAT_PROXY"; return 1; }
    WARNINGS+=("wattun-manager comes from main, not from the signed release (WAT_ALLOW_UNSIGNED_MANAGER=1)")
    DETAIL="$DETAIL · manager unsigned"
  elif [ -n "$TAG" ] && fetch "https://raw.githubusercontent.com/$REPO/$TAG/wattun-manager" "$TMP/mgr"; then
    [ -n "$PROXY" ] && { ERRMSG="this release does not ship wattun-manager; refusing to fetch it unsigned through WAT_PROXY"; return 1; }
    WARNINGS+=("wattun-manager comes from $TAG, not from the signed release (WAT_ALLOW_UNSIGNED_MANAGER=1)")
    DETAIL="$DETAIL · manager unsigned"
  else
    ERRMSG="could not download wattun-manager"; return 1
  fi
  head -c 2 "$TMP/mgr" | grep -q '#!' || { ERRMSG="wattun-manager payload is corrupt"; return 1; }
  if [ "${WAT_REQUIRE_SANDBOX:-0}" = 1 ] && ! grep -q 'WAT_PREFIX' "$TMP/mgr"; then
    ERRMSG="the downloaded wattun-manager lacks sandbox support; preserving current version"; return 1
  fi
  if [ -f "$MGR" ]; then
    local vold vnew
    vold=$(sed -n 's/^MGR_VERSION=\([0-9]\{10\}\).*/\1/p' "$MGR" 2>/dev/null | head -n1)
    vnew=$(sed -n 's/^MGR_VERSION=\([0-9]\{10\}\).*/\1/p' "$TMP/mgr" | head -n1)
    if [ -n "$vold" ] && [ -n "$vnew" ] && [ "$vnew" -lt "$vold" ]; then
      ERRMSG="the downloaded wattun-manager ($vnew) is older than installed ($vold); keeping current version"; return 1
    fi
  fi
}

# Stage 3: Cryptographic Signature & SHA-256 Verification
step_verify_sig() {
  local got=$1 sums="$TMP/SHA256SUMS" sig="$TMP/SHA256SUMS.sig" pub="$TMP/sigpub.pem"
  [ "$FROM_DIST" = 1 ] && { DETAIL="$DETAIL · local build (unsigned)"; return 0; }
  if ! command -v openssl >/dev/null 2>&1; then
    ERRMSG="openssl is required to verify the release signature (install openssl and retry)"; return 1
  fi
  if [ "$LOCAL_SIG" != 1 ]; then
    if ! fetch "$DL_BASE/SHA256SUMS" "$sums" || ! fetch "$DL_BASE/SHA256SUMS.sig" "$sig"; then
      ERRMSG="release signature not available; refusing to install unverified (use a local dist/ build)"; return 1
    fi
  fi
  printf '%s\n' "$SIG_PUB" > "$pub"
  if ! openssl dgst -sha256 -verify "$pub" -signature "$sig" "$sums" >/dev/null 2>&1; then
    ERRMSG="release RSA signature failed verification (download tampered with)"; return 1
  fi
  grep -qx -- "$got  $NAME" "$sums" || { ERRMSG="binary hash missing from signed SHA256SUMS"; return 1; }
  if [ "$MGR_FROM_REL" = 1 ]; then
    got=$(sha256sum "$TMP/mgr" | awk '{print $1}')
    grep -qx -- "$got  wattun-manager" "$sums" || { ERRMSG="manager hash missing from signed SHA256SUMS"; return 1; }
  fi
  DETAIL="RSA-SHA256 verified · $DETAIL"
}

step_stage3_verify_crypto() {
  local want got
  got=$(sha256sum "$TMP/wattun" | awk '{print $1}')
  if [ -f "$TMP/sum" ]; then
    want=$(awk '{print $1}' "$TMP/sum")
    [ "$want" = "$got" ] || { ERRMSG="checksum mismatch (want $want, got $got)"; return 1; }
    DETAIL="sha256 ${got:0:8}"
  else
    if [ "${WAT_SKIP_CHECKSUM:-0}" != 1 ]; then
      ERRMSG="no checksum file found (include SHA256SUMS + SHA256SUMS.sig or .sha256 next to $NAME, or set WAT_SKIP_CHECKSUM=1)"; return 1
    fi
    DETAIL="checksum skipped (WAT_SKIP_CHECKSUM=1)"
  fi
  step_verify_sig "$got" || return 1
  chmod 755 "$TMP/wattun"
  NEW=$("$TMP/wattun" -version 2>&1 | awk '{print $2; exit}')
  [ -n "$NEW" ] || { ERRMSG="retrieved binary failed execution on this host"; return 1; }
  bash -n "$TMP/mgr" 2>/dev/null || { ERRMSG="retrieved wattun-manager failed bash syntax check"; return 1; }
}

# Stage 4: Binary & Permission Installation
step_stage4_install_binaries() {
  [ -x "$BIN" ] && OLD=$("$BIN" -version 2>/dev/null | awk '{print $2; exit}')
  if [ "$OLD" = "$NEW" ] && [ "$FORCE" = 0 ]; then
    # Binary already current, install/update manager
    install -m 755 "$TMP/mgr" "$MGR.new" && mv -f "$MGR.new" "$MGR" || { ERRMSG="cannot write $MGR"; return 1; }
    DETAIL="$NEW current · manager updated"
    return 2
  fi

  if [ -x "$BIN" ]; then
    if cp -f "$BIN" "$BIN.prev.tmp" && mv -f "$BIN.prev.tmp" "$BIN.prev"; then :
    else rm -f "$BIN.prev.tmp"; PREV_WARN=1; fi
  fi

  install -m 755 "$TMP/wattun" "$BIN.new" && mv -f "$BIN.new" "$BIN" || { ERRMSG="cannot write $BIN"; return 1; }
  # No file capabilities: on a mode-755 binary they would give every local user raw sockets through wattun. The
  # systemd unit grants what the service needs; clear any left by an older installer.
  if command -v setcap >/dev/null 2>&1; then
    setcap -r "$BIN" 2>/dev/null || true
  fi

  local now; now=$("$BIN" -version 2>/dev/null | awk '{print $2; exit}')
  [ "$now" = "$NEW" ] || { ERRMSG="$BIN reports ${now:-nothing} after installing $NEW"; return 1; }

  install -m 755 "$TMP/mgr" "$MGR.new" && mv -f "$MGR.new" "$MGR" || { ERRMSG="cannot write $MGR"; return 1; }
  DETAIL="$NEW -> ${BIN%/*}"
}

# Stage 5: Systemd Service Unit Generation
step_stage5_systemd_setup() {
  mkdir -p "$CONF" && chmod 700 "$CONF"
  cat >"$TMP/unit" <<'EOF'
[Unit]
Description=WatTun Anti-Censorship Tunnel (%i)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/wattun -config /etc/wattun/%i.yml
Restart=always
RestartSec=2
LimitNOFILE=1048576
LimitMEMLOCK=infinity
# Ambient capabilities: CAP_NET_RAW (ICMP & raw sockets), CAP_NET_ADMIN (TCP_REPAIR & pacing), CAP_NET_BIND_SERVICE (privileged ports)
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET AF_NETLINK AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
# -state-dir may point at tmpfs (/run/wattun, the documented value). RuntimeDirectory creates it writable
# inside the ProtectSystem=strict sandbox; Preserve keeps it across a unit restart (the multi-instance template
# shares the path) and ReadWritePaths is kept for the legacy /etc/wattun state next to configs.
RuntimeDirectory=wattun
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
ReadWritePaths=/etc/wattun /run/wattun

[Install]
WantedBy=multi-user.target
EOF
  # WAT_BIN override (2026-11-20 review F6): the heredoc stays quoted, so the documented WAT_BIN path is
  # substituted afterwards — without this the unit always ExecStart'd /usr/local/bin/wattun, silently
  # ignoring the override (systemd would restart the old binary forever)
  sed -i "s|^ExecStart=.*|ExecStart=$BIN -config /etc/wattun/%i.yml|" "$TMP/unit"
  if ! cmp -s "$TMP/unit" "$UNIT" 2>/dev/null; then
    install -m 644 "$TMP/unit" "$UNIT" || { ERRMSG="cannot write $UNIT"; return 1; }
  fi
  systemctl daemon-reload || { ERRMSG="systemctl daemon-reload failed"; return 1; }
  DETAIL="${UNIT##*/} (sandboxed)"
}

# Stage 6: Kernel Network Tuning (bbr, fq and large socket buffers; wattun boost --undo opts out)
# Field 2026-11-08: an untuned Iran VPS (cubic, pfifo_fast, 212 KB buffers) moved 7 MB/s up over 16 raw TCP
# connections, 68 MB/s after boost; the tunnel's upload went from 49 to 66 MB/s.
is_container_host() {
  [ -f /.dockerenv ] || [ -f /run/.containerenv ] || [ -f /proc/user_beancounters ] && return 0
  command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container -q 2>/dev/null && return 0
  [ ! -w /proc/sys/net/ipv4/tcp_congestion_control ] && return 0
  return 1
}
step_stage6_kernel_boost() {
  local cc qdisc
  if [ "$(uname -s)" != Linux ] || [ "$(id -u)" -ne 0 ] || [ "${WAT_REQUIRE_SANDBOX:-0}" = 1 ]; then
    DETAIL="skipped (sandbox)"
    return 2
  fi
  if [ -f "$CONF/.boost-off" ]; then
    DETAIL="opted out (boost --undo)"
    return 2
  fi
  if is_container_host; then
    DETAIL="skipped (container)"
    return 2
  fi
  "$MGR" boost auto >/dev/null 2>&1 || true
  cc=$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || echo "")
  qdisc=$(cat /proc/sys/net/core/default_qdisc 2>/dev/null || echo "")
  DETAIL="${cc:-bbr} · ${qdisc:-fq} · 64 MB buffers"
  return 0
}

prompt_download_recovery() { # interactive recovery when GitHub is blocked
  local ans
  echo
  err "Could not reach github.com"
  echo
  hint "If GitHub is blocked on this server:"
  hint "  1. Enter a mirror or proxy URL (https://ghproxy.net/ or socks5h://127.0.0.1:1080)"
  hint "  2. Enter a path to an offline bundle (.tar.gz or directory)"
  hint "  3. Press Enter to exit and build one on Kharej:"
  hint "     wattun bundle $ARCH  &&  scp wattun-offline-$ARCH.tar.gz root@IRAN_IP:/root/"
  echo
  printf '  %s?%s Proxy, mirror, or bundle path %s[Enter to exit]%s: ' "$CYN" "$RST" "$GRY" "$RST"
  IFS= read -r ans || ans=''
  [ -n "$ans" ] || return 1
  if [ -e "$ans" ]; then
    unpack_offline_bundle "$ans" || { err "$ERRMSG"; return 1; }
  else
    apply_proxy_input "$ans"
  fi
  LOCAL_SIG=0; FROM_DIST=0; MGR_FROM_REL=0; DL_BASE=''; TAG=''
  rm -f "$TMP/wattun" "$TMP/sum" "$TMP/mgr" "$TMP/hdr" "$TMP/SHA256SUMS" "$TMP/SHA256SUMS.sig"
  return 0
}

# ======================================================================================
#  Main Execution
# ======================================================================================
TMP=$(mktemp -d)
page "Installer" "linux/$ARCH"
cl_init \
  "Architecture" \
  "Download" \
  "RSA Signature" \
  "Install Files" \
  "Systemd Unit" \
  "Kernel Boost"

run_step 0 step_stage1_verify_env
if ! run_step 1 step_stage2_retrieve_payload; then
  if [ -t 0 ] && [ -t 1 ] && [ "${WAT_YES:-0}" != 1 ]; then
    while :; do
      prompt_download_recovery || exit 1
      echo
      cl_init \
        "Download" \
        "RSA Signature" \
        "Install Files" \
        "Systemd Unit" \
        "Kernel Boost"
      if run_step 0 step_stage2_retrieve_payload; then
        run_step 1 step_stage3_verify_crypto
        run_step 2 step_stage4_install_binaries
        run_step 3 step_stage5_systemd_setup
        run_step 4 step_stage6_kernel_boost
        break
      fi
    done
  else
    echo; die "${ERRMSG:-download failed}"
  fi
else
  run_step 2 step_stage3_verify_crypto
  run_step 3 step_stage4_install_binaries
  run_step 4 step_stage5_systemd_setup
  run_step 5 step_stage6_kernel_boost
fi
echo

for _w in ${WARNINGS[@]+"${WARNINGS[@]}"}; do warn "$_w"; done
if [ "$PREV_WARN" = 1 ]; then
  warn "Could not create $BIN.prev backup copy. Rollback keeps the previous copy, if any."
fi
if [ "${#WARNINGS[@]}" -gt 0 ] || [ "$PREV_WARN" = 1 ]; then echo; fi

# Scepter pairing no longer needs installer material (owner directive 2026-11-22: zero manual steps — the pairing rides the wizard's token as field 10, the engine derives it); a .pairing.pending left by an older install is inert — the engine never reads it.

# ---- web panel (3.6.0, opt-in; docs/TECHNICAL.md "Web panel") ----
# An update restarts a running panel so it serves the new binary; it never turns the panel on or off.
if systemctl is-active -q wattun-panel 2>/dev/null; then systemctl restart wattun-panel >/dev/null 2>&1 || true; fi
# Non-interactive installs turn it on only when asked (WAT_PANEL=1); the interactive Iran wizard asks below.
if [ "${WAT_PANEL:-0}" = 1 ] && ! [ -f "$CONF/panel.conf" ]; then "$BIN" panel on || warn "Web panel could not start (wattun panel on)."; echo; fi

# ---- summary & post-install status card ----
total=0; running=0; stale_names=''
is_stale() {
  local pid; pid=$(systemctl show -p MainPID --value "wattun@$1" 2>/dev/null)
  [ -n "$pid" ] && [ "$pid" != 0 ] && [[ "$(readlink "/proc/$pid/exe" 2>/dev/null)" == *"(deleted)"* ]]
}
while IFS= read -r n; do
  [ -n "$n" ] || continue
  total=$((total+1))
  if systemctl is-active -q "wattun@$n" 2>/dev/null; then
    running=$((running+1))
    is_stale "$n" && stale_names="$stale_names $n"
  fi
done < <(tunnel_list)

prev=''; [ -x "$BIN.prev" ] && prev=$("$BIN.prev" -version 2>/dev/null | awk '{print $2; exit}')
if [ -n "$OLD" ] && [ "$OLD" = "$NEW" ] && [ "$FORCE" = 0 ]; then
  title="Already on $NEW"
elif [ -n "$OLD" ]; then
  title="Updated $OLD -> $NEW"
else
  title="Installed $NEW"
fi

box "$title" \
  "${GRY}command   ${RST} ${CYN}wattun${RST}" \
  "${GRY}binary    ${RST} $BIN" \
  "${GRY}config    ${RST} $CONF · $total tunnel$([ "$total" = 1 ] || echo s) ($running running)" \
  "${GRY}rollback  ${RST} ${prev:-none}${prev:+ ${GRY}(wattun -> Settings -> v)${RST}}"

if [ -n "$stale_names" ]; then
  echo
  warn "Still running the old binary:${stale_names}"
  hint "Restart them to load $NEW: wattun, then s, then r (open connections drop)."
fi
echo

# ---- interactive first-run wizard ----
if [ "${WAT_FROM_MANAGER:-0}" = 1 ]; then exit 0; fi
if [ -t 0 ] && [ -t 1 ]; then
  if [ "$total" -eq 0 ]; then
    step_diagram
    echo
    printf '  %s Kharej  %soutside server, where the service runs%s\n' "$(key_label 1)" "$GRY" "$RST"
    printf '  %s Iran    %sinside server users connect to (needs Kharej token)%s\n' "$(key_label 2)" "$GRY" "$RST"
    printf '  %s later   %srun wattun when ready%s\n' "$(key_label 3)" "$GRY" "$RST"
    echo
    for t in 1 2 3; do
      printf '  %s?%s This server is %s[1/2/3, Enter = 3]%s ' "$CYN" "$RST" "$GRY" "$RST"
      IFS= read -rsn1 side || { echo; side=3; }
      echo "$side"
      case "$side" in
        1) save_side kharej; cleanup; exec "$MGR" kharej ;;
        2) save_side iran
           if ! [ -f "$CONF/panel.conf" ]; then
             echo
             printf '  %s?%s Turn on the web panel (password + 2FA, browser dashboard for this server)? %s[Y/n]%s ' "$CYN" "$RST" "$GRY" "$RST"
             IFS= read -rsn1 a || a=y; echo
             case "$a" in
               n|N) hint "Later: wattun panel on" ;;
               *) echo; "$BIN" panel on || warn "Web panel could not start. Try later: wattun panel on"
                  echo; printf '  %sSave the login above, it is shown once. Press Enter to continue.%s' "$GRY" "$RST"
                  IFS= read -r _ || true; echo ;;
             esac
           fi
           cleanup; exec "$MGR" iran ;;
        3|''|q|Q) break ;;
        *) warn "Please press 1, 2 or 3." ;;
      esac
    done
  else
    printf '  %s?%s Open wattun now? %s[Y/n]%s ' "$CYN" "$RST" "$GRY" "$RST"
    IFS= read -rsn1 a || a=y
    echo
    case "$a" in n|N) ;; *) cleanup; exec "$MGR" ;; esac
  fi
fi

echo
ok "Done. Run ${BOLD}wattun${RST} to manage tunnels."
