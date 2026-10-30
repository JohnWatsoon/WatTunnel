#!/usr/bin/env bash
# WatTun installer.
#   bash <(curl -fsSL https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
# Options:
#   --version vX.Y.Z   install that release instead of the latest
#   --force            reinstall even when the same version is installed
#   --uninstall        stop every tunnel and remove WatTun (asks before deleting /etc/wattun)
# Environment:
#   WAT_PROXY=https://ghproxy.net/   prefix for every GitHub URL (when github.com is blocked; untrusted: the
#                                    release signature is then verified mandatorily)
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
# Local files (dist/ build, wattun-manager) are used only when this script sits in a real checkout or unpacked
# release. The manager's update runs a downloaded copy from a temp dir: there a stale /tmp/dist/ must not be
# picked up and "installed" again, so it always downloads.
if [ "${WAT_FROM_MANAGER:-0}" = 1 ] || [ ! -f "$HERE/install.sh" ]; then HERE=/nonexistent; fi

case "$(locale charmap 2>/dev/null)" in UTF-8) ;; *) export LC_ALL=C.UTF-8 ;; esac

# ======================================================================================
#  Terminal UI: colours, gradient banner, spinner, step checklist
# ======================================================================================
IS_TTY=0; [ -t 1 ] && IS_TTY=1
USE_COLOR=0
if [ "${WAT_FORCE_COLOR:-0}" = 1 ] || { [ "$IS_TTY" = 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; }; then USE_COLOR=1; fi
NCOL=8
if [ "$USE_COLOR" = 1 ]; then
  NCOL=$(tput colors 2>/dev/null || echo 8)
  case "${TERM:-}" in *256color*) NCOL=256 ;; esac
  case "$NCOL" in ''|*[!0-9]*) NCOL=8 ;; esac
  RST=$'\e[0m'; BOLD=$'\e[1m'; RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; GRY=$'\e[90m'
else
  RST=''; BOLD=''; RED=''; GRN=''; YEL=''; CYN=''; GRY=''
fi
ANIM=0
if [ "$IS_TTY" = 1 ] && [ "${WAT_NO_ANIM:-0}" != 1 ]; then ANIM=1; fi

SPIN_PID=''
TMP=''
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
vlen() { local s=${1//$'\e'\[*([0-9;?])[a-zA-Z]/}; VLEN=${#s}; }
VLEN=0
ok()   { printf '  %s✔%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$RST" "$*"; }
err()  { printf '  %s✘%s %s\n' "$RED" "$RST" "$*"; }
hint() { printf '  %s%s%s\n' "$GRY" "$*" "$RST"; }
die()  { cur_show; err "$*"; exit 1; }
hr()   { printf '  %s%s%s\n' "$GRY" "$(rep ─ 74)" "$RST"; }
key_label() { printf '%s[%s]%s' "$CYN" "$1" "$RST"; }

GR_N=(51 45 39 33 63 99 135 171)
GR_F=(36 36 36 34 34 35 35 35)
GFG=''
gfg() {
  GFG=''; [ "$USE_COLOR" = 1 ] || return 0
  local i=$(( $1 % 8 ))
  if [ "$NCOL" -ge 256 ]; then printf -v GFG '\e[1;38;5;%sm' "${GR_N[$i]}"; else printf -v GFG '\e[1;%sm' "${GR_F[$i]}"; fi
}

WATTUN_BANNER=(
  '██     ██  ▄▄▄ ▄▄▄▄▄▄ ██████ ▄▄ ▄▄ ▄▄  ▄▄ ▄▄  ▄▄ '
  '██ ▄█▄ ██ ██▀██  ██     ██   ██ ██ ███▄██ ███▄██ '
  ' ▀██▀██▀  ██▀██  ██     ██   ▀███▀ ██ ▀██ ██ ▀██ '
)
META_TELEGRAM='@WatxDev'

banner() { # [1 = animated line-by-line reveal] : logo, links beside it when the terminal is wide enough, else below
  local i cols side=("github.com/JohnWatsoon" "t.me/${META_TELEGRAM#@}" '')
  cols=$(tput cols 2>/dev/null || echo 80)
  for i in 0 1 2; do
    gfg "$i"
    if [ "$cols" -ge 78 ]; then printf '  %s%s%s  %s%s%s\n' "$GFG" "${WATTUN_BANNER[$i]}" "$RST" "$GRY" "${side[$i]}" "$RST"
    else printf '  %s%s%s\n' "$GFG" "${WATTUN_BANNER[$i]}" "$RST"; fi
    [ "${1:-0}" = 1 ] && sleep 0.03
  done
  [ "$cols" -ge 78 ] || printf '  %s%s · %s%s\n' "$GRY" "${side[0]}" "${side[1]}" "$RST"
  return 0
}

page() { # title [subtitle]
  [ "$IS_TTY" = 1 ] && printf '\e[H\e[2J\e[3J'
  echo
  if [ "$ANIM" = 1 ]; then banner 1; else banner 0; fi
  echo
  printf '  %s%s%s%s\n' "$BOLD" "$1" "$RST" "${2:+  ${GRY}$2${RST}}"
  hr; echo
}

step_diagram() {
  printf '  %s1 Kharej%s %s(outside, first)%s  %s──token──►%s  %s2 Iran%s %s(inside)%s\n' \
    "$BOLD" "$RST" "$GRY" "$RST" "$GRY" "$RST" "$BOLD" "$RST" "$GRY" "$RST"
}

# ---- step checklist: high-contrast status badges and animated spinners ----
SPIN_FR=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
CL_LABELS=(); CL_N=0; DETAIL=''; ERRMSG=''
cl_row() { # idx text : rewrite checklist row idx in place
  local up=$((CL_N - $1))
  printf '\e[%dA\r\e[K%s\e[%dB\r' "$up" "$2" "$up"
}
cl_init() {
  local l
  CL_LABELS=("$@"); CL_N=$#
  [ "$ANIM" = 1 ] || return 0
  for l in "$@"; do printf '  %s·%s %s%s%s\n' "$GRY" "$RST" "$GRY" "$l" "$RST"; done
}
cl_start() { # idx
  [ "$ANIM" = 1 ] || return 0
  local idx=$1 label=${CL_LABELS[$1]}
  cur_hide
  (
    local i=0 t0=$SECONDS up=$((CL_N - idx))
    while :; do
      printf '\e[%dA\r\e[K  %s%s%s %-32s %s%ds%s\e[%dB\r' "$up" "$CYN" "${SPIN_FR[$i]}" "$RST" "$label" "$GRY" $((SECONDS-t0)) "$RST" "$up"
      i=$(( (i+1) % 10 )); sleep 0.1
    done
  ) &
  SPIN_PID=$!
}
cl_end() { # idx rc
  local idx=$1 rc=$2 label=${CL_LABELS[$1]} line
  kill_spin
  if [ "$rc" -eq 0 ]; then line=$(printf '  %s✔%s %-32s %s' "$GRN" "$RST" "$label" "${DETAIL:+$GRY$DETAIL$RST}")
  elif [ "$rc" -eq 2 ]; then line=$(printf '  %s–%s %-32s %s' "$GRY" "$RST" "$label" "${DETAIL:+$GRY$DETAIL$RST}")
  else line=$(printf '  %s✘%s %s' "$RED" "$RST" "$label"); fi
  if [ "$ANIM" = 1 ]; then cl_row "$idx" "$line"; cur_show; else printf '%s\n' "$line"; fi
}
run_step() { # idx fn : rc 0 ok, 2 skipped (fn returns 2), else failure -> abort with ERRMSG
  local idx=$1 rc; DETAIL=''; ERRMSG=''
  cl_start "$idx"
  "$2"; rc=$?
  cl_end "$idx" "$rc"
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then echo; die "${ERRMSG:-step failed}"; fi
  return 0
}

box() { # title lines... (plain or coloured)
  local w=74 t=$1 l pad; shift
  printf '  %s┌─ %s%s%s%s %s┐%s\n' "$GRY" "$RST" "$BOLD$t" "$RST" "$GRY" "$(rep ─ $((w-${#t}-3)))" "$RST"
  for l in "$@"; do
    vlen "$l"; pad=$((w-2-VLEN)); [ "$pad" -lt 0 ] && pad=0
    printf '  %s│%s %s%*s %s│%s\n' "$GRY" "$RST" "$l" "$pad" '' "$GRY" "$RST"
  done
  printf '  %s└%s┘%s\n' "$GRY" "$(rep ─ "$w")" "$RST"
}

usage() {
  cat <<'EOF'
WatTun installer
Usage: bash install.sh [options]

Options:
  --version vX.Y.Z   Install that specific release instead of the latest
  --force            Reinstall even when the same version is already installed
  --uninstall        Stop all tunnels and remove WatTun from this server
  -h, --help         Show this help screen

Environment:
  WAT_PROXY=https://ghproxy.net/   Proxy prefix for GitHub downloads (when github.com is filtered)
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

tunnel_list() { local f b; for f in "$CONF"/*.yml; do [ -e "$f" ] || continue; b=${f##*/}; echo "${b%.yml}"; done; }

# ======================================================================================
#  Uninstall
# ======================================================================================
uninstall() {
  local list=() n u a
  while IFS= read -r n; do [ -n "$n" ] && list+=("$n"); done < <(tunnel_list)
  page "Uninstall WatTun"
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

  ok "Removed the unit files"
  rm -f "$UNIT" /etc/systemd/system/wattun-heal.service /etc/systemd/system/wattun-heal.timer /etc/systemd/system/wattun-auto-optimize.service /etc/systemd/system/wattun-auto-optimize.timer
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

NEW=''; OLD=''
fetch() { # url dest
  if command -v curl >/dev/null; then curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 -o "$2" "$PROXY$1"
  elif command -v wget >/dev/null; then wget -q -T 20 -t 3 -O "$2" "$PROXY$1"
  else return 127; fi
}

resolve_tag() {
  local u
  [ "$VERSION" = latest ] || { TAG=$VERSION; return 0; }
  command -v curl >/dev/null || return 1
  u=$(curl -fsSL -o /dev/null -w '%{url_effective}' --connect-timeout 15 --max-time 30 "${PROXY}https://github.com/$REPO/releases/latest" 2>/dev/null) || return 1
  u=${u%/}; u=${u##*/}
  [[ "$u" =~ ^v[0-9]+\.[0-9]+ ]] || return 1
  TAG=$u
}
TAG=''; PREV_WARN=0; MGR_FROM_REL=0; FROM_DIST=0; DL_BASE=''
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

# ======================================================================================
#  5-Stage Installation Pipeline
# ======================================================================================

# Stage 1: Environment & Capability Verification
step_stage1_verify_env() {
  command -v curl >/dev/null || command -v wget >/dev/null || [ -f "$HERE/dist/$NAME" ] || { ERRMSG="curl or wget is required to retrieve WatTun"; return 1; }
  mkdir -p "$TMP" || { ERRMSG="cannot create temporary working directory"; return 1; }
  DETAIL="$OS_DISTRO, $RAM_TOTAL RAM, $SYSTEMD_VER"
}

# Stage 2: Engine & Manager Retrieval
step_stage2_retrieve_payload() {
  local base
  if [ -f "$HERE/dist/$NAME" ]; then
    cp "$HERE/dist/$NAME" "$TMP/wattun" || { ERRMSG="cannot read $HERE/dist/$NAME"; return 1; }
    [ -f "$HERE/dist/$NAME.sha256" ] && cp "$HERE/dist/$NAME.sha256" "$TMP/sum"
    FROM_DIST=1
    DETAIL="local build (dist/)"
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
    if fetch "$base/$NAME" "$TMP/wattun"; then
      fetch "$base/$NAME.sha256" "$TMP/sum" || { ERRMSG="could not download checksum file"; return 1; }
      DETAIL="release ${TAG:-latest}, $(human_size "$(stat -c %s "$TMP/wattun")")"
    else
      ERRMSG="download failed. If GitHub is blocked, try: WAT_PROXY=https://ghproxy.net/ bash install.sh"; return 1
    fi
  fi

  # Retrieve manager payload. From a release it must come from that same release (and is checked against the signed
  # SHA256SUMS in stage 3); raw.githubusercontent is only a fallback for releases that predate the asset, never
  # through a proxy.
  if [ -f "$HERE/wattun-manager" ]; then
    cp "$HERE/wattun-manager" "$TMP/mgr"
  elif [ -n "$DL_BASE" ] && fetch "$DL_BASE/wattun-manager" "$TMP/mgr"; then
    MGR_FROM_REL=1
  elif fetch "https://raw.githubusercontent.com/$REPO/${WAT_MGR_REF:-main}/wattun-manager" "$TMP/mgr"; then
    [ -n "$PROXY" ] && { ERRMSG="this release does not ship wattun-manager; refusing to fetch it unsigned through WAT_PROXY"; return 1; }
    DETAIL="$DETAIL, manager from main (not in the signed release)"
  elif [ -n "$TAG" ] && fetch "https://raw.githubusercontent.com/$REPO/$TAG/wattun-manager" "$TMP/mgr"; then
    [ -n "$PROXY" ] && { ERRMSG="this release does not ship wattun-manager; refusing to fetch it unsigned through WAT_PROXY"; return 1; }
    DETAIL="$DETAIL, manager from $TAG (not in the signed release)"
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

# Stage 3: Cryptographic Signature & SHA256 Verification
step_verify_sig() {
  local got=$1 sums="$TMP/SHA256SUMS" sig="$TMP/SHA256SUMS.sig" pub="$TMP/sigpub.pem"
  [ "$FROM_DIST" = 1 ] && { DETAIL="$DETAIL, local build (no remote sig)"; return 0; }
  if ! command -v openssl >/dev/null 2>&1; then
    [ -n "$PROXY" ] && { ERRMSG="openssl is required to verify the release signature when WAT_PROXY is set"; return 1; }
    DETAIL="$DETAIL, signature check skipped (no openssl)"; return 0
  fi
  if ! fetch "$DL_BASE/SHA256SUMS" "$sums" || ! fetch "$DL_BASE/SHA256SUMS.sig" "$sig"; then
    [ -n "$PROXY" ] && { ERRMSG="could not download SHA256SUMS(.sig): refusing to install via proxy without signature"; return 1; }
    DETAIL="$DETAIL, signature not published"; return 0
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
  DETAIL="$DETAIL, signature ok"
}

step_stage3_verify_crypto() {
  local want got
  if [ -f "$TMP/sum" ]; then
    want=$(awk '{print $1}' "$TMP/sum"); got=$(sha256sum "$TMP/wattun" | awk '{print $1}')
    [ "$want" = "$got" ] || { ERRMSG="checksum mismatch (want $want, got $got)"; return 1; }
    DETAIL="sha256 ${got:0:10}... ok"
  else
    if [ "${WAT_SKIP_CHECKSUM:-0}" != 1 ]; then
      ERRMSG="no checksum file found (WAT_SKIP_CHECKSUM=1 permits unverified local binaries)"; return 1
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
    DETAIL="$NEW up to date (wattun + wattun-manager -> ${BIN%/*})"
    return 2
  fi

  if [ -x "$BIN" ]; then
    if cp -f "$BIN" "$BIN.prev.tmp" && mv -f "$BIN.prev.tmp" "$BIN.prev"; then :
    else rm -f "$BIN.prev.tmp"; PREV_WARN=1; fi
  fi

  install -m 755 "$TMP/wattun" "$BIN.new" && mv -f "$BIN.new" "$BIN" || { ERRMSG="cannot write $BIN"; return 1; }
  if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service=+ep "$BIN" 2>/dev/null || true
  fi

  local now; now=$("$BIN" -version 2>/dev/null | awk '{print $2; exit}')
  [ "$now" = "$NEW" ] || { ERRMSG="$BIN reports ${now:-nothing} after installing $NEW"; return 1; }

  install -m 755 "$TMP/mgr" "$MGR.new" && mv -f "$MGR.new" "$MGR" || { ERRMSG="cannot write $MGR"; return 1; }
  DETAIL="$NEW installed to ${BIN%/*} (capabilities enabled)"
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
ReadWritePaths=/etc/wattun

[Install]
WantedBy=multi-user.target
EOF
  if ! cmp -s "$TMP/unit" "$UNIT" 2>/dev/null; then
    install -m 644 "$TMP/unit" "$UNIT" || { ERRMSG="cannot write $UNIT"; return 1; }
  fi
  systemctl daemon-reload || { ERRMSG="systemctl daemon-reload failed"; return 1; }
  DETAIL="${UNIT##*/} (hardened sandbox template)"
}

# ======================================================================================
#  Main Execution
# ======================================================================================
TMP=$(mktemp -d)
page "Installer" "linux/$ARCH"
cl_init \
  "Check system" \
  "Download wattun and the manager" \
  "Verify signature and sha256" \
  "Install files" \
  "Write the systemd unit"

run_step 0 step_stage1_verify_env
run_step 1 step_stage2_retrieve_payload
run_step 2 step_stage3_verify_crypto
run_step 3 step_stage4_install_binaries
run_step 4 step_stage5_systemd_setup
echo

if [ "$PREV_WARN" = 1 ]; then
  warn "Could not create $BIN.prev backup copy. Rollback keeps the previous copy, if any."
fi

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
  title="Updated $OLD → $NEW"
else
  title="Installed $NEW"
fi

box "$title" \
  "${GRY}binary   ${RST} $BIN" \
  "${GRY}manager  ${RST} $MGR ${GRY}(run: wattun)${RST}" \
  "${GRY}unit     ${RST} $UNIT" \
  "${GRY}config   ${RST} $CONF" \
  "${GRY}tunnels  ${RST} $total configured · $running running" \
  "${GRY}rollback ${RST} ${prev:-none}${prev:+ ${GRY}(Settings, then v)${RST}}"

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
    echo "  A tunnel joins two servers, in this order:"
    echo
    step_diagram
    echo
    printf '  %s Kharej  %soutside server, where the service runs. Set it up first.%s\n' "$(key_label 1)" "$GRY" "$RST"
    printf '  %s Iran    %sinside server users connect to. Needs the token from Kharej.%s\n' "$(key_label 2)" "$GRY" "$RST"
    printf '  %s later   %srun wattun when you are ready%s\n' "$(key_label 3)" "$GRY" "$RST"
    echo
    for t in 1 2 3; do
      printf '  %s?%s This server is %s[1/2/3, Enter = 3]%s ' "$CYN" "$RST" "$GRY" "$RST"
      IFS= read -rsn1 side || { echo; side=3; }
      echo "$side"
      case "$side" in
        1) cleanup; exec "$MGR" kharej ;;
        2) cleanup; exec "$MGR" iran ;;
        3|''|q|Q) break ;;
        *) warn "Please press 1, 2 or 3." ;;
      esac
    done
  else
    printf '  %s?%s Open the manager now? %s[Y/n]%s ' "$CYN" "$RST" "$GRY" "$RST"
    IFS= read -rsn1 a || a=y
    echo
    case "$a" in n|N) ;; *) cleanup; exec "$MGR" ;; esac
  fi
fi

echo
ok "Done. Run ${BOLD}wattun${RST} to manage tunnels."
