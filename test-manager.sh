#!/usr/bin/env bash
# self-check for wattun-manager: resilience profiles (profile save/list/show/del/apply), the wizard's
# profile defaults, the unattended flags (--fake-sni/--fake-mode/--fake-ttl/--pool-rotate/--pool-rotate-bytes),
# the value validators, and the flow gates (profiles are Linux-only; the resilience prompts are off
# the plain wizard flow unless a flag or profile pre-fills them). No root, no systemd, no binary needed.
cd "$(dirname "$0")" || exit 1
# L16: a private scratch root, so two runs (or a run next to a checkout) never share or delete each other's files
SMOKE=$(mktemp -d) || { echo "FAIL cannot create a scratch directory"; exit 1; }
trap 'rm -rf "$SMOKE"' EXIT
export WAT_MANAGER_LIB=1 WAT_PREFIX=wattest
export WAT_CONF="$SMOKE/conf" WAT_BIN="$SMOKE/wattun"
export WAT_AUTO_RUN="$SMOKE/run-auto" WAT_RUN="$SMOKE/run"
mkdir -p "$WAT_CONF" "$WAT_AUTO_RUN" "$WAT_RUN"
fail=0
chk() { [ "$2" = "$3" ] && echo "ok   $1" || { echo "FAIL $1: got '$2', want '$3'"; fail=1; return; }; }
expect_fail() { "$@" 2>/dev/null && { echo "FAIL $*: accepted a bad value"; fail=1; } || echo "ok   rejected: $*"; }

cat >"$WAT_CONF/t1.yml" <<'EOF'
mode: client
carrier: wss
peer: example.com:443
fake-sni: mci.ir
fake-mode: seqsum
pool-rotate: 30m
pool-rotate-bytes: 500MB
EOF
. ./wattun-manager
bin_ver_ok() { echo 1; }
role() { echo Iran; }
uname() { echo Linux; }
systemctl() { return 0; }
logger() { :; }
step() { shift; "$@"; }

profile_cmd save p1 t1
chk "save wrote the file" "$(cat "$WAT_CONF/profiles/p1.env" | grep -c '^FAKEMODE=seqsum')" "1"
profile_cmd list
profile_cmd show p1
profile_cmd apply p1 t1
chk "apply keeps seqsum" "$(grep '^fake-mode:' "$WAT_CONF/t1.yml")" "fake-mode: seqsum"
chk "apply keeps pool-rotate" "$(grep '^pool-rotate:' "$WAT_CONF/t1.yml")" "pool-rotate: 30m"

profile_cmd save p1 >/dev/null 2>&1 && echo "ok   save without a tunnel name: exactly one pool tunnel -> t1" || { echo "FAIL save without a tunnel name: exactly one pool tunnel -> t1"; fail=1; }

printf '# cleared elsewhere\nFAKESNI=\nFAKEMODE=\nFAKETTL=\nPOOLROT=\nPOOLBYTES=\n' >"$WAT_CONF/profiles/blank.env"
profile_cmd apply blank t1
chk "blank profile clears fake-sni" "$(grep -c '^fake-' "$WAT_CONF/t1.yml")" "0"
chk "blank profile clears pool keys" "$(grep -c '^pool-' "$WAT_CONF/t1.yml")" "0"

ni_parse --carrier wss --name x --pool-rotate 4h --pool-rotate-bytes 1.5GB
chk "unattended --pool-rotate" "$NI_POOLROT" "4h"
chk "unattended --pool-rotate-bytes" "$NI_POOLBYTES" "1.5GB"
NI_FAKESNI=''; NI_FAKEMODE=''
ni_parse --fake-sni mci.ir --fake-mode seqsum
chk "unattended --fake-sni pair form" "$NI_FAKESNI" "mci.ir"
chk "unattended --fake-mode seqsum" "$NI_FAKEMODE" "seqsum"
ni_parse --fake-mode auto
chk "unattended --fake-mode auto" "$NI_FAKEMODE" "auto"
ni_parse --fake-mode rst
chk "unattended --fake-mode rst" "$NI_FAKEMODE" "rst"
ni_parse --preset mci --ech ladder --governor true
chk "unattended --preset mci" "$NI_PRESET" "mci"
chk "unattended --ech ladder" "$NI_ECH" "ladder"
chk "unattended --governor true" "$NI_GOVERNOR" "true"
ni_parse --preset "Iran Whitelist - Irancell/Mokhaberat" --ech auto --governor false
chk "unattended --preset canonical irancell" "$NI_PRESET" "irancell"
chk "unattended --ech auto" "$NI_ECH" "auto"
chk "unattended --governor false" "$NI_GOVERNOR" "false"
ECH_B64="VGhpcy1pcy11cmxzYWZlX2Jhc2U2NF9lY2g="
ni_parse --ech "$ECH_B64"
chk "unattended --ech preserves base64 case" "$NI_ECH" "$ECH_B64"

expect_fail ni_parse --pool-rotate 30x
expect_fail ni_parse --fake-mode gq
expect_fail ni_parse --pool-rotate-bytes 20QQ
expect_fail ni_parse --fake-ttl 999
expect_fail ni_parse --preset bad_preset
expect_fail ni_parse --ech bad_ech
expect_fail ni_parse --governor bad_gov

v_pool_rotate off && echo "ok   v_pool_rotate off" || { echo "FAIL v_pool_rotate off"; fail=1; }
for v in 500MB 4G 300k 1.5gb 0b 0 off; do v_pool_bytes "$v" && echo "ok   v_pool_bytes $v" || { echo "FAIL v_pool_bytes $v"; fail=1; }; done

for e in ladder auto off "VGhpcyBpcyBhIHZhbGlkIGJhc2U2NCBFQ0g=" "VGhpcy1pcy11cmxzYWZlX2Jhc2U2NF9lY2g="; do
  v_ech "$e" && echo "ok   v_ech $e" || { echo "FAIL v_ech $e"; fail=1; }
done
expect_fail v_ech "invalid"
expect_fail v_ech "short="

for m in seq ttl sum seqsum auto rst; do
  v_fake_mode "$m" && echo "ok   v_fake_mode $m" || { echo "FAIL v_fake_mode $m"; fail=1; }
done
expect_fail v_fake_mode "bad_mode"

for s in mci.ir "mci.ir,divar.ir" "mci.ir, divar.ir, digikala.com"; do
  v_sni_name "$s" && echo "ok   v_sni_name $s" || { echo "FAIL v_sni_name $s"; fail=1; }
done
expect_fail v_sni_name "bad name!"
expect_fail v_sni_name "mci.ir, bad name"

for g in on off true false 1 0; do
  v_governor "$g" && echo "ok   v_governor $g" || { echo "FAIL v_governor $g"; fail=1; }
done
expect_fail v_governor "maybe"

for p in mci irancell blackout conservative off "iran whitelist - mci" "emergency blackout mode"; do
  v_preset "$p" && echo "ok   v_preset $p" || { echo "FAIL v_preset $p"; fail=1; }
done
expect_fail v_preset "unknown"

chk "profile show mci FAKESNI" "$(profile_cmd show mci | grep '^FAKESNI=')" "FAKESNI=mci.ir"
chk "profile show mci FAKEMODE" "$(profile_cmd show mci | grep '^FAKEMODE=')" "FAKEMODE=rst"
chk "profile show mci POOLROT" "$(profile_cmd show mci | grep '^POOLROT=')" "POOLROT=30m"
chk "profile show mci ECH" "$(profile_cmd show mci | grep '^ECH=')" "ECH=ladder"
chk "profile show blackout FAKEMODE" "$(profile_cmd show blackout | grep '^FAKEMODE=')" "FAKEMODE=rst"
chk "profile show blackout POOLROT" "$(profile_cmd show blackout | grep '^POOLROT=')" "POOLROT=90s"
chk "profile show conservative POOLROT" "$(profile_cmd show conservative | grep '^POOLROT=')" "POOLROT=4h"
chk "profile show conservative ECH" "$(profile_cmd show conservative | grep '^ECH=')" "ECH=auto"
chk "profile show long name" "$(profile_cmd show 'iran whitelist - mci' | grep '^FAKESNI=')" "FAKESNI=mci.ir"
expect_fail profile_cmd show nonexistent
expect_fail profile_cmd del mci
expect_fail profile_cmd save mci t1

# Applying built-in presets to tunnels
bin_ver_ok() { echo 1; }
profile_cmd apply mci t1
chk "apply mci fake-sni" "$(grep '^fake-sni:' "$WAT_CONF/t1.yml")" "fake-sni: mci.ir"
chk "apply mci fake-mode" "$(grep '^fake-mode:' "$WAT_CONF/t1.yml")" "fake-mode: rst"
chk "apply mci pool-rotate" "$(grep '^pool-rotate:' "$WAT_CONF/t1.yml")" "pool-rotate: 30m"
chk "apply mci pool-rotate-bytes" "$(grep '^pool-rotate-bytes:' "$WAT_CONF/t1.yml")" "pool-rotate-bytes: 500MB"
chk "apply mci ech" "$(grep '^ech:' "$WAT_CONF/t1.yml")" "ech: ladder"

preset_cmd t1 blackout
chk "preset blackout fake-mode" "$(grep '^fake-mode:' "$WAT_CONF/t1.yml")" "fake-mode: rst"
chk "preset blackout pool-rotate" "$(grep '^pool-rotate:' "$WAT_CONF/t1.yml")" "pool-rotate: 90s"
chk "preset blackout pool-rotate-bytes" "$(grep '^pool-rotate-bytes:' "$WAT_CONF/t1.yml")" "pool-rotate-bytes: 100MB"

preset_cmd t1 conservative
chk "preset conservative fake-mode" "$(grep '^fake-mode:' "$WAT_CONF/t1.yml")" "fake-mode: seq"
chk "preset conservative pool-rotate" "$(grep '^pool-rotate:' "$WAT_CONF/t1.yml")" "pool-rotate: 4h"
chk "preset conservative ech" "$(grep '^ech:' "$WAT_CONF/t1.yml")" "ech: auto"

preset_cmd t1 off
chk "preset off clears fake-sni" "$(grep -c '^fake-' "$WAT_CONF/t1.yml")" "0"
chk "preset off clears pool-rotate" "$(grep -c '^pool-' "$WAT_CONF/t1.yml")" "0"
chk "preset off clears ech" "$(grep -c '^ech:' "$WAT_CONF/t1.yml")" "0"

# ICMP carrier & volume governor preset
cat >"$WAT_CONF/t_icmp.yml" <<'EOF'
mode: client
carrier: icmp
peer: 198.51.100.1
EOF
apply_preset t_icmp mci
chk "icmp preset sets governor" "$(grep '^governor:' "$WAT_CONF/t_icmp.yml")" "governor: true"
apply_preset t_icmp off
chk "icmp preset off clears governor" "$(grep -c '^governor:' "$WAT_CONF/t_icmp.yml")" "0"
# Reverse pool carrier & unsupported carrier rejection
cat >"$WAT_CONF/t_rev.yml" <<'EOF'
mode: client
carrier: tcp
listen: :443
reverse: true
EOF
expect_fail apply_preset t_rev mci
rm -f "$WAT_CONF/t_rev.yml"

cat >"$WAT_CONF/t_udp.yml" <<'EOF'
mode: client
carrier: udp
peer: 1.2.3.4:443
EOF
expect_fail apply_preset t_udp mci
rm -f "$WAT_CONF/t_udp.yml"

# Preset detection edge cases
cat >"$WAT_CONF/t_det.yml" <<'EOF'
mode: client
carrier: tcp
fake-sni: irancell.ir
pool-rotate: 20m
EOF
chk "detect_preset defaults omitted fake-mode to seq" "$(detect_preset t_det)" "Iran Whitelist - Irancell/Mokhaberat"
rm -f "$WAT_CONF/t_det.yml"

cat >"$WAT_CONF/t_icmp_det.yml" <<'EOF'
mode: client
carrier: icmp
governor: true
EOF
chk "detect_preset icmp governor" "$(detect_preset t_icmp_det)" "Governor Active (ICMP Pacer)"
rm -f "$WAT_CONF/t_icmp_det.yml"

uname() { echo Darwin; } # profiles are a CAP_NET_RAW feature: refuse to save off-Linux
expect_fail profile_cmd save win t1
chk "off-Linux save wrote nothing" "$([ -e "$WAT_CONF/profiles/win.env" ] && echo y || echo n)" "n"
uname() { echo Linux; }

# blackout_cmd: preset vs domain
printf 'mode: client\ncarrier: tcp\npeer: example.com:443\n' >"$WAT_CONF/t2.yml"
bin_ver_ok() { echo 1; }
WAT_PREFIX=wattest blackout_cmd t2 mci
chk "blackout preset fake-sni" "$(grep '^fake-sni:' "$WAT_CONF/t2.yml")" "fake-sni: mci.ir"
chk "blackout preset fake-mode" "$(grep '^fake-mode:' "$WAT_CONF/t2.yml")" "fake-mode: rst"
chk "blackout preset pool-rotate" "$(grep '^pool-rotate:' "$WAT_CONF/t2.yml")" "pool-rotate: 30m"

sed -i -E '/^pool-rotate:/d' "$WAT_CONF/t2.yml"
bin_ver_ok() { [ "$1" = 2.7.0 ] || { echo "FAIL bin_ver_ok got '$1'"; fail=1; }; echo 1; }
WAT_PREFIX=wattest blackout_cmd t2 mci.ir
chk "blackout wrote fake-sni" "$(grep '^fake-sni:' "$WAT_CONF/t2.yml")" "fake-sni: mci.ir"
chk "blackout default mode rst" "$(grep '^fake-mode:' "$WAT_CONF/t2.yml")" "fake-mode: rst"
chk "blackout leaves fake-ttl unset" "$(grep -c '^fake-ttl:' "$WAT_CONF/t2.yml")" "0"
chk "blackout domain leaves pool-rotate unset" "$(grep -c '^pool-rotate:' "$WAT_CONF/t2.yml")" "0"
expect_fail blackout_cmd t2 'bad name!'
rm -f "$WAT_CONF/t2.yml"
bin_ver_ok() { echo 1; }

# Numbered pickers default return under NONINTERACTIVE=1
NONINTERACTIVE=1
NI_PRESET='' pick_preset
chk "pick_preset default" "$REPLY_V" "mci"
NI_PRESET='irancell' pick_preset
chk "pick_preset explicit" "$REPLY_V" "irancell"

# reverse tunnels refuse the checksum-marker modes (3.0.0), plain ones keep them
printf 'mode: server\ncarrier: tcp\nreverse: true\n' >"$WAT_CONF/trev.yml"
chk "reverse refuses seqsum" "$(rev_sum_refused trev seqsum 2>/dev/null && echo refused)" "refused"
chk "reverse keeps rst" "$(rev_sum_refused trev rst 2>/dev/null && echo refused)" ""
chk "direct keeps sum" "$(rev_sum_refused t1 sum 2>/dev/null && echo refused)" ""
rm -f "$WAT_CONF/trev.yml"

# anti-censor toggle: the Cloudflare preset on, off again, and who dials in a reverse tunnel
chk "preset alias cf" "$(preset_canonical CF)" "cloudflare"
chk "v_preset cloudflare" "$(v_preset cloudflare && echo ok)" "ok"
apply_preset t1 cloudflare >/dev/null
chk "cloudflare fake-sni" "$(grep '^fake-sni:' "$WAT_CONF/t1.yml")" "fake-sni: www.cloudflare.com"
chk "cloudflare fake-mode" "$(grep '^fake-mode:' "$WAT_CONF/t1.yml")" "fake-mode: rst"
chk "cloudflare clears pool-rotate" "$(grep -c '^pool-rotate' "$WAT_CONF/t1.yml")" "0"
apply_preset t1 off >/dev/null
chk "off clears fake-sni" "$(grep -c '^fake-' "$WAT_CONF/t1.yml")" "0"
chk "iran normal dials" "$(ac_dialer t1 && echo y || echo n)" "y"
printf 'mode: server
carrier: tcp
reverse: true
peer: "1.2.3.4:4443"
' >"$WAT_CONF/t3.yml"
role() { echo Kharej; }
chk "kharej reverse dials" "$(ac_dialer t3 && echo y || echo n)" "y"
chk "kharej normal listens" "$(ac_dialer t1 && echo y || echo n)" "n"
apply_preset t3 cloudflare >/dev/null
chk "kharej reverse preset" "$(grep '^fake-sni:' "$WAT_CONF/t3.yml")" "fake-sni: www.cloudflare.com"
role() { echo Iran; }
chk "iran reverse listens" "$(ac_dialer t3 && echo y || echo n)" "n"
rm -f "$WAT_CONF/t3.yml"
chk "udp can reverse" "$(rev_capable udp && echo y || echo n)" "y"
chk "udp reverse port is udp" "$(rproto udp)" "udp"
chk "tls reverse port is tcp" "$(rproto tls)" "tcp"
chk "udp has no fake-sni dialer" "$(is_pool udp && echo y || echo n)" "n"
ip() { case "$*" in *"route get"*) echo "198.51.100.7 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0" ;; *"addr show"*) printf '2: eth0 inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0
3: eth0 inet 203.0.113.9/24 scope global secondary eth0
' ;; esac; }
chk "out_ip reads the route's source" "$(out_ip 198.51.100.7)" "10.0.0.5"
chk "local_ips lists every global address" "$(local_ips | paste -sd' ' -)" "10.0.0.5 203.0.113.9"
unset -f ip

NI_FAKESNI='' pick_sni_preset
chk "pick_sni_preset default" "$REPLY_V" "mci.ir"
NI_FAKESNI='divar.ir' pick_sni_preset
chk "pick_sni_preset explicit" "$REPLY_V" "divar.ir"
NI_FAKESNI='off' pick_sni_preset
chk "pick_sni_preset off" "$REPLY_V" "off"

NI_FAKEMODE='' pick_fake_mode
chk "pick_fake_mode default" "$REPLY_V" "rst"
NI_FAKEMODE='auto' pick_fake_mode
chk "pick_fake_mode explicit" "$REPLY_V" "auto"
NI_FAKEMODE='rst' pick_fake_mode
chk "pick_fake_mode rst" "$REPLY_V" "rst"

NI_POOLROT='' pick_pool_rotate
chk "pick_pool_rotate default" "$REPLY_V" "30m"
NI_POOLROT='90s' pick_pool_rotate
chk "pick_pool_rotate explicit" "$REPLY_V" "90s"

NI_POOLBYTES='' pick_pool_rotate_bytes
chk "pick_pool_rotate_bytes default" "$REPLY_V" "500MB"
NI_POOLBYTES='1GB' pick_pool_rotate_bytes
chk "pick_pool_rotate_bytes explicit" "$REPLY_V" "1GB"

NI_ECH='' pick_ech
chk "pick_ech default" "$REPLY_V" "ladder"
NI_ECH='auto' pick_ech
chk "pick_ech explicit" "$REPLY_V" "auto"

# Validators & pickers for dns-listen and src-ip
v_dns_listen "127.0.0.1:53" || { echo "FAIL v_dns_listen 127.0.0.1:53"; fail=1; }
v_dns_listen "0.0.0.0:5353" || { echo "FAIL v_dns_listen 0.0.0.0:5353"; fail=1; }
v_dns_listen "off" || { echo "FAIL v_dns_listen off"; fail=1; }
expect_fail v_dns_listen "invalid_addr"
expect_fail v_dns_listen "127.0.0.1:99999"

v_src_ip "192.168.1.50" || { echo "FAIL v_src_ip 192.168.1.50"; fail=1; }
v_src_ip "10.0.0.2" || { echo "FAIL v_src_ip 10.0.0.2"; fail=1; }
v_src_ip "off" || { echo "FAIL v_src_ip off"; fail=1; }
expect_fail v_src_ip "999.999.999.999"
expect_fail v_src_ip "bad_ip"

NI_DNSLISTEN='' pick_dns_listen
chk "pick_dns_listen default" "$REPLY_V" "off"
NI_DNSLISTEN='127.0.0.1:53' pick_dns_listen
chk "pick_dns_listen explicit" "$REPLY_V" "127.0.0.1:53"

NI_SRCIP='' pick_src_ip
chk "pick_src_ip default" "$REPLY_V" "off"
NI_SRCIP='192.168.43.100' pick_src_ip
chk "pick_src_ip explicit" "$REPLY_V" "192.168.43.100"

# ni_parse handles --dns-listen and --src-ip
NI_DNSLISTEN='' NI_SRCIP=''
ni_parse --dns-listen 127.0.0.1:53 --src-ip 10.10.10.5
chk "ni_parse dns-listen" "$NI_DNSLISTEN" "127.0.0.1:53"
chk "ni_parse src-ip" "$NI_SRCIP" "10.10.10.5"

# Automated link bypass verification (anticensor_test)
cat >"$WAT_CONF/t_probe.yml" <<'EOF'
mode: client
carrier: wss
peer: example.com:443
metrics: 127.0.0.1:54321
fake-sni: mci.ir
fake-mode: seqsum
ech: ladder
ports:
  - 8443:443/tcp
EOF
_pb_def=$(declare -f port_busy) # restored below: later wizard tests need the real check
port_busy() { return 0; }
stats() {
  echo '{"alive": true, "srtt_ms": 22.4, "pkts_in": 120, "pkts_out": 135, "filter_profile": "desync-seqsum", "ech": "ladder"}'
}
ANTICENSOR_TEST_WAIT=1 anticensor_test t_probe && echo "ok   anticensor_test passed for alive tunnel" || { echo "FAIL anticensor_test alive"; fail=1; }

stats() {
  echo '{"alive": false}'
}
expect_fail env ANTICENSOR_TEST_WAIT=1 anticensor_test t_probe
expect_fail anticensor_test non_existent_tunnel
rm -f "$WAT_CONF/t_probe.yml"
eval "$_pb_def" # the port-busy stub was only for this tunnel probe

# Regression test for F9: AT_EXTRA deduplication with T_ECH
t_extra=$(printf "fp: chrome\nech: auto\ntls-frag: 100")
t_ech="ladder"
if [ -n "$t_ech" ]; then
  [ "$t_ech" != off ] && t_out="ech: $t_ech"
  [ -n "$t_extra" ] && t_extra=$(printf '%s\n' "$t_extra" | grep -v '^ech:' || true)
fi
chk "F9 regression: t_extra stripped ech" "$(printf '%s\n' "$t_extra" | grep -c '^ech:' || true)" "0"
chk "F9 regression: t_out preserved ladder" "$t_out" "ech: ladder"

# Anti-censor matrix: av_add carries fake-sni/fake-mode; at_start passes them to the binary
bin_ver_ok() { echo 1; }
AV_LABEL=(); AV_CAR=(); AV_KIND=(); AV_PEER=(); AV_PORT=(); AV_SNI=(); AV_FP=(); AV_ECH=(); AV_FRAG=()
AV_FS=(); AV_FM=()
av_add "desync mci.ir · seqsum" tcp d "198.51.100.1:443" '' '' '' '' '' mci.ir seqsum
av_add "base" tcp d "198.51.100.1:443" '' ''
chk "matrix: AV_FS set" "${AV_FS[0]}" "mci.ir"
chk "matrix: AV_FM set" "${AV_FM[0]}" "seqsum"
chk "matrix: AV_FS empty for base" "${AV_FS[1]}" ""

# ac_matrix builds the full variant list
T_CARRIER=tcp; T_PEER=198.51.100.1:443; T_SNI=example.com; T_PATH=/wat; T_KEY=k; T_ICMP=''
at_prep() { AT_DIR="$AUTO_RUN/t.$$"; mkdir -p "$AT_DIR"; printf 'k' >"$AT_DIR/key"; return 0; }
at_probe() { AR_OK[$1]=1; AR_DOWN[$1]=5; AR_UP[$1]=5; AR_RTT[$1]=10; return 0; }
ac_matrix t1
chk "matrix: variant count" "${#AV_LABEL[@]}" "14" # 1 base + 7 modes + 3 SNIs + 2 cloudflare + 1 auto-probe
chk "matrix: baseline first" "${AV_LABEL[0]}" "base (no desync)"
chk "matrix: seq present" "$(printf '%s\n' "${AV_FM[@]}" | grep -c '^seq$')" "1"
chk "matrix: auto-probe present" "$(printf '%s\n' "${AV_FM[@]}" | grep -c '^auto$')" "1"
chk "matrix: 13 desync rows carry fake-sni" "$(printf '%s\n' "${AV_FS[@]}" | grep -c .)" "13"
chk "matrix: ranking fills" "${#AT_RANK[@]}" "14"

# ac_matrix_apply writes the winner and strips desync keys for the baseline
AT_SEL=("${AV_LABEL[*]}") # dummy to satisfy set -u shape; real selection below
AT_SEL=(0)
AT_QUIET=1 ac_matrix_apply t1
chk "matrix apply: strips fake-sni on baseline" "$(grep -c '^fake-sni:' "$WAT_CONF/t1.yml" || true)" "0"
chk "matrix apply: strips fake-ttl on baseline" "$(grep -c '^fake-ttl:' "$WAT_CONF/t1.yml" || true)" "0"
AV_SEL=(); for ((i=0; i<${#AV_LABEL[@]}; i++)); do [ "${AV_FM[$i]}" = seqsum ] && AV_SEL+=("$i"); done
AT_SEL=("${AV_SEL[0]}")
AT_QUIET=1 ac_matrix_apply t1
chk "matrix apply: writes fake-sni" "$(grep '^fake-sni:' "$WAT_CONF/t1.yml")" "fake-sni: mci.ir"
chk "matrix apply: writes fake-mode" "$(grep '^fake-mode:' "$WAT_CONF/t1.yml")" "fake-mode: seqsum"
chk "matrix apply: resets fake-ttl" "$(grep -c '^fake-ttl:' "$WAT_CONF/t1.yml" || true)" "0"

# matrix gate: a bond carrier is rejected with a pointer at auto-test
echo "carrier: tcp+wss" >"$WAT_CONF/t_bond.yml"
echo "mode: client" >>"$WAT_CONF/t_bond.yml"
echo "peer: 198.51.100.1:443" >>"$WAT_CONF/t_bond.yml"
NONINTERACTIVE=1 expect_fail ac_matrix_cmd t_bond
rm -f "$WAT_CONF/t_bond.yml"

# blackout arming and audit tests
role() { [ "$1" = t_kharej ] && echo Kharej || echo Iran; }
echo "carrier: tcp" >"$WAT_CONF/t_kharej.yml"
echo "mode: server" >>"$WAT_CONF/t_kharej.yml"
printf 'testkey' >"$WAT_CONF/t_kharej.key"
NONINTERACTIVE=1 arm_blackout_cmd t_kharej
chk "arm-blackout kharej carrier" "$(grep '^carrier:' "$WAT_CONF/t_kharej.yml")" "carrier: fortress"
chk "arm-blackout kharej dns relay" "$(grep '^dns-relay-upstream:' "$WAT_CONF/t_kharej.yml")" "dns-relay-upstream: 1.1.1.1:53"
NONINTERACTIVE=1 audit_blackout_cmd t_kharej
chk "audit-blackout exit code" "$?" "0"
rm -f "$WAT_CONF/t_kharej.yml" "$WAT_CONF/t_kharej.key"

NONINTERACTIVE=1 arm_blackout_cmd t1
chk "arm-blackout iran probe max" "$(grep '^path-probe-max:' "$WAT_CONF/t1.yml")" "path-probe-max: 6s"
chk "arm-blackout iran governor" "$(grep '^governor:' "$WAT_CONF/t1.yml")" "governor: true"

# ======================================================================================
# Phase 1-4: Engine & Transport Suites, Bonding, SLA Healing, Policies & UX Tooling
# ======================================================================================

# 1. Validators: v_sessions, v_conns, v_mtu (engine limits: maxSessions=16, poolMaxConns=64, MaxPayload 256..16384)
for s in 1 16 - 0 default; do v_sessions "$s" && echo "ok   v_sessions $s" || { echo "FAIL v_sessions $s"; fail=1; }; done
for s in 17 64 65 -1 00 abc; do expect_fail v_sessions "$s"; done

for c in 1 8 64 - 0 default; do v_conns "$c" && echo "ok   v_conns $c" || { echo "FAIL v_conns $c"; fail=1; }; done
for c in 65 128 129 -1 00 abc; do expect_fail v_conns "$c"; done

for m in 256 576 1400 1500 16384 - 0 default; do v_mtu "$m" && echo "ok   v_mtu $m" || { echo "FAIL v_mtu $m"; fail=1; }; done
for m in 255 16385 65535 70000 -1 abc; do expect_fail v_mtu "$m"; done

# carrier-aware: a bond is one session and merges to its smallest leg's mtu
v_sessions 4 tcp && echo "ok   v_sessions 4 tcp" || { echo "FAIL v_sessions 4 tcp"; fail=1; }
v_sessions 4 udp && echo "ok   v_sessions 4 udp" || { echo "FAIL v_sessions 4 udp"; fail=1; }
expect_fail v_sessions 4 icmp
expect_fail v_sessions 4 gre
expect_fail v_sessions 4 'tcp+tls'
expect_fail v_sessions 4 tcp 1
chk "mtu_max_for a pool carrier" "$(mtu_max_for tcp)" "16384"
chk "mtu_max_for a pool bond" "$(mtu_max_for 'tcp+tls')" "16384"
chk "mtu_max_for icmp" "$(mtu_max_for icmp)" "1400"
chk "mtu_max_for udp" "$(mtu_max_for udp)" "1400"
chk "mtu_max_for a bond uses its smallest leg" "$(mtu_max_for 'icmp+tcp')" "1400"
v_mtu 16384 tcp && echo "ok   v_mtu 16384 tcp" || { echo "FAIL v_mtu 16384 tcp"; fail=1; }
v_mtu 1400 icmp && echo "ok   v_mtu 1400 icmp" || { echo "FAIL v_mtu 1400 icmp"; fail=1; }
expect_fail v_mtu 1401 icmp
expect_fail v_mtu 16385 tcp
# a config written from the unattended flags: carrier known only at write time
_TC=$T_CARRIER; _TR=$T_REV; _SS=$SESS_USE; _NM=${NI_MTU:-}
T_CARRIER=tcp; T_REV=''; SESS_USE=4; NI_MTU=16384
chk "sessions_line writes one pool carrier" "$(sessions_line 2>/dev/null)" "sessions: 4"
chk "mtu_line writes a pool mtu" "$(mtu_line 2>/dev/null)" "mtu: 16384"
T_CARRIER=icmp
chk "sessions_line ignores icmp" "$(sessions_line 2>/dev/null)" ""
chk "mtu_line ignores an mtu icmp would clamp" "$(mtu_line 2>/dev/null)" ""
T_CARRIER=tcp+tls
chk "sessions_line ignores a bond" "$(sessions_line 2>/dev/null)" ""
T_CARRIER=tcp; T_REV=1
chk "sessions_line ignores reverse" "$(sessions_line 2>/dev/null)" ""
T_CARRIER=$_TC; T_REV=$_TR; SESS_USE=$_SS; NI_MTU=$_NM

# 1b. F19 shaped carriers (3.3.0): raw tier sit/6to4/xfrm-ipsec/etherip/l2tpv3 (bare-IP peer like icmp, no listen, no
# reverse, one session, Linux+CAP_NET_RAW) and the UDP tier fou-gre/gue-ipip/vxlan/geneve/dnscrypt-udp/ntp-direct/
# openvpn-dco/srtp-direct (peer/listen with the protocol's conventional port by default). These are wattun-internal
# shapes, not the real protocols: everything here mirrors cmd/wattun/main.go and wat/udpshape.go.
for c in sit 6to4 xfrm-ipsec etherip l2tpv3 fou-gre gue-ipip vxlan geneve dnscrypt-udp ntp-direct openvpn-dco srtp-direct; do
  carrier_ok "$c" && echo "ok   carrier_ok $c" || { echo "FAIL carrier_ok $c"; fail=1; }
done
expect_fail carrier_ok auto
expect_fail carrier_ok vlxan
chk "shaped: five raw-tier names" "$(for c in $SHAPED_RAW; do echo x; done | wc -l | tr -d ' ')" "5"
chk "shaped: eight UDP-tier names" "$(for c in $SHAPED_UDP; do echo x; done | wc -l | tr -d ' ')" "8"
chk "shaped: raw tier detected" "$(is_shaped_raw etherip && echo y)" "y"
chk "shaped: UDP tier detected" "$(is_shaped_udp srtp-direct && echo y)" "y"
chk "shaped: vxlan is not the raw tier" "$(is_shaped_raw vxlan && echo y)" ""
chk "shaped: icmp is not shaped" "$(is_shaped_carrier icmp && echo y)" ""
chk "shaped: a raw shape takes no listen" "$(carrier_has_listen l2tpv3 && echo y)" ""
chk "shaped: a UDP shape takes a listen" "$(carrier_has_listen fou-gre && echo y)" "y"
chk "shaped: no global listen for a raw shape" "$(carrier_write_listen sit && echo y)" ""
chk "shaped: a global listen for a UDP shape" "$(carrier_write_listen ntp-direct && echo y)" "y"
chk "shaped: no global listen for a raw-only bond" "$(carrier_write_listen 'sit+etherip' && echo y)" ""
chk "shaped: a bond with a pool leg needs a global listen" "$(carrier_write_listen 'sit+tcp' && echo y)" "y"
# conventional port table, kept in sync with wat/udpshape.go (an explicit port in the address wins)
for p in 'fou-gre 5555' 'gue-ipip 6080' 'vxlan 4789' 'geneve 6081' 'dnscrypt-udp 443' 'ntp-direct 123' 'openvpn-dco 1194' 'srtp-direct 5004'; do
  set -- $p
  chk "shaped port $1" "$(shaped_udp_port "$1")" "$2"
done
chk "shaped: raw-tier protocol numbers" "$(shaped_raw_proto sit)/$(shaped_raw_proto xfrm-ipsec)/$(shaped_raw_proto l2tpv3)" "41/50/115"
chk "shaped: the fixed header comes out of the datagram ceiling" "$(mtu_max_for dnscrypt-udp)" "1326"
chk "shaped: a shaped bond merges to the smallest leg" "$(mtu_max_for 'tcp+dnscrypt-udp')" "1326"
# M1/M15: raw-tier ceilings are 1400 minus the IP-protocol header (not the generic 1400)
chk "shaped: sit ceiling" "$(mtu_max_for sit)" "1360"
chk "shaped: 6to4 ceiling" "$(mtu_max_for 6to4)" "1360"
chk "shaped: xfrm-ipsec ceiling" "$(mtu_max_for xfrm-ipsec)" "1392"
chk "shaped: etherip ceiling" "$(mtu_max_for etherip)" "1384"
chk "shaped: l2tpv3 ceiling" "$(mtu_max_for l2tpv3)" "1396"
chk "shaped: raw ceiling in a mixed list" "$(mtu_max_for sit)" "1360"
chk "shaped: a UDP shape's carrier port is udp" "$(rproto vxlan)" "udp"
chk "shaped: peer gets the conventional UDP port" "$(shaped_peer_for_client fou-gre kharej.example)" "kharej.example:5555"
chk "shaped: an explicit UDP port wins" "$(shaped_peer_for_client fou-gre kharej.example:6000)" "kharej.example:6000"
chk "shaped: raw tier keeps a bare peer" "$(shaped_peer_for_client sit kharej.example)" "kharej.example"
chk "shaped: a hand-made raw token loses its port" "$(shaped_peer_for_client 6to4 kharej.example:41)" "kharej.example"
# D7: 3.3.0 refuses shaped carriers in a '+'-bond; only single shaped carriers are accepted
for c in sit fou-gre 6to4 srtp-direct; do
  v_carrier_list "$c" && echo "ok   v_carrier_list $c" || { echo "FAIL v_carrier_list $c"; fail=1; }
done
v_carrier_list auto && echo "ok   v_carrier_list auto" || { echo "FAIL v_carrier_list auto"; fail=1; }
v_carrier_list 'icmp+tcp' && echo "ok   v_carrier_list a normal bond" || { echo "FAIL v_carrier_list a normal bond"; fail=1; }
for c in 'icmp+sit' 'tcp+fou-gre' 'sit+6to4' 'icmp++sit' 'icmp+icmp' bogus 'auto+icmp' '+sit'; do expect_fail v_carrier_list "$c"; done
chk "shaped bond: the per-leg YAML writer is gone" "$(grep -c '^shaped_bond_yaml()' wattun-manager)" "0"
NI_CARRIER=sit; CARRIER=''
pick_carrier auto >/dev/null 2>&1
chk "shaped: the picker accepts a raw shape" "$CARRIER" "sit"
NI_CARRIER='tcp+sit'; CARRIER=''
expect_fail pick_carrier auto
NI_CARRIER=auto; CARRIER=''
pick_carrier auto >/dev/null 2>&1
chk "shaped: the picker still accepts auto" "$CARRIER" "auto"
NI_CARRIER=bogus; expect_fail pick_carrier auto
ni_parse --carrier fou-gre
chk "unattended --carrier a UDP shape" "$NI_CARRIER" "fou-gre"
expect_fail ni_parse --carrier 'icmp+gue-ipip'
expect_fail ni_parse --carrier bogus
expect_fail ni_parse --carrier 'icmp++sit'
expect_fail v_sessions 2 fou-gre # the F19 shapes run one session
expect_fail v_sessions 2 sit
# this host gate: 3.3.0 on both ends, and Linux for the raw tier (uname/bin_ver_ok are stubbed in this harness)
shaped_supported_here fou-gre && echo "ok   shaped_supported_here a UDP shape" || { echo "FAIL shaped_supported_here a UDP shape"; fail=1; }
_bb=$(declare -f bin_ver_ok); _un=$(declare -f uname)
bin_ver_ok() { echo ''; }
expect_fail shaped_supported_here fou-gre
eval "$_bb"
uname() { echo Windows; }
expect_fail shaped_supported_here sit
eval "$_un"
shaped_supported_here sit && echo "ok   shaped_supported_here a raw shape on Linux" || { echo "FAIL shaped_supported_here a raw shape on Linux"; fail=1; }
# Kharej wizard offline: the UDP tier writes the conventional listen port and a peer that carries it; the raw tier
# writes no listen key and a bare-IP peer. Then the Iran wizard reads that token and writes the client side.
( free_metrics_port() { echo 19999; }
  NONINTERACTIVE=1 NI_CARRIER=fou-gre NI_NAME=t_f19u NI_ADDR=203.0.113.5 wizard_kharej ) >/dev/null 2>&1
chk "F19 UDP wizard: Kharej listens on the conventional port" "$(grep -c '^listen: ":5555"$' "$WAT_CONF/t_f19u.yml")" "1"
chk "F19 UDP wizard: the token peer carries the port" "$(read_token "$(cat "$WAT_CONF/t_f19u.token")"; printf '%s' "$T_PEER")" "203.0.113.5:5555"
( free_metrics_port() { echo 19999; }
  NONINTERACTIVE=1 NI_CARRIER=sit NI_NAME=t_f19r NI_ADDR=203.0.113.5 wizard_kharej ) >/dev/null 2>&1
chk "F19 raw wizard: no listen key at all" "$(grep -c '^listen:' "$WAT_CONF/t_f19r.yml")" "0"
chk "F19 raw wizard: the token peer is a bare address" "$(read_token "$(cat "$WAT_CONF/t_f19r.token")"; printf '%s' "$T_PEER")" "203.0.113.5"
( free_metrics_port() { echo 19999; }; wait_link() { return 1; }; test_tunnel() { :; }
  NI_PRESET='' NI_FAKESNI='' NI_FAKEMODE='' NI_FAKETTL='' NI_POOLROT='' NI_POOLBYTES='' NI_ECH=''
  NONINTERACTIVE=1 NI_TOKEN=$(cat "$WAT_CONF/t_f19u.token") NI_MAP='47811:18899' NI_NAME=t_f19i wizard_iran ) >/dev/null 2>&1
chk "F19 Iran wizard: carrier and peer from the token" "$(grep -c '^carrier: fou-gre$' "$WAT_CONF/t_f19i.yml")/$(grep -c '^peer: 203.0.113.5:5555$' "$WAT_CONF/t_f19i.yml")" "1/1"
chk "F19 Iran wizard: no listen/reverse for a UDP shape" "$(grep -cE '^(listen|reverse):' "$WAT_CONF/t_f19i.yml")" "0"
( free_metrics_port() { echo 19999; }; wait_link() { return 1; }; test_tunnel() { :; }
  NI_PRESET='' NI_FAKESNI='' NI_FAKEMODE='' NI_FAKETTL='' NI_POOLROT='' NI_POOLBYTES='' NI_ECH=''
  NONINTERACTIVE=1 NI_TOKEN=$(cat "$WAT_CONF/t_f19r.token") NI_MAP='47812:18899' NI_NAME=t_f19j wizard_iran ) >/dev/null 2>&1
chk "F19 Iran wizard: a raw shape writes the bare peer" "$(grep -c '^peer: 203.0.113.5$' "$WAT_CONF/t_f19j.yml")" "1"
rm -f "$WAT_CONF"/t_f19*.yml "$WAT_CONF"/t_f19*.key "$WAT_CONF"/t_f19*.token "$WAT_CONF"/t_f19*.ech
# A4: the interactive Kharej picker gets a "More transports (advanced)" branch for the 13 shaped carriers; a shaped
# selection must pass the same validators and produce the same config/token as the unattended --carrier path.
shaped_pick_list
chk "shaped picker: 13 choices (A4)" "${#SHAPED_OPTS[@]}" "13"
chk "shaped picker: raw tier first (A4)" "${SHAPED_OPTS[0]}/${SHAPED_OPTS[5]}/${SHAPED_OPTS[12]}" "sit/fou-gre/srtp-direct"
chk "shaped picker: index maps to a carrier (A4)" "$(shaped_pick_index 8 2>/dev/null || true)" "vxlan"
for i in 0 14 abc ''; do expect_fail shaped_pick_index "$i"; done
_ni=$NONINTERACTIVE; NONINTERACTIVE=0
printf 'q' | pick_carrier auto >"$SMOKE/pick.out" 2>&1
chk "shaped picker: the branch is offered in the picker (A4)" "$(grep -c 'More transports' "$SMOKE/pick.out")" "1"
printf 'm8\n' >"$SMOKE/pick.in"
CARRIER=''; pick_carrier auto <"$SMOKE/pick.in" >/dev/null 2>&1
chk "shaped picker: choosing vxlan returns it (A4)" "$CARRIER" "vxlan"
rm -f "$SMOKE/pick.in"
NONINTERACTIVE=$_ni
rm -f "$SMOKE/pick.out"
( free_metrics_port() { echo 19998; }
  NONINTERACTIVE=1 NI_CARRIER=vxlan NI_NAME=t_a4u NI_ADDR=203.0.113.5 wizard_kharej ) >/dev/null 2>&1
chk "shaped picker: the chosen UDP shape is written (A4)" "$(grep -c '^carrier: vxlan$' "$WAT_CONF/t_a4u.yml")" "1"
chk "shaped picker: the UDP shape listens on 4789 (A4)" "$(grep -c '^listen: ":4789"$' "$WAT_CONF/t_a4u.yml")" "1"
chk "shaped picker: its token carries the shape (A4)" "$(read_token "$(cat "$WAT_CONF/t_a4u.token")"; printf '%s %s' "$T_CARRIER" "$T_PEER")" "vxlan 203.0.113.5:4789"
( free_metrics_port() { echo 19997; }
  NONINTERACTIVE=1 NI_CARRIER=sit NI_NAME=t_a4r NI_ADDR=203.0.113.5 wizard_kharej ) >/dev/null 2>&1
chk "shaped picker: the chosen raw shape writes no listen (A4)" "$(grep -c '^listen:' "$WAT_CONF/t_a4r.yml")" "0"
rm -f "$WAT_CONF"/t_a4*.yml "$WAT_CONF"/t_a4*.key "$WAT_CONF"/t_a4*.token
NI_CARRIER=''; NI_NAME=''; CARRIER=''

# 2. Unattended flags: --sessions, --conns, --mtu, --policy
ni_parse --sessions 16 --conns 16 --mtu 1400 --policy latency
chk "unattended --sessions" "$NI_SESSIONS" "16"
chk "unattended --conns" "$NI_CONNS" "16"
chk "unattended --mtu" "$NI_MTU" "1400"
chk "unattended --policy latency" "$NI_POLICY" "latency"

ni_parse --policy direct
chk "unattended --policy direct" "$NI_POLICY" "direct"

expect_fail ni_parse --sessions 17
expect_fail ni_parse --conns 200
expect_fail ni_parse --mtu 100
expect_fail ni_parse --policy bogus

# 3. Boost Suite: boost_status, boost_apply, boost_undo
BOOST_SYSCTL="$SMOKE/boost.conf"
boost_apply >/dev/null 2>&1
chk "boost_apply created conf" "$([ -f "$BOOST_SYSCTL" ] && echo 1 || echo 0)" "1"
chk "boost_apply set 64MB rmem" "$(grep -c 'rmem_max = 67108864' "$BOOST_SYSCTL" || true)" "1"
chk "boost_apply set bbr" "$(grep -c 'tcp_congestion_control = bbr' "$BOOST_SYSCTL" || true)" "1"
boost_status >/dev/null 2>&1
chk "boost_status exit code" "$?" "0"
boost_undo >/dev/null 2>&1
chk "boost_undo removed conf" "$([ ! -f "$BOOST_SYSCTL" ] && echo 1 || echo 0)" "1"

# 4. Backup & Restore roundtrip
echo "test_payload: 12345" >"$WAT_CONF/backup_sample.yml"
backup_cmd "$SMOKE/test_backup.tar.gz" >/dev/null 2>&1
chk "backup_cmd created archive" "$([ -f "$SMOKE/test_backup.tar.gz" ] && echo 1 || echo 0)" "1"
rm -f "$WAT_CONF/backup_sample.yml"
restore_cmd "$SMOKE/test_backup.tar.gz" >/dev/null 2>&1
chk "restore_cmd restored sample file" "$(grep -c 'test_payload: 12345' "$WAT_CONF/backup_sample.yml" || true)" "1"
rm -f "$WAT_CONF/backup_sample.yml" "$SMOKE/test_backup.tar.gz"

# 5. at_rank policies: speed, latency, direct
AV_LABEL=("cdn-fast" "direct-low-rtt" "direct-high-speed")
AV_CAR=("h2" "tcp" "tls")
AV_KIND=("c" "d" "d")
AR_OK=(1 1 1)
AR_DOWN=(25 5 15)
AR_UP=(25 5 15)
AR_RTT=(80 15 30)

at_rank speed
chk "at_rank speed first" "${AT_RANK[0]}" "0"

at_rank latency
chk "at_rank latency first" "${AT_RANK[0]}" "1"

at_rank direct
chk "at_rank direct first" "${AT_RANK[0]}" "2"

# 6. listen_conflict_desc format
tunnel_using_listen() { [ "$1" = 8443 ] && echo "t_conflict" || echo ""; }
port_user() { [ "$1" = 443 ] && echo "nginx (PID 1234)" || echo ""; }
chk "conflict_desc tunnel" "$(listen_conflict_desc tcp 8443)" "tunnel 't_conflict'"
chk "conflict_desc process" "$(listen_conflict_desc tcp 443)" "nginx (PID 1234)"
chk "conflict_desc fallback" "$(listen_conflict_desc tcp 9999)" "another process or tunnel"

# 7. SLA monitoring in heal()
cat >"$WAT_CONF/t_sla.yml" <<'EOF'
mode: client
carrier: tcp
peer: 198.51.100.1:443
EOF
cat >"$WAT_CONF/t_sla.sla" <<'EOF'
sla_min_rate_kbps=1000
sla_max_rtt_ms=50
sla_max_loss_pct=5
EOF
touch "$WAT_CONF/t_sla.auto"
tunnels() { echo t_sla; }
role() { echo Iran; }
systemctl() { case "$1" in is-active) echo active ;; esac; return 0; }
retest_triggered=0
heal_retest() { retest_triggered=1; }

# SLA breach case (rtt = 120ms > 50ms)
stats() { echo '{"alive": true, "last_rx_age_ms": 100, "srtt_ms": 120, "loss_pct": 0, "rate_bps": 2000000}'; }
heal; chk "sla breach cnt 1" "$(cat "$RUN/t_sla.sla_breach" 2>/dev/null)" "1"
heal; chk "sla breach cnt 2" "$(cat "$RUN/t_sla.sla_breach" 2>/dev/null)" "2"
heal; chk "sla breach triggered retest at 3" "$retest_triggered" "1"
chk "sla breach reset after trigger" "$([ ! -f "$RUN/t_sla.sla_breach" ] && echo 1 || echo 0)" "1"

# SLA healthy case (clears breach file if count < 3)
echo "1" >"$RUN/t_sla.sla_breach"
stats() { echo '{"alive": true, "last_rx_age_ms": 100, "srtt_ms": 20, "loss_pct": 0, "rate_bps": 2000000}'; }
heal
chk "sla healthy clears breach" "$([ ! -f "$RUN/t_sla.sla_breach" ] && echo 1 || echo 0)" "1"
# 8. set_port_limit preserves ports block and updates limits
cat >"$WAT_CONF/t_lim.yml" <<'EOF'
mode: client
ports:
  - 8080
  - 9090
EOF
set_port_limit t_lim 8080 5MB 10GB
chk "set_port_limit preserved ports 8080" "$(grep -c '^[[:space:]]*- 8080$' "$WAT_CONF/t_lim.yml" || true)" "1"
chk "set_port_limit preserved ports 9090" "$(grep -c '^[[:space:]]*- 9090$' "$WAT_CONF/t_lim.yml" || true)" "1"
chk "set_port_limit wrote limit" "$(grep -c '8080 rate=5MB quota=10GB' "$WAT_CONF/t_lim.yml" || true)" "1"
# update existing limit
set_port_limit t_lim 8080 10MB 0
chk "set_port_limit updated limit" "$(grep -c '8080 rate=10MB' "$WAT_CONF/t_lim.yml" || true)" "1"
chk "set_port_limit preserved ports after update" "$(grep -c '^[[:space:]]*- 8080$' "$WAT_CONF/t_lim.yml" || true)" "1"
rm -f "$WAT_CONF/t_lim.yml"

# 9. pe_from: the port rows of another tunnel can be copied, and the copy can move them off it
cat >"$WAT_CONF/t_src.yml" <<'EOF'
mode: client
carrier: udp
peer: 203.0.113.9:4443
ports:
  - 8443:443
  - 9000
EOF
cat >"$WAT_CONF/t_dst.yml" <<'EOF'
mode: client
carrier: udp
peer: 203.0.113.9:4443
ports:
  - 7000
EOF
confirm() { return 0; } # the "add these rows?" and "remove them from the source?" prompts
PE_ROLE=Iran; PE_TUNNEL=t_dst; PE_ALLOW=(); PE_OWNED=(); PE_MSG=''
load_maps t_dst
pe_from t_src
chk "pe_from: destination has all rows" "${#MAPS[@]}" "3"
chk "pe_from: kept the row it had" "$(printf '%s\n' "${MAPS[@]}" | grep -c 7000 || true)" "1"
chk "pe_from: copied 8443" "$(printf '%s\n' "${MAPS[@]}" | grep -c 8443 || true)" "1"
chk "pe_from: copied 9000" "$(printf '%s\n' "${MAPS[@]}" | grep -c '^9000' || true)" "1"
chk "pe_from: moved them off the source" "$(yml_maps t_src | grep -c . || true)" "0"
chk "pe_from: source keeps its other keys" "$(grep -c '^peer:' "$WAT_CONF/t_src.yml" || true)" "1"
rm -f "$WAT_CONF/t_src.yml" "$WAT_CONF/t_dst.yml"

# Tunnel page: the two-column command deck. Pure functions (no systemd, root or binary), so every action the flat
# menu used to expose must stay reachable, the cursor must follow arrows and typed hotkeys, and the descriptions the
# page shows must exist for every action.
deck_keys() { printf ' %s ' "${TL_KEY[@]}" "${TR_KEY[@]}"; }
missing=''
TM_SELKEY=''
tunnel_menu_build t_deck Iran active enabled icmp 1 0 0 0
for k in l d v m p c q b z t h a r s e o; do case "$(deck_keys)" in *" $k "*) ;; *) missing+="$k " ;; esac; done
chk "deck: Iran has every action" "$missing" ""
chk "deck: Iran has no Kharej-only key" "$(case "$(deck_keys)" in *' k '*) echo has;; *) echo no;; esac)" "no"
chk "deck: Iran auto mode present" "$(case "$(deck_keys)" in *' a '*) echo has;; *) echo no;; esac)" "has"
TM_SELKEY=''
tunnel_menu_build t_deck Kharej active enabled tcp 1 1 0 0
missing=''
for k in l d v m p c q b z r s e o t k h; do case "$(deck_keys)" in *" $k "*) ;; *) missing+="$k " ;; esac; done
chk "deck: Kharej has every action" "$missing" ""
chk "deck: Kharej has no auto mode" "$(case "$(deck_keys)" in *' a '*) echo has;; *) echo no;; esac)" "no"
chk "deck: reverse Kharej can change the Iran address" "$(case "$(deck_keys)" in *' h '*) echo has;; *) echo no;; esac)" "has"
TM_SELKEY=''
tunnel_menu_build t_deck Kharej active enabled icmp 1 0 1 0
chk "deck: auto Kharej can close unused carriers" "$(case "$(deck_keys)" in *' u '*) echo has;; *) echo no;; esac)" "has"
TM_SELKEY=''
tunnel_menu_build t_deck Iran inactive disabled icmp 1 0 0 0
chk "deck: stopped tunnel offers Start" "$(printf '%s\n' "${TR_LAB[@]}" | grep -c '^Start$')" "1"
chk "deck: boot off says so" "$(printf '%s\n' "${TR_DESC[@]}" | grep -c 'off · toggle')" "1"
# navigation: arrows walk the actions, headers are skipped, left/right switch columns
TM_SELKEY=l; tunnel_menu_move down; chk "deck: down l->d" "$TM_SELKEY" "d"
tunnel_menu_move down; chk "deck: down d->v" "$TM_SELKEY" "v"
tunnel_menu_move right; chk "deck: right v->e" "$TM_SELKEY" "e"
tunnel_menu_move up; chk "deck: up e->s" "$TM_SELKEY" "s"
tunnel_menu_move left; chk "deck: left s->d" "$TM_SELKEY" "d"
TM_SELKEY=d; tunnel_menu_move up; tunnel_menu_move up; chk "deck: up stops at the first action" "$TM_SELKEY" "l"
# rendering: the cursor, the selected action and its explanation are on screen
tunnel_menu_build t_deck Iran active enabled icmp 1 0 0 0
deck=$(tunnel_menu_render; tunnel_menu_help_line)
case "$deck" in *'▸ [l] Logs'*) got=yes;; *) got=no;; esac
chk "deck: draws the cursor on the selected action" "$got" "yes"
case "$deck" in *'follow the log'*) got=yes;; *) got=no;; esac
chk "deck: draws the explanation line" "$got" "yes"
# key_read: arrows become key names only on a page that navigates; everywhere else they are still swallowed
# (NONINTERACTIVE stays 1 for the rest of this suite, so an interactive-key test has to clear it locally)
chk "deck: arrow decoded on the page" "$( NONINTERACTIVE=0; KEY_NAV=1; { key_read; echo "$KEY"; } <<< $'\033[A')" "up"
chk "deck: arrow swallowed elsewhere" "$( NONINTERACTIVE=0; KEY_NAV=0; { key_read; echo "$KEY"; } <<< $'\033[Ax')" "x"

# F8 state-dir (3.3.0): the engine's statePaths mirror. A tunnel with `state-dir:` keeps its quota/totals pair in that
# directory under the config basename (`<dir>/NAME.yml.*`); without the key the files stay next to the config, so the
# cleanup paths do not change for existing tunnels. reset-traffic must delete the lifetime totals where the engine
# actually keeps them, and must not touch a stale file at the old location.
chk "state base: next to the config by default" "$(state_base_path kb '')" "$WAT_CONF/kb.yml"
chk "state base: state-dir honoured" "$(state_base_path kb /run/wattun)" "/run/wattun/kb.yml"
chk "state base: trailing slash normalised" "$(state_base_path kb /run/wattun/)" "/run/wattun/kb.yml"
chk "state base: a hand-edited relative value resolves from /" "$(state_base_path kb run/wattun)" "/run/wattun/kb.yml"
chk "state base: a root state-dir keeps its slash" "$(state_base_path kb /)" "/kb.yml"
cat >"$WAT_CONF/t_state.yml" <<EOF
mode: client
carrier: tcp
state-dir: $SMOKE/state
EOF
mkdir -p "$SMOKE/state"
chk "state dir read from the config" "$(state_dir_of t_state)" "$SMOKE/state"
chk "state file: totals in the state-dir" "$(state_file t_state totals)" "$SMOKE/state/t_state.yml.totals.json"
chk "state file: quota in the state-dir" "$(state_file t_state quota)" "$SMOKE/state/t_state.yml.quota.json"
chk "state files: every file the engine can leave" "$(state_files t_state | tr '\n' ' ')" "$SMOKE/state/t_state.yml.totals.json $SMOKE/state/t_state.yml.totals.json.host $SMOKE/state/t_state.yml.totals.json.tmp $SMOKE/state/t_state.yml.quota.json $SMOKE/state/t_state.yml.quota.json.tmp "
printf 'totals\n' >"$SMOKE/state/t_state.yml.totals.json"
printf 'quota\n' >"$SMOKE/state/t_state.yml.quota.json"
printf 'stale\n' >"$WAT_CONF/t_state.yml.totals.json" # a stale file at the old location
reset_traffic t_state >/dev/null 2>&1
chk "reset_traffic deletes the totals where the engine keeps them" "$([ -f "$SMOKE/state/t_state.yml.totals.json" ] && echo y || echo n)" "n"
chk "reset_traffic keeps the quota usage" "$([ -f "$SMOKE/state/t_state.yml.quota.json" ] && echo y || echo n)" "y"
chk "reset_traffic does not touch the old location" "$([ -f "$WAT_CONF/t_state.yml.totals.json" ] && echo y || echo n)" "y"
rm -rf "$SMOKE/state" "$WAT_CONF/t_state.yml" "$WAT_CONF/t_state.yml.totals.json"

# F11/F8 advanced settings: the validators mirror the engine, because an out-of-range value is a startup failure
# (cmd/wattun/fecgate.go: 0 < on <= 50 and 0 <= off < on; stateSaveInterval: >= 0 seconds; state-dir must be an
# absolute usable directory). Defaults are unchanged: empty/-/default means "unset, engine default".
v_fec_on 2 && echo "ok   v_fec_on 2" || { echo "FAIL v_fec_on 2"; fail=1; }
v_fec_on 50 && echo "ok   v_fec_on 50" || { echo "FAIL v_fec_on 50"; fail=1; }
v_fec_on 0.5 0 && echo "ok   v_fec_on 0.5 above 0" || { echo "FAIL v_fec_on 0.5 above 0"; fail=1; }
expect_fail v_fec_on 0
expect_fail v_fec_on 51
expect_fail v_fec_on 2 2
expect_fail v_fec_on abc
v_fec_off 0 && echo "ok   v_fec_off 0" || { echo "FAIL v_fec_off 0"; fail=1; }
v_fec_off 0.5 && echo "ok   v_fec_off 0.5" || { echo "FAIL v_fec_off 0.5"; fail=1; }
v_fec_off 1.9 2 && echo "ok   v_fec_off 1.9 below 2" || { echo "FAIL v_fec_off 1.9 below 2"; fail=1; }
expect_fail v_fec_off 2 2
expect_fail v_fec_off 2.5 2
expect_fail v_fec_off -1
# A3: stable knob validators — the engine clamps -win-max to 4..64 and takes -loss-ceiling as a bool
for v in 4 64 0 - default; do v_win_max "$v" && echo "ok   v_win_max $v" || { echo "FAIL v_win_max $v"; fail=1; }; done
for v in 3 65 abc 1.5; do expect_fail v_win_max "$v"; done
for v in on off true false 1 0; do v_loss_ceiling "$v" && echo "ok   v_loss_ceiling $v" || { echo "FAIL v_loss_ceiling $v"; fail=1; }; done
expect_fail v_loss_ceiling maybe
# A2: the wizard FEC shortcut — `a` means auto + open the loss-band rows, but only when the engine has the band keys
fec_choice off
chk "wizard FEC: off keeps off (A2)" "$REPLY_V:$REPLY_FEC_BAND" "off:0"
fec_choice auto
chk "wizard FEC: auto keeps auto (A2)" "$REPLY_V:$REPLY_FEC_BAND" "auto:0"
fec_choice a
chk "wizard FEC: a opens the band rows on 3.3.0 (A2)" "$REPLY_V:$REPLY_FEC_BAND" "auto:1"
_bbf=$(declare -f bin_ver_ok)
bin_ver_ok() { return 0; }
fec_choice a
chk "wizard FEC: a falls back to plain auto on an older engine (A2)" "$REPLY_V:$REPLY_FEC_BAND:$REPLY_FEC_OLD" "auto:0:1"
expect_fail fec_choice gq
eval "$_bbf"
ask_fec auto
chk "wizard FEC: the non-interactive prompt takes the default (A2)" "$REPLY_V:$REPLY_FEC_BAND" "auto:0"
chk "wizard FEC: both wizards use ask_fec (A2)" "$(grep -c 'ask_fec off' wattun-manager)" "2"
v_state_save 0 && echo "ok   v_state_save 0" || { echo "FAIL v_state_save 0"; fail=1; }
v_state_save 30 && echo "ok   v_state_save 30" || { echo "FAIL v_state_save 30"; fail=1; }
v_state_save 2592000 && echo "ok   v_state_save 2592000 (the engine's 30-day cap)" || { echo "FAIL v_state_save 2592000"; fail=1; }
expect_fail v_state_save -1
expect_fail v_state_save 3x
expect_fail v_state_save 2592001
expect_fail v_state_save 2147483648
v_state_dir /run/wattun && echo "ok   v_state_dir /run/wattun" || { echo "FAIL v_state_dir /run/wattun"; fail=1; }
_vsd=$(v_state_dir /var/lib/wattun-test-audit 2>&1)
chk "state-dir: a custom path warns about the unit sandbox (H1)" "$(grep -c 'ReadWritePaths' <<<"$_vsd")" "1"
v_state_dir - && echo "ok   v_state_dir - (default)" || { echo "FAIL v_state_dir - (default)"; fail=1; }
expect_fail v_state_dir relative/path
expect_fail v_state_dir /run/../etc
expect_fail v_state_dir '/run/x y'
: >"$SMOKE/not-a-dir"
expect_fail v_state_dir "$SMOKE/not-a-dir"
rm -f "$SMOKE/not-a-dir"

# F13/W10 settings: shape-data, noise/noise-bps/noise-window and the server-side admission allowlist. Every validator
# mirrors the engine's own startup check (cmd/wattun/noise.go, cmd/wattun/clientallow.go), because a value the engine
# refuses stops the tunnel at the next restart.
v_shape_data 0 && echo "ok   v_shape_data 0" || { echo "FAIL v_shape_data 0"; fail=1; }
v_shape_data 25 && echo "ok   v_shape_data 25" || { echo "FAIL v_shape_data 25"; fail=1; }
v_shape_data 12.5 && echo "ok   v_shape_data 12.5" || { echo "FAIL v_shape_data 12.5"; fail=1; }
expect_fail v_shape_data 25.1
expect_fail v_shape_data 26
expect_fail v_shape_data -1
expect_fail v_shape_data abc
for m in off low med custom; do v_noise_mode "$m" && echo "ok   v_noise_mode $m" || { echo "FAIL v_noise_mode $m"; fail=1; }; done
expect_fail v_noise_mode loud
for b in 64 1024 1000000; do v_noise_bps "$b" && echo "ok   v_noise_bps $b" || { echo "FAIL v_noise_bps $b"; fail=1; }; done
for b in 63 1000001 0 abc; do expect_fail v_noise_bps "$b"; done
for w in 02:00-06:00 2:00-06:00 22:00-06:00 00:00-23:59 23:59-00:00; do
  v_noise_window "$w" && echo "ok   v_noise_window $w" || { echo "FAIL v_noise_window $w"; fail=1; }
done
for w in 02:00-02:00 24:00-01:00 02:60-03:00 2-3 all 02:00-06:00-07:00; do expect_fail v_noise_window "$w"; done
# admission allowlist: bare IPv4/IPv6 addresses and CIDR prefixes (netip.ParsePrefix/ParseAddr in the engine)
for a in ::1 2a06:98c1:3121::7 fe80::1%eth0 1:2:3:4:5:6:7:8 ::ffff:1.2.3.4 ::; do
  ipv6_ok "$a" && echo "ok   ipv6_ok $a" || { echo "FAIL ipv6_ok $a"; fail=1; }
done
for a in 1::2::3 :1:2:3:4:5:6:7 1:2:3:4:5:6:7 12345::1 gg::1 1.2.3.4 1:2:3:4:5:6:7:8:9; do expect_fail ipv6_ok "$a"; done
for a in 203.0.113.5 10.0.0.0/8 2a06:98c1::/32 2001:db8::1/128 ::1/128; do
  ip_or_cidr_ok "$a" && echo "ok   ip_or_cidr_ok $a" || { echo "FAIL ip_or_cidr_ok $a"; fail=1; }
done
for a in 10.0.0.0/33 2001:db8::/129 example.com /8 ''; do expect_fail ip_or_cidr_ok "$a"; done
v_allow_clients "203.0.113.5, 10.0.0.0/8" && echo "ok   v_allow_clients list" || { echo "FAIL v_allow_clients list"; fail=1; }
v_allow_clients "2001:db8::1" && echo "ok   v_allow_clients ipv6" || { echo "FAIL v_allow_clients ipv6"; fail=1; }
v_allow_clients "" && echo "ok   v_allow_clients empty = any source" || { echo "FAIL v_allow_clients empty = any source"; fail=1; }
expect_fail v_allow_clients "example.com"
expect_fail v_allow_clients "10.0.0.0/33"
v_allow_clients "::ffff:203.0.113.0/120" && echo "ok   v_allow_clients mapped CIDR" || { echo "FAIL v_allow_clients mapped CIDR"; fail=1; }
expect_fail v_allow_clients "::ffff:203.0.113.0/64" # M3: the engine refuses mapped prefixes shorter than /96
# M4: the shipped unit can only read /etc/wattun; in the sandbox the allowed dir is $CONF. The file must be there.
ALLOWF=$WAT_CONF/allowlist.txt
printf '203.0.113.5\n10.0.0.0/8\n' >"$ALLOWF"
v_allow_clients_file "$ALLOWF" && echo "ok   v_allow_clients_file entries" || { echo "FAIL v_allow_clients_file entries"; fail=1; }
printf '203.0.113.5, bogus\n' >"$ALLOWF"
expect_fail v_allow_clients_file "$ALLOWF"
: >"$ALLOWF"
expect_fail v_allow_clients_file "$ALLOWF" # the engine refuses an empty file, so a typo cannot allow every source
rm -f "$ALLOWF"
expect_fail v_allow_clients_file "$SMOKE/outside-allowlist.txt" # outside the unit's readable dir
expect_fail v_allow_clients_file /tmp/allowlist.txt
expect_fail v_allow_clients_file relative.txt
expect_fail v_allow_clients_file /nonexistent-wattun-allowlist.txt
v_allow_clients_file - && echo "ok   v_allow_clients_file - = none" || { echo "FAIL v_allow_clients_file - = none"; fail=1; }
# M4: the engine refuses the allowlist on a CDN carrier (source would be the CDN edge); the manager must refuse it too
allow_clients_cdn_risk tcp '' && echo "FAIL direct carrier flagged as CDN" || { echo "ok   allowlist allowed on a direct carrier"; }
allow_clients_cdn_risk wss '' && echo "ok   allowlist refused on wss" || { echo "FAIL wss not flagged"; fail=1; }
allow_clients_cdn_risk 'tcp+wss' '' && echo "ok   allowlist refused on a bond with a CDN leg" || { echo "FAIL CDN bond not flagged"; fail=1; }
allow_clients_cdn_risk tcp 'cdn.example.com' && echo "ok   allowlist refused when sni is set" || { echo "FAIL sni not flagged"; fail=1; }

# F20 discovery: the "Spoofing & shaping" page has to render the docs' classification and be reachable from the
# anti-censor menu and from the tunnel deck's "?" key map. Plain functions, no network, no engine.
help_out=$(spoofhelp_page t1)
chk "spoof help: fake-sni is the only spoof" "$(grep -c 'Only fake-sni does this' <<<"$help_out")" "1"
chk "spoof help: names the shape options" "$(grep -c 'tcp-mimic, hdr-mask, shape, tls-frag, ech, udp-dns, pool-rotate' <<<"$help_out")" "1"
chk "spoof help: lists shape-data and noise" "$(grep -c 'shape-data (pad stream packets to random sizes) and noise (idle filler packets)' <<<"$help_out")" "1"
chk "spoof help: says both spend bandwidth" "$(grep -c 'Both are opt-in and spend bandwidth' <<<"$help_out")" "1"
chk "spoof help: tunnel-level spoofing is not shipped" "$(grep -c 'Tunnel-level spoofing is NOT shipped' <<<"$help_out")" "1"
chk "spoof help: points at the docs section" "$(grep -c 'Spoofing and shaping, explained' <<<"$help_out")" "1"
chk "spoof help: extended auto opt-in is explained (B5)" "$(grep -c 'Auto mode can also test the 13 F19 shaped carriers' <<<"$help_out")" "1"
_usage=$(usage 2>&1)
chk "usage: documents --extended (B5)" "$([ "$(grep -c -- '--extended' <<<"$_usage")" -ge 1 ] && echo y)" "y"
chk "usage: says normal Auto includes gre/ipip (B5)" "$(grep -c 'gre/ipip, which need 3.2.0 on both ends' <<<"$_usage")" "1"
chk "usage: says old Iran leaves extended ports open (B5)" "$(grep -c 'stay open until auto-prune NAME --direct' <<<"$_usage")" "1"
ni_parse --extended; chk "unattended --extended sets NI_EXTENDED (B5)" "$NI_EXTENDED" "1"; NI_EXTENDED=0
ac_help=$( NONINTERACTIVE=0; printf 'hb' | anticensor_menu t1 ) # h opens the page, b leaves it
chk "spoof help: opens from the anti-censor menu" "$(grep -c 'Tunnel-level spoofing is NOT shipped' <<<"$ac_help")" "1"
TM_SELKEY=''
tunnel_menu_build t1 Iran active enabled wss 1 0 0 0
keys_out=$(tunnel_menu_keys t1)
chk "spoof help: listed in the deck key map" "$(grep -c 'Spoofing & shaping' <<<"$keys_out")" "1"

# Advanced page wiring: the new rows exist where the engine accepts them (FEC band only with fec: auto; admission
# allowlist only on the server), and the page still renders with the engine defaults when no keys are set.
cat >"$WAT_CONF/t_adv.yml" <<'EOF'
mode: server
carrier: tcp
EOF
role() { echo Kharej; }
adv_out=$( NONINTERACTIVE=1; adv_menu t_adv )
# A1: the page is grouped, in a fixed order, and every grouped row is still on its original key
chk "advanced groups: four headings in order (A1)" "$(grep -oE 'Performance|Shaping & DPI|Safety|State & data' <<<"$adv_out" | paste -sd'|' -)" "Performance|Shaping & DPI|Safety|State & data"
chk "advanced groups: Performance rows keep their keys (A1)" "$(grep -c '\[m\].*speed limit\|\[c\].*conns\|\[u\].*mtu' <<<"$adv_out")" "3"
chk "advanced groups: Shaping rows keep their keys (A1)" "$(grep -c '\[f\].*fec\|\[p\].*shape data\|\[n\].*noise' <<<"$adv_out")" "3"
chk "advanced groups: Safety rows keep their keys (A1)" "$(grep -c '\[j\].*allow clients\|\[l\].*allow clients file' <<<"$adv_out")" "2"
chk "advanced help: file-only expert keys are named (A5)" "$(grep -ci 'file-only expert keys' <<<"$adv_out")" "1"
chk "advanced rows: shape-data" "$(grep -c 'shape data' <<<"$adv_out")" "1"
chk "advanced rows: win-max row (A3)" "$(grep -c '\[e\].*win max' <<<"$adv_out")" "1"
chk "advanced rows: loss-ceiling row (A3)" "$(grep -c '\[r\].*loss ceiling' <<<"$adv_out")" "1"
_adv_v2=$( NONINTERACTIVE=1; bin_ver_ok() { return 0; }; adv_menu t_adv ) # a 2.x engine: neither knob exists
chk "advanced rows: win-max hidden on an old engine (A3)" "$(grep -c 'win max' <<<"$_adv_v2")" "0"
chk "advanced rows: loss-ceiling hidden on an old engine (A3)" "$(grep -c 'loss ceiling' <<<"$_adv_v2")" "0"
_adv_v303=$( NONINTERACTIVE=1; bin_ver_ok() { [ "$1" = 3.0.3 ] && return 0; echo 1; }; adv_menu t_adv ) # 3.0.2: loss-ceiling yes, win-max no
chk "advanced rows: loss-ceiling exists before win-max (A3)" "$(grep -c 'loss ceiling' <<<"$_adv_v303")" "1"
chk "advanced rows: win-max hidden before 3.0.3 (A3)" "$(grep -c 'win max' <<<"$_adv_v303")" "0"
chk "advanced rows: noise" "$(grep -c 'noise' <<<"$adv_out")" "1"
chk "advanced rows: allow clients (list + file)" "$(grep -c 'allow clients' <<<"$adv_out")" "2"
chk "advanced rows: FEC band hidden while fec off" "$(grep -c 'fec on loss' <<<"$adv_out")" "0"
printf 'fec: auto\n' >>"$WAT_CONF/t_adv.yml"
adv_out=$( NONINTERACTIVE=1; adv_menu t_adv )
chk "advanced rows: FEC on-loss with fec auto" "$(grep -c 'fec on loss' <<<"$adv_out")" "1"
chk "advanced rows: FEC off-loss with fec auto" "$(grep -c 'fec off loss' <<<"$adv_out")" "1"
role() { echo Iran; }
adv_out=$( NONINTERACTIVE=1; adv_menu t_adv )
chk "advanced rows: admission allowlist hidden on Iran" "$(grep -c 'allow clients' <<<"$adv_out")" "0"
rm -f "$WAT_CONF/t_adv.yml"
# A5: coverage test — every engine flag (cmd/wattun/main.go) must have a manager path: a cfg/set_row/set_value/
# unset_value/ask_ok use site (or an explicit file-only/ports-UI exclusion). Synthetic per-carrier flags are excluded
# by prefix. A fake name passed as an argument must be reported, proving the test can fail.
cfg_flag_names() { # every engine flag, whatever the flag.<Kind>() registration shape
  grep -oE 'flag\.(String|Int|Bool|Float64|Duration|Func|BoolFunc)\("[^"]+"' cmd/wattun/main.go | sed -E 's/.*\("//; s/"$//'
  grep -oE 'flag\.Var\([^,]+, *"[^"]+"' cmd/wattun/main.go | sed -E 's/.*, *"//; s/"$//'
}
cfg_sites() { grep -E '(^|[^[:alnum:]_-])(cfg|set_row|set_value|unset_value|ask_ok)[[:space:]]' wattun-manager; }
cfg_flag_used() { # flag -> 0 when a real use site names it; a comment, a hint or the file-only list alone does not count
  local sites
  sites=$(cfg_sites) || return 1
  grep -qE "(^|[^[:alnum:]_-])$1([^[:alnum:]_-]|$)" <<<"$sites" # capture first: a pipe into grep -q trips pipefail on a large file
}
cfg_coverage_missing() { # [extra names...] -> engine flags with no manager path, space separated (empty = complete)
  local f miss=''
  for f in $(cfg_flag_names) "$@"; do
    case "$f" in
      config|mode|key|key-file|map|udp|ports|listen|peer|host|path|sni|metrics|version) continue ;;
      listen-*|peer-*|src-ip-*) continue ;;
    esac
    case " $CFG_FILE_ONLY $CFG_PORTS_UI " in *" $f "*) continue ;; esac
    cfg_flag_used "$f" || miss+="$f "
  done
  printf '%s' "${miss% }"
}
chk "config coverage: the parser sees the engine flags (A5)" "$(cfg_flag_names | grep -c '^shape-data$')" "1"
chk "config coverage: a flag.Func key is seen too (M2)" "$(cfg_flag_names | grep -c '^header$')" "1"
chk "config coverage: every engine flag has a manager or a declared file-only path (A5)" "$(cfg_coverage_missing)" ""
chk "config coverage: a fake flag is caught (A5)" "$(cfg_coverage_missing made-up-flag)" "made-up-flag"
chk "config coverage: a real use site counts (M2)" "$(cfg_flag_used shape-data && echo y)" "y"
chk "config coverage: a hint/comment mention alone is not a use site (M2)" "$(cfg_flag_used tls-pin && echo y || echo n)" "n"
chk "config coverage: a hint/comment mention alone is not a use site either (M2)" "$(cfg_flag_used header && echo y || echo n)" "n"
chk "config coverage: -header stays covered via the file-only list (M2)" "$(case " $CFG_FILE_ONLY " in *" header "*) echo y ;; *) echo n ;; esac)" "y"
chk "config coverage: file-only expert keys are declared (A5)" "$(grep -c '^CFG_FILE_ONLY=' wattun-manager)" "1"
chk "config coverage: the file-only list names the documented keys (A5)" "$(grep -o 'debug ping-every udp-idle tcp-cc slack-ms hedge lanes mem-budget plain port-offset tls-cert tls-key header' <<<"$CFG_FILE_ONLY" | wc -l | tr -d ' ')" "1"
chk "config coverage: the ports UI covers the allowlist flags (A5)" "$(grep -c 'allow-min allow-max allow-ports allow-file' <<<"$CFG_PORTS_UI")" "1"


# Bond auto-retest (F10): the setting is visible only on a bonded Iran client, defaults to off (a sidecar value, never
# a YAML key: the engine rejects unknown keys), and every value maps to a real systemd schedule. The decision helpers
# are pure; the timer itself needs root/systemd, so only the schedule text and the safety rules are pinned here.
chk "bond: a '+' carrier list is a bond" "$(bond_is_bond 'tcp+tls' && echo y || echo n)" "y"
chk "bond: one carrier is not a bond" "$(bond_is_bond tcp && echo y || echo n)" "n"
chk "bond-retest: shown on a bonded Iran tunnel" "$(bond_retest_visible Iran 'tcp+tls' && echo y || echo n)" "y"
chk "bond-retest: hidden on Kharej" "$(bond_retest_visible Kharej 'tcp+tls' && echo y || echo n)" "n"
chk "bond-retest: hidden on a single carrier" "$(bond_retest_visible Iran tcp && echo y || echo n)" "n"
chk "bond-retest: default is off" "$(bondretest_get t_absent)" "off"
for v in off 30m 1h 6h daily-offpeak; do
  bondretest_ok "$v" >/dev/null && echo "ok   bondretest_ok $v" || { echo "FAIL bondretest_ok $v"; fail=1; }
done
chk "bond-retest: normalizes Daily-Offpeak" "$(bondretest_ok 'Daily-Offpeak')" "daily-offpeak"
expect_fail bondretest_ok 15m
printf 'daily-offpeak\n' >"$WAT_CONF/t_br.bondretest"
chk "bond-retest: reads the sidecar" "$(bondretest_get t_br)" "daily-offpeak"
printf 'junk\n' >"$WAT_CONF/t_br.bondretest"
chk "bond-retest: a bad sidecar falls back to off" "$(bondretest_get t_br)" "off"
rm -f "$WAT_CONF/t_br.bondretest"
chk "bond-retest timer: 30m" "$(bondretest_timer_lines 30m)" $'OnBootSec=5min\nOnUnitActiveSec=30min\nRandomizedDelaySec=60\nPersistent=true'
chk "bond-retest timer: 1h" "$(bondretest_timer_lines 1h)" $'OnBootSec=5min\nOnUnitActiveSec=1h\nRandomizedDelaySec=60\nPersistent=true'
chk "bond-retest timer: 6h" "$(bondretest_timer_lines 6h)" $'OnBootSec=5min\nOnUnitActiveSec=6h\nRandomizedDelaySec=60\nPersistent=true'
chk "bond-retest timer: daily off-peak" "$(bondretest_timer_lines daily-offpeak)" $'OnCalendar=*-*-* 04:15:00\nRandomizedDelaySec=300\nPersistent=true'
chk "bond-retest unit name" "$(bondretest_unit kb)" "${WAT_PREFIX}-bondretest-kb"
chk "bond candidates: a plan carrier the bond lacks gets its plan port" \
  "$(bond_candidates_plan 'tcp+udp' 'udp:4443,tcp:4443,tls:8443' '203.0.113.10')" \
  $'icmp 203.0.113.10\ntls 203.0.113.10:8443'
chk "bond candidates: a carrier already in the bond is skipped" \
  "$(bond_candidates_plan 'icmp+udp+tcp' 'udp:4443,tcp:4443' '203.0.113.10')" ""
chk "bondfail_next: keeps an old failure the budget did not reach" "$(bondfail_next 'tls,wss' 'tcp+udp' 'tcp udp tls' 'tls')" "tls,wss"
chk "bondfail_next: drops a recovered one" "$(bondfail_next 'tls,wss' 'tcp+udp' 'tcp udp tls wss' '')" ""
chk "bondfail_next: records a new failure" "$(bondfail_next '' 'tcp+udp' 'tcp udp ws' 'ws')" "ws"
chk "bondfail_next: never lists a leg the bond already has" "$(bondfail_next 'tls' 'tcp+tls' 'tcp tls' 'tls')" ""
chk "bond_worth: no working leg, any working carrier counts" "$(bond_worth 3 0 && echo y || echo n)" "y"
chk "bond_worth: 10% of the best leg is enough" "$(bond_worth 10 100 && echo y || echo n)" "y"
chk "bond_worth: slower than 10% is not added" "$(bond_worth 9 100 && echo y || echo n)" "n"
chk "bond_worth: a dead candidate is never added" "$(bond_worth 0 0 && echo y || echo n)" "n"
chk "bond_budget_fit: 20 MB fits ten 2 MB probes" "$(bond_budget_fit 12 20)" "10"
chk "bond_budget_fit: a 1 MB budget still probes one" "$(bond_budget_fit 5 1)" "1"

# Auto mode (R1): the variant lists and the tuning table are data (AUTO_VAR_*, AUTO_TUNE_*), so this suite can prove a
# carrier is picked up from the list instead of a hard-coded loop, and that the tuning knobs respect the engine limits
# (sessions ≤ 16 and never on a bond/reverse, conns ≤ 64, mtu per carrier, win-max 16/32/64) and the installed version.
FULL_PLAN='d=udp:4443,tcp:4443,tls:8443,ws:2052,wss:2053,h2:2087,h2c:2082,grpc:2083;r=tcp:24431,tls:24432,ws:24433,wss:24434,h2:24435,h2c:24436,grpc:24437'
_T_AUTO=$T_AUTO; _T_PEER=$T_PEER; _T_PATH=$T_PATH; _T_SNI=$T_SNI; _AT_PRESET=$AT_PRESET
T_AUTO=$FULL_PLAN; T_PEER='203.0.113.10'; T_PATH='/wat'; T_SNI=''; AT_PRESET=normal
auto_variants
chk "auto variants: the full plan has 17 rows" "${#AV_LABEL[@]}" "17"
chk "auto variants: icmp is the first row" "${AV_CAR[0]}" "icmp"
# B1: the token plan, not AUTO_VAR_DIRECT, is the source of the direct variant order (a carrier the plan omits is not
# tested, and a bare entry is a port-less raw carrier)
missing=''
for c in ${FULL_PLAN#*d=}; do
  c=${c%%;*}; [ "$c" = icmp ] && continue
  n=0; for ((i=0; i<${#AV_LABEL[@]}; i++)); do [ "${AV_KIND[$i]}" = d ] && [ "${AV_CAR[$i]}" = "${c%%:*}" ] && n=$((n+1)); done
  [ "$n" = 1 ] || missing+="${c%%:*} "
done
chk "auto variants: every planned direct carrier is tested once (B1)" "$missing" ""
chk "auto variants: a carrier absent from the plan is not tested (B1)" "$(AUTO_VAR_DIRECT='icmp gre'; auto_variants >/dev/null; echo "${#AV_LABEL[@]}")" "17"
GRE_PLAN='d=udp:4443,gre,ipip;r=icmp'
T_AUTO=$GRE_PLAN; auto_variants
chk "auto variants: bare plan entries become variants (B1)" "${#AV_LABEL[@]}" "5"
chk "auto variants: bare raw entry uses the bare peer (B1)" "${AV_PEER[2]}/${AV_PEER[3]}" "203.0.113.10/203.0.113.10"
chk "auto variants: the labeled carriers are gre and ipip (B1)" "${AV_CAR[2]}+${AV_CAR[3]}" "gre+ipip"
chk "plan: a bare entry has no port (B1)" "$(plan_port 'udp:4443,gre' gre)" ""
chk "plan: a surrounding port entry still resolves (B1)" "$(plan_port 'udp:4443,gre' udp)" "4443"
chk "plan: plan_has sees a bare entry (B1)" "$(plan_has 'udp:4443,gre' gre && echo y)" "y"
chk "plan: plan_has misses an absent carrier (B1)" "$(plan_has 'udp:4443,gre' ipip && echo y)" ""
T_AUTO=$FULL_PLAN; auto_variants
chk "auto variants: restored after the bare-entry test (B1)" "${#AV_LABEL[@]}" "17"
# B1: the token plan is the source, so changing the old data list must NOT change the test any more
AUTO_VAR_DIRECT='icmp tcp'
auto_variants
chk "auto variants: the old data list no longer prunes the plan (B1)" "${#AV_LABEL[@]}" "17"
AUTO_VAR_DIRECT='icmp udp tcp tls wss h2 grpc ws h2c gre ipip'
T_AUTO='d=tcp:4443;r=icmp'; auto_variants
chk "auto variants: a shortened direct plan is honoured (B1)" "${#AV_LABEL[@]}" "3"
T_AUTO='d=udp:4443,tcp:4443;r=tcp:24431'; auto_variants
chk "auto variants: a shortened reverse plan is honoured (B1)" "${#AV_LABEL[@]}" "5"
T_AUTO=$FULL_PLAN; auto_variants
chk "auto variants: restored with the full plan (B1)" "${#AV_LABEL[@]}" "17"
T_AUTO=$_T_AUTO; T_PEER=$_T_PEER; T_PATH=$_T_PATH; T_SNI=$_T_SNI; AT_PRESET=$_AT_PRESET
chk "auto reverse plan: one port per AUTO_VAR_REVERSE carrier" "$AUTO_RPLAN" "tcp:24431,tls:24432,ws:24433,wss:24434,h2:24435,h2c:24436,grpc:24437"
_AVR=$AUTO_VAR_REVERSE; AUTO_VAR_REVERSE='icmp tcp udp'
chk "auto reverse plan: follows the data list" "$(auto_rplan_build)" "tcp:24431,udp:24432"
AUTO_VAR_REVERSE=$_AVR
chk "auto reverse plan: restored with the data list" "$(auto_rplan_build)" "$AUTO_RPLAN"
_lb_def=$(declare -f listen_blocked) # the Kharej listen set is built from the same AUTO_VAR_DIRECT data
listen_blocked() { return 1; }
auto_pick_ports
eval "$_lb_def"
missing=''
for c in $AUTO_VAR_DIRECT; do
  [ "$c" = icmp ] && continue
  carrier_has_listen "$c" || continue # B1: raw carriers have no listen port by design
  [ -n "$(plan_port "$AUTO_D" "$c")" ] || missing+="$c "
done
chk "auto Kharej: listens on every portable AUTO_VAR_DIRECT carrier" "$missing" ""
chk "auto Kharej: icmp has no listen port" "$(plan_port "$AUTO_D" icmp)" ""
chk "auto Kharej: gre/ipip are bare plan entries (B1)" "$(plan_has "$AUTO_D" gre && plan_has "$AUTO_D" ipip && [ -z "$(plan_port "$AUTO_D" gre)$(plan_port "$AUTO_D" ipip)" ] && echo y)" "y"
chk "auto Kharej: the plan ends with the raw entries (B1)" "${AUTO_D##*,}" "ipip"
# B2: carrier version gates on both ends (gre/ipip 3.2.0, the 13 shapes 3.3.0, everything else the Auto minimum)
chk "carrier version: icmp needs the Auto minimum (B2)" "$(carrier_min_ver icmp)" "2.1.0"
chk "carrier version: gre needs 3.2.0 (B2)" "$(carrier_min_ver gre)/$(carrier_min_ver ipip)" "3.2.0/3.2.0"
chk "carrier version: a shaped carrier needs 3.3.0 (B2)" "$(carrier_min_ver vxlan)/$(carrier_min_ver sit)" "3.3.0/3.3.0"
_bvd=$(declare -f bin_ver); _bvokd=$(declare -f bin_ver_ok); _verd=$VER; VER=3.1.0
bin_ver() { echo "$VER"; }
bin_ver_ok() { ver_ge "$(bin_ver)" "$1" && echo 1; } # the real gate, not this harness's always-yes stub
chk "carrier gate: gre is unsupported on 3.1 (B2)" "$(carrier_ok_here gre && echo y || echo n)" "n"
chk "carrier gate: icmp is always supported (B2)" "$(carrier_ok_here icmp && echo y || echo n)" "y"
T_AUTO='d=udp:4443,gre;r=icmp'; T_PEER='203.0.113.10'; auto_variants
chk "Iran gate: a gre variant is skipped on 3.1 (B2)" "${AT_SKIPPED}/${#AV_LABEL[@]}" "gre/3"
chk "Iran gate: the skip hint is one clear sentence (B2)" "$(at_skipped_hint)" "Token includes gre; this server runs 3.1.0 and cannot test them (both ends need newer wattun for these transports)."
VER=3.2.0; T_AUTO='d=gre;r=icmp'; auto_variants
chk "Iran gate: gre works on 3.2 (B2)" "${AT_SKIPPED}/${#AV_LABEL[@]}" "/3"
T_AUTO='d=vxlan:4789;r=icmp'; auto_variants
chk "Iran gate: a shaped variant is skipped on 3.2 (B2)" "${AT_SKIPPED}/${#AV_LABEL[@]}" "vxlan/2"
VER=3.3.0; T_AUTO='d=vxlan:4789,sit;r=icmp'; auto_variants
chk "Iran gate: shaped variants work on 3.3 (B2)" "${AT_SKIPPED}/${#AV_LABEL[@]}" "/4"
VER=3.1.0; listen_blocked() { return 1; }; auto_pick_ports
chk "Kharej gate: gre/ipip are left out of the plan on 3.1 (B2)" "$(plan_has "$AUTO_D" gre && echo y || echo n)/$AUTO_SKIP" "n/gre, ipip"
VER=3.2.0; auto_pick_ports
chk "Kharej gate: gre/ipip enter the plan on 3.2 (B2)" "$(plan_has "$AUTO_D" gre && plan_has "$AUTO_D" ipip && echo y)" "y"
VER=3.2.1; T_CARRIER=vxlan; printf 'mode: client\ncarrier: tcp\npeer: 203.0.113.10:4443\n' >"$WAT_CONF/t_v2.yml"
expect_fail auto_apply t_v2
chk "apply gate: an unsupported carrier is never written (B2)" "$(cfg t_v2 carrier)" "tcp"
rm -f "$WAT_CONF/t_v2.yml"; T_CARRIER=''
eval "$_bvokd"; eval "$_bvd"; VER=$_verd
T_AUTO=''; AT_SKIPPED=''
# B4: shaped variants — peer forms, no anti/CDN extras, bond exclusion, auto_apply config+token
VER=3.3.0
bin_ver() { echo "$VER"; }
bin_ver_ok() { ver_ge "$(bin_ver)" "$1" && echo 1; }
T_AUTO='d=vxlan:4789,sit,gre;r=icmp'; T_PEER='203.0.113.10'; AT_PRESET=normal; auto_variants
chk "shaped variants: UDP shape peer carries the plan port (B4)" "${AV_PEER[1]}" "203.0.113.10:4789"
chk "shaped variants: raw shape peer is bare (B4)" "${AV_PEER[2]}" "203.0.113.10"
chk "shaped variants: gre peer is bare (B4)" "${AV_PEER[3]}" "203.0.113.10"
chk "shaped variants: labels warn they are shapes (B4)" "$(grep -o 'shape only' <<<"${AV_LABEL[1]} ${AV_LABEL[2]}" | wc -l | tr -d ' ')" "2"
chk "shaped variants: no anti/CDN variants are generated (B4)" "${#AV_LABEL[@]}" "5"
# bond picker: a shaped row must never be joined (the engine refuses shaped-in-bond)
AV_LABEL=(vxlan tcp sit); AV_CAR=(vxlan tcp sit); AV_KIND=(d d d); AV_PEER=('203.0.113.10:4789' '203.0.113.10:4443' '203.0.113.10')
AT_RANK=(1 0 2); AR_DOWN=(10 20 30); AR_UP=(1 2 3); NI_PICK=bond
at_choose >/dev/null 2>&1
chk "bond picker: excludes shaped rows (B4)" "$(IFS=,; echo "${AV_CAR[${AT_SEL[0]}]}")/$((${#AT_SEL[@]}))" "tcp/1"
AT_RANK=(0 1); AV_LABEL=(vxlan tcp); AV_CAR=(vxlan tcp); AV_KIND=(d d); AV_PEER=('203.0.113.10:4789' '203.0.113.10:4443')
expect_fail at_rows '1 2'
NI_PICK=best; AT_RANK=()
# auto_apply: a chosen UDP shape writes a valid single-carrier client config and a token naming the shape
cat >"$WAT_CONF/t_b4.yml" <<'EOF'
mode: client
carrier: tcp
peer: 203.0.113.10:4443
key-file: /etc/wattun/t_b4.key
EOF
_T_CARRIER=$T_CARRIER; _T_PEER=$T_PEER; _T_KEY=${T_KEY:-}; _T_PATH=$T_PATH; _T_SNI=$T_SNI; _T_ICMP=$T_ICMP; _T_PORTS=$T_PORTS; _T_REV=$T_REV; _AT_EXTRA=$AT_EXTRA; _AT_TUNE_KEYS=$AT_TUNE_KEYS; _AT_QUIET=$AT_QUIET; _AT_SEL_KEY=$AT_SEL_KEY
T_CARRIER=vxlan; T_PEER='203.0.113.10:4789'; T_KEY='testkey'; T_PATH=''; T_SNI=''; T_ICMP=''; T_PORTS=''; T_REV=''; AT_EXTRA=''; AT_TUNE_KEYS=''; AT_QUIET=1; AT_SEL_KEY='vxlan/d'
auto_apply t_b4 >/dev/null 2>&1
chk "auto_apply: UDP shape carrier (B4)" "$(cfg t_b4 carrier)" "vxlan"
chk "auto_apply: UDP shape peer keeps the port (B4)" "$(cfg t_b4 peer)" "203.0.113.10:4789"
chk "auto_apply: no listen on the client (B4)" "$(cfg t_b4 listen)" ""
chk "auto_apply: token names the chosen shape (B4)" "$(sed 's/^wat1://' "$WAT_CONF/t_b4.token" | base64 -d | cut -d'|' -f1,2)" "vxlan|203.0.113.10:4789"
chk "auto_apply: no sessions/reverse keys written (B4)" "$(grep -cE '^(sessions|reverse):' "$WAT_CONF/t_b4.yml")" "0"
T_CARRIER=sit; T_PEER='203.0.113.10'; AT_SEL_KEY='sit/d'; AT_TUNE_KEYS=''
printf 'mode: client\ncarrier: tcp\npeer: 203.0.113.10:4443\nkey-file: /etc/wattun/t_b4.key\n' >"$WAT_CONF/t_b4.yml"
auto_apply t_b4 >/dev/null 2>&1
chk "auto_apply: raw shape peer stays bare (B4)" "$(cfg t_b4 peer)" "203.0.113.10"
chk "auto_apply: raw shape writes no listen (B4)" "$(cfg t_b4 listen)" ""
chk "auto_apply: raw shape token names it (B4)" "$(sed 's/^wat1://' "$WAT_CONF/t_b4.token" | base64 -d | cut -d'|' -f1)" "sit"
T_CARRIER=$_T_CARRIER; T_PEER=$_T_PEER; T_KEY=$_T_KEY; T_PATH=$_T_PATH; T_SNI=$_T_SNI; T_ICMP=$_T_ICMP; T_PORTS=$_T_PORTS; T_REV=$_T_REV
AT_EXTRA=$_AT_EXTRA; AT_TUNE_KEYS=$_AT_TUNE_KEYS; AT_QUIET=$_AT_QUIET; AT_SEL_KEY=$_AT_SEL_KEY
rm -f "$WAT_CONF/t_b4.yml" "$WAT_CONF/t_b4.token" "$WAT_CONF/t_b4.key"
eval "$_bvokd"; eval "$_bvd"; VER=$_verd
AV_LABEL=(); AV_CAR=(); AV_KIND=()
# A6: the Iran auto screen splits the token plan standard/extended and never counts skipped carriers in the budget
chk "auto plan display: standard carriers keep plan order (A6)" "$(auto_plan_standard 'udp:4443,vxlan:4789,sit,gre')" "udp gre"
chk "auto plan display: extended carriers are listed (A6)" "$(auto_plan_extnames 'udp:4443,vxlan:4789,sit,gre')" "vxlan sit"
chk "auto plan display: a normal plan has no extended line (A6)" "$(auto_plan_intro 'udp:4443,tcp:4443')" $'standard carriers: udp tcp'
chk "auto plan display: an extended plan is labelled (A6)" "$(auto_plan_intro 'udp:4443,vxlan:4789,sit')" $'standard carriers: udp\nextended carriers: vxlan sit (both ends must run 3.3.0; shaped transports, not the real protocols)'
_bvd6=$(declare -f bin_ver); _bvokd6=$(declare -f bin_ver_ok); _verd6=$VER
bin_ver() { echo "$VER"; }; bin_ver_ok() { ver_ge "$(bin_ver)" "$1" && echo 1; }
VER=3.2.1; T_AUTO='d=udp:4443,vxlan:4789;r=icmp'; T_PEER='203.0.113.10'; AT_PRESET=normal; auto_variants
_n32=${#AV_LABEL[@]}; _p32=$(at_budget "$_n32" "$AT_SCREEN_CAP_MB" "$AT_FINAL_MB_MAX" "$AT_TUNE_PROBES_MAX" "$AT_TUNE_PROBE_MB")
VER=3.3.0; auto_variants
_n33=${#AV_LABEL[@]}; _p33=$(at_budget "$_n33" "$AT_SCREEN_CAP_MB" "$AT_FINAL_MB_MAX" "$AT_TUNE_PROBES_MAX" "$AT_TUNE_PROBE_MB")
chk "auto budget: a skipped carrier is not counted (A6)" "$([ "$_n32" -lt "$_n33" ] && echo y)/$([ "$_p32" != "$_p33" ] && echo y)" "y/y"
chk "auto screen: the skip hint names the carrier (A6)" "$(AT_SKIPPED=vxlan at_skipped_hint | grep -c vxlan)" "1"
chk "auto screen: the test screen prints the plan split (A6)" "$(grep -c 'auto_plan_intro "$(plan_part "$T_AUTO" d)"' wattun-manager)" "1"
eval "$_bvokd6"; eval "$_bvd6"; VER=$_verd6
T_AUTO=''; AT_SKIPPED=''; AV_LABEL=(); AV_CAR=(); AV_KIND=()
# B3: extended Auto = one hidden single-carrier server unit per shaped carrier (the engine refuses shaped-in-bond)
_bt_sctl=$(declare -f systemctl); _bt_fmp=$(declare -f free_metrics_port); _bt_lb=$(declare -f listen_blocked)
_bt_bv=$(declare -f bin_ver); _bt_bvok=$(declare -f bin_ver_ok); _bt_ver=$VER; _bt_su=$(declare -f start_unit)
systemctl() { printf '%s\n' "$*" >>"$SMOKE/sys.log"; return 0; }
systemd-run() { :; }
start_unit() { :; } # the wizard's unit start needs /etc/systemd; the config/token/unit files are what this checks
listen_blocked() { return 1; }
free_metrics_port() { echo $(( 26000 + $(ls "$WAT_CONF"/*.yml 2>/dev/null | wc -l) )) ; }
VER=3.3.0; bin_ver() { echo "$VER"; }; bin_ver_ok() { ver_ge "$(bin_ver)" "$1" && echo 1; }
: >"$SMOKE/sys.log"
( NONINTERACTIVE=1 NI_CARRIER=auto NI_NAME=t_ext NI_ADDR=203.0.113.5 NI_EXTENDED=1 wizard_kharej ) >"$SMOKE/ext.out" 2>&1
chk "extended auto: parent config created (B3)" "$([ -f "$WAT_CONF/t_ext.yml" ] && echo y)" "y"
chk "extended auto: parent keeps standard carriers + gre/ipip (B3)" "$(grep -c '^carrier: icmp+udp+tcp+tls+wss+h2+grpc+ws+h2c+gre+ipip$' "$WAT_CONF/t_ext.yml")" "1"
chk "extended auto: parent has no shaped carrier (B3)" "$(grep -cE '^carrier:.*(vxlan|sit)' "$WAT_CONF/t_ext.yml")" "0"
chk "extended auto: 13 hidden configs (B3)" "$(ls "$WAT_CONF"/t_ext-e-*.yml 2>/dev/null | wc -l | tr -d ' ')" "13"
chk "extended auto: hidden config carries the shape (B3)" "$(grep -c '^carrier: vxlan$' "$WAT_CONF/t_ext-e-vxlan.yml")" "1"
chk "extended auto: UDP shape listens on its port (B3)" "$(grep -c '^listen: ":4789"$' "$WAT_CONF/t_ext-e-vxlan.yml")" "1"
chk "extended auto: raw shape writes no listen (B3)" "$(grep -c '^listen:' "$WAT_CONF/t_ext-e-sit.yml")" "0"
chk "extended auto: hidden configs share the parent key (B3)" "$(grep -c "^key-file: $WAT_CONF/t_ext.key$" "$WAT_CONF/t_ext-e-sit.yml")" "1"
chk "extended auto: hidden configs get unique metrics ports (B3)" "$(for f in "$WAT_CONF"/t_ext-e-*.yml; do sed -n 's/^metrics: 127.0.0.1://p' "$f"; done | sort -u | wc -l | tr -d ' ')" "13"
chk "extended auto: sidecar names the parent (B3)" "$(cat "$WAT_CONF/t_ext-e-vxlan.autoext")" "t_ext"
chk "extended auto: listeners were enabled and started (B3)" "$(grep -cE '(enable|restart) wattest@t_ext-e-vxlan' "$SMOKE/sys.log")" "2"
chk "extended auto: plan carries all 13 shapes + marker (B3)" "$(read_token "$(cat "$WAT_CONF/t_ext.token")"; printf '%s/%s' "$(printf '%s' "$T_AUTO" | grep -oE '(fou-gre|gue-ipip|vxlan|geneve|dnscrypt-udp|ntp-direct|openvpn-dco|srtp-direct|sit|6to4|xfrm-ipsec|etherip|l2tpv3)' | sort -u | wc -l | tr -d ' ')" "$(case "$T_AUTO" in *';e=1'*) echo y ;; *) echo n ;; esac)")" "13/y"
chk "extended auto: plan keeps the standard direct part (B3)" "$(read_token "$(cat "$WAT_CONF/t_ext.token")"; plan_part "$T_AUTO" d | grep -c '^udp:4443,tcp:4443')" "1"
chk "extended auto: hidden from the tunnel list (B3)" "$(tunnels | grep -c '^t_ext-e-')" "0"
chk "extended auto: tunnels_all sees the listeners (B3)" "$(tunnels_all | grep -c '^t_ext-e-')" "13"
chk "extended auto: the hint warns old Iran leaves the ports open (B3)" "$(grep -c 'auto-prune t_ext --direct' "$SMOKE/ext.out")" "2"
# lifecycle: a down enabled listener is restarted by heal's helper
systemctl() { case "$*" in
  "is-enabled -q wattest@t_ext-e-sit") return 0 ;;
  "is-active -q wattest@t_ext-e-sit") return 1 ;;
  *"restart wattest@t_ext-e-sit"*) printf '%s\n' "$*" >>"$SMOKE/sys.log"; return 0 ;; esac; return 1; }
: >"$SMOKE/sys.log"
heal_ext_listeners >/dev/null 2>&1
chk "extended heal: restarts a down listener (B3)" "$(grep -c 'restart wattest@t_ext-e-sit' "$SMOKE/sys.log")" "1"
# prune keeps the shape Iran picked and stops the rest. Each shaped listener is its own single-carrier server, so the
# pick is only visible in that child's /stats — never in the parent's (H1). Fixture: a live client on vxlan, none on sit.
systemctl() { printf '%s\n' "$*" >>"$SMOKE/sys.log"; return 0; }
_bt_stats=$(declare -f stats)
stats() { case "$1" in
  t_ext-e-vxlan) echo '{"alive": true, "clients": [{"ip": "203.0.113.9", "carrier": "vxlan"}]}' ;;
  *) echo '{"alive": true, "clients": []}' ;;
esac; }
: >"$SMOKE/sys.log"
auto_ext_prune t_ext >/dev/null 2>&1
chk "extended prune: keeps the shape Iran uses (B3)" "$(grep -c 'stop wattest@t_ext-e-vxlan' "$SMOKE/sys.log")" "0"
chk "extended prune: stops an unused shape (B3)" "$(grep -c 'stop wattest@t_ext-e-sit' "$SMOKE/sys.log")" "1"
# H1 guards: a running child whose /stats cannot be read is unknown (not unused), and no client at all is not a pick
stats() { case "$1" in t_ext-e-sit) return 3 ;; *) echo '{"alive": true, "clients": [{"ip": "203.0.113.9"}]}' ;; esac; }
chk "extended live: an unreadable child is unknown (H1)" "$(auto_ext_live t_ext; echo "$?")" "1"
: >"$SMOKE/sys.log"; auto_ext_prune t_ext >/dev/null 2>&1
chk "extended prune: an unknown pick keeps every shape (H1)" "$(grep -c 'stop ' "$SMOKE/sys.log")" "0"
stats() { echo '{"alive": true, "clients": []}'; }
chk "extended live: no live client is not a pick (H1)" "$(auto_ext_live t_ext; printf '%s/%s' "$?" "$AE_LIVE")" "0/"
: >"$SMOKE/sys.log"; auto_ext_prune t_ext >/dev/null 2>&1
chk "extended prune: no live client keeps every shape (H1)" "$(grep -c 'stop ' "$SMOKE/sys.log")" "0"
eval "$_bt_stats"
: >"$SMOKE/sys.log"
auto_ext_start t_ext >/dev/null 2>&1
chk "extended widen: reopens the listeners for a retest (B3)" "$(grep -c 'restart wattest@t_ext-e-vxlan' "$SMOKE/sys.log")" "1"
# delete removes the hidden listeners with their parent
_bt_fw=$(declare -f fw_close); fw_close() { printf '%s\n' "$*" >>"$SMOKE/fw.log"; }
: >"$SMOKE/sys.log"; : >"$SMOKE/fw.log"
NONINTERACTIVE=1 delete_tunnel t_ext >/dev/null 2>&1
eval "$_bt_fw"
chk "extended delete: configs removed with the parent (B3)" "$(ls "$WAT_CONF"/t_ext*.yml 2>/dev/null | wc -l | tr -d ' ')" "0"
chk "extended delete: the hidden units are stopped (B3)" "$(grep -c 'disable --now wattest@t_ext-e-vxlan' "$SMOKE/sys.log")" "1"
chk "extended delete: each UDP child's rule is closed (L8)" "$(grep -c '^4789/udp$' "$SMOKE/fw.log")" "1"
chk "extended delete: no tcp rule is closed for a child (L8)" "$(grep -c '/tcp' "$SMOKE/fw.log")" "0"
# default stays unchanged: no --extended, no hidden configs and no plan marker
( NONINTERACTIVE=1 NI_CARRIER=auto NI_NAME=t_extn NI_ADDR=203.0.113.5 wizard_kharej ) >/dev/null 2>&1
chk "extended off by default: no hidden configs (B3)" "$(ls "$WAT_CONF"/t_extn-e-*.yml 2>/dev/null | wc -l | tr -d ' ')" "0"
chk "extended off by default: the plan has no marker (B3)" "$(read_token "$(cat "$WAT_CONF/t_extn.token")"; case "$T_AUTO" in *';e=1'*) echo y ;; *) echo n ;; esac)" "n"
rm -f "$WAT_CONF"/t_extn*
# an old Kharej refuses --extended with one clear message and writes nothing
VER=3.2.1; : >"$SMOKE/ext.out"
( NONINTERACTIVE=1 NI_CARRIER=auto NI_NAME=t_ext2 NI_ADDR=203.0.113.5 NI_EXTENDED=1 wizard_kharej ) >"$SMOKE/ext.out" 2>&1
_ext_rc=$?
chk "extended: an old Kharej refuses --extended (B3)" "$_ext_rc/$(grep -c 'needs wattun 3.3.0' "$SMOKE/ext.out")" "1/1"
chk "extended: the refusal creates nothing (B3)" "$(ls "$WAT_CONF"/t_ext2* 2>/dev/null | wc -l | tr -d ' ')" "0"
eval "$_bt_fmp"; eval "$_bt_lb"; eval "$_bt_sctl"; eval "$_bt_su"
eval "$_bt_bv"; eval "$_bt_bvok"; VER=$_bt_ver
unset -f systemd-run
NI_EXTENDED=0; AUTO_EXT=0; AUTO_EXT_D=''
rm -f "$SMOKE/sys.log" "$SMOKE/ext.out"

chk "tune knobs: pool lanes test sessions up to the engine max 16" "$(at_tune_knobs tcp | grep -c 'sessions:1,2,4,8,16')" "1"
chk "tune knobs: pool lanes test conns up to 64" "$(at_tune_knobs tcp | grep -c 'conns:4,8,32,64')" "1"
chk "tune knobs: the reduced D8 grid has no mtu/batch/loss-ceiling/win-max" "$(at_tune_knobs tcp | grep -cE 'mtu:|batch:|loss-ceiling:|win-max:')" "0"
chk "tune knobs: reverse never tests sessions" "$(at_tune_knobs reverse | grep -c 'sessions')" "0"
chk "tune knobs: reverse tests conns only" "$(at_tune_knobs reverse)" "conns:4,8,32"
T_CARRIER='icmp+tcp'
chk "tune knobs: a bond never tests sessions" "$(at_tune_knobs bond | grep -c 'sessions')" "0"
chk "tune knobs: a bond tests conns" "$(at_tune_knobs bond)" "conns:4,8,32,64"
T_CARRIER=''
chk "tune knobs: an icmp carrier has no tunable sessions/conns" "$(at_tune_knobs icmp)" ""
chk "tune knobs: the reduced grid is the budget's probe count" "$(at_tune_probe_count "$AUTO_TUNE_POOL")" "10"
chk "tune knobs: every remaining knob exists on every supported engine" "$(at_tune_knobs_avail tcp)" "$AUTO_TUNE_POOL"
AV_LABEL=(); AV_CAR=(); AV_KIND=(); AV_PEER=(); AV_PORT=(); AV_SNI=(); AV_FP=(); AV_ECH=(); AV_FRAG=(); AV_FS=(); AV_FM=(); AV_X=()
av_add tcp tcp d '203.0.113.10:4443' '' ''; av_add tls tls d '203.0.113.10:8443' '' ''
T_CARRIER='tcp+tls'; AT_SEL=(0 1); AT_X=() # at_tune_bond_variant appends to the AV arrays from a clean state
at_tune_bond_variant
chk "bond tune variant: one extra row probes the whole bond" "${#AV_LABEL[@]}" "3"
chk "bond tune variant: its label names the carrier list" "${AV_LABEL[2]}" "bond tcp+tls"
chk "bond tune variant: every leg's peer goes in as a flag" "${AV_X[2]}" "-peer-tcp 203.0.113.10:4443 -peer-tls 203.0.113.10:8443"
chk "bond tune variant: base index" "$AT_TUNE_BASE" "2"
# Reverse tuning: Kharej dialer has up to 30 s backoff, so tuning probes wait 45 s
AV_LABEL=(); AV_CAR=(); AV_KIND=(); AV_PEER=(); AV_PORT=(); AV_SNI=(); AV_FP=(); AV_ECH=(); AV_FRAG=(); AV_FS=(); AV_FM=(); AV_X=()
av_add "ws reverse" ws r '203.0.113.10:24433' '24433' ''
AT_SEL=(0)
_tune_w=$( at_probe() { printf '%s' "$2"; return 0; }; at_cleanup() { :; }; at_prep() { return 0; }; AT_QUIET=1; at_tune )
chk "at_tune: reverse pool carrier probes with 45 s wait" "$_tune_w" "45"
# H2/H3: the budget now counts all three phases, and the probe size is duration-based
chk "at_budget: screening+finalists+tuning worst case" "$(at_budget 17 16 40 10 20)" "up to 1184 MB, about 3 min"
chk "at_budget: an empty plan stays at the minimum" "$(at_budget 0 0 0 0 0)" "up to 0 MB, about 1 min"
chk "at_probe_mb: unknown rate starts at 8 MB" "$(at_probe_mb 0)" "8"
chk "at_probe_mb: a slow link keeps 8 MB" "$(at_probe_mb 0.5)" "8"
chk "at_probe_mb: a fast link escalates to the cap" "$(at_probe_mb 100 1.5 200)" "200"
chk "at_probe_mb: the screening cap bounds it" "$(at_probe_mb 100 1.5 16)" "16"
chk "at_probe_mb: the finalist cap bounds it" "$(at_probe_mb 100 1.5 40)" "40"
chk "at_probe_mb: 1.5 s floor reached below the cap" "$(at_probe_mb 4 1.5 200)" "8"
chk "at_probe_mb: a broken rate falls back to 8" "$(at_probe_mb abc)" "8"

# R3 auto lifecycle prune: the decision is pure (no systemd, no /stats). A selection that changes restarts the window,
# an empty tunnel is never touched, and the grace setting only lives in .manager.conf (default 12 min, 0 = off).
chk "prune: nothing connected -> idle" "$(prune_decision '' '' '' 1000 600)" "idle - -"
chk "prune: first sighting starts the window" "$(prune_decision 'tcp+wss' '' '' 1000 600)" "reset tcp+wss 1000"
chk "prune: a changed selection restarts the window" "$(prune_decision tcp 'tcp+wss' 100 1000 600)" "reset tcp 1000"
chk "prune: inside the grace window -> wait" "$(prune_decision tcp tcp 500 1000 600)" "wait tcp 500"
chk "prune: grace elapsed -> prune" "$(prune_decision tcp tcp 300 1000 600)" "prune tcp 300"
chk "prune: a 12 minute window" "$(prune_decision 'r:icmp' 'r:icmp' 0 720 720)" "prune r:icmp 0"
chk "prune: grace 0 waits (off is decided by the caller)" "$(prune_decision tcp tcp 0 100000 0)" "wait tcp 0"
( umask 077; printf 'autoprune=0\n' >"$WAT_CONF/.manager.conf" )
chk "autoprune: 0 disables the automatic pass" "$(autoprune_grace)" "0"
printf 'autoprune=7\n' >"$WAT_CONF/.manager.conf"
chk "autoprune: a custom window" "$(autoprune_grace)" "7"
printf 'autoprune=soon\n' >"$WAT_CONF/.manager.conf"
chk "autoprune: junk falls back to the default" "$(autoprune_grace)" "$AUTOPRUNE_DEFAULT_MIN"
rm -f "$WAT_CONF/.manager.conf"
chk "autoprune: default is 5 minutes" "$(autoprune_grace)" "5"

# R3 scheduling + widen safety net: the automatic prune pass runs from heal(), so a Kharej-only server must get that
# timer installed; and a narrowed tunnel that loses every open carrier reopens the plan, bounded by autowiden minutes.
chk "widen decision: a working open carrier resets the counter" "$(autowiden_decision 1 5 9999 3 30)" "reset"
chk "widen decision: one failed check only waits" "$(autowiden_decision 0 0 9999 3 30)" "wait 1"
chk "widen decision: the third failed check widens" "$(autowiden_decision 0 2 9999 3 30)" "widen"
chk "widen decision: a just-widened tunnel is not widened again" "$(autowiden_decision 0 5 60 3 30)" "wait 6"
chk "widen decision: after the cooldown it may widen again" "$(autowiden_decision 0 5 1800 3 30)" "widen"
chk "widen decision: broken counters do not widen" "$(autowiden_decision 0 junk junk 3 30)" "wait 1"
chk "prune timer: a Kharej auto tunnel needs the heal timer" "$(prune_timer_needed Kharej 1 && echo y)" "y"
chk "prune timer: an Iran tunnel does not" "$(prune_timer_needed Iran 1 && echo y)" ""
chk "prune timer: a fixed Kharej tunnel does not" "$(prune_timer_needed Kharej 0 && echo y)" ""
( umask 077; printf 'autowiden=0\n' >"$WAT_CONF/.manager.conf" )
chk "autowiden: 0 turns the automatic widen off" "$(autowiden_grace)" "0"
rm -f "$WAT_CONF/.manager.conf"
chk "autowiden: default cooldown is 10 minutes (D1)" "$(autowiden_grace)" "10"
# the timer unit itself: install writes a oneshot that runs heal every minute, remove deletes both files
UNITS=$SMOKE/units; rm -rf "$UNITS"
WAT_UNIT_DIR=$UNITS heal_enable >/dev/null 2>&1
chk "heal timer: service installed" "$([ -f "$UNITS/$HEAL_UNIT.service" ] && echo y || echo n)" "y"
chk "heal timer: timer installed" "$([ -f "$UNITS/$HEAL_UNIT.timer" ] && echo y || echo n)" "y"
chk "heal timer: runs the heal pass" "$(grep -c '^ExecStart=.* heal$' "$UNITS/$HEAL_UNIT.service")" "1"
chk "heal timer: fires every minute" "$(grep -c '^OnUnitActiveSec=1min$' "$UNITS/$HEAL_UNIT.timer")" "1"
WAT_UNIT_DIR=$UNITS heal_disable >/dev/null 2>&1
chk "heal timer: remove drops the service" "$([ -e "$UNITS/$HEAL_UNIT.service" ] && echo y || echo n)" "n"
chk "heal timer: remove drops the timer" "$([ -e "$UNITS/$HEAL_UNIT.timer" ] && echo y || echo n)" "n"
# a Kharej-only auto setup installs it with no operator action (and does nothing when it is already enabled)
cat >"$WAT_CONF/t_auto.yml" <<'EOF'
mode: server
carrier: icmp+tcp
listen-tcp: ":4443"
EOF
make_token auto '203.0.113.10' 'testkey123' '/wat' '' '' '' '' 'd=udp:4443,tcp:4443;r=tcp:24431' >"$WAT_CONF/t_auto.token"
chmod 600 "$WAT_CONF/t_auto.token"
role() { echo Kharej; }
tunnels() { echo t_auto; } # the SLA test above leaves a tunnels() stub; point it at the auto tunnel for this check
systemctl() { case "${1:-}" in is-enabled) return 1 ;; *) return 0 ;; esac; }
WAT_UNIT_DIR=$UNITS ensure_prune_timer
chk "prune scheduling: an auto Kharej setup installs the heal timer" "$([ -f "$UNITS/$HEAL_UNIT.timer" ] && echo y || echo n)" "y"
systemctl() { case "${1:-}" in is-enabled) return 0 ;; *) return 0 ;; esac; }
WAT_UNIT_DIR=$UNITS ensure_prune_timer >/dev/null 2>&1
chk "prune scheduling: an enabled timer is left alone" "$([ -f "$UNITS/$HEAL_UNIT.timer" ] && echo y || echo n)" "y"
# the widen pass itself: three failed checks reopen the token plan and start the cooldown, without operator action
: >"$WAT_RUN/t_auto.autoprune.done"
auto_widen_tick t_auto >/dev/null 2>&1
chk "widen pass: the first failed check is counted" "$(cat "$WAT_RUN/t_auto.autowiden.down" 2>/dev/null || echo 0)" "1"
auto_widen_tick t_auto >/dev/null 2>&1
auto_widen_tick t_auto >/dev/null 2>&1
chk "widen pass: the third check reopens every planned carrier" "$(grep -c '^carrier: icmp+udp+tcp$' "$WAT_CONF/t_auto.yml")" "1"
chk "widen pass: widening clears the pruned marker" "$([ -e "$WAT_RUN/t_auto.autoprune.done" ] && echo y || echo n)" "n"
chk "widen pass: widening starts the cooldown stamp" "$([ -f "$WAT_RUN/t_auto.autowiden" ] && echo y || echo n)" "y"
chk "widen pass: widening resets the failed-check counter" "$([ -e "$WAT_RUN/t_auto.autowiden.down" ] && echo y || echo n)" "n"
# heal() on a Kharej-only host must never restart a client tunnel: only the prune/widen pass may run
SYSCALLS=$SMOKE/syscalls
cat >"$WAT_CONF/t_kh.yml" <<'EOF'
mode: server
carrier: icmp+tcp
listen-tcp: ":4443"
EOF
: >"$SYSCALLS"
tunnels() { echo t_kh; } # a Kharej-only host: heal() must not restart it (it is not an Iran client)
systemctl() { case "${1:-}" in restart) echo restart >>"$SYSCALLS" ;; esac; return 0; }
heal >/dev/null 2>&1 || true
chk "heal on a Kharej host: no client restarts" "$(grep -c '^restart$' "$SYSCALLS" || true)" "0"
role() { echo Iran; }
tunnels() { echo t_sla; } # restore the stub the SLA test left behind
systemctl() { return 0; }
WAT_UNIT_DIR=$UNITS heal_disable >/dev/null 2>&1
rm -rf "$UNITS" "$SYSCALLS" "$WAT_CONF/t_kh.yml" "$WAT_CONF/t_auto.yml" "$WAT_CONF/t_auto.token" \
       "$WAT_RUN/t_auto.autowiden" "$WAT_RUN/t_auto.autowiden.down" "$WAT_RUN/t_auto.autoprune.done"

# Release checksums: sums_has matches one exact "<sha>  <name>" line; sums_verify is the RSA check update() runs
# before it executes the installer as root, so it is exercised here with a throwaway key. The release key embedded
# in install.sh and in the manager must stay byte-identical (the manager's own comment requires it).
SUMS_FILE=$SMOKE/SHA256SUMS
SUMS_SHA=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
printf '%s  %s\n' "$SUMS_SHA" install.sh >"$SUMS_FILE"
chk "sums_has match install.sh" "$(sums_has "$SUMS_FILE" install.sh "$SUMS_SHA" && echo y || echo n)" "y"
chk "sums_has rejects a wrong hash" "$(sums_has "$SUMS_FILE" install.sh 0000000000000000000000000000000000000000000000000000000000000000 && echo y || echo n)" "n"
chk "sums_has rejects another name" "$(sums_has "$SUMS_FILE" wattun-manager "$SUMS_SHA" && echo y || echo n)" "n"
INSTALL_PEM=$(awk '/^SIG_PUB=/{on=1;next} on&&/^PEM$/{on=0} on' install.sh)
chk "release signing key matches install.sh" "$([ "$INSTALL_PEM" = "$SIG_PUB" ] && echo y || echo n)" "y"
if command -v openssl >/dev/null 2>&1; then
  KEY=$SMOKE/test-sign.pem PUB=$SMOKE/test-sign.pub SIG=$SUMS_FILE.sig
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY" 2>/dev/null
  openssl pkey -in "$KEY" -pubout -out "$PUB" 2>/dev/null
  openssl dgst -sha256 -sign "$KEY" -out "$SIG" "$SUMS_FILE"
  chk "sums_verify accepts a valid signature" "$(sums_verify "$SUMS_FILE" "$SIG" "$PUB" && echo y || echo n)" "y"
  printf 'tampered\n' >>"$SUMS_FILE"
  chk "sums_verify rejects a changed list" "$(sums_verify "$SUMS_FILE" "$SIG" "$PUB" && echo y || echo n)" "n"
  printf '%s  install.sh\n' "$SUMS_SHA" >"$SUMS_FILE"
  printf 'x' >"$SIG"
  chk "sums_verify rejects a changed signature" "$(sums_verify "$SUMS_FILE" "$SIG" "$PUB" && echo y || echo n)" "n"
  rm -f "$KEY" "$PUB" "$SIG"
else
  echo "skip sums_verify: openssl not available"
fi
rm -f "$SUMS_FILE"

# ---- task-14: manager Wave 0+1 of the 2026-11-04 audit fix plan (H8/H4/H6/H10/M1/D7/M4/M17/M8/H2/H3/D8) ----
# H8: delete_tunnel must stop the unit BEFORE removing its state files; the engine's SIGTERM save would otherwise
# re-create quota/totals after the rm (the 3.2.1 regression). Assert by position inside the function body.
_dt=$(sed -n '/^delete_tunnel() {/,/^}/p' wattun-manager)
_stop=$(grep -n 'disable --now "${WAT_PREFIX}@\$n"' <<<"$_dt" | head -1 | cut -d: -f1)
_rm=$(grep -n 'state_files "\$n"' <<<"$_dt" | head -1 | cut -d: -f1)
chk "delete: stops the unit before removing its state files (H8)" "$([ -n "$_stop" ] && [ -n "$_rm" ] && [ "$_stop" -lt "$_rm" ] && echo y)" "y"
# H6: one mode list; the old second list in --fake-mode missed 5 documented modes
chk "fake-mode: one shared list of 13 modes (H6)" "$(for m in $AC_ALLMODES; do echo x; done | wc -l | tr -d ' ')" "13"
_h6=0; for m in $AC_ALLMODES; do v_fake_mode "$m" || _h6=1; done
chk "fake-mode: every listed mode validates" "$_h6" "0"
expect_fail v_fake_mode bogus
NI_FAKEMODE=ff; REPLY_V=''
pick_fake_mode rst >/dev/null 2>&1
chk "fake-mode: the picker accepts a listed mode (ff)" "$REPLY_V" "ff"
NI_FAKEMODE=nope; expect_fail pick_fake_mode rst
NI_FAKEMODE=''
ni_parse --fake-sni example.com --fake-mode ff
chk "fake-mode: --fake-mode parses a listed mode (ff)" "$NI_FAKEMODE" "ff"
expect_fail ni_parse --fake-sni example.com --fake-mode nope
chk "fake-mode: the matrix uses the shared list" "$(grep -c 'for fm in \$AC_ALLMODES' wattun-manager)" "1"
NI_FAKEMODE=''
# H4: every 3.3.0-only Advanced row and write is refused on an older engine (the manager ships from main, the engine
# from releases/latest, so an unknown key would crash the tunnel)
cat >"$WAT_CONF/t_h4.yml" <<'EOF'
mode: client
carrier: tcp
fec: auto
EOF
_h4_old=$( NONINTERACTIVE=1; bin_ver_ok() { return 1; }; adv_menu t_h4 ) 2>/dev/null
chk "H4: 3.3.0-only Advanced rows hidden on an older engine" "$(grep -cE 'state dir|state save|shape data|allow clients|fec on loss|fec off loss|noise' <<<"$_h4_old")" "0"
_h4_gate=$( bin_ver_ok() { return 1; }; adv_33 >/dev/null 2>&1 && echo ok || echo refused )
chk "H4: the 3.3.0 write gate refuses an older engine" "$_h4_gate" "refused"
chk "H4: the write gate allows a 3.3.0 engine" "$(adv_33 >/dev/null 2>&1 && echo ok)" "ok"
rm -f "$WAT_CONF/t_h4.yml"
# H10/D1: default automatic cleanup is reverse-side only; direct narrowing is opt-in (a bonded Iran client looks like
# one direct carrier, so narrowing it by default could break failover)
chk "prune scope: default closes the reverse side only" "$(prune_targets 0 'tcp' 'icmp' 1)" "reverse"
chk "prune scope: no companion -> nothing to clean" "$(prune_targets 0 'tcp' '' 0)" "none"
chk "prune scope: a live direct set never narrows by default (bond safety)" "$(prune_targets 0 'tcp' 'icmp' 1)" "reverse"
chk "prune scope: autoprune-direct=1 narrows both sides" "$(prune_targets 1 'tcp' 'icmp' 1)" "both"
chk "prune scope: direct opt-in with nothing live -> none" "$(prune_targets 1 '' '' 0)" "none"
chk "prune signature: reverse-only ignores the direct set" "$(prune_signature 0 'tcp' 'icmp' 1)" "r:icmp"
chk "prune signature: an unused companion is still watched" "$(prune_signature 0 'tcp' '' 1)" "r:-"
chk "prune signature: the opt-in covers both sides" "$(prune_signature 1 'tcp' 'icmp' 1)" "tcp+r:icmp"
chk "prune scope: both sides close by default" "$(autoprune_direct_setting)" "1"
( umask 077; printf 'autoprune-direct=0\n' >"$WAT_CONF/.manager.conf" )
chk "prune scope: autoprune-direct=0 is read from .manager.conf" "$(autoprune_direct_setting)" "0"
rm -f "$WAT_CONF/.manager.conf"
chk "prune: the reverse-only pass is a separate function" "$(grep -c '^auto_prune_reverse_only()' wattun-manager)" "1"
chk "prune: the default pass cannot call auto_narrow directly" "$(awk '/^auto_prune_tick\(\)/,/^}/' wattun-manager | grep -c 'targets.*= both')" "1"
# end-to-end offline pass: with the default scope a companion that Iran does not use is closed by the pass, and the
# direct carrier list is left exactly as it was (systemd is stubbed by this harness); grace 0 would disable it, so the
# stamp is pre-seeded as the stable signature and the window is 1 minute.
cat >"$WAT_CONF/t_pr.yml" <<'EOF'
mode: server
carrier: tcp+icmp
EOF
cat >"$WAT_CONF/t_pr-r.yml" <<'EOF'
mode: client
carrier: icmp
peer: 203.0.113.5
EOF
printf 'wat1:%s\n' "$(printf 'auto|203.0.113.5|k||||||d:icmp,tcp;r:icmp' | base64 | tr -d '\n')" >"$WAT_CONF/t_pr.token"
( umask 077; printf 'autoprune=1\nautoprune-direct=0\n' >"$WAT_CONF/.manager.conf" )
mkdir -p "$WAT_RUN"; printf 'r:- 0\n' >"$WAT_RUN/t_pr.autoprune"
_pr_sys="$WAT_RUN/.prune-sys"; rm -f "$_pr_sys"
_pr_out=$( NONINTERACTIVE=1; systemctl() { echo "$*" >>"$_pr_sys"; return 0; }; stats() { echo '{"alive": false, "clients": []}'; }; auto_prune_tick t_pr ) 2>/dev/null
chk "prune pass: the default scope closes the unused reverse side" "$(grep -c 'stop wattest@t_pr-r' "$_pr_sys" 2>/dev/null)" "1"
chk "prune pass: it never touches the direct unit" "$(grep -cE '(stop|restart|disable).*@t_pr($|[^-])' "$_pr_sys")" "0"
chk "prune pass: it never rewrites the direct carrier list" "$(cfg t_pr carrier)" "tcp+icmp"
chk "prune pass: it records the done marker" "$([ -f "$WAT_RUN/t_pr.autoprune.done" ] && echo y)" "y"
# a reverse side that is fully in use must stay open and keep being watched (no done marker)
rm -f "$WAT_RUN/t_pr.autoprune.done"; printf 'r:icmp 0\n' >"$WAT_RUN/t_pr.autoprune"
_pr_out2=$( NONINTERACTIVE=1; auto_live() { AN_D=''; AN_R='icmp'; }; auto_prune_tick t_pr ) 2>/dev/null
chk "prune pass: a fully used reverse side is left open" "$([ -f "$WAT_RUN/t_pr.autoprune.done" ] && echo y || echo n)" "n"
chk "prune pass: the window restarts instead of marking done" "$(cut -d' ' -f1 "$WAT_RUN/t_pr.autoprune")" "r:icmp"
# H1: extended cleanup must not depend on the reverse/direct narrowing succeeding (reverse-only returns 2 here).
_ext_log="$WAT_RUN/.ext-prune"; : >"$_ext_log"
rm -f "$WAT_RUN/t_pr.autoprune.done"; printf 'r:icmp 0\n' >"$WAT_RUN/t_pr.autoprune"
_pr_out3=$( NONINTERACTIVE=1; auto_live() { AN_D=''; AN_R='icmp'; }; auto_ext_names() { echo t_pr-e-vxlan; }; auto_ext_prune() { echo called >>"$_ext_log"; }; auto_prune_tick t_pr ) 2>/dev/null
chk "prune pass: ext cleanup runs when every reverse leg is in use (H1)" "$(grep -c called "$_ext_log" 2>/dev/null)" "1"
rm -f "$_ext_log"
rm -f "$WAT_CONF/t_pr.yml" "$WAT_CONF/t_pr-r.yml" "$WAT_CONF/t_pr.token" "$WAT_CONF/.manager.conf" \
      "$WAT_RUN/t_pr.autoprune" "$WAT_RUN/t_pr.autoprune.done" "$WAT_RUN/.prune-sys"
# M8: a hand-edited relative state-dir resolves from / in the manager (the unit's CWD), and says so out loud
cat >"$WAT_CONF/t_m8.yml" <<'EOF'
mode: client
carrier: tcp
state-dir: relstate
EOF
chk "state-dir: a relative value is detected (M8)" "$(state_dir_is_relative t_m8 && echo y)" "y"
_m8w=$(state_dir_relative_warn t_m8 2>&1)
chk "state-dir: a relative value warns instead of resolving silently (M8)" "$(grep -c 'resolves it from /' <<<"$_m8w")" "1"
chk "state-dir: a relative value resolves from / (M8)" "$(state_base_path t_m8 relstate)" "/relstate/t_m8.yml"
printf 'mode: client\ncarrier: tcp\nstate-dir: /var/lib/wattun\n' >"$WAT_CONF/t_m8.yml"
chk "state-dir: an absolute value is not flagged" "$(state_dir_is_relative t_m8 && echo y || echo n)" "n"
rm -f "$WAT_CONF/t_m8.yml"
# M1: raw-tier shaped MTU ceilings come from the engine profile (1400 minus the IP-protocol header)
for p in 'sit 1360' '6to4 1360' 'xfrm-ipsec 1392' 'etherip 1384' 'l2tpv3 1396' 'dnscrypt-udp 1326' 'ntp-direct 1352' 'srtp-direct 1388' 'fou-gre 1392' 'gue-ipip 1392' 'vxlan 1392' 'geneve 1392' 'openvpn-dco 1396'; do
  set -- $p
  chk "mtu ceiling: shaped $1" "$(mtu_max_for "$1")" "$2"
done
v_mtu 1360 sit && echo "ok   v_mtu accepts the sit ceiling" || { echo "FAIL v_mtu sit ceiling"; fail=1; }
expect_fail v_mtu 1361 sit
v_mtu 1392 xfrm-ipsec && echo "ok   v_mtu accepts the xfrm-ipsec ceiling" || { echo "FAIL v_mtu xfrm ceiling"; fail=1; }
expect_fail v_mtu 1393 xfrm-ipsec
ADV_CR=sit; v_mtu_adv 1360 && echo "ok   v_mtu_adv uses the shaped ceiling" || { echo "FAIL v_mtu_adv shaped"; fail=1; }
expect_fail v_mtu_adv 1400
ADV_CR=''
# H2/H3/D8: at_best_rate sizes the next screening probe from the fastest measured direction
AR_OK=(1 1 0); AR_DOWN=(10 5 999); AR_UP=(3 20 999)
chk "at_best_rate: fastest measured direction" "$(at_best_rate 0 0 1 2)" "20"
chk "at_best_rate: a failed variant is ignored" "$(at_best_rate 0 2)" "0"
AR_OK=(); AR_DOWN=(); AR_UP=()
# H1: the documented tmpfs path is the one the unit makes writable
chk "state-dir: hints/validator point at /run/wattun (H1)" "$([ "$(grep -c '/run/wattun' wattun-manager)" -ge 3 ] && echo y)" "y"

# ======================================================================================
# Finding fixes M2/L16/L17 and the behaviour behind the 2026-11-05 manager fixes
# (H1/H2/H3/H4/M1/L1/L2/L3/L7/L8/L10/L12). Each case calls the real manager function with a temp
# WAT_CONF/WAT_RUN/WAT_PREFIX; systemd, /stats, the firewall and the engine binary are stubs, so no root,
# no systemd and no binary are needed.
# ======================================================================================
_bv_s=$(declare -f bin_ver); _bvok_s=$(declare -f bin_ver_ok); _ver_s=$VER
VER=3.3.0; bin_ver() { echo "$VER"; }; bin_ver_ok() { ver_ge "$(bin_ver)" "$1" && echo 1; }
SY=$SMOKE/sys2.log
role() { echo Iran; }
systemctl() { printf '%s\n' "$*" >>"$SY"; return 0; }

# H1/M1: a shaped-only pick. The parent's /stats cannot name a shaped shape, so the pick is read from each hidden
# child's own /stats ("clients" -> a live client). The parent name itself contains "-e-" to pin the exact-prefix parse.
cat >"$WAT_CONF/a-e-b.yml" <<'EOF'
mode: server
carrier: icmp+tcp
listen-tcp: ":4443"
EOF
make_token auto '203.0.113.10' 'testkey123' '/wat' '' '' '' '' 'd=icmp,tcp;r=icmp' >"$WAT_CONF/a-e-b.token"
chmod 600 "$WAT_CONF/a-e-b.token"
{ echo "mode: server"; echo "key-file: $WAT_CONF/a-e-b.key"; echo "carrier: vxlan"; echo 'listen: ":4789"'; } >"$WAT_CONF/a-e-b-e-vxlan.yml"
{ echo "mode: server"; echo "key-file: $WAT_CONF/a-e-b.key"; echo "carrier: sit"; } >"$WAT_CONF/a-e-b-e-sit.yml"
printf 'a-e-b\n' >"$WAT_CONF/a-e-b-e-vxlan.autoext"
printf 'a-e-b\n' >"$WAT_CONF/a-e-b-e-sit.autoext"
chk "shaped children: the exact prefix is parsed, not the first -e- (M1)" "$(auto_ext_names a-e-b | tr '\n' ' ')" "a-e-b-e-sit a-e-b-e-vxlan "
chk "shaped pick: the signature names the live child alone (H1)" \
  "$( stats() { case "$1" in a-e-b-e-vxlan) echo '{"alive": true, "clients": [{"ip": "203.0.113.9"}]}' ;; *) echo '{"alive": true, "clients": []}' ;; esac; }; auto_ext_sig a-e-b )" "e:vxlan"
( umask 077; printf 'autoprune=1\n' >"$WAT_CONF/.manager.conf" ) # a one-minute stable-pick window
printf 'e:vxlan 0\n' >"$WAT_RUN/a-e-b.autoprune"                # the pick has been stable since then
rm -f "$WAT_RUN/a-e-b.autoprune.done"
chk "prune pass: no reverse companion, so only the shapes can be the pick (H1)" "$([ -e "$WAT_CONF/a-e-b-r.yml" ] && echo y || echo n)" "n"
: >"$SY"
( stats() { case "$1" in
    a-e-b-e-vxlan) echo '{"alive": true, "clients": [{"ip": "203.0.113.9", "carrier": "vxlan"}]}' ;;
    *) echo '{"alive": true, "clients": []}' ;;
  esac; }
  auto_prune_tick a-e-b ) >/dev/null 2>&1
chk "prune pass: a shaped-only live child is the pick (H1)" "$(grep -c 'stop wattest@a-e-b-e-vxlan' "$SY")" "0"
chk "prune pass: the shapes Iran does not use are closed (H1)" "$(grep -c 'stop wattest@a-e-b-e-sit' "$SY")" "1"
chk "prune pass: the shaped pick marks the pass done (H1)" "$([ -f "$WAT_RUN/a-e-b.autoprune.done" ] && echo y || echo n)" "y"
printf '2' >"$WAT_RUN/a-e-b.autowiden.down"
( stats() { case "$1" in
    a-e-b-e-vxlan) echo '{"alive": true, "clients": [{"ip": "203.0.113.9"}]}' ;;
    *) echo '{"alive": true, "clients": []}' ;;
  esac; }
  auto_widen_tick a-e-b ) >/dev/null 2>&1
chk "widen pass: a live shaped child counts as up (H1)" "$([ -e "$WAT_RUN/a-e-b.autowiden.down" ] && echo y || echo n)" "n"
: >"$SY"
( systemctl() { printf '%s\n' "$*" >>"$SY"; return 0; }; NONINTERACTIVE=1 auto_widen a-e-b ) >/dev/null 2>&1
chk "widen: the hidden listeners are re-enabled and restarted (B3)" "$(grep -c 'restart wattest@a-e-b-e-vxlan' "$SY")" "1"
: >"$SY"
( systemctl() { printf '%s\n' "$*" >>"$SY"; return 0; }; auto_prune_cmd a-e-b --direct ) >/dev/null 2>&1
chk "prune --direct: reopens the listeners for a retest (B3)" "$(grep -c 'restart wattest@a-e-b-e-vxlan' "$SY")" "1"
rm -f "$WAT_CONF/.manager.conf" "$WAT_CONF/a-e-b.yml" "$WAT_CONF/a-e-b.token" "$WAT_CONF/a-e-b-e-vxlan.yml" \
      "$WAT_CONF/a-e-b-e-sit.yml" "$WAT_CONF/a-e-b-e-vxlan.autoext" "$WAT_CONF/a-e-b-e-sit.autoext" \
      "$WAT_RUN/a-e-b.autoprune" "$WAT_RUN/a-e-b.autoprune.done" "$WAT_RUN/a-e-b.autowiden.down"

# H2/L12: a hidden child inherits the parent's allowlist (otherwise the engine falls back to the permissive 1-65535),
# and no metrics line is written when free_metrics_port finds no free port.
MAPS=("47811:18899/tcp" "53:53/udp")
cat >"$WAT_CONF/t_h2.yml" <<'EOF'
mode: server
allow-clients: 203.0.113.5
metrics: 127.0.0.1:19870
ports:
  - 47811:18899/tcp
limits:
  - 18899 rate=5MB quota=1GB
EOF
( free_metrics_port() { echo 19871; }; fw_open() { :; }; auto_ext_write_units t_h2 'vxlan:4789' ) >/dev/null 2>&1
chk "H2: the child carries the parent's ports: block" "$(grep -c '^  - 47811:18899$' "$WAT_CONF/t_h2-e-vxlan.yml")" "1"
chk "H2: a UDP allowlist row is copied too" "$(grep -c '^  - 53/udp$' "$WAT_CONF/t_h2-e-vxlan.yml")" "1"
chk "H2: the child inherits limits: (H2)" "$(grep -c '^limits:' "$WAT_CONF/t_h2-e-vxlan.yml")" "1"
chk "H2: the child inherits allow-clients (H2)" "$(grep -c '^allow-clients: 203.0.113.5$' "$WAT_CONF/t_h2-e-vxlan.yml")" "1"
chk "H2: the child still names its shape" "$(grep -c '^carrier: vxlan$' "$WAT_CONF/t_h2-e-vxlan.yml")" "1"
chk "H2: a free port gets a metrics line" "$(grep -c '^metrics: 127.0.0.1:19871$' "$WAT_CONF/t_h2-e-vxlan.yml")" "1"
MAPS=()
( free_metrics_port() { return 1; }; fw_open() { :; }; auto_ext_write_units t_l12 'vxlan:4789' ) >/dev/null 2>&1
chk "L12: no free port means no metrics line, not an invalid one (F25)" "$(grep -c '^metrics:' "$WAT_CONF/t_l12-e-vxlan.yml")" "0"
chk "L12: the child config is still complete (F25)" "$(grep -c '^carrier: vxlan$' "$WAT_CONF/t_l12-e-vxlan.yml")" "1"
_pb2=$(declare -f port_busy)
port_busy() { return 0; } # every port taken
_merr=$(WAT_METRICS_BASE=20399 free_metrics_port 2>&1 >/dev/null); _mrc=$?
chk "L12: an exhausted range is a failure, not 20400+ (F25)" "$_mrc" "1"
chk "L12: it says the tunnel gets no /stats listener (F25)" "$(grep -c 'No free metrics port' <<<"$_merr")" "1"
chk "L12: it prints no port (F25)" "$(WAT_METRICS_BASE=20399 free_metrics_port 2>/dev/null)" ""
eval "$_pb2"
( free_metrics_port() { return 1; }; start_unit() { :; }; fw_open() { :; }
  NONINTERACTIVE=1 NI_CARRIER=fou-gre NI_NAME=t_l12w NI_ADDR=203.0.113.5 wizard_kharej ) >/dev/null 2>&1
chk "L12: the Kharej wizard omits the metrics line too (F25)" "$(grep -c '^metrics:' "$WAT_CONF/t_l12w.yml")" "0"
chk "L12: the Kharej wizard still writes the tunnel (F25)" "$(grep -c '^carrier: fou-gre$' "$WAT_CONF/t_l12w.yml")" "1"

# H3: a new key must reach the hidden shaped listeners (they read key-file only at startup); a disabled (pruned) one
# stays closed.
{ echo "mode: server"; echo "carrier: tcp"; } >"$WAT_CONF/t_h3.yml"
make_token tcp '203.0.113.10:4443' 'oldkey' '/wat' '' '' '' '' >"$WAT_CONF/t_h3.token"
{ echo "mode: server"; echo "carrier: vxlan"; } >"$WAT_CONF/t_h3-e-vxlan.yml"
{ echo "mode: server"; echo "carrier: sit"; } >"$WAT_CONF/t_h3-e-sit.yml"
printf 't_h3\n' >"$WAT_CONF/t_h3-e-vxlan.autoext"
printf 't_h3\n' >"$WAT_CONF/t_h3-e-sit.autoext"
: >"$SY"
( role() { echo Kharej; }; confirm() { return 0; }
  systemctl() { case "$1" in
    is-enabled) [ "${3:-}" = "wattest@t_h3-e-sit" ] && return 1; return 0 ;;
  esac
    printf '%s\n' "$*" >>"$SY"; return 0; }
  change_key t_h3 ) >/dev/null 2>&1
chk "H3: the new key restarts the parent" "$(grep -c '^restart wattest@t_h3$' "$SY")" "1"
chk "H3: an enabled hidden listener restarts with the new key" "$(grep -c 'restart wattest@t_h3-e-vxlan' "$SY")" "1"
chk "H3: a disabled (pruned) listener stays closed" "$(grep -c 'restart wattest@t_h3-e-sit' "$SY")" "0"
rm -f "$WAT_CONF"/t_h3*

# H4: shaped carriers and bare/portless plan entries are never offered as bond legs, and a composed carrier list the
# engine would refuse is not written and does not restart the tunnel. The plan repeats tls (a hand-edited token) so the
# composed list has a duplicate leg — the refusal the guard exists for.
chk "bond candidates: a shaped plan carrier is skipped (H4)" "$(bond_candidates_plan 'tcp+udp' 'udp:4443,vxlan:4789,tls:8443' '203.0.113.10')" $'icmp 203.0.113.10\ntls 203.0.113.10:8443'
chk "bond candidates: a bare raw entry has no port to probe (H4)" "$(bond_candidates_plan 'tcp+udp' 'udp:4443,gre,ipip' '203.0.113.10')" "icmp 203.0.113.10"
chk "bond candidates: an out-of-range port is skipped (H4)" "$(bond_candidates_plan 'tcp' 'tls:0,ws:70000,tls:8443' '203.0.113.10')" $'icmp 203.0.113.10\ntls 203.0.113.10:8443'
chk "bond retest: the composed list would be refused (H4)" "$(v_carrier_list 'tcp+udp+icmp+tls+tls' >/dev/null 2>&1 && echo ok || echo refused)" "refused"
printf 'mode: client\ncarrier: tcp+udp\npeer: 203.0.113.10:4443\n' >"$WAT_CONF/t_h4.yml"
printf 'k' >"$WAT_CONF/t_h4.key"
make_token auto '203.0.113.10' 'k' '/wat' '' '' '' '' 'd=udp:4443,tls:8443,tls:9443,ws:2053;r=icmp' >"$WAT_CONF/t_h4.auto"
chmod 600 "$WAT_CONF/t_h4.auto"
: >"$SY"; : >"$SMOKE/h4.log"
( role() { echo Iran; }
  logger() { printf 'LOG %s\n' "$*" >>"$SMOKE/h4.log"; }
  systemctl() { printf '%s\n' "$*" >>"$SY"; return 0; }
  at_probe() { AR_OK[0]=1; AR_DOWN[0]=10; AR_UP[0]=10; AR_RTT[0]=20; AR_WHY[0]=''; }
  at_cleanup() { :; }
  bond_retest_job t_h4 ) >/dev/null 2>&1
chk "H4: the refused list is reported, not silently dropped" "$(grep -c 'is not a carrier list this engine can run' "$SMOKE/h4.log")" "1"
chk "H4: a refused carrier list is not written" "$(cfg t_h4 carrier)" "tcp+udp"
chk "H4: a refused carrier list does not restart the tunnel" "$(grep -c 'restart wattest@t_h4$' "$SY")" "0"
rm -f "$WAT_CONF"/t_h4*

# M1/L1/L8: a user tunnel that merely looks like a hidden child is never one; delete removes the real child's config,
# its own state files and its UDP rule, and leaves the user's tunnel alone.
{ echo "mode: server"; echo "carrier: tcp"; } >"$WAT_CONF/bar.yml"
printf 'mode: client\ncarrier: tcp\npeer: 203.0.113.9:443\n' >"$WAT_CONF/bar-e-vxlan.yml" # user tunnel, no .autoext
{ echo "mode: server"; echo "carrier: geneve"; echo 'listen: ":6081"'; echo "state-dir: $SMOKE/l1state"; } >"$WAT_CONF/bar-e-geneve.yml"
printf 'bar\n' >"$WAT_CONF/bar-e-geneve.autoext"
mkdir -p "$SMOKE/l1state"; printf 'totals\n' >"$SMOKE/l1state/bar-e-geneve.yml.totals.json"
chk "M1: a user NAME-e-* tunnel is not a hidden child" "$(auto_ext_names bar)" "bar-e-geneve"
chk "M1: writing units refuses to overwrite a user tunnel" "$(auto_ext_write_units bar 'vxlan:4789' >/dev/null 2>&1; echo "$?")" "1"
chk "M1: the refusal leaves the user tunnel untouched" "$(cfg bar-e-vxlan carrier)" "tcp"
_bt_fw2=$(declare -f fw_close); fw_close() { printf '%s\n' "$*" >>"$SMOKE/fw2.log"; }
: >"$SMOKE/fw2.log"
NONINTERACTIVE=1 delete_tunnel bar >/dev/null 2>&1
eval "$_bt_fw2"
chk "L1: delete removes the hidden child's state files (F08)" "$([ -e "$SMOKE/l1state/bar-e-geneve.yml.totals.json" ] && echo y || echo n)" "n"
chk "L1: delete removes the hidden child's config (B3)" "$([ -e "$WAT_CONF/bar-e-geneve.yml" ] && echo y || echo n)" "n"
chk "M1: delete keeps the user's NAME-e-* tunnel" "$([ -e "$WAT_CONF/bar-e-vxlan.yml" ] && echo y || echo n)" "y"
chk "L8: delete closes the child's UDP listen rule (F17)" "$(grep -c '^6081/udp$' "$SMOKE/fw2.log")" "1"
rm -f "$WAT_CONF/bar-e-vxlan.yml"; rm -rf "$SMOKE/l1state"

# L8: uninstall closes every hidden child's UDP rule while its config is still readable (isolated CONF/RUN).
mkdir -p "$SMOKE/u/conf" "$SMOKE/u/run" "$SMOKE/u/units"
{ echo "mode: server"; echo "carrier: vxlan"; echo 'listen: ":4789"'; } >"$SMOKE/u/conf/u_ext-e-vxlan.yml"
{ echo "mode: server"; echo "carrier: sit"; } >"$SMOKE/u/conf/u_ext-e-sit.yml"
printf 'u_ext\n' >"$SMOKE/u/conf/u_ext-e-vxlan.autoext"
printf 'u_ext\n' >"$SMOKE/u/conf/u_ext-e-sit.autoext"
( CONF=$SMOKE/u/conf; RUN=$SMOKE/u/run; AUTO_RUN=$SMOKE/u/autorun; BIN=$SMOKE/u/wattun
  MGR=$SMOKE/u/mgr; WAT_UNIT_DIR=$SMOKE/u/units
  tunnels_all() { printf 'u_ext\nu_ext-e-vxlan\nu_ext-e-sit\n'; }
  systemctl() { :; }
  fw_close() { printf '%s\n' "$*" >>"$SMOKE/u/fw"; }
  NONINTERACTIVE=1 uninstall_all ) >/dev/null 2>&1
chk "L8: uninstall closes a hidden child's UDP rule (F17)" "$(grep -c '^4789/udp$' "$SMOKE/u/fw")" "1"
chk "L8: only the shaped child had a rule to close (F17)" "$(grep -c . "$SMOKE/u/fw")" "1"
rm -rf "$SMOKE/u"

# L2: a busy conventional UDP port is not handed out as the listen port; the fallback probes UDP, not TCP.
_lb2=$(declare -f listen_blocked)
listen_blocked() { printf '%s %s\n' "$1" "$2" >>"$SMOKE/lb2.log"; [ "$2" = 4789 ]; }
: >"$SMOKE/lb2.log"
chk "L2: a free conventional port is used as-is (F19)" "$(listen_blocked() { return 1; }; default_listen vxlan)" "4789"
chk "L2: a busy conventional port falls back (F10)" "$(default_listen vxlan)" "4443"
eval "$_lb2"
chk "L2: the fallback probe is udp for a shaped carrier (F10)" "$(grep -c '^udp 4443$' "$SMOKE/lb2.log")" "1"

# L3: "0" in the Advanced state-dir row means the engine default, never a "/0" directory.
printf 'mode: client\ncarrier: tcp\nstate-dir: /run/wattun\n' >"$WAT_CONF/t_l3.yml"
( NONINTERACTIVE=0; IS_TTY=0; printf 't0\nb' | adv_menu t_l3 ) >/dev/null 2>&1
chk "L3: Advanced state-dir 0 unsets the key (F11)" "$(grep -c '^state-dir:' "$WAT_CONF/t_l3.yml")" "0"
chk "L3: the state-dir validator accepts 0 (F11)" "$(v_state_dir 0 && echo y)" "y"
rm -f "$WAT_CONF/t_l3.yml"

# L7: auto_apply keeps a backup and restores it when the new variant does not connect; quiet (heal) applies drop it.
printf 'mode: client\ncarrier: tcp\npeer: 203.0.113.10:4443\nkey-file: /etc/wattun/t_l7.key\n' >"$WAT_CONF/t_l7.yml"
printf 'old-token\n' >"$WAT_CONF/t_l7.token"
_T_CARRIER_s=$T_CARRIER; _T_PEER_s=$T_PEER; _T_KEY_s=${T_KEY:-}; _T_PATH_s=$T_PATH; _T_SNI_s=$T_SNI
_T_ICMP_s=$T_ICMP; _T_PORTS_s=$T_PORTS; _T_REV_s=$T_REV; _AT_EXTRA_s=$AT_EXTRA
_AT_TUNE_KEYS_s=$AT_TUNE_KEYS; _AT_QUIET_s=$AT_QUIET; _AT_SEL_KEY_s=$AT_SEL_KEY
T_CARRIER=tcp; T_PEER='203.0.113.99:9999'; T_KEY=''; T_PATH=''; T_SNI=''; T_ICMP=''; T_PORTS=''; T_REV=''
AT_EXTRA=''; AT_TUNE_KEYS=''; AT_SEL_KEY=''
_l7_fail=$( systemctl() { :; }; wait_link() { return 1; }; NONINTERACTIVE=1 AT_QUIET=0
  auto_apply t_l7; _rc=$?; printf '\n%s/%s' "$_rc" "$AT_APPLIED" ) 2>/dev/null
_l7_state=$(printf '%s\n' "$_l7_fail" | tail -n 1) # auto_apply's warning is also stdout; the state is the last line
_rc7=${_l7_state%%/*}
_l7_applied=${_l7_state##*/}
chk "L7: a failed link check restores the previous config (F16)" "$(cfg t_l7 peer)" "203.0.113.10:4443"
chk "L7: the restore removes the backup (F16)" "$([ -e "$WAT_CONF/t_l7.yml.bak" ] && echo y || echo n)" "n"
chk "L7: the token is restored with the config (F16)" "$(cat "$WAT_CONF/t_l7.token" 2>/dev/null)" "old-token"
chk "L7: the token backup is removed (F16)" "$([ -e "$WAT_CONF/t_l7.token.bak" ] && echo y || echo n)" "n"
chk "L7: a rolled-back apply clears AT_APPLIED (F16)" "$_l7_applied" "0"
chk "L7: the failure is reported to the caller (F16)" "$_rc7" "1"
( systemctl() { :; }; wait_link() { LINK_RTT=12; return 0; }; NONINTERACTIVE=1 AT_QUIET=0 auto_apply t_l7 ) >/dev/null 2>&1
chk "L7: a successful check keeps the new config and drops the backup (F16)" "$(cfg t_l7 peer)/$([ -e "$WAT_CONF/t_l7.yml.bak" ] && echo bak || echo clean)" "203.0.113.99:9999/clean"
( systemctl() { :; }; wait_link() { return 1; }; NONINTERACTIVE=1 AT_QUIET=1 auto_apply t_l7 ) >/dev/null 2>&1
chk "L7: a quiet apply drops the backup without waiting (F16)" "$([ -e "$WAT_CONF/t_l7.yml.bak" ] && echo bak || echo clean)" "clean"
T_CARRIER=$_T_CARRIER_s; T_PEER=$_T_PEER_s; T_KEY=$_T_KEY_s; T_PATH=$_T_PATH_s; T_SNI=$_T_SNI_s; T_ICMP=$_T_ICMP_s
T_PORTS=$_T_PORTS_s; T_REV=$_T_REV_s; AT_EXTRA=$_AT_EXTRA_s; AT_TUNE_KEYS=$_AT_TUNE_KEYS_s
AT_QUIET=$_AT_QUIET_s; AT_SEL_KEY=$_AT_SEL_KEY_s
rm -f "$WAT_CONF"/t_l7*

# Reverse wait_link: Kharej dialer has up to 30 s backoff, so reverse tunnels wait at least 45 s
cat >"$WAT_CONF/t_wl_r.yml" <<EOF
mode: client
carrier: ws
reverse: true
listen: ":24433"
EOF
_wl_max=$( link_alive() { return 0; }; ANIM=0; wait_link t_wl_r 25 )
chk "wait_link: reverse tunnel extends max wait to 45 s" "$(grep -o 'up to 45s' <<<"$_wl_max")" "up to 45s"
rm -f "$WAT_CONF/t_wl_r.yml"

# L10: one manager pass at a time. A fake flock keeps this deterministic on a host without util-linux flock.
mkdir -p "$SMOKE/bin"
printf '#!/bin/sh\nexit 1\n' >"$SMOKE/bin/flock"; chmod +x "$SMOKE/bin/flock"
_lk=$( PATH="$SMOKE/bin:$PATH"; mgr_lock 2>&1; echo "rc=$?" )
chk "L10: a held lock skips this pass (flock -n)" "$(tail -1 <<<"$_lk")" "rc=1"
chk "L10: it says why the pass was skipped" "$(grep -c 'Another wattun-manager pass is running' <<<"$_lk")" "1"
printf '#!/bin/sh\nexit 0\n' >"$SMOKE/bin/flock"; chmod +x "$SMOKE/bin/flock"
chk "L10: an uncontended pass runs" "$( PATH="$SMOKE/bin:$PATH"; mgr_lock >/dev/null 2>&1; echo "rc=$?" )" "rc=0"
chk "L10: the lock file lives in WAT_RUN" "$([ -f "$WAT_RUN/manager.lock" ] && echo y || echo n)" "y"

# L17: the documented state directory must stay writable in the shipped unit, or the engine would stop at startup.
chk "installer unit: RuntimeDirectory=wattun (L17)" "$(grep -c '^RuntimeDirectory=wattun$' install.sh)" "1"
chk "installer unit: RuntimeDirectoryMode=0700 (L17)" "$(grep -c '^RuntimeDirectoryMode=0700$' install.sh)" "1"
_rwp=$(grep '^ReadWritePaths=' install.sh)
chk "installer unit: ReadWritePaths keeps /run/wattun (L17)" "$(case "$_rwp" in *"/run/wattun"*) echo y ;; *) echo n ;; esac)" "y"
chk "installer unit: ReadWritePaths keeps /etc/wattun (L17)" "$(case "$_rwp" in *"/etc/wattun"*) echo y ;; *) echo n ;; esac)" "y"

rm -f "$WAT_CONF"/t_h2.yml "$WAT_CONF"/t_h2-e-* "$WAT_CONF"/t_l12-e-* "$WAT_CONF"/t_l12w*
eval "$_bv_s"; eval "$_bvok_s"; VER=$_ver_s

# Real status: an auto Kharej is one tunnel on two units, and no stats answer is not "no link".
_ti_stats=$(declare -f stats); _ti_sys=$(declare -f systemctl); _ti_tun=$(declare -f tunnels)
tunnels() { printf 't_ti
t_ti-r
'; }
printf 'mode: server\ncarrier: tcp+wss\nmetrics: 127.0.0.1:1\n' >"$WAT_CONF/t_ti.yml"
printf 'mode: server\ncarrier: tcp+wss\nreverse: true\nmetrics: 127.0.0.1:2\n' >"$WAT_CONF/t_ti-r.yml"
printf 'wat1:%s\n' "$(printf 'auto|203.0.113.5|k||||||d:tcp;r:tcp' | base64 | tr -d '\n')" >"$WAT_CONF/t_ti.token"
printf 'mode: client\ncarrier: udp\nmetrics: 127.0.0.1:3\n' >"$WAT_CONF/t_tb.yml"
systemctl() { local u=${!#}; case "$1" in is-active) case " $_ACT " in *" ${u##*@} "*) return 0 ;; esac; return 1 ;; esac; return 0; }
stats() { local v=''; case "$1" in t_ti) v=$_SP ;; t_ti-r) v=$_SR ;; t_tb) v=$_SB ;; esac; [ -n "$v" ] && printf '%s' "$v"; }
_on='{"alive":true,"sessions":1}'; _off='{"alive":false,"sessions":0}'
_ACT='t_ti t_ti-r'; _SP=$_off; _SR=$_on; tinfo t_ti
chk "status: a parent with the link on its reverse side is up" "$TI_STATE|$TI_WHY" "up|Iran is connected through t_ti-r"
_ACT='t_ti-r'; _SP=''; tinfo t_ti
chk "status: a parent the cleanup stopped is still up through its reverse side" "$TI_STATE" "up"
_ACT='t_ti t_ti-r'; _SP=$_on; _SR=$_off; tinfo t_ti-r
chk "status: the reverse side stands by while Iran is on the direct side" "$TI_STATE" "standby"
_SP=$_off; tinfo t_ti
chk "status: no link on either side is down" "$TI_STATE" "down"
_SP=''; _SR=$_on; tinfo t_ti
chk "status: a silent stats port is unknown, not down" "$TI_STATE" "unknown"
_SP=$_off; _SR=''; tinfo t_ti
chk "status: a silent other side is unknown, not down" "$TI_STATE" "unknown"
_ACT=''; tinfo t_ti
chk "status: both units stopped is stopped" "$TI_STATE" "stopped"
_ACT='t_tb'; _SB='{"alive":true,"loss_pct":9.2}'; tinfo t_tb
chk "status: packet loss alone does not change the state" "$TI_STATE" "up"
_SB='{"alive":true,"carriers":[{"alive":true,"name":"tcp"},{"alive":false,"name":"wss"}]}'; tinfo t_tb
chk "status: a dead bond leg is partial, with the reason" "$TI_STATE|$TI_WHY" "degraded|1 of 2 carriers down"
state_cell Iran degraded; chk "status: degraded reads partial" "$SC_TXT" "partial"
_SP='{"alive":true,"clients":[{"carrier":"tcp"}],"carriers":[{"alive":true,"name":"tcp"},{"alive":true,"name":"wss"},{"alive":false,"name":"h2"}]}'; _SR=''
rm -f "$WAT_CONF/t_ti-r.yml"; auto_live t_ti
chk "cleanup: every live leg of a bond counts as in use" "$AN_D" "tcp wss "
printf 'mode: server\ncarrier: tcp+wss\nreverse: true\nmetrics: 127.0.0.1:2\n' >"$WAT_CONF/t_ti-r.yml"
printf 'mode: server\ncarrier: tcp\nreverse: true\nmetrics: 127.0.0.1:2\n' >"$WAT_CONF/t_ti-r.yml"; _SP=$_off; _SR=$_on; auto_live t_ti
chk "cleanup: a narrowed reverse side with one carrier still counts as in use" "$AN_R" "tcp "
_ACT='t_ti'; chk "lists: a stopped reverse side is hidden" "$(listed_tunnels | grep -c '^t_ti-r$')" "0"
_ACT='t_ti t_ti-r'; chk "lists: a running reverse side is shown" "$(listed_tunnels | grep -c '^t_ti-r$')" "1"
rm -f "$WAT_CONF"/t_ti.yml "$WAT_CONF"/t_ti-r.yml "$WAT_CONF"/t_ti.token "$WAT_CONF"/t_tb.yml
eval "$_ti_stats"; eval "$_ti_sys"; eval "$_ti_tun"

[ "$fail" = 0 ] && echo "ALL OK" || echo "FAILURES: $fail"
exit "$fail"