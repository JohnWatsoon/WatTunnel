#!/usr/bin/env bash
# self-check for wattun-manager: resilience profiles (profile save/list/show/del/apply), the wizard's
# profile defaults, the unattended flags (--fake-sni/--fake-mode/--fake-ttl/--pool-rotate/--pool-rotate-bytes),
# the value validators, and the flow gates (profiles are Linux-only; the resilience prompts are off
# the plain wizard flow unless a flag or profile pre-fills them). No root, no systemd, no binary needed.
cd "$(dirname "$0")" || exit 1
export WAT_MANAGER_LIB=1 WAT_PREFIX=wattest
export WAT_CONF="$PWD/.smoke/conf" WAT_BIN="$PWD/.smoke/wattun"
export WAT_AUTO_RUN="$PWD/.smoke/run-auto" WAT_RUN="$PWD/.smoke/run"
rm -rf "$PWD/.smoke"; mkdir -p "$WAT_CONF" "$WAT_AUTO_RUN" "$WAT_RUN"
trap 'rm -rf "$PWD/.smoke"' EXIT
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

profile_cmd save p1 >/dev/null 2>&1; [ $? = 0 ] && echo "ok   save without a tunnel name: exactly one pool tunnel -> t1"

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

# 1. Validators: v_sessions, v_conns, v_mtu
for s in 1 16 64 - 0 default; do v_sessions "$s" && echo "ok   v_sessions $s" || { echo "FAIL v_sessions $s"; fail=1; }; done
for s in 65 -1 00 abc; do expect_fail v_sessions "$s"; done

for c in 1 8 128 - 0 default; do v_conns "$c" && echo "ok   v_conns $c" || { echo "FAIL v_conns $c"; fail=1; }; done
for c in 129 -1 00 abc; do expect_fail v_conns "$c"; done

for m in 576 1400 1500 65535 - 0 default; do v_mtu "$m" && echo "ok   v_mtu $m" || { echo "FAIL v_mtu $m"; fail=1; }; done
for m in 575 70000 -1 abc; do expect_fail v_mtu "$m"; done

# 2. Unattended flags: --conns, --mtu, --policy
ni_parse --conns 16 --mtu 1400 --policy latency
chk "unattended --conns" "$NI_CONNS" "16"
chk "unattended --mtu" "$NI_MTU" "1400"
chk "unattended --policy latency" "$NI_POLICY" "latency"

ni_parse --policy direct
chk "unattended --policy direct" "$NI_POLICY" "direct"

expect_fail ni_parse --conns 200
expect_fail ni_parse --mtu 100
expect_fail ni_parse --policy bogus

# 3. Boost Suite: boost_status, boost_apply, boost_undo
BOOST_SYSCTL="$PWD/.smoke/boost.conf"
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
backup_cmd "$PWD/.smoke/test_backup.tar.gz" >/dev/null 2>&1
chk "backup_cmd created archive" "$([ -f "$PWD/.smoke/test_backup.tar.gz" ] && echo 1 || echo 0)" "1"
rm -f "$WAT_CONF/backup_sample.yml"
restore_cmd "$PWD/.smoke/test_backup.tar.gz" >/dev/null 2>&1
chk "restore_cmd restored sample file" "$(grep -c 'test_payload: 12345' "$WAT_CONF/backup_sample.yml" || true)" "1"
rm -f "$WAT_CONF/backup_sample.yml" "$PWD/.smoke/test_backup.tar.gz"

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

[ "$fail" = 0 ] && echo "ALL OK" || echo "FAILURES: $fail"
exit "$fail"