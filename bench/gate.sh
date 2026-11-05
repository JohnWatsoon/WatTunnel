#!/bin/sh
# Data-path performance gate (audit M6): run the session/shaped-carrier benchmarks and compare each ns/op with
# bench/baseline.txt. The baseline was measured on the Windows amd64 dev checkout; CI runners differ, so this is a
# loose catastrophic-regression floor (fail >4x, warn >1.6x), not a precise benchmark. Update the baseline only with
# real measurements and a note of the machine/date.
set -eu
cd "$(dirname "$0")/.."
out=$(go test -run '^$' -bench 'SessionBulk|ShapedUDP' -benchtime 1s -count=1 ./wat/ 2>&1)
printf '%s\n' "$out"
printf '%s\n' "$out" | awk '
BEGIN {
  while ((getline line < "bench/baseline.txt") > 0) {
    n = split(line, a, " ")
    if (n >= 2 && a[1] !~ /^#/) { base[a[1]] = a[2]; nbase++ }
  }
}
/^Benchmark/ && $4 == "ns/op" {
  name = $1
  sub(/-[0-9]+$/, "", name)          # strip the GOMAXPROCS suffix (-16/-4)
  v = $3
  if (!(name in base)) { print "WARN no baseline for " name; next }
  ncmp++
  r = v / base[name]
  printf "gate %-40s %.2fx baseline (%s ns/op)\n", name, r, v
  if (r > 4.0) { print "FAIL " name " is " r "x baseline"; bad = 1 }
  else if (r > 1.6) print "WARN " name " is " r "x baseline"
}
END {
  printf "gate compared %d/%d baseline entries\n", ncmp, nbase
  # A renamed or missing benchmark used to turn this gate into a silent no-op (audit L4/F12).
  if (ncmp == 0 || ncmp < nbase) {
    printf "FAIL compared %d of %d baseline entries\n", ncmp, nbase
    exit 1
  }
  exit bad
}
'
