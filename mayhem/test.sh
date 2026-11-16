#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer checks of open-amp (the probe is built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PROBE=/mayhem/kat_probe
if [ ! -x "$PROBE" ]; then
  echo "missing $PROBE: mayhem/build.sh did not produce it" >&2
  emit_ctrf "open-amp-kat" 0 1 0
  exit 1
fi

# Known answers, one per probe line: the remoteproc ELF loader (PT_LOAD copied to its target, bss
# zeroed, entry point, bad magic rejected without touching memory), the resource table parser
# (bad version rejected, vdev id / notify ids / vring count) and the rpmsg-over-virtio driver
# (buffer sizes, tx header and payload on the vring, rx dispatch to the endpoint callback).
EXPECTED=(
  "KAT elf_load ret=0 entry=0x1004 seg=OPENAMP-KAT-0123 pad=0000"
  "KAT elf_badmagic ret=-2 untouched=aa"
  "KAT rsc_badver ret=-6"
  "KAT rsc_table ret=0 vdev_id=7 notifyid=7 vrings=2 ring1_notifyid=11"
  "KAT rpmsg_init ret=0 tx_size=496 rx_size=496"
  "KAT rpmsg_send ret=4 avail_idx=1 desc_len=512 src=0x400 dst=0x500 len=4 payload=ping"
  "KAT rpmsg_recv src=0x500 len=4 data=pong"
  "KAT done"
)

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT
timeout 60 "$PROBE" > "$OUT" 2>&1
echo "probe exit status: $?"
cat "$OUT"

passed=0 ; failed=0
for line in "${EXPECTED[@]}"; do
  if grep -qxF -- "$line" "$OUT"; then
    passed=$(( passed + 1 ))
  else
    failed=$(( failed + 1 ))
    echo "FAIL: expected line not found: $line" >&2
  fi
done
emit_ctrf "open-amp-kat" "$passed" "$failed" 0
