#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

LIBMETAL=/opt/toolchains/deps/libmetal-1.11.0
INC="-I$SRC/lib/include -I$LIBMETAL/include"
# libmetal/open-amp append -Wall -Wextra -Werror after CMAKE_C_FLAGS; clang-19 flags ATOMIC_VAR_INIT.
NOWARN="-Wno-deprecated-pragma"
# libmetal's metal_container_of/metal_offset_of is the null-based offsetof idiom ((T *)0)->member, which
# UBSan's `null` check flags on every list walk (remoteproc_get_mem), so no input ever survives. Only that
# check is relaxed; ASan and the rest of UBSan stay on and halting.
RELAX="-fno-sanitize=null"

# 1) The library, built (static only; libmetal.a is not PIC-linked into a shared lib) with the
#    sanitizers and DWARF 3. sanitizer-coverage instruments the library too.
#    -fsanitize=fuzzer-no-link: the harness engine is only linked at step 2.
cmake -S "$SRC" -B "$SRC/mayhem/build-fuzz" -DCMAKE_BUILD_TYPE=None \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link $NOWARN" \
  -DCMAKE_FIND_ROOT_PATH="$LIBMETAL" -DWITH_STATIC_LIB=ON -DWITH_SHARED_LIB=OFF -DWITH_APPS=OFF
cmake --build "$SRC/mayhem/build-fuzz" -j"$MAYHEM_JOBS" --target open_amp-static
FUZZ_LIB="$(find "$SRC/mayhem/build-fuzz" -name libopen_amp.a | head -n1)"

# 2) Each harness twice: libFuzzer engine and the standalone run-once reproducer. lsan_off.cc is
#    linked into every binary so LeakSanitizer never aborts a run on exit.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$SRC/mayhem/build-fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/mayhem/build-fuzz/standalone_main.o"
for t in fuzz_elf_load fuzz_rsc_table fuzz_rpmsg_virtio; do
  src="$SRC/mayhem/$t/$t.c"
  $CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS $NOWARN $INC "$src" "$FUZZ_LIB" "$LIBMETAL/lib/libmetal.a" \
      "$SRC/mayhem/build-fuzz/lsan_off.o" $LIB_FUZZING_ENGINE -lsysfs -lhugetlbfs -lpthread -lrt -lm -o "/mayhem/$t"
  $CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS $NOWARN $INC "$src" "$SRC/mayhem/build-fuzz/standalone_main.o" \
      "$FUZZ_LIB" "$LIBMETAL/lib/libmetal.a" "$SRC/mayhem/build-fuzz/lsan_off.o" \
      -lsysfs -lhugetlbfs -lpthread -lrt -lm -o "/mayhem/$t-standalone"
done

# 3) The test oracle: an independent build with NORMAL flags (no sanitizers, no -gdwarf-3, dynamic
#    libc) of the same library plus the known-answer probe that mayhem/test.sh runs.
cmake -S "$SRC" -B "$SRC/mayhem/build-oracle" -DCMAKE_BUILD_TYPE=None \
  -DCMAKE_C_FLAGS="-O1 $NOWARN $COVERAGE_FLAGS" \
  -DCMAKE_FIND_ROOT_PATH="$LIBMETAL" -DWITH_STATIC_LIB=ON -DWITH_SHARED_LIB=OFF -DWITH_APPS=OFF
cmake --build "$SRC/mayhem/build-oracle" -j"$MAYHEM_JOBS" --target open_amp-static
ORACLE_LIB="$(find "$SRC/mayhem/build-oracle" -name libopen_amp.a | head -n1)"
$CC -O1 $NOWARN $COVERAGE_FLAGS $INC "$SRC/mayhem/kat_probe.c" "$ORACLE_LIB" "$LIBMETAL/lib/libmetal.a" \
    -lsysfs -lhugetlbfs -lpthread -lrt -lm -o /mayhem/kat_probe
