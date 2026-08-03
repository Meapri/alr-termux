#!/usr/bin/env bash
# Push the tree to the device and run something inside a REAL Termux context.
#
# Why ssh and not `adb shell`: the Android app seccomp filter is installed by
# the zygote only for uid >= 10000, so adb shell (u:r:shell:s0, Seccomp: 0) and
# run-as (u:r:runas_app:s0, Seccomp: 0) both measure a device that does not
# exist.  Only a process forked from the Termux app carries the filter.
# See scripts/dev-bootstrap.md for the one-time setup.
set -euo pipefail

PORT="${ALR_SSH_PORT:-8022}"
KEY="${ALR_SSH_KEY:?set ALR_SSH_KEY to the private key authorised in Termux}"
HOST="${ALR_SSH_HOST:-localhost}"
REMOTE="${ALR_REMOTE_DIR:-alr}"

SSH=(ssh -p "$PORT" -i "$KEY" -o StrictHostKeyChecking=no
     -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$HOST")
SCP=(scp -P "$PORT" -i "$KEY" -o StrictHostKeyChecking=no
     -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

adb forward "tcp:$PORT" "tcp:$PORT" >/dev/null

assert_context() {
    local out
    out=$("${SSH[@]}" 'id -u; grep -oE "^Seccomp:[[:space:]]*[0-9]+" /proc/self/status | tr -dc 0-9; echo; cat /proc/self/attr/current')
    local uid seccomp ctx
    uid=$(sed -n 1p <<<"$out")
    seccomp=$(sed -n 2p <<<"$out")
    ctx=$(sed -n 3p <<<"$out")
    if [ "${uid:-0}" -lt 10000 ] || [ "${seccomp:-0}" != "2" ]; then
        echo "REFUSING: not a measurable context (uid=$uid Seccomp=$seccomp ctx=$ctx)" >&2
        echo "Results from here would be false ALLOWEDs. See scripts/dev-bootstrap.md." >&2
        exit 2
    fi
    echo "context OK: uid=$uid Seccomp=$seccomp ${ctx%%:c*}"
}

sync_tree() {
    "${SSH[@]}" "mkdir -p ~/$REMOTE/src/common ~/$REMOTE/src/cli \
                          ~/$REMOTE/src/supervisor ~/$REMOTE/tests/host \
                          ~/$REMOTE/tests/device ~/$REMOTE/tests/cases"
    "${SCP[@]}" src/common/*.h src/common/*.c     "$HOST:$REMOTE/src/common/"
    "${SCP[@]}" src/cli/*.c                       "$HOST:$REMOTE/src/cli/"
    "${SCP[@]}" src/supervisor/*.h src/supervisor/*.c "$HOST:$REMOTE/src/supervisor/"
    "${SCP[@]}" tests/host/*.c                    "$HOST:$REMOTE/tests/host/"
    "${SCP[@]}" tests/device/*.c tests/device/*.sh "$HOST:$REMOTE/tests/device/"
    "${SCP[@]}" tests/cases/*.tsv                 "$HOST:$REMOTE/tests/cases/"
    "${SSH[@]}" "mkdir -p ~/$REMOTE/bench/microbench"
    "${SCP[@]}" bench/microbench/*.c              "$HOST:$REMOTE/bench/microbench/"
}

CFLAGS_DEV='-O1 -Wall -Wextra -std=c11 -D_GNU_SOURCE'

case "${1:-test}" in
test)
    assert_context
    sync_tree
    "${SSH[@]}" "cd ~/$REMOTE && \
        clang -O1 -Wall -Wextra -Werror -std=c11 -Isrc/common -o test_path tests/host/test_path.c && \
        clang -O1 -Wall -Wextra -Werror -std=c11 -Isrc/common -o test_exec_rule \
              tests/host/test_exec_rule.c src/common/alr_elf.c src/common/alr_exec_rule.c && \
        ./test_path tests/cases/paths.tsv && ./test_exec_rule"
    ;;
accept)
    assert_context
    sync_tree
    # ALR_DISTROS_DIR selects which rootfs `preload` deploys into; the CLI reads
    # ALR_ROOT_DIR. Without this bridge, hand-testing against one rootfs while
    # the suite ran against the default made 9 passing tests report FAIL --
    # the code was fine, the suite was running an older preload.
    "${SSH[@]}" "cd ~/$REMOTE && \
        clang $CFLAGS_DEV -Isrc/common -Isrc/supervisor -o alr \
              src/cli/alr.c src/cli/alr_resolvd.c src/common/alr_exec_rule.c src/common/alr_elf.c src/supervisor/alr_supervisor.c && \
        chmod +x tests/device/acceptance.sh && \
        ${ALR_DISTROS_DIR:+ALR_ROOT_DIR=\$HOME/$ALR_DISTROS_DIR }ALR=./alr tests/device/acceptance.sh"
    ;;
bench)
    assert_context
    sync_tree
    "${SSH[@]}" "cd ~/$REMOTE && \
        clang -O2 -Wall -Isrc/common -o rw_cost bench/microbench/rw_cost.c && \
        ./rw_cost"
    ;;
bench-ab)
    assert_context
    sync_tree
    "${SSH[@]}" "cd ~/$REMOTE && \
        clang $CFLAGS_DEV -Isrc/common -Isrc/supervisor -o alr \
              src/cli/alr.c src/cli/alr_resolvd.c src/common/alr_exec_rule.c src/common/alr_elf.c src/supervisor/alr_supervisor.c && \
        chmod +x tests/device/bench.sh && \
        ${ALR_DISTROS_DIR:+ALR_ROOT_DIR=\$HOME/$ALR_DISTROS_DIR }ALR=./alr tests/device/bench.sh"
    ;;
breadth)
    assert_context
    sync_tree
    "${SSH[@]}" "cd ~/$REMOTE && \
        clang $CFLAGS_DEV -Isrc/common -Isrc/supervisor -o alr \
              src/cli/alr.c src/cli/alr_resolvd.c src/common/alr_exec_rule.c src/common/alr_elf.c src/supervisor/alr_supervisor.c && \
        chmod +x tests/device/breadth.sh && \
        ${ALR_DISTROS_DIR:+ALR_ROOT_DIR=\$HOME/$ALR_DISTROS_DIR }ALR=./alr tests/device/breadth.sh"
    ;;
preload)
    assert_context
    ./scripts/build-preload.sh
    R="${ALR_DISTROS_DIR:-alr-distros}/${ALR_DISTRO:-ubuntu-24.04}"
    "${SSH[@]}" "mkdir -p ~/$R/usr/lib/alr"
    "${SCP[@]}" build/libalr_preload.so build/libalr_preload.manifest.json \
                "$HOST:$R/usr/lib/alr/"
    "${SSH[@]}" "cd ~/$R/usr/lib/alr && \
        echo '-- glibc versions needed (must be 2.17 only) --' && \
        llvm-readelf -V libalr_preload.so 2>/dev/null | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tr '\n' ' ' && echo && \
        echo '-- defined FUNC symbols --' && \
        echo -n 'defined FUNC symbols: ' && \
        llvm-readelf --dyn-symbols libalr_preload.so 2>/dev/null | grep -c 'FUNC .*DEFAULT *[0-9]'"
    ;;
alr)
    assert_context
    ./scripts/build-preload.sh >/dev/null 2>&1 || true
    sync_tree
    "${SCP[@]}" build/libalr_preload.so "$HOST:$REMOTE/" 2>/dev/null || true
    "${SSH[@]}" "cd ~/$REMOTE && \
        clang $CFLAGS_DEV -Isrc/common -Isrc/supervisor -o alr \
              src/cli/alr.c src/cli/alr_resolvd.c src/common/alr_exec_rule.c src/common/alr_elf.c src/supervisor/alr_supervisor.c && \
        echo built"
    ;;
supervisor)
    assert_context
    sync_tree
    "${SSH[@]}" "cd ~/$REMOTE && \
        clang $CFLAGS_DEV -Isrc/supervisor -o test_supervisor \
              tests/device/test_supervisor.c src/supervisor/alr_supervisor.c && \
        ./test_supervisor"
    ;;
doctor)
    assert_context
    sync_tree
    "${SSH[@]}" "cd ~/$REMOTE && clang -O1 -o alr-doctor src/cli/doctor.c && ./alr-doctor"
    ;;
shell)
    exec "${SSH[@]}"
    ;;
*)
    echo "usage: $0 {test|supervisor|preload|alr|accept|bench|doctor|shell}" >&2; exit 1;;
esac
