#!/data/data/com.termux/files/usr/bin/bash
# The install path has no automated coverage, and that is the largest hole in
# this repo's testing.
#
# tests/device/acceptance.sh exits 2 unless the rootfs already exists
# (acceptance.sh's own validity gate), so every one of its 114 checks measures
# a rootfs provisioned by an EARLIER binary.  A change that broke extraction,
# mangled /etc, or failed to place the preload would leave that number
# untouched.  This repo's most expensive recurring bug is "the rootfs was not
# what I thought" -- and nothing ran the code that builds it.
#
# This provisions a throwaway rootfs from the CACHED tarball (no network) and
# asserts properties of the RESULT, then deliberately breaks two things and
# asserts the failures are loud.  It is separate from acceptance.sh because it
# costs a full extraction; run it when cmd_install changes.
#
#   ALR_SSH_KEY=<key> ./scripts/dev-push.sh install-gate
set -u

cd "$(dirname "$0")/../.." 2>/dev/null || true
ALR=${ALR:-./alr}
CACHE="$PREFIX/var/lib/alr/cache"
SRC="$CACHE/ubuntu-24.04.tar.gz"
GATE_ROOT="$HOME/alr-gate"
NAME=alrgate
G="$GATE_ROOT/$NAME"

pass=0; fail=0; skip=0
emit() {
    printf '%-40s %s' "$1:" "$2"
    [ $# -ge 3 ] && printf '   %s' "$3"
    printf '\n'
    case "$2" in PASS) pass=$((pass+1));; FAIL) fail=$((fail+1));; SKIP) skip=$((skip+1));; esac
}

cleanup() { rm -rf "$GATE_ROOT" "$CACHE/$NAME.tar.gz" "$CACHE/$NAME-trunc.tar.gz" 2>/dev/null; }
trap cleanup EXIT INT TERM

# ── validity gate: same rule as every other harness here ────────────────
uid=$(id -u)
sec=$(grep -oE '^Seccomp:[[:space:]]*[0-9]+' /proc/self/status | tr -dc 0-9)
if [ "${uid:-0}" -lt 10000 ] || [ "${sec:-0}" != "2" ]; then
    echo "REFUSING: not a measurable context (uid=$uid Seccomp=$sec)."
    exit 2
fi
[ -x "$ALR" ] || { echo "alr not built: $ALR"; exit 2; }

# A missing input is a REFUSAL, not a SKIP: a token on something that was never
# run is exactly what docs/07-acceptance.md:39 forbids.
if [ ! -r "$SRC" ]; then
    echo "REFUSING: no cached tarball at $SRC"
    echo "  seed it with:  alr install ubuntu-24.04"
    exit 2
fi
# Never let this point at the real rootfs.
if [ "$GATE_ROOT" = "${ALR_ROOT_DIR:-$HOME/alr-distros}" ]; then
    echo "REFUSING: GATE_ROOT equals the live ALR_ROOT_DIR; this harness deletes it"
    exit 2
fi

echo "── alr install gate ─────────────────────────────────────────"
echo "  source $SRC"
echo "  target $G   (deleted on exit)"
echo

cleanup
mkdir -p "$GATE_ROOT"

# ── 1. a real install, from the cache, no network ───────────────────────
# --url makes cmd_install skip release discovery entirely, and the distro name
# keys the cache entry, so `alrgate` forces a fetch of the file:// URL rather
# than silently reusing the ubuntu-24.04 entry.
ALR_ROOT_DIR="$GATE_ROOT" "$ALR" install "$NAME" --url "file://$SRC" >/dev/null 2>&1
rc=$?
[ "$rc" = 0 ] && emit "INSTALL EXIT" PASS || emit "INSTALL EXIT" FAIL "rc=$rc"

# Hardlink members are the ones that broke silently before: tar cannot create
# them under Android's SELinux policy and M3 recorded these exact two vanishing.
for f in usr/bin/uncompress usr/bin/perl5.38.2; do
    [ -f "$G/$f" ] && emit "INSTALL HARDLINK $(basename $f)" PASS \
                   || emit "INSTALL HARDLINK $(basename $f)" FAIL "missing"
done
[ -r "$G/usr/lib/alr/libalr_preload.so" ] \
    && emit "INSTALL PRELOAD PRESENT" PASS || emit "INSTALL PRELOAD PRESENT" FAIL "absent"
[ -x "$G/lib/ld-linux-aarch64.so.1" ] \
    && emit "INSTALL LDSO PRESENT" PASS || emit "INSTALL LDSO PRESENT" FAIL "absent"

# ── 2. the rootfs actually boots, and is actually virtualized ───────────
ALR_ROOT_DIR="$GATE_ROOT" ALR_DISTRO="$NAME" "$ALR" run /bin/true >/dev/null 2>&1
rc=$?
[ "$rc" = 0 ] && emit "INSTALL BOOT" PASS || emit "INSTALL BOOT" FAIL "rc=$rc"

# THE ONE THAT PROVES VIRTUALIZATION.  /bin/true passing proves nothing: it
# touches no guest path and succeeds on an unvirtualized rootfs too.  Android
# has no /usr, so reading a file BY ITS GUEST PATH can only work if rewriting
# is in effect.
got=$(ALR_ROOT_DIR="$GATE_ROOT" ALR_DISTRO="$NAME" "$ALR" run \
        /bin/cat /etc/os-release 2>/dev/null | head -1)
case "$got" in
    *Ubuntu*) emit "INSTALL VIRTUALIZED" PASS "$got";;
    *)        emit "INSTALL VIRTUALIZED" FAIL "guest could not read its own /etc/os-release: '$got'";;
esac

# ── 3. negative controls: the failures must be LOUD ─────────────────────
# Without these the gate above cannot distinguish "install works" from "install
# reports success no matter what" -- which is precisely the bug that made this
# harness necessary (the return of install_preload() was discarded).

# (a) a truncated tarball must not produce a successful install
head -c 2000000 "$SRC" > "$CACHE/$NAME-trunc.tar.gz" 2>/dev/null
rm -rf "$GATE_ROOT/trunc" "$CACHE/trunc.tar.gz"
ALR_ROOT_DIR="$GATE_ROOT" "$ALR" install trunc \
    --url "file://$CACHE/$NAME-trunc.tar.gz" >/dev/null 2>&1
rc=$?
[ "$rc" != 0 ] && emit "INSTALL REJECTS TRUNCATED" PASS "rc=$rc" \
               || emit "INSTALL REJECTS TRUNCATED" FAIL "reported success on a truncated tarball"
rm -rf "$GATE_ROOT/trunc"

# (b) an unusable preload must not boot silently.  glibc WARNS and IGNORES an
# LD_PRELOAD object it cannot load, so the guest comes up unvirtualized -- the
# exact silent mode alr now refuses.
cp "$G/usr/lib/alr/libalr_preload.so" "$G/.pl.save" 2>/dev/null
rm -f "$G/usr/lib/alr/libalr_preload.so"
w=$(ALR_ROOT_DIR="$GATE_ROOT" ALR_DISTRO="$NAME" "$ALR" run /bin/echo hi 2>&1 \
      | grep -c 'reason=preload-missing-in-rootfs')
cp "$G/.pl.save" "$G/usr/lib/alr/libalr_preload.so" 2>/dev/null; rm -f "$G/.pl.save"
[ "${w:-0}" -ge 1 ] && emit "INSTALL WARNS ON MISSING PRELOAD" PASS \
                    || emit "INSTALL WARNS ON MISSING PRELOAD" FAIL "silent"

echo
echo "─────────────────────────────────────────────────────────────"
echo "  PASS=$pass  FAIL=$fail  SKIP=$skip"
echo "ALR INSTALL GATE: $([ "$fail" = 0 ] && echo PASS || echo FAIL)"
[ "$fail" = 0 ]
