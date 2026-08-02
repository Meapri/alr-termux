#!/data/data/com.termux/files/usr/bin/bash
# On-device acceptance suite.  Emits the canonical acceptance strings from
# docs/07-acceptance.md so results can be grepped and diffed across runs.
#
# MUST run inside a real Termux context: the Android app seccomp filter only
# exists for zygote-spawned app processes, so adb shell / run-as would produce
# false PASSes.  This refuses to run anywhere else.
#
#   ALR_SSH_KEY=<key> ./scripts/dev-push.sh accept
#
# Exit 0 iff every gate passed.  KNOWN_FAIL entries are expected and do not
# fail the run; they are the honest record of what does not work yet.
set -u

cd "$(dirname "$0")/../.." 2>/dev/null || true
ALR=${ALR:-./alr}
export ALR_ROOT_DIR=${ALR_ROOT_DIR:-$HOME/alr-distros}
R="$ALR_ROOT_DIR/${ALR_DISTRO:-ubuntu-24.04}"

pass=0; fail=0; known=0; skip=0

emit() { # emit <NAME> <PASS|FAIL|SKIP|KNOWN_FAIL:reason> [detail]
    printf '%-38s %s' "$1:" "$2"
    [ $# -ge 3 ] && printf '   %s' "$3"
    printf '\n'
    case "$2" in
        PASS) pass=$((pass+1));;
        FAIL) fail=$((fail+1));;
        SKIP) skip=$((skip+1));;
        KNOWN_FAIL*) known=$((known+1));;
    esac
}

# ck <NAME> <expected> <command...>   — compares exact stdout
ck() { local n="$1" want="$2"; shift 2
    local got; got=$("$@" 2>/dev/null | head -1)
    [ "$got" = "$want" ] && emit "$n" PASS || emit "$n" FAIL "got='$got' want='$want'"
}
# ckc <NAME> <substring> <command...> — substring match
ckc() { local n="$1" want="$2"; shift 2
    # search the WHOLE output: warnings (perl locale, apt notices) precede the
    # line we care about, so matching only the first line reports false FAILs
    local got; got=$("$@" 2>&1)
    case "$got" in *"$want"*) emit "$n" PASS;;
                   *) emit "$n" FAIL "no '$want' in output; first line: $(printf '%s' "$got"|head -1)";; esac
}
# ckrc <NAME> <expected rc> <command...>
ckrc() { local n="$1" want="$2"; shift 2
    "$@" >/dev/null 2>&1; local got=$?
    [ "$got" = "$want" ] && emit "$n" PASS || emit "$n" FAIL "rc=$got want=$want"
}
# ckre <NAME> <ERE> <command...> — first line matches the regex.  Use this
# instead of ckc for anything version-shaped: a pinned literal turns a healthy
# rootfs on a newer release into a FAIL.
ckre() { local n="$1" re="$2"; shift 2
    local got; got=$("$@" 2>/dev/null | head -1)
    printf '%s' "$got" | grep -qE "$re" \
        && emit "$n" PASS "$got" || emit "$n" FAIL "got='$got' want=~'$re'"
}

# ── validity gate: everything below is meaningless without this ──────────
uid=$(id -u)
sec=$(grep -oE '^Seccomp:[[:space:]]*[0-9]+' /proc/self/status | tr -dc 0-9)
ctx=$(cat /proc/self/attr/current 2>/dev/null | tr -d '\0')
if [ "${uid:-0}" -lt 10000 ] || [ "${sec:-0}" != "2" ]; then
    emit "ACCEPTANCE CONTEXT" FAIL "uid=$uid Seccomp=$sec ctx=$ctx"
    echo
    echo "REFUSING: not a measurable context.  The app seccomp filter is installed"
    echo "by the zygote for uid>=10000 only, so adb shell (Seccomp: 0) and run-as"
    echo "would report every syscall as ALLOWED.  See scripts/dev-bootstrap.md."
    exit 2
fi
emit "ACCEPTANCE CONTEXT" PASS "uid=$uid Seccomp=$sec ${ctx%%:c*}"
[ -x "$ALR" ] || { emit "ALR BINARY" FAIL "not built: $ALR"; exit 2; }
[ -d "$R" ]   || { emit "ALR ROOTFS" FAIL "not installed: $R"; exit 2; }
echo

# ── M3: first boot ──────────────────────────────────────────────────────
echo "── M3 첫 부팅 ──"
ckrc "ALR BOOT /bin/true"        0     $ALR run /bin/true
ck   "ALR BOOT /bin/echo"        alr   $ALR run /bin/echo alr
ckrc "ALR BOOT bash -c true"     0     $ALR run /bin/bash -c true
ckc  "ALR GUEST GLIBC VERSION"   "2.39" $ALR run /lib/aarch64-linux-gnu/libc.so.6

# The counterproofs: these are what make ADR 0001 and ADR 0002 evidence
# rather than argument.  Both MUST fail, and fail in the specific way.
LP="$R/lib/aarch64-linux-gnu:$R/usr/lib/aarch64-linux-gnu:$R/lib:$R/usr/lib"
env -i "$R/lib/ld-linux-aarch64.so.1" --library-path "$LP" --inhibit-cache \
        --argv0 true "$R/usr/bin/true" >/dev/null 2>&1
rc=$?
[ $rc -eq 159 ] && emit "ADR0001 NO SUPERVISOR DIES" PASS "exit=159 (128+31 SIGSYS)" \
                || emit "ADR0001 NO SUPERVISOR DIES" FAIL "exit=$rc want 159"
env -i "$R/usr/bin/true" >/dev/null 2>&1
rc=$?
[ $rc -ne 0 ] && emit "ADR0002 BARE EXECVE FAILS" PASS "exit=$rc (PT_INTERP unresolved)" \
              || emit "ADR0002 BARE EXECVE FAILS" FAIL "bare execve unexpectedly worked"
echo

# ── M4: path virtualization ─────────────────────────────────────────────
echo "── M4 경로 가상화 ──"
ckc "PRELOAD GUEST ETC"          "Ubuntu 24.04" $ALR run /bin/cat /etc/os-release
ck  "PRELOAD PROC SELF EXE"      /bin/readlink  $ALR run /bin/readlink /proc/self/exe
ck  "PRELOAD GETCWD CANON"       /usr/bin       $ALR run /bin/bash -c 'cd /usr/bin && pwd'
ck  "PRELOAD REALPATH CANON"     /usr/bin/dash  $ALR run /bin/bash -c 'readlink -f /bin/sh'
ckc "PRELOAD PATH SEARCH GUEST"  "Ubuntu GLIBC" $ALR run /bin/bash -c 'ldd --version'
# The escape that the normalize-before-sysdir ordering exists to stop: with the
# checks in the wrong order this reads ANDROID's /etc/os-release.
ck  "PRELOAD NORMALIZE BEFORE SYSDIR" "ID=ubuntu" \
    $ALR run /bin/bash -c 'grep -m1 ^ID= /proc/../etc/os-release'
ckc "PRELOAD SYSDIR PASSTHROUGH"  "Name:" $ALR run /bin/bash -c 'grep -m1 Name /proc/self/status'
ckrc "PRELOAD OPENDIR"            0 $ALR run /bin/ls /
n=$($ALR run /bin/ls / 2>/dev/null | wc -l | tr -d ' ')
[ "${n:-0}" -ge 15 ] && emit "PRELOAD LS ENTRY COUNT" PASS "$n entries" \
                     || emit "PRELOAD LS ENTRY COUNT" FAIL "$n entries"

# An absolute symlink TARGET is resolved by the kernel against the real host
# root, below anything we can hook, so it must be stored relative instead.
# Leaving it absolute is what emptied apt's /tmp/apt-dpkg-install-XXXXXX and
# broke `alr install --with git`.
ck  "PRELOAD SYMLINK RELATIVIZED"  ../etc/os-release \
    $ALR run /bin/bash -c 'ln -sf /etc/os-release /tmp/alrsl && readlink /tmp/alrsl'
ckc "PRELOAD SYMLINK DEREFERENCES" "Ubuntu" \
    $ALR run /bin/bash -c 'head -1 /tmp/alrsl'
ck  "PRELOAD SYMLINK DEPTH"        ../../../etc/os-release \
    $ALR run /bin/bash -c 'ln -sf /etc/os-release /usr/local/bin/alrsl && readlink /usr/local/bin/alrsl'
# /proc, /sys and /dev are NOT rewritten, so targets into them must stay
# absolute -- relativizing those would break them.
ck  "PRELOAD SYMLINK SYSDIR ABS"   /proc/self/exe \
    $ALR run /bin/bash -c 'ln -sf /proc/self/exe /tmp/alrsy && readlink /tmp/alrsy'
$ALR run /bin/bash -c 'rm -f /tmp/alrsl /tmp/alrsy /usr/local/bin/alrsl' >/dev/null 2>&1

# The image itself ships absolute symlinks, created by tar and so never seen by
# the preload.  ubuntu-base has 20; /usr/bin/awk -> /etc/alternatives/awk was
# among them, which is why ucf, locales, mercurial and php died with
# "awk: not found".  `alr install` relativizes them after extraction.
n=$(find "$R" -type l -lname '/*' 2>/dev/null \
    | grep -vE '/(proc|sys|dev)/' | wc -l | tr -d ' ')
[ "${n:-1}" -eq 0 ] && emit "ROOTFS NO ABSOLUTE SYMLINKS" PASS \
                    || emit "ROOTFS NO ABSOLUTE SYMLINKS" FAIL "$n broken link(s)"
ckc "ROOTFS AWK RESOLVES" "awk" $ALR run /usr/bin/awk --version
# The ldconfig no-op must be registered as a dpkg diversion, not merely written:
# a libc-bin upgrade restores the real wrapper, that wrapper runs the STATIC
# ldconfig.real, and its failure leaves libc-bin half-configured -- which makes
# every LATER apt install die too.  Check the database, not the file.
n=$(grep -c '^/usr/sbin/ldconfig$' "$R/var/lib/dpkg/diversions" 2>/dev/null)
[ "${n:-0}" -ge 1 ] && emit "ROOTFS LDCONFIG DIVERTED" PASS \
                    || emit "ROOTFS LDCONFIG DIVERTED" FAIL "no diversion registered"
ckrc "ROOTFS NO BROKEN PACKAGES" 1 \
    $ALR run /bin/sh -c 'dpkg -l 2>/dev/null | grep -q "^i[^i]"' 

# glibc 2.34+ builds nss_files into libc and opens the LITERAL /etc/passwd and
# /etc/group through an internal fopen, so without our own files backend every
# lookup answers from Android's /system/etc instead of the rootfs.
ckc "PRELOAD NSS GETPWNAM"  "root:x:0:0:"  $ALR run /usr/bin/getent passwd root
ck  "PRELOAD NSS GETGRNAM"  "root:x:0:"    $ALR run /usr/bin/getent group root
ckc "PRELOAD NSS GETPWUID"  "root"         $ALR run /usr/bin/getent passwd 0
n=$($ALR run /usr/bin/getent passwd 2>/dev/null | wc -l | tr -d ' ')
[ "${n:-0}" -ge 10 ] && emit "PRELOAD NSS ENUMERATE" PASS "$n entries" \
                     || emit "PRELOAD NSS ENUMERATE" FAIL "$n entries"

# Covers two interpositions at once: shadow aborts outright if the NETLINK_AUDIT
# socket fails with anything but EPROTONOSUPPORT, and then cannot lock unless
# lckpwdf() reaches the rootfs's /etc/.pwd.lock rather than the host's.
if $ALR run /usr/bin/test -x /sbin/groupadd >/dev/null 2>&1; then
    out=$(env ALR_FAKEROOT=1 $ALR run /sbin/groupadd -g 65123 alrck 2>&1)
    env ALR_FAKEROOT=1 $ALR run /sbin/groupdel alrck >/dev/null 2>&1
    case "$out" in
        *"cannot lock"*)     emit "PRELOAD SHADOW LOCK" FAIL "$out" ;;
        *"audit interface"*) emit "PRELOAD SHADOW AUDIT" FAIL "$out" ;;
        "")                  emit "PRELOAD SHADOW LOCK" PASS ;;
        *)                   emit "PRELOAD SHADOW LOCK" FAIL "$out" ;;
    esac
else
    emit "PRELOAD SHADOW LOCK" SKIP "no /sbin/groupadd"
fi
echo

# ── M5: exec continuity ─────────────────────────────────────────────────
echo "── M5 exec 연속성 ──"
ck  "PRELOAD EXEC DYNAMIC"       OLLEH $ALR run /bin/bash -c 'echo hello | tr a-z A-Z | rev'
ck  "PRELOAD EXEC NESTED"        NEST_OK $ALR run /bin/bash -c 'bash -c "bash -c \"echo NEST_OK\""'
ck  "PRELOAD EXEC SHEBANG"       SHEBANG_OK $ALR run /bin/bash -c \
    'printf "#!/bin/sh\necho SHEBANG_OK\n" > /tmp/t.sh; chmod +x /tmp/t.sh; /tmp/t.sh'
ck  "PRELOAD EXEC SHEBANG ENV"   ENV_OK $ALR run /bin/bash -c \
    'printf "#!/usr/bin/env sh\necho ENV_OK\n" > /tmp/e.sh; chmod +x /tmp/e.sh; /tmp/e.sh'
ck  "PRELOAD EXEC FIND"          /etc/os-release \
    $ALR run /usr/bin/find /etc -maxdepth 1 -name os-release
echo

# ── M6 preflight (package managers respond; transactions need fakeroot) ──
echo "── M6 사전점검 ──"
ckc "ALR APT VERSION"            "apt 2." $ALR run /usr/bin/apt-get --version
ck  "ALR DPKG ARCH"              arm64    $ALR run /usr/bin/dpkg --print-architecture
ckc "ALR DPKG VERSION"           "Debian" $ALR run /usr/bin/dpkg --version
echo

# ── M6: package manager (needs fakeroot) ────────────────────────────────
echo "── M6 패키지 매니저 ──"
if $ALR run /usr/bin/git --version >/dev/null 2>&1; then
    ck  "ALR GIT VERSION"  "git version 2.43.0" $ALR run /usr/bin/git --version
    ckc "ALR APT INSTALLED git" "git is already" \
        env ALR_FAKEROOT=1 $ALR run /usr/bin/apt-get install -y --no-install-recommends git
    ckc "ALR PERL DLOPEN"  "OK" $ALR run /usr/bin/perl -e 'use Cwd; print "OK\n"'
    # git's own workloads
    ckc "ALR GIT INIT"     "INIT_OK" $ALR run /bin/bash -c \
        'rm -rf /tmp/r && mkdir -p /tmp/r && cd /tmp/r && git init -q . && echo INIT_OK'
    ckc "ALR GIT COMMIT"   "COMMIT_OK" $ALR run /bin/bash -c \
        'cd /tmp/r && git config user.email a@b && git config user.name a && \
         echo x > f && git add f && git commit -qm t && echo COMMIT_OK'
    ckc "ALR GIT STATUS"   "STATUS_OK" $ALR run /bin/bash -c \
        'cd /tmp/r && git status --porcelain >/dev/null && echo STATUS_OK'
    ckc "ALR GIT CLONE LOCAL" "CLONE_OK" $ALR run /bin/bash -c \
        'rm -rf /tmp/r2 && git clone -q /tmp/r /tmp/r2 && echo CLONE_OK'
else
    emit "ALR GIT VERSION" SKIP "git not installed; run apt-get install git"
fi
echo

# ── M7: target workloads ────────────────────────────────────────────────
echo "── M7 타깃 워크로드 ──"
if [ -x "$R/opt/node/bin/node" ]; then
    # Any working major -- pinning v22 made a v24 rootfs report FAIL for a
    # product that was fine. Assert the shape, not the release.
    ckre "ALR NODE VERSION"  '^v[0-9][0-9]*\.[0-9]' $ALR run /opt/node/bin/node --version
    # process.execPath must be the GUEST path: npm/npx respawn through it
    ck  "ALR NODE EXECPATH"  /opt/node/bin/node \
        $ALR run /opt/node/bin/node -e 'console.log(process.execPath)'
    # libuv issues raw path syscalls; without syscall() interposition this ENOENTs
    ckc "ALR NODE FS STAT"   STAT_OK $ALR run /opt/node/bin/node -e \
        'console.log(require("fs").statSync("/etc/os-release").size>0?"STAT_OK":"BAD")'
    # Node>=20 calls io_uring_setup at loop init and dies on SIGSYS without rescue
    ckc "ALR NODE IO_URING SURVIVE" URING_OK $ALR run /opt/node/bin/node -e \
        'require("fs").promises.readFile("/etc/hostname").then(()=>console.log("URING_OK")).catch(()=>console.log("URING_OK"))'
    ckre "ALR NPM VERSION"   '^[0-9][0-9]*\.[0-9]' $ALR run /usr/local/bin/npm --version
    ckc "ALR NODE SHEBANG"   NODE_SHEBANG_OK $ALR run /bin/bash -c \
        'printf "#!/usr/bin/env node\nconsole.log(\"NODE_SHEBANG_OK\")\n">/tmp/s.js; chmod +x /tmp/s.js; /tmp/s.js'
else
    emit "ALR NODE VERSION" SKIP "node not installed"
fi
if [ -x "$R/usr/local/bin/codex" ]; then
    # codex ships as a STATIC binary (no INTERP, no NEEDED), so LD_PRELOAD cannot
# reach it: it runs with NO path virtualization and sees ANDROID's filesystem,
# not the rootfs.  `codex --version` succeeding proves the binary executes -- it
# does NOT prove codex operates inside the guest.  Track the linkage so a future
# dynamic build is noticed rather than assumed.
if llvm-readelf -d "$R/usr/local/bin/codex" 2>/dev/null | grep -q NEEDED; then
    emit "ALR CODEX LINKAGE" PASS "dynamic - preload reaches it"
else
    emit "ALR CODEX LINKAGE" KNOWN_FAIL:static-unhooked \
         "no NEEDED: runs without path virtualization"
fi
ckc "ALR CODEX VERSION" "codex-cli" $ALR run /usr/local/bin/codex --version
else
    emit "ALR CODEX VERSION" SKIP "codex not installed"
fi
echo

# ── supervisor invariants — the line separating this from PRoot ─────────
echo "── 슈퍼바이저 불변식 ──"
stats=$(ALR_LOG=1 $ALR run /bin/bash -c 'ls / >/dev/null' 2>&1 >/dev/null | tail -1)
case "$stats" in
  *"path_traps=0"*"syscall_stops=0"*) emit "SUPERVISOR NO SYSCALL STOPS" PASS "$stats";;
  *) emit "SUPERVISOR NO SYSCALL STOPS" FAIL "$stats";;
esac
sig=$(printf '%s' "$stats" | grep -oE 'sigsys=[0-9]+' | cut -d= -f2)
[ "${sig:-99}" -le 8 ] && emit "SUPERVISOR SIGSYS PER RUN" PASS "sigsys=$sig (<=8)" \
                       || emit "SUPERVISOR SIGSYS PER RUN" FAIL "sigsys=$sig"
echo

# ── stability ───────────────────────────────────────────────────────────
ok=0; for i in 1 2 3 4 5 6 7 8 9 10; do $ALR run /bin/ls / >/dev/null 2>&1 && ok=$((ok+1)); done
[ $ok -eq 10 ] && emit "ALR STABILITY 10x" PASS "10/10" || emit "ALR STABILITY 10x" FAIL "$ok/10"

# ── documented gaps: asserted so they cannot regress silently ───────────
echo
echo "── 프로세스 생성 (docs/04-preload-spec.md §9.4) ──"
# glibc's posix_spawn/system/popen reach the kernel through internal aliases
# (__spawnix, an internal execve), never our execve, so their children were
# exec'd with PT_INTERP resolved against the ANDROID root.  Every shell-based
# test passed while this was broken -- so verify with the REAL consumers:
# GNU make 4.3+ spawns each recipe line with posix_spawn, and CPython's
# os.system is libc system().
if $ALR run /usr/bin/test -x /usr/bin/make >/dev/null 2>&1; then
    ckc "SPAWN MAKE RECIPE" MAKEOK $ALR run /bin/sh -c \
        'cd /tmp && printf "all:\n\t@echo MAKEOK\n" > alrmk.mk && make -s -f alrmk.mk'
else
    emit "SPAWN MAKE RECIPE" SKIP "make not installed"
fi
if $ALR run /usr/bin/test -x /usr/bin/python3 >/dev/null 2>&1; then
    ckc "SPAWN LIBC SYSTEM"    SYSOK  $ALR run /usr/bin/python3 -c 'import os;os.system("echo SYSOK")'
    ckc "SPAWN LIBC SYSTEM RC" "rc=0" $ALR run /usr/bin/python3 -c 'import os;print("rc=%d"%os.system("true"))'
else
    emit "SPAWN LIBC SYSTEM" SKIP "python3 not installed"
fi
# posix_spawn and popen have no dependable CLI consumer, so bind them directly.
# Guard on the HEADER, not just the compiler: `apt install gcc
# --no-install-recommends` leaves libc6-dev out, and the probe then fails to
# build with "spawn.h: No such file" -- which reads identically to the runtime
# failure it is meant to detect.
if $ALR run /usr/bin/test -f /usr/include/spawn.h >/dev/null 2>&1; then
    cp tests/device/probe_spawn.c "$R/tmp/" 2>/dev/null
    if $ALR run /usr/bin/gcc -o /tmp/alrspawn /tmp/probe_spawn.c >/dev/null 2>&1; then
        ckc "SPAWN POSIX_SPAWN" PSOK    $ALR run /tmp/alrspawn
        ckc "SPAWN POPEN"       POPENOK $ALR run /tmp/alrspawn
    else
        emit "SPAWN POSIX_SPAWN" FAIL "probe did not compile"
    fi
else
    emit "SPAWN POSIX_SPAWN" SKIP "no libc6-dev (spawn.h absent)"
fi

echo
echo "── 호스트 이름 해석 ──"
# The bridge answers from BIONIC, so it reads Android's /system/etc/hosts --
# the rootfs's own /etc/hosts had no consumer on either path until the files
# backend landed.  Use an address Android cannot possibly supply.
$ALR run /bin/sh -c \
    'grep -q alracc /etc/hosts || echo "10.77.77.77 alracc.invalid" >> /etc/hosts' \
    >/dev/null 2>&1
ckc "RESOLV HOSTS FILES"    10.77.77.77    $ALR run /usr/bin/getent hosts  alracc.invalid
ckc "RESOLV AHOSTS FILES"   10.77.77.77    $ALR run /usr/bin/getent ahosts alracc.invalid
ckc "RESOLV REVERSE FILES"  alracc.invalid $ALR run /usr/bin/getent hosts  10.77.77.77
# `getent ahosts` is the getaddrinfo path (already bridged); `getent hosts` is
# the legacy gethostby* path, which was NOT.  Both must resolve.
if $ALR run /usr/bin/getent ahosts ports.ubuntu.com >/dev/null 2>&1; then
    ckc "RESOLV LEGACY DNS" ports.ubuntu.com $ALR run /usr/bin/getent hosts ports.ubuntu.com
else
    emit "RESOLV LEGACY DNS" SKIP "no network"
fi

echo
echo "── 알려진 미구현 (회귀 감시) ──"
# Android denies /proc/stat to app UIDs, so libuv finds no cpuN lines and
# os.cpus() returned [].  The COUNT is real (sched_getaffinity works); the time
# fields are zeros and must not be read as utilisation.
if [ -x "$R/opt/node/bin/node" ]; then
    n=$($ALR run /opt/node/bin/node -e 'console.log(require("os").cpus().length)' 2>/dev/null)
    [ "${n:-0}" -ge 1 ] && emit "PROC STAT CPU COUNT" PASS "$n cpus" \
                        || emit "PROC STAT CPU COUNT" FAIL "os.cpus() = ${n:-?}"
    ckc "PROC CPUINFO UNTOUCHED" "CPU part" $ALR run /bin/grep -m1 "CPU part" /proc/cpuinfo
else
    emit "PROC STAT CPU COUNT" SKIP "node not installed"
fi
# Scan the WHOLE table, not just line 1: a leak on any row is a leak.  Checks
# /proc/mounts, /proc/self/mountinfo and the setmntent() path df uses.
leak=""
for f in /proc/mounts /proc/self/mounts /proc/self/mountinfo; do
    t=$($ALR run /bin/cat "$f" 2>/dev/null)
    case "$t" in
      *"/dev/block"*|*erofs*|*/apex/*|*/vendor*|*/data/data/*|*/storage/*)
        leak="$f: $(printf '%s' "$t" | grep -m1 -E '/dev/block|erofs|/apex/|/vendor|/data/data/|/storage/')";;
    esac
    [ -n "$t" ] || leak="$f: empty"
done
[ -z "$leak" ] && emit "PRELOAD PROC MOUNTS" PASS \
               || emit "PRELOAD PROC MOUNTS" FAIL "$leak"
ckc "PRELOAD DF READS SYNTH" "/dev/root" $ALR run /bin/df /
nm=$($ALR run /bin/bash -c 'grep -m1 Name /proc/self/status' 2>/dev/null)
case "$nm" in
  *ld-linux*) emit "PRELOAD PROC SELF STATUS" FAIL "loader name visible: $nm";;
  *grep*)     emit "PRELOAD PROC SELF STATUS" PASS "$nm";;
  *)          emit "PRELOAD PROC SELF STATUS" FAIL "unexpected: $nm";;
esac
# comm and status must agree -- one prctl feeds both, so a mismatch means the
# name was set somewhere else and only half the views are corrected.
ck "PRELOAD PROC SELF COMM" cat $ALR run /bin/cat /proc/self/comm
# The identity must travel through exec re-dispatch, not just the first program:
# ALR_GUEST_EXE feeds /proc/self/exe, and npm re-spawns node from it through a
# shell wrapper.  Before this was fixed, every child reported its PARENT.
ck "PRELOAD EXEC IDENTITY EXE"  /usr/bin/readlink \
    $ALR run /bin/bash -c 'readlink /proc/self/exe'
ck "PRELOAD EXEC IDENTITY COMM" cat \
    $ALR run /bin/bash -c 'bash -c "cat /proc/self/comm"' 
$ALR run /bin/bash -c 'f=$(mktemp /tmp/alrXXXXXX) && echo ok > "$f" && cat "$f"' 2>/dev/null \
    | grep -q ok && emit "PRELOAD MKSTEMP" PASS \
                 || emit "PRELOAD MKSTEMP" KNOWN_FAIL:mkstemp-not-interposed
# stat() and fstat() must agree on a copy-fallback "hardlink" -- docs/04 §6.2
# documents the failure: without fstat/fstat64 interposed, stat(path) reports
# nlink=2 while fstat(fd) on the same file reports 1 with a DIFFERENT inode, and
# dpkg's integrity check breaks on the disagreement.  Measured control (M13):
# with the wrappers removed this prints MISMATCH, ino 355816 vs 355817.
# Must be ONE process -- the identity table is per-process by design (§8.2), so
# a shell test with `ln` and the check in separate processes proves nothing.
if $ALR run /usr/bin/test -f /usr/include/spawn.h >/dev/null 2>&1; then
    cp tests/device/probe_nlink.c "$R/tmp/" 2>/dev/null
    if $ALR run /usr/bin/gcc -o /tmp/alrnl /tmp/probe_nlink.c >/dev/null 2>&1; then
        ckc "PRELOAD LINK IDENTITY NLINK" NLINKOK $ALR run /tmp/alrnl
    else
        emit "PRELOAD LINK IDENTITY NLINK" FAIL "probe did not compile"
    fi
else
    emit "PRELOAD LINK IDENTITY NLINK" SKIP "no libc6-dev (spawn.h absent)"
fi
$ALR run /bin/bash -c 'ln /etc/os-release /tmp/l2s.$$ 2>&1 | head -1; :' 2>/dev/null \
    | grep -qi 'denied\|not permitted' && emit "PRELOAD LINK2SYMLINK" KNOWN_FAIL:not-implemented \
                                       || emit "PRELOAD LINK2SYMLINK" PASS
# Probe with a WRITE, not an open: `: < /dev/full` is O_RDONLY and would pass
# on a /dev/zero redirect that never delivers ENOSPC -- exactly the shortcut
# docs/04-preload-spec.md §12 forbids.  /dev/full is a deliberate non-goal
# (docs/RISKS.md): serving it means interposing write(), the hottest syscall in
# the process, for a device node no target workload touches, and every stdio
# symbol missed would fail SILENTLY as a successful write.
$ALR run /bin/bash -c 'echo x > /dev/full' 2>&1 | grep -qi 'no space left' \
    && emit "PRELOAD DEV FULL ENOSPC" PASS \
    || emit "PRELOAD DEV FULL ENOSPC" KNOWN_FAIL:non-goal-devfull

echo
echo "─────────────────────────────────────────────────────────────"
echo "  PASS=$pass  FAIL=$fail  KNOWN_FAIL=$known  SKIP=$skip"
echo "ALR DEVICE ACCEPTANCE: $([ $fail -eq 0 ] && echo PASS || echo FAIL)"
exit $([ $fail -eq 0 ] && echo 0 || echo 1)
