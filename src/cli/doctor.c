/* alr doctor — device capability probe.
 *
 * Answers the PENDING_DEVICE questions in docs/01-platform-facts.md §G (P1..P12)
 * and emits the SIGSYS emulation table the supervisor needs
 * (docs/03-supervisor-spec.md §5).
 *
 * VALIDITY CONTRACT — read before trusting any output:
 *   The Android app seccomp filter is installed by the zygote and only for
 *   uid >= AID_APP_START (10000).  A process that did NOT descend from a
 *   zygote-forked app has NO filter, so every syscall looks ALLOWED and every
 *   result here is meaningless.  That includes `adb shell` (u:r:shell:s0) and
 *   `run-as` (u:r:runas_app:s0).  P1 detects this and refuses to continue.
 *   Run this from inside a real Termux session (or over sshd started from one).
 *
 * Build on-device:   clang -O1 -o alr-doctor doctor.c
 * Build with NDK:    $NDK/.../clang --target=aarch64-linux-android24 -O1 -o alr-doctor doctor.c
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/system_properties.h>

/* bionic exposes these via <asm/ioctls.h> pulled in by <sys/ioctl.h>, but the
 * definitions moved around across NDK versions — define them if absent. */
#ifndef TIOCGPTN
#define TIOCGPTN    _IOR('T', 0x30, unsigned int)
#endif
#ifndef TIOCSPTLCK
#define TIOCSPTLCK  _IOW('T', 0x31, int)
#endif

/* aarch64 numbers we name explicitly so header variance cannot bite us. */
#define NR_set_robust_list 99
#define NR_get_robust_list 100
#define NR_rseq            293
#define NR_getrandom       278
#define NR_memfd_create    279
#define NR_openat2         437
#define NR_faccessat2      439
#define NR_close_range     436
#define NR_io_uring_setup  425
#define NR_statx           291
#define NR_clone3          435
#define SWEEP_MAX          468

/* ── result bookkeeping ─────────────────────────────────────────────────── */

enum grade { G_PASS, G_MITIGATED, G_EXPECTED, G_WARN, G_FATAL, G_INVALID };
static const char *grade_s[] = { "PASS", "MITIGATED", "EXPECTED", "WARN",
                                 "FATAL", "INVALID" };
static int counts[6];
static int probe_no;

static void say(const char *probe, enum grade g, const char *fmt, ...)
{
    va_list ap;
    counts[g]++;
    printf("  [%-3s] %-34s %-9s ", probe, "", grade_s[g]);
    /* re-print with the label in place; keeps columns stable */
    printf("\r  [%-3s] ", probe);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("   -> %s\n", grade_s[g]);
    fflush(stdout);
    (void)probe_no;
}

/* ── P1: is this context even measurable? ───────────────────────────────── */

static int seccomp_mode(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    int mode = -1;
    if (!f) return -1;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "Seccomp:", 8)) { mode = atoi(line + 8); break; }
    fclose(f);
    return mode;
}

static void read_first_line(const char *path, char *out, size_t n)
{
    int fd = open(path, O_RDONLY);
    ssize_t r;
    out[0] = 0;
    if (fd < 0) return;
    r = read(fd, out, n - 1);
    close(fd);
    if (r > 0) { out[r] = 0; out[strcspn(out, "\n")] = 0; }
}

/* The Android release this build supports.  ADR 0007: 16 only -- 12~15 are out
 * of scope, not merely unmeasured.  The zygote seccomp allowlist grows with
 * every release (android12 365 lines -> android16 392), and that is the axis
 * the whole design rests on. */
#define ALR_SUPPORTED_RELEASE "16"

static int probe_release(void)
{
    char rel[PROP_VALUE_MAX] = "", sdk[PROP_VALUE_MAX] = "";
    int supported;

    __system_property_get("ro.build.version.release", rel);
    __system_property_get("ro.build.version.sdk", sdk);

    supported = (strcmp(rel, ALR_SUPPORTED_RELEASE) == 0);
    printf("  [P0 ] Android %s (SDK %s)  -> %s\n",
           rel[0] ? rel : "?", sdk[0] ? sdk : "?",
           supported ? "PASS (supported)" : "WARN (UNSUPPORTED)");

    if (!supported) {
        /* Say it, do not block it.  We measured "we did not test this", not
         * "this does not work" -- refusing here would claim more than we know.
         * But a silent READY on an untested release hides that distinction,
         * and the sweep below is exactly the evidence the user needs to decide.
         * ADR 0007 has the reasoning. */
        printf("        !! alr supports Android " ALR_SUPPORTED_RELEASE
               " only (docs/adr/0007-android-16-only.md).\n"
               "           This release was never tested and will not be.\n"
               "           alr does NOT refuse to run -- the P2 sweep below is\n"
               "           measured on THIS device, so compare it against\n"
               "           docs/evidence/sweeps/ with scripts/diff-sweep.sh.\n"
               "           A non-empty diff means the shipped emulation table\n"
               "           does not describe this phone.\n");
        counts[G_WARN]++;
    } else {
        counts[G_PASS]++;
    }
    return supported;
}

static int probe_validity(void)
{
    char ctx[128];
    int mode = seccomp_mode(), ok = 1;
    uid_t uid = getuid();

    read_first_line("/proc/self/attr/current", ctx, sizeof ctx);

    printf("  [P1 ] uid=%u  selinux=%s  Seccomp=%d\n", uid,
           ctx[0] ? ctx : "?", mode);

    if (uid < 10000) {
        printf("        !! uid < 10000: not an app process.  adb shell / run-as\n"
               "           are NOT zygote-spawned and carry no app seccomp filter.\n");
        ok = 0;
    }
    if (mode != 2) {
        printf("        !! Seccomp mode is %d, expected 2 (SECCOMP_MODE_FILTER).\n"
               "           With no filter installed every syscall looks ALLOWED.\n", mode);
        ok = 0;
    }
    if (strstr(ctx, "shell") || strstr(ctx, "runas_app")) {
        printf("        !! SELinux context is %s, not untrusted_app*.\n", ctx);
        ok = 0;
    }
    counts[ok ? G_PASS : G_INVALID]++;
    printf("        -> %s\n", ok ? "PASS (context is measurable)"
                                 : "INVALID (results would be meaningless)");
    return ok;
}

/* ── P2: syscall sweep ──────────────────────────────────────────────────── */

enum sysres { S_ALLOWED, S_BLOCKED, S_NOSYS, S_HUNG, S_CRASH, S_SKIPPED };
static unsigned char sweep[SWEEP_MAX];

/* Syscalls we must not invoke even with poison arguments: they either affect
 * something outside this process or make the harness itself unreliable. */
static int is_dangerous(long nr)
{
    switch (nr) {
    case 93:  case 94:                    /* exit, exit_group                */
    case 129: case 130: case 131:         /* kill, tkill, tgkill  (-1 = ALL) */
    case 142:                             /* reboot                          */
    case 117:                             /* ptrace                          */
    case 220: case NR_clone3:             /* clone, clone3                   */
    case 221: case 281:                   /* execve, execveat                */
    case 211: case 212:                   /* sendmsg / recvmsg on stray fds  */
    case 167:                             /* prctl (can mutate this process) */
    case 277:                             /* seccomp (could install a filter) */
    case 97:                              /* unshare (tested properly in P7) */
    case 81:  case 82:                    /* sync, fsync: slow, no info      */
        return 1;
    default:
        return 0;
    }
}

static const char *sysname(long nr)
{
    switch (nr) {
    case NR_set_robust_list: return "set_robust_list";
    case NR_get_robust_list: return "get_robust_list";
    case NR_rseq:            return "rseq";
    case NR_getrandom:       return "getrandom";
    case NR_memfd_create:    return "memfd_create";
    case NR_openat2:         return "openat2";
    case NR_faccessat2:      return "faccessat2";
    case NR_close_range:     return "close_range";
    case NR_statx:           return "statx";
    case 425: return "io_uring_setup";  case 426: return "io_uring_enter";
    case 427: return "io_uring_register";
    case 441: return "epoll_pwait2";    case 449: return "futex_waitv";
    case 452: return "fchmodat2";
    case 39:  return "umount2";         case 40:  return "mount";
    case 51:  return "chroot";          case 161: return "sethostname";
    case 162: return "setdomainname";   case 170: return "settimeofday";
    case 171: return "adjtimex";        case 112: return "clock_settime";
    case 266: return "clock_adjtime";   case 143: return "setregid";
    case 144: return "setgid";          case 145: return "setreuid";
    case 146: return "setuid";          case 147: return "setresuid";
    case 149: return "setresgid";       case 151: return "setfsuid";
    case 152: return "setfsgid";        case 159: return "setgroups";
    case 96:  return "set_tid_address"; case 98:  return "futex";
    case 116: return "syslog";          case 224: return "swapon";
    case 225: return "swapoff";         case 105: return "init_module";
    case 106: return "delete_module";   case 89:  return "acct";
    default:  return NULL;
    }
}

static enum sysres run_one(long nr)
{
    pid_t p;
    int st;

    if (is_dangerous(nr)) return S_SKIPPED;

    p = fork();
    if (p < 0) return S_CRASH;
    if (p == 0) {
        /* Poison every argument: -1 is an invalid fd AND an invalid pointer,
         * so a permitted syscall fails fast with EBADF/EFAULT/EINVAL and never
         * does real work.  alarm() is the backstop for anything that blocks. */
        long r;
        alarm(2);
        errno = 0;
        r = syscall(nr, -1L, -1L, -1L, -1L, -1L, -1L);
        _exit(r == -1 ? (errno & 0xff) : 0);
    }
    if (waitpid(p, &st, 0) < 0) return S_CRASH;

    if (WIFSIGNALED(st)) {
        int s = WTERMSIG(st);
        if (s == SIGSYS)   return S_BLOCKED;
        if (s == SIGALRM)  return S_HUNG;
        return S_CRASH;
    }
    if (WIFEXITED(st))
        return WEXITSTATUS(st) == ENOSYS ? S_NOSYS : S_ALLOWED;
    return S_CRASH;
}

static void probe_sweep(void)
{
    long nr;
    int blocked = 0, nosys = 0, hung = 0, skipped = 0;

    printf("\n  [P2 ] syscall sweep 0..%d (fork-per-syscall, poison args)\n",
           SWEEP_MAX - 1);

    for (nr = 0; nr < SWEEP_MAX; nr++) {
        sweep[nr] = (unsigned char)run_one(nr);
        switch (sweep[nr]) {
        case S_BLOCKED: blocked++; break;
        case S_NOSYS:   nosys++;   break;
        case S_HUNG:    hung++;    break;
        case S_SKIPPED: skipped++; break;
        default: break;
        }
    }

    printf("        blocked=%d  not-implemented=%d  hung=%d  skipped=%d\n",
           blocked, nosys, hung, skipped);
    printf("\n        BLOCKED (SIGSYS / SYS_SECCOMP) — these need emulation:\n");
    for (nr = 0; nr < SWEEP_MAX; nr++) {
        if (sweep[nr] != S_BLOCKED) continue;
        const char *n = sysname(nr);
        printf("          %3ld  %s\n", nr, n ? n : "(unnamed)");
    }
    if (hung) {
        printf("\n        HUNG (alarm fired — inconclusive, re-probe by hand):\n");
        for (nr = 0; nr < SWEEP_MAX; nr++)
            if (sweep[nr] == S_HUNG) printf("          %3ld\n", nr);
    }
    counts[blocked ? G_PASS : G_WARN]++;
}

/* ── individually meaningful syscalls ───────────────────────────────────── */

static void probe_named(void)
{
    struct { const char *p; long nr; const char *why; int fatal; } t[] = {
        { "P10", NR_getrandom,   "getrandom — NO glibc fallback",        1 },
        { "P10", NR_memfd_create,"memfd_create — NO glibc fallback",     1 },
        { "P2a", NR_set_robust_list,
          "set_robust_list — ld.so calls this before any ctor", 0 },
        { "P2a", NR_rseq,        "rseq — GLIBC_TUNABLES can avoid it",   0 },
        { "P2a", NR_clone3,      "clone3 — glibc falls back on ENOSYS",  0 },
        { "P2a", NR_faccessat2,  "faccessat2",                           0 },
        { "P2a", NR_openat2,     "openat2",                              0 },
        { "P2a", NR_io_uring_setup,
          "io_uring_setup — Node>=20/libuv>=1.45 dies here",             0 },
        { "P2a", NR_statx,       "statx",                                0 },
    };
    size_t i;

    printf("\n  named syscalls that decide the design\n");
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        enum sysres r = sweep[t[i].nr];
        const char *v = r == S_BLOCKED ? "BLOCKED" :
                        r == S_NOSYS   ? "not-implemented" :
                        r == S_SKIPPED ? "skipped" :
                        r == S_HUNG    ? "hung" : "allowed";
        enum grade g;
        if (r == S_BLOCKED) g = t[i].fatal ? G_FATAL : G_MITIGATED;
        else                g = G_PASS;
        counts[g]++;
        printf("  [%-3s] %-52s %-16s -> %s\n",
               t[i].p, t[i].why, v, grade_s[g]);
        if (r == S_BLOCKED && t[i].fatal)
            printf("        !! FATAL: no fallback exists.  A guest calling this\n"
                   "           dies with no graceful degradation.\n");
    }
}

/* ── P3: exec from app-private storage ──────────────────────────────────── */

/* A minimal aarch64 static ELF that exits 42, emitted byte-for-byte so the
 * probe needs no toolchain at runtime. */
static int probe_exec(const char *dir)
{
    static const unsigned char elf[] = {
        0x7f,'E','L','F',2,1,1,0, 0,0,0,0,0,0,0,0,
        2,0,0xb7,0, 1,0,0,0, 0x78,0,0x40,0,0,0,0,0,
        0x40,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0, 0x40,0,0x38,0, 1,0,0x40,0, 0,0,0,0,
        1,0,0,0, 5,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0x40,0,0,0,0,0, 0,0,0x40,0,0,0,0,0,
        0x88,0,0,0,0,0,0,0, 0x88,0,0,0,0,0,0,0,
        0,0x10,0,0,0,0,0,0,
        /* _start: mov x0,#42 ; mov x8,#94 (exit_group) ; svc #0 */
        0x40,0x05,0x80,0xd2, 0xc8,0x0b,0x80,0xd2, 0x01,0x00,0x00,0xd4,
    };
    char path[512];
    int fd, st, ok = 0;
    pid_t p;

    snprintf(path, sizeof path, "%s/.alr-exec-probe", dir);
    unlink(path);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) {
        counts[G_FATAL]++;
        printf("  [P3 ] cannot create %s: %s -> FATAL\n", path, strerror(errno));
        return 0;
    }
    if (write(fd, elf, sizeof elf) != (ssize_t)sizeof elf) { close(fd); return 0; }
    close(fd);
    chmod(path, 0700);

    p = fork();
    if (p == 0) { execl(path, path, (char *)NULL); _exit(errno & 0xff); }
    waitpid(p, &st, 0);

    if (WIFEXITED(st) && WEXITSTATUS(st) == 42) ok = 1;

    counts[ok ? G_PASS : G_FATAL]++;
    if (ok)
        printf("  [P3 ] execve of app-private ELF (%s) -> PASS\n", dir);
    else
        printf("  [P3 ] execve of app-private ELF (%s) FAILED (%s) -> FATAL\n"
               "        This host cannot run guest binaries at all.  Either it is\n"
               "        a targetSdk>=29 build (Play Store Termux, unsupported —\n"
               "        see ADR 0005) or Android policy changed.\n",
               dir, WIFEXITED(st) ? strerror(WEXITSTATUS(st)) : "signalled");
    unlink(path);
    return ok;
}

/* ── P4/P5: executable memory ───────────────────────────────────────────── */

static void probe_execmem(const char *dir)
{
    /* P4: anonymous RW -> RX -> call.  Needed by V8/Node JIT. */
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    unsigned int code[] = { 0xd2800540u, 0xd65f03c0u };  /* mov w0,#42 ; ret */
    void *m = mmap(NULL, ps, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int ok4 = 0, ok5 = 0;

    if (m != MAP_FAILED) {
        memcpy(m, code, sizeof code);
        __builtin___clear_cache((char *)m, (char *)m + sizeof code);
        if (mprotect(m, ps, PROT_READ | PROT_EXEC) == 0) {
            int (*fn)(void) = (int (*)(void))m;
            ok4 = (fn() == 42);
        }
        munmap(m, ps);
    }
    counts[ok4 ? G_PASS : G_FATAL]++;
    printf("  [P4 ] anon mmap RW -> mprotect RX -> call -> %s%s\n",
           ok4 ? "PASS" : "FATAL",
           ok4 ? "" : "   (Node/V8 JIT impossible)");

    /* P5: file-backed PROT_EXEC mmap.  ld.so maps every guest .so this way;
     * if this is denied the whole design collapses. */
    {
        char path[512];
        int fd;
        snprintf(path, sizeof path, "%s/.alr-mmap-probe", dir);
        unlink(path);
        fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            if (write(fd, code, sizeof code) == (ssize_t)sizeof code) {
                void *f = mmap(NULL, ps, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
                if (f != MAP_FAILED) {
                    int (*fn)(void) = (int (*)(void))f;
                    ok5 = (fn() == 42);
                    munmap(f, ps);
                }
            }
            close(fd);
            unlink(path);
        }
    }
    counts[ok5 ? G_PASS : G_FATAL]++;
    printf("  [P5 ] file-backed PROT_EXEC mmap -> %s%s\n",
           ok5 ? "PASS" : "FATAL",
           ok5 ? "" : "   (ld.so cannot map guest libraries — design dead)");
}

/* ── P6: hardlink ───────────────────────────────────────────────────────── */

static void probe_link(const char *dir)
{
    char a[512], b[512];
    int fd, ok;

    snprintf(a, sizeof a, "%s/.alr-l-a", dir);
    snprintf(b, sizeof b, "%s/.alr-l-b", dir);
    unlink(a); unlink(b);
    fd = open(a, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { printf("  [P6 ] cannot create probe file -> WARN\n");
                  counts[G_WARN]++; return; }
    close(fd);

    errno = 0;
    ok = (link(a, b) == 0);
    counts[ok ? G_PASS : G_MITIGATED]++;
    if (ok)
        printf("  [P6 ] link(2) same-dir -> PASS   (link2symlink NOT needed —\n"
               "        turn the whole layer off: docs/adr/0004)\n");
    else
        printf("  [P6 ] link(2) same-dir -> %s (%s)   -> MITIGATED\n"
               "        link2symlink emulation REQUIRED (dpkg, git clone --local, pnpm)\n",
               strerror(errno), errno == EACCES ? "EACCES as documented" : "unexpected errno");
    unlink(a); unlink(b);
}

/* ── P7: user namespace ─────────────────────────────────────────────────── */

static void probe_userns(void)
{
    pid_t p = fork();
    int st, e;
    if (p == 0) { alarm(2); errno = 0;
                  _exit(unshare(CLONE_NEWUSER) == 0 ? 0 : (errno & 0xff)); }
    waitpid(p, &st, 0);
    e = WIFEXITED(st) ? WEXITSTATUS(st) : -1;

    counts[G_EXPECTED]++;
    printf("  [P7 ] unshare(CLONE_NEWUSER) -> %s -> EXPECTED\n",
           e == 0 ? "SUCCEEDED (!)" : strerror(e));
    if (e == 0)
        printf("        !! Unexpected: this kernel HAS user namespaces.  A future\n"
               "           zero-overhead pivot_root tier is possible here (not v1).\n");
    else if (e != EINVAL)
        printf("        note: expected EINVAL (feature absent), got %s\n", strerror(e));
}

/* ── P8/P9: devices ─────────────────────────────────────────────────────── */

static void probe_devices(void)
{
    static const char *devs[] = { "/dev/null", "/dev/zero", "/dev/urandom",
                                  "/dev/random", "/dev/tty", "/dev/ptmx" };
    size_t i;
    int fd, ok = 1;

    for (i = 0; i < sizeof devs / sizeof devs[0]; i++) {
        fd = open(devs[i], O_RDWR);
        if (fd < 0) { printf("  [P8 ] %-14s open failed: %s\n",
                             devs[i], strerror(errno)); ok = 0; }
        else close(fd);
    }
    counts[ok ? G_PASS : G_WARN]++;
    printf("  [P8 ] core /dev nodes -> %s\n", ok ? "PASS" : "WARN");

    /* PTY allocation — if this works the socketpair PTY emulation the APK
     * project needed is unnecessary. */
    fd = open("/dev/ptmx", O_RDWR);
    if (fd >= 0) {
        int lock = 0; unsigned int n = 0;
        int a = ioctl(fd, TIOCSPTLCK, &lock);
        int b = ioctl(fd, TIOCGPTN, &n);
        counts[(a == 0 && b == 0) ? G_PASS : G_WARN]++;
        printf("  [P8 ] posix_openpt/unlockpt/ptsname -> %s (pts/%u)\n",
               (a == 0 && b == 0) ? "PASS" : "WARN", n);
        close(fd);
    } else { counts[G_WARN]++; printf("  [P8 ] /dev/ptmx unavailable -> WARN\n"); }

    /* P9: /dev/full is expected to be denied (no SELinux type in AOSP). */
    fd = open("/dev/full", O_WRONLY);
    if (fd < 0) {
        /* NOT MITIGATED.  06-cli-spec §3.2 defines MITIGATED as "기능이 켜져서
         * 해결됨" -- a feature is on and the problem is handled.  /dev/full
         * emulation was never implemented and is a documented permanent
         * non-goal (docs/00-product.md §5, RISKS §4): serving it means
         * interposing write(), the hottest syscall in the process, and the
         * failure surface is open-ended enough that one missed symbol passes
         * silently as a successful write.  Reporting MITIGATED here was the
         * code itself claiming a mitigation that does not exist. */
        counts[G_EXPECTED]++;
        printf("  [P9 ] /dev/full -> %s -> EXPECTED (non-goal, not emulated)\n",
               strerror(errno));
    } else {
        counts[G_PASS]++;
        printf("  [P9 ] /dev/full -> PASS (works natively, emulation off)\n");
        close(fd);
    }
}

/* ── emit the supervisor's emulation table ──────────────────────────────── */

static void emit_table(void)
{
    long nr;
    printf("\n"
           "── paste into src/supervisor/alr_sigsys_table.h ────────────────\n"
           "/* generated by alr doctor on this device */\n"
           "static const struct { long nr; long ret; } alr_sigsys_tab[] = {\n");
    for (nr = 0; nr < SWEEP_MAX; nr++) {
        long ret; const char *n;
        if (sweep[nr] != S_BLOCKED) continue;
        /* success(0) for the credential-drop family and set_robust_list;
         * EPERM for privileged operations with no ENOSYS-keyed fallback;
         * -ENOSYS otherwise so glibc's fallbacks engage. */
        switch (nr) {
        case 99: case 143: case 144: case 145: case 146: case 147:
        case 149: case 151: case 152: case 159:
            ret = 0; break;
        case 39: case 40: case 51: case 161: case 162:
        case 170: case 171: case 112: case 266:
            ret = -EPERM; break;
        default:
            ret = -ENOSYS; break;
        }
        n = sysname(nr);
        printf("    { %3ld, %-8s },   /* %s */\n", nr,
               ret == 0 ? "0" : ret == -EPERM ? "-EPERM" : "-ENOSYS",
               n ? n : "unnamed");
    }
    printf("};\n"
           "────────────────────────────────────────────────────────────────\n");
}

int main(int argc, char **argv)
{
    const char *dir = getenv("TMPDIR");
    struct utsname u;
    int measurable;

    /* argv[1] is the probe DIRECTORY, and it used to be taken unconditionally.
     * docs/06-cli-spec.md documents `alr doctor [--json] [--full]`, neither of
     * which exists, so following the documentation gave "--json" to mkdir-ish
     * probes and produced a confident FALSE FATAL on a healthy phone:
     *
     *   [P3 ] cannot create --json/.alr-exec-probe: No such file... -> FATAL
     *   [P5 ] file-backed PROT_EXEC mmap -> FATAL (ld.so cannot map guest
     *         libraries -- design dead)
     *   VERDICT: NOT READY (fatal probes failed)
     *
     * "design dead" is the most alarming thing this tool can say, and it said
     * it because of an unimplemented flag.  Refuse unknown options instead:
     * an honest "I do not have that flag" beats a diagnosis that is wrong. */
    if (argc > 1 && argv[1][0] == '-') {
        if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            printf("usage: alr-doctor [probe-dir]\n"
                   "  probe-dir  where to create scratch files (default $TMPDIR)\n"
                   "\nNo other options exist.  Output is a human-readable report;\n"
                   "there is no --json.\n");
            return 0;
        }
        fprintf(stderr,
                "alr-doctor: unknown option '%s'\n"
                "  reason=doctor-unknown-option\n"
                "  This tool takes an optional probe DIRECTORY and no flags.\n"
                "  (docs may mention --json/--full; they are not implemented.)\n",
                argv[1]);
        return 2;
    }
    if (argc > 1) dir = argv[1];
    if (!dir) dir = ".";

    uname(&u);
    printf("alr doctor — device capability report\n\n");
    printf("  kernel   %s %s\n", u.release, u.machine);
    printf("  probe dir %s\n\n", dir);

    /* Release first: it is a SUPPORT statement, and it must be visible even
     * when the context turns out to be unmeasurable and we abort below. */
    (void)probe_release();
    measurable = probe_validity();
    if (!measurable) {
        printf("\n  ABORTING: this context has no app seccomp filter, so every\n"
               "  syscall result would be a false ALLOWED.  Re-run from inside a\n"
               "  Termux session (docs/01-platform-facts.md §A1).\n");
        return 2;
    }

    probe_sweep();
    probe_named();
    printf("\n  execution\n");
    probe_exec(dir);
    probe_execmem(dir);
    printf("\n  filesystem\n");
    probe_link(dir);
    probe_devices();
    printf("\n  namespaces\n");
    probe_userns();

    emit_table();

    printf("\n  totals: PASS=%d MITIGATED=%d EXPECTED=%d WARN=%d FATAL=%d\n",
           counts[G_PASS], counts[G_MITIGATED], counts[G_EXPECTED],
           counts[G_WARN], counts[G_FATAL]);
    printf("  VERDICT: %s\n", counts[G_FATAL] ? "NOT READY (fatal probes failed)"
                                              : "READY");
    return counts[G_FATAL] ? 1 : 0;
}
