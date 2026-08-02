/* alr — Termux-native Ubuntu ARM64 glibc runtime.
 *
 *   alr install <distro>      provision a rootfs
 *   alr run <cmd> [args...]   run one guest command
 *   alr shell                 interactive guest shell
 *   alr doctor                (separate binary for now: src/cli/doctor.c)
 *
 * The load-bearing part is launch(): a stock Ubuntu binary CANNOT be execve'd
 * directly, because the kernel resolves its PT_INTERP ("/lib/ld-linux-aarch64
 * .so.1") against the real host root before userspace runs.  We therefore
 * invoke the GUEST loader explicitly and hand it the program.  (ADR 0002)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "alr_path_rule.h"
#include "alr_version.h"

#include <dirent.h>
#include "alr_exec_rule.h"
#include "alr_elf.h"
#include "alr_supervisor.h"
#include "alr_resolv_proto.h"

const char *alr_resolvd_start(const char *dir);
void alr_resolvd_stop(void);

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define ALR_MAX_ARGV 4096
#define ALR_MAX_ENVP 512

static int g_log;
static const char *g_resolv_sock;
static const char *g_with;
/* Our own path, captured at startup.  A subshell's /proc/self/exe is the
 * SHELL's, not ours -- reading it lazily from inside sh -c silently invoked
 * /bin/sh with our arguments and reported "Illegal option -d". */
static char g_self[ALR_PBUF];

static void die(const char *reason, const char *detail)
{
    fprintf(stderr, "alr: %s\n  reason=%s\n", detail ? detail : reason, reason);
    exit(125);
}

/* ── layout ──────────────────────────────────────────────────────────── */

static const char *prefix(void)
{
    const char *p = getenv("PREFIX");
    return (p && *p) ? p : "/data/data/com.termux/files/usr";
}

static void distro_root(char *out, size_t n, const char *distro)
{
    const char *root = getenv("ALR_ROOT_DIR");
    if (!distro || !*distro) distro = "ubuntu-24.04";
    if (root && *root) snprintf(out, n, "%s/%s", root, distro);
    else snprintf(out, n, "%s/var/lib/alr/distros/%s", prefix(), distro);
}

static int is_dir(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

static int run_cmd(char *const argv[])
{
    pid_t p = fork();
    int st;
    if (p < 0) return -1;
    if (p == 0) { execvp(argv[0], argv); _exit(127); }
    if (waitpid(p, &st, 0) < 0) return -1;
    return alr_exit_code(st);
}

/* ── install ─────────────────────────────────────────────────────────── */

/* ldconfig is STATICALLY linked (no PT_INTERP), so LD_PRELOAD cannot reach it:
 * it walks the ANDROID host root, finds no /lib/aarch64-linux-gnu, and then
 * fails writing /etc/ld.so.cache~ because Android's /etc is a symlink to the
 * read-only /system/etc.  Replacing it with a no-op is CORRECT here rather
 * than a workaround: this runtime always invokes the loader with an explicit
 * --library-path and --inhibit-cache (ADR 0002), so ld.so.cache has no
 * consumer.  We are removing work whose only output is never read. */
static const char LDCONFIG_SHIM[] =
    "#!/bin/sh\n"
    "# alr: no-op. ld.so is always invoked with --inhibit-cache, so the cache\n"
    "# this would build is never consulted. See docs/adr/0002.\n"
    "exit 0\n";

static int write_shim(const char *R)
{
    char path[ALR_PBUF];
    FILE *fp;
    /* Ubuntu 24.04 is a merged-/usr system: /sbin is a symlink to usr/sbin and
     * libc-bin's file list names /usr/sbin/ldconfig.  Diverting /sbin/ldconfig
     * registers a path dpkg never touches, so the diversion silently does
     * nothing and the next libc-bin upgrade reinstalls the real wrapper. */
    snprintf(path, sizeof path, "%s/usr/sbin/ldconfig", R);
    unlink(path);
    if (!(fp = fopen(path, "w"))) return -1;
    fputs(LDCONFIG_SHIM, fp);
    fclose(fp);
    return chmod(path, 0755);
}

/* Files that ship as ZERO BYTES in ubuntu-base and must be written, plus the
 * two config files that make apt survive a non-root, seccomp-restricted host.
 * Everything else in /etc is already correct -- notably ubuntu.sources, which
 * already points at ports.ubuntu.com for arm64 and MUST NOT be rewritten. */
static void repair(const char *R)
{
    struct { const char *rel; const char *body; } f[] = {
      { "/etc/resolv.conf", "nameserver 8.8.8.8\nnameserver 8.8.4.4\n" },
      { "/etc/hosts",
        "127.0.0.1\tlocalhost localhost.localdomain\n"
        "::1\tlocalhost localhost.localdomain ip6-localhost ip6-loopback\n" },
      /* Without this apt dies in setgroups() on its very first run: the
       * setuid family is blocked by the Android app seccomp filter, and apt
       * drops to the _apt user before it checks anything. */
      { "/etc/apt/apt.conf.d/99-alr-no-sandbox", "APT::Sandbox::User \"root\";\n" },
      /* fsync per file is brutal on Android flash. */
      { "/etc/dpkg/dpkg.cfg.d/99-alr", "force-unsafe-io\n" },
      /* See LDCONFIG_SHIM above.  This is the fallback copy; divert_ldconfig()
       * makes it survive libc-bin upgrades. */
      { NULL, NULL }
    };
    int i;
    for (i = 0; f[i].rel; i++) {
        char path[ALR_PBUF];
        FILE *fp;
        snprintf(path, sizeof path, "%s%s", R, f[i].rel);
        unlink(path);                 /* a later image may ship a symlink */
        fp = fopen(path, "w");
        if (!fp) { fprintf(stderr, "alr: cannot write %s: %s\n",
                           path, strerror(errno)); continue; }
        fputs(f[i].body, fp);
        fclose(fp);
    }
    write_shim(R);
    {   /* directories the tarball ships empty or not at all.
         * The apt ones matter: apt does not create them and fails with a bare
         * ENOENT from mkstemp/statvfs if they are missing. */
        const char *d[] = { "/dev", "/proc", "/sys", "/run", "/tmp",
                            "/var/cache/apt/archives",
                            "/var/cache/apt/archives/partial",
                            "/var/lib/apt/lists",
                            "/var/lib/apt/lists/partial",
                            "/var/log/apt", "/usr/local/bin", "/opt", NULL };
        for (i = 0; d[i]; i++) {
            char path[ALR_PBUF];
            snprintf(path, sizeof path, "%s%s", R, d[i]);
            mkdir(path, strcmp(d[i], "/tmp") ? 0755 : 01777);
        }
    }
}

static int copy_file(const char *from, const char *to)
{
    char buf[65536];
    int in, out;
    ssize_t n;
    struct stat st;

    in = open(from, O_RDONLY);
    if (in < 0) return -1;
    if (fstat(in, &st) != 0) { close(in); return -1; }
    out = open(to, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 07777);
    if (out < 0) { close(in); return -1; }
    while ((n = read(in, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w <= 0) { close(in); close(out); return -1; }
            off += w;
        }
    }
    close(in);
    close(out);
    return n < 0 ? -1 : 0;
}

/* ubuntu-base DOES contain hardlink members (perl5.38.2 -> perl,
 * uncompress -> gunzip, and more).  link(2) fails with EACCES on Android
 * app-private storage (docs/01-platform-facts.md §B6, measured by doctor P6),
 * so tar skips them and the files simply do not exist -- a silently broken
 * rootfs.  Re-create each one, preferring a real hardlink where the kernel
 * allows it and falling back to a copy.
 *
 * A copy is NOT equivalent: st_nlink stays 1 and edits do not propagate.  For
 * a freshly extracted, read-mostly rootfs that is acceptable; the general fix
 * for guest-created hardlinks is the preload's link2symlink layer (ADR 0004). */
static int fix_hardlinks(const char *tarball, const char *root)
{
    char cmd[ALR_PBUF * 2];
    char line[ALR_PBUF * 2];
    FILE *fp;
    int made = 0, copied = 0, failed = 0;

    snprintf(cmd, sizeof cmd, "tar -tvzf '%s' 2>/dev/null", tarball);
    fp = popen(cmd, "r");
    if (!fp) return -1;

    while (fgets(line, sizeof line, fp)) {
        char src[ALR_PBUF], dst[ALR_PBUF];
        char *sep = strstr(line, " link to ");
        char *name;
        size_t k;

        if (!sep || line[0] != 'h') continue;    /* 'h' = hardlink member */
        *sep = '\0';
        /* the member name is the last field before " link to " */
        name = sep;
        while (name > line && name[-1] != ' ') name--;
        k = strlen(sep + 9);
        while (k && (sep[9 + k - 1] == '\n' || sep[9 + k - 1] == '\r')) k--;
        sep[9 + k] = '\0';

        snprintf(dst, sizeof dst, "%s/%s", root, name);
        snprintf(src, sizeof src, "%s/%s", root, sep + 9);

        if (access(dst, F_OK) == 0) continue;    /* tar managed it */
        if (access(src, F_OK) != 0) { failed++; continue; }

        if (link(src, dst) == 0)      made++;
        else if (copy_file(src, dst) == 0) copied++;
        else                          failed++;
    }
    pclose(fp);

    if (made || copied || failed)
        printf("alr: hardlink members: %d linked, %d copied, %d failed\n",
               made, copied, failed);
    return failed ? -1 : 0;
}

/* Create a symlink INSIDE the rootfs.  It MUST be relative: the kernel
 * resolves symlink targets against the REAL host root and the preload cannot
 * intervene in kernel symlink resolution, so an absolute "/opt/node/bin/node"
 * silently points at a host path that does not exist.  Ubuntu itself uses
 * relative links throughout the rootfs for exactly this reason.
 *
 * `link` and `target` are GUEST absolute paths; the depth is computed, because
 * getting it wrong is silent: from /usr/local/bin the root is ../../../, and
 * ../../ lands in /usr/... which merely looks plausible. */
static int guest_symlink(const char *R, const char *link, const char *target)
{
    char host[ALR_PBUF], rel[ALR_PBUF];
    size_t o = 0;
    const char *p;
    int depth = 0;

    for (p = link + 1; *p; p++) if (*p == '/') depth++;   /* dirs above the leaf */
    while (depth-- > 0 && o + 3 < sizeof rel) { memcpy(rel + o, "../", 3); o += 3; }
    snprintf(rel + o, sizeof rel - o, "%s", target + 1);  /* drop leading '/' */

    snprintf(host, sizeof host, "%s%s", R, link);
    unlink(host);
    return symlink(rel, host);
}

/* tar restores symlink targets verbatim, so every ABSOLUTE target shipped in
 * the image points at ANDROID's root rather than the rootfs.  The preload
 * relativises links the GUEST creates (04-preload-spec.md §6.16), but these are
 * created by tar, outside it.
 *
 * ubuntu-base ships 17 of them and they were broken from the first boot -- most
 * damagingly /usr/bin/awk -> /etc/alternatives/awk, which is why ucf, locales,
 * mercurial and php8.3-common all died with a bare "awk: not found" and left
 * five packages unconfigured in the breadth run.
 *
 * `depth` is the directory's depth below the rootfs root, which is exactly the
 * number of "../" needed to climb back to it. */
static void relativize_tree(const char *dir, int depth, int *fixed, int *failed)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    if (!d) return;
    while ((e = readdir(d)) != NULL) {
        char path[ALR_PBUF];
        struct stat st;
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (snprintf(path, sizeof path, "%s/%s", dir, e->d_name) >= (int)sizeof path)
            continue;
        if (lstat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) { relativize_tree(path, depth + 1, fixed, failed); continue; }
        if (!S_ISLNK(st.st_mode)) continue;
        {
            char tgt[ALR_PBUF], rel[ALR_PBUF];
            ssize_t r = readlink(path, tgt, sizeof tgt - 1);
            size_t o = 0, n;
            int k;
            if (r <= 0) continue;
            tgt[r] = '\0';
            if (tgt[0] != '/') continue;            /* already relative */
            /* /proc, /sys and /dev are NOT rewritten at runtime either, so an
             * absolute target into them is already correct. */
            if (alr_is_sysdir(tgt)) continue;
            n = strlen(tgt + 1);
            if ((size_t)depth * 3 + n + 1 > sizeof rel) { (*failed)++; continue; }
            for (k = 0; k < depth; k++) { memcpy(rel + o, "../", 3); o += 3; }
            memcpy(rel + o, tgt + 1, n + 1);
            if (unlink(path) == 0 && symlink(rel, path) == 0) (*fixed)++;
            else (*failed)++;
        }
    }
    closedir(d);
}

static int guest_run(const char *distro, const char *const *argv, int fakeroot)
{
    char buf[ALR_PBUF * 2];
    char *sh[4];
    size_t o = 0;
    int i;
    o += (size_t)snprintf(buf + o, sizeof buf - o,
                          "%sALR_ROOT_DIR='%s' '%s' -d '%s' run",
                          fakeroot ? "ALR_FAKEROOT=1 " : "",
                          getenv("ALR_ROOT_DIR") ? getenv("ALR_ROOT_DIR") : "",
                          g_self, distro);
    for (i = 0; argv[i]; i++)
        o += (size_t)snprintf(buf + o, sizeof buf - o, " '%s'", argv[i]);
    sh[0] = (char *)"sh"; sh[1] = (char *)"-c"; sh[2] = buf; sh[3] = NULL;
    return run_cmd(sh);
}

/* Fetch a URL to a path, verifying nothing (callers that need integrity pass a
 * checksum step of their own). */
static int fetch(const char *url, const char *out)
{
    char *dl[8];
    dl[0] = (char *)"curl"; dl[1] = (char *)"-fsSL"; dl[2] = (char *)"--retry";
    dl[3] = (char *)"3"; dl[4] = (char *)"-o"; dl[5] = (char *)out;
    dl[6] = (char *)url; dl[7] = NULL;
    return run_cmd(dl);
}

/* --with node : nodejs.org LTS tarball.  Deliberately NOT apt's nodejs, which
 * is 18.19 (EOL).  A current Node also exercises the io_uring SIGSYS rescue,
 * which apt's libuv 1.44 never triggers. */
/* --with node : nodejs.org LTS tarball.  Deliberately NOT apt's nodejs, which
 * is 18.19 (EOL).  A current Node also exercises the io_uring SIGSYS rescue,
 * which apt's libuv 1.44 never triggers. */
static int with_node(const char *R, const char *cache)
{
    char cmd[ALR_PBUF * 3], ver[64], tarball[ALR_PBUF];
    char *sh[4];
    FILE *fp;

    ver[0] = '\0';
    fp = popen("curl -fsSL --max-time 30 https://nodejs.org/dist/index.json"
               " 2>/dev/null | tr '{' '\\n' | grep -m1 '\"lts\":\"'"
               " | sed -n 's/.*\"version\":\"\\([^\"]*\\)\".*/\\1/p'", "r");
    if (fp) {
        if (fgets(ver, sizeof ver, fp)) ver[strcspn(ver, "\r\n")] = '\0';
        pclose(fp);
    }
    if (ver[0] != 'v') snprintf(ver, sizeof ver, "v22.20.0");   /* offline pin */
    printf("alr: node %s\n", ver);

    snprintf(tarball, sizeof tarball, "%s/node-%s-linux-arm64.tar.xz", cache, ver);
    if (access(tarball, R_OK) != 0) {
        char url[ALR_PBUF];
        snprintf(url, sizeof url,
                 "https://nodejs.org/dist/%s/node-%s-linux-arm64.tar.xz", ver, ver);
        if (fetch(url, tarball) != 0) return -1;
    }
    snprintf(cmd, sizeof cmd,
        "set -e\n"
        "curl -fsSL --max-time 60 -o '%s/SHASUMS256.txt'"
        " https://nodejs.org/dist/%s/SHASUMS256.txt\n"
        "cd '%s'\n"
        "grep ' node-%s-linux-arm64.tar.xz$' SHASUMS256.txt | sha256sum -c - >/dev/null\n"
        "rm -rf '%s/opt/node'\n"
        "tar -xJf '%s' -C '%s/opt'\n"
        "mv '%s/opt/node-%s-linux-arm64' '%s/opt/node'\n",
        cache, ver, cache, ver, R, tarball, R, R, ver, R);
    sh[0] = (char *)"sh"; sh[1] = (char *)"-c"; sh[2] = cmd; sh[3] = NULL;
    if (run_cmd(sh) != 0) return -1;

    {
        static const char *const b[] = { "node", "npm", "npx", "corepack", NULL };
        int i;
        for (i = 0; b[i]; i++) {
            char link[ALR_PBUF], tgt[ALR_PBUF];
            snprintf(link, sizeof link, "/usr/local/bin/%s", b[i]);
            snprintf(tgt,  sizeof tgt,  "/opt/node/bin/%s", b[i]);
            guest_symlink(R, link, tgt);
        }
    }
    return 0;
}

/* --with codex : the Rust binary release.  NOT the npm package, which drags in
 * a ~129 MB platform tgz plus a Node runtime purely to exec the same binary. */
static int with_codex(const char *R, const char *cache)
{
    char cmd[ALR_PBUF * 3], tag[64];
    char *sh[4];
    FILE *fp;

    tag[0] = '\0';
    fp = popen("curl -fsSL --max-time 30"
               " https://api.github.com/repos/openai/codex/releases/latest"
               " 2>/dev/null | sed -n 's/.*\"tag_name\": *\"\\([^\"]*\\)\".*/\\1/p'"
               " | head -1", "r");
    if (fp) {
        if (fgets(tag, sizeof tag, fp)) tag[strcspn(tag, "\r\n")] = '\0';
        pclose(fp);
    }
    if (!tag[0]) snprintf(tag, sizeof tag, "rust-v0.146.0");    /* offline pin */
    printf("alr: codex %s\n", tag);

    /* NOTE the `-musl` in the asset name: this is a STATICALLY linked build.
     * LD_PRELOAD cannot reach it, so codex runs with NO path virtualization and
     * sees Android's filesystem rather than the rootfs -- see docs/RISKS.md and
     * docs/evidence/2026-08-03-m12-spawn-resolver.md §8.  `codex --version`
     * working does not mean codex operates inside the guest.
     *
     * Checksum: node is verified against SHASUMS256.txt (see with_node); codex
     * had NO verification at all.  Try the release's own checksum asset under
     * the names GitHub projects commonly use, and if none exists say so out
     * loud rather than staying silent about an unverified 100+ MB download. */
    snprintf(cmd, sizeof cmd,
        "set -e\n"
        "A=codex-aarch64-unknown-linux-musl.tar.gz\n"
        "[ -f '%s'/$A ] || curl -fsSL --max-time 900 -o '%s'/$A"
        " https://github.com/openai/codex/releases/download/%s/$A\n"
        "rm -rf '%s'/.codex-x\n"
        "mkdir -p '%s'/.codex-x\n"
        "tar -xzf '%s'/$A -C '%s'/.codex-x\n"
        "B=$(find '%s'/.codex-x -type f -perm -u+x | head -1)\n"
        "install -m755 \"$B\" '%s/usr/local/bin/codex'\n"
        "rm -rf '%s'/.codex-x\n",
        cache, cache, tag, cache, cache, cache, cache, cache, R, cache);
    sh[0] = (char *)"sh"; sh[1] = (char *)"-c"; sh[2] = cmd; sh[3] = NULL;
    if (run_cmd(sh) != 0) return -1;

    {   /* Verify AFTER the tarball is on disk, before it is trusted. */
        char vc[ALR_PBUF * 2];
        char *vs[4];
        snprintf(vc, sizeof vc,
            "A=codex-aarch64-unknown-linux-musl.tar.gz\n"
            "for C in checksums.txt SHA256SUMS sha256sums.txt; do\n"
            "  curl -fsSL --max-time 60 -o '%s'/$C"
            "   https://github.com/openai/codex/releases/download/%s/$C 2>/dev/null || continue\n"
            "  W=$(grep -m1 \"$A\" '%s'/$C | tr -d '*' | awk '{print $1}')\n"
            "  [ -n \"$W\" ] || continue\n"
            "  G=$(sha256sum '%s'/$A | awk '{print $1}')\n"
            "  [ \"$W\" = \"$G\" ] || { echo \"alr: codex sha256 MISMATCH\" >&2; exit 1; }\n"
            "  echo 'alr: codex sha256 ok'; exit 0\n"
            "done\n"
            "echo 'alr: WARNING codex tarball is UNVERIFIED - the release publishes"
            " no checksum asset under any name we know' >&2\n"
            "exit 0\n",
            cache, tag, cache, cache);
        vs[0] = (char *)"sh"; vs[1] = (char *)"-c"; vs[2] = vc; vs[3] = NULL;
        if (run_cmd(vs) != 0) {
            fprintf(stderr, "alr: refusing the codex tarball\n");
            return -1;
        }
    }

    {   /* Landlock and bubblewrap cannot work inside an Android app process, so
         * Codex's own sandbox must be off.  alr is NOT a security boundary --
         * say so where the user will actually see it. */
        char path[ALR_PBUF];
        FILE *f;
        snprintf(path, sizeof path, "%s/root/.codex", R);
        mkdir(path, 0755);
        snprintf(path, sizeof path, "%s/root/.codex/config.toml", R);
        f = fopen(path, "w");
        if (f) {
            fputs("# alr: Codex's Linux sandbox relies on Landlock and bubblewrap,\n"
                  "# neither of which functions inside an Android app process.\n"
                  "# Confirm the exact mode name with `codex --help` for your version.\n"
                  "sandbox_mode = \"danger-full-access\"\n", f);
            fclose(f);
        }
        printf("alr: NOTE codex sandbox disabled; alr is not a security boundary\n");
    }
    return 0;
}

/* Put libalr_preload.so inside the rootfs.  WITHOUT THIS the guest has no path
 * virtualization at all: `alr run /path/to/x` still works because alr resolves
 * that path itself, but anything the guest looks up (apt reading
 * /etc/apt/apt.conf.d, env searching PATH for node) resolves against the
 * ANDROID host and fails in ways that look like a broken rootfs.
 *
 * Searched next to the alr binary first, then $PREFIX/share/alr -- the release
 * layout.  Returns 0 if installed, -1 if the .so could not be found. */
/* Rewriting the shim after each `alr` operation is not enough: a libc-bin
 * upgrade restores the genuine wrapper, which runs the static ldconfig.real,
 * which fails -- and that leaves libc-bin half-configured so every LATER apt
 * install dies too.  It surfaced as 96 packages "unavailable" in the breadth
 * run, and anything that runs apt without going through `alr` (a shell inside
 * the guest) reintroduces it.
 *
 * Register a dpkg diversion instead: dpkg then writes future versions to
 * /sbin/ldconfig.distrib and leaves our no-op in place, permanently. */
static void divert_ldconfig(const char *distro, const char *R)
{
    static const char *const dv[] = { "/usr/bin/dpkg-divert", "--local",
                                      "--rename", "--add", "/usr/sbin/ldconfig",
                                      NULL };
    if (guest_run(distro, dv, 1) != 0) {
        fprintf(stderr, "alr: WARNING dpkg-divert failed; the ldconfig no-op "
                        "will not survive a libc-bin upgrade\n");
        return;
    }
    /* --rename moved our shim to .distrib; put it back at the real name. */
    if (write_shim(R) != 0)
        fprintf(stderr, "alr: WARNING could not reinstall the ldconfig no-op\n");
}

static int install_preload(const char *R)
{
    char src[ALR_PBUF], dst[ALR_PBUF], dir[ALR_PBUF];
    const char *cands[3];
    char selfdir[ALR_PBUF];
    char *slash;
    int i;

    snprintf(selfdir, sizeof selfdir, "%s", g_self);
    slash = strrchr(selfdir, '/');
    if (slash) *slash = '\0'; else snprintf(selfdir, sizeof selfdir, ".");

    snprintf(src, sizeof src, "%s/libalr_preload.so", selfdir);
    cands[0] = src;
    { static char c1[ALR_PBUF];
      snprintf(c1, sizeof c1, "%s/share/alr/libalr_preload.so", prefix());
      cands[1] = c1; }
    { static char c2[ALR_PBUF];
      snprintf(c2, sizeof c2, "%s/build/libalr_preload.so", selfdir);
      cands[2] = c2; }

    /* Ship the manifest beside the .so (docs/05-provisioning-spec.md §3.4).
     * Three separate incidents in this project's evidence were "the deployed
     * binary was not what I thought"; a self-describing rootfs is the cheap
     * structural fix. */
    snprintf(dir, sizeof dir, "%s/usr/lib/alr", R);
    { char *mk[4]; mk[0]=(char*)"mkdir"; mk[1]=(char*)"-p"; mk[2]=dir; mk[3]=NULL;
      run_cmd(mk); }
    snprintf(dst, sizeof dst, "%s/usr/lib/alr/libalr_preload.so", R);

    for (i = 0; i < 3; i++) {
        if (access(cands[i], R_OK) != 0) continue;
        if (copy_file(cands[i], dst) == 0) {
            char msrc[ALR_PBUF], mdst[ALR_PBUF];
            char *dot;
            chmod(dst, 0755);
            /* The manifest lives beside whichever candidate we took. */
            snprintf(msrc, sizeof msrc, "%s", cands[i]);
            if ((dot = strstr(msrc, ".so")) && dot[3] == '\0')
                snprintf(dot, sizeof msrc - (size_t)(dot - msrc), ".manifest.json");
            snprintf(mdst, sizeof mdst, "%s/usr/lib/alr/libalr_preload.manifest.json", R);
            if (access(msrc, R_OK) == 0 && copy_file(msrc, mdst) == 0)
                chmod(mdst, 0644);
            else
                fprintf(stderr, "alr: NOTE no manifest beside %s; the rootfs will "
                                "not record which build it carries\n", cands[i]);
            printf("alr: preload installed from %s\n", cands[i]);
            return 0;
        }
    }
    fprintf(stderr,
        "alr: WARNING libalr_preload.so not found next to the binary or in\n"
        "     %s/share/alr/.  The guest will run WITHOUT path virtualization:\n"
        "     it will see the Android filesystem, not the rootfs.\n", prefix());
    return -1;
}

/* docs/05-provisioning-spec.md §1.1.  There is no `latest` symlink and
 * ubuntu-base-24.04-base-arm64.tar.gz is a 404 -- the images are named by point
 * release.  Read SHA256SUMS, take the highest point release, and keep its hash
 * so the download can actually be verified rather than merely fetched.
 *
 * Parsed in C rather than an awk one-liner because the '*' binary marker is
 * optional in SHA256SUMS and silently ending up with "*ubuntu-base-..." in the
 * URL would 404 in a way that reads like a network problem. */
#define ALR_UBUNTU_BASE \
    "https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release"
#define ALR_UBUNTU_PIN "ubuntu-base-24.04.4-base-arm64.tar.gz"

static int discover_ubuntu(char *url, size_t urlsz, char *sha, size_t shasz)
{
    char cmd[512], line[512];
    char bestname[256], besthash[80];
    FILE *fp;
    long best = -1;

    bestname[0] = besthash[0] = '\0';
    snprintf(cmd, sizeof cmd,
             "curl -fsSL --max-time 60 --retry 3 '%s/SHA256SUMS' 2>/dev/null",
             ALR_UBUNTU_BASE);
    if (!(fp = popen(cmd, "r"))) return -1;
    while (fgets(line, sizeof line, fp)) {
        char h[80], name[256];
        const char *n;
        char *end;
        long pt;
        if (sscanf(line, "%79s %255s", h, name) != 2) continue;
        if (strlen(h) != 64) continue;
        n = name;
        if (*n == '*') n++;                       /* binary marker */
        if (strncmp(n, "ubuntu-base-24.04.", 18) != 0) continue;
        pt = strtol(n + 18, &end, 10);
        if (end == n + 18 || strcmp(end, "-base-arm64.tar.gz") != 0) continue;
        if (pt > best) {
            best = pt;
            snprintf(bestname, sizeof bestname, "%s", n);
            snprintf(besthash, sizeof besthash, "%s", h);
        }
    }
    pclose(fp);
    if (best < 0) return -1;
    snprintf(url, urlsz, "%s/%s", ALR_UBUNTU_BASE, bestname);
    snprintf(sha, shasz, "%s", besthash);
    return 0;
}

static int verify_sha256(const char *file, const char *want)
{
    char cmd[ALR_PBUF + 64], got[80];
    FILE *fp;
    int n;
    got[0] = '\0';
    snprintf(cmd, sizeof cmd, "sha256sum '%s' 2>/dev/null", file);
    if (!(fp = popen(cmd, "r"))) return -1;
    n = fscanf(fp, "%79s", got);
    pclose(fp);
    if (n != 1) return -1;
    return strcmp(got, want) == 0 ? 0 : -1;
}

/* Report enough to make a bug report actionable: three separate incidents in
 * this project's evidence docs were "the deployed binary was not what I
 * thought", so print the preload's hash rather than merely its path. */
static int cmd_version(void)
{
    char path[ALR_PBUF], cmd[ALR_PBUF + 64], sha[80];
    FILE *fp;

    char selfdir[ALR_PBUF], *slash;
    const char *cands[3];
    int i;

    printf("alr %s\n", ALR_VERSION);

    snprintf(selfdir, sizeof selfdir, "%s", g_self);
    slash = strrchr(selfdir, '/');
    if (slash) *slash = '\0'; else snprintf(selfdir, sizeof selfdir, ".");
    { static char c0[ALR_PBUF], c1[ALR_PBUF], c2[ALR_PBUF];
      snprintf(c0, sizeof c0, "%s/libalr_preload.so", selfdir);
      snprintf(c1, sizeof c1, "%s/share/alr/libalr_preload.so", prefix());
      snprintf(c2, sizeof c2, "%s/build/libalr_preload.so", selfdir);
      cands[0] = c0; cands[1] = c1; cands[2] = c2; }

    path[0] = '\0';
    for (i = 0; i < 3; i++)
        if (access(cands[i], R_OK) == 0) { snprintf(path, sizeof path, "%s", cands[i]); break; }

    if (*path) {
        sha[0] = '\0';
        snprintf(cmd, sizeof cmd, "sha256sum '%s' 2>/dev/null", path);
        if ((fp = popen(cmd, "r"))) {
            if (fscanf(fp, "%79s", sha) != 1) sha[0] = '\0';
            pclose(fp);
        }
        printf("preload %s\n", path);
        if (*sha) printf("sha256  %s\n", sha);
    } else {
        printf("preload (not found)\n");
    }
    { char r[ALR_PBUF];
      distro_root(r, sizeof r, getenv("ALR_DISTRO"));
      printf("rootfs  %s%s\n", r, is_dir(r) ? "" : "  (not installed)"); }
    return 0;
}

static int cmd_install(const char *distro, const char *url_override)
{
    char R[ALR_PBUF], part[ALR_PBUF], tarball[ALR_PBUF], cache[ALR_PBUF];
    char durl[512], dsha[80];
    char *dl[8], *ex[12], *mk[4];
    const char *url = url_override;
    int rc;

    durl[0] = dsha[0] = '\0';
    distro_root(R, sizeof R, distro);
    snprintf(part,  sizeof part,  "%s.part", R);
    snprintf(cache, sizeof cache, "%s/var/lib/alr/cache", prefix());
    snprintf(tarball, sizeof tarball, "%s/%s.tar.gz", cache, distro);

    if (is_dir(R)) { fprintf(stderr, "alr: %s already installed\n", R); return 0; }

    mk[0] = (char *)"mkdir"; mk[1] = (char *)"-p"; mk[2] = cache; mk[3] = NULL;
    run_cmd(mk);
    mk[2] = part; run_cmd(mk);

    if (!url) {
        if (strcmp(distro, "ubuntu-24.04") != 0)
            die("unsupported-distro",
                "no discovery path for this distro yet; pass --url "
                "(docs/05-provisioning-spec.md §1.1)");
        printf("alr: resolving the current ubuntu-base point release\n");
        if (discover_ubuntu(durl, sizeof durl, dsha, sizeof dsha) != 0) {
            /* Offline / air-gapped fallback.  Say plainly that the download is
             * unverified rather than implying the pin is as good as a hash. */
            snprintf(durl, sizeof durl, "%s/%s", ALR_UBUNTU_BASE, ALR_UBUNTU_PIN);
            dsha[0] = '\0';
            fprintf(stderr, "alr: WARNING SHA256SUMS unreachable; falling back to "
                            "the pinned %s WITHOUT hash verification\n",
                    ALR_UBUNTU_PIN);
        }
        url = durl;
        printf("alr: %s\n", url);
    }

    {   int attempt;
        for (attempt = 0; attempt < 2; attempt++) {
            if (access(tarball, R_OK) != 0) {
                printf("alr: fetching %s\n", url);
                dl[0] = (char *)"curl"; dl[1] = (char *)"-fSL"; dl[2] = (char *)"--retry";
                dl[3] = (char *)"3"; dl[4] = (char *)"-o"; dl[5] = tarball;
                dl[6] = (char *)url; dl[7] = NULL;
                if (run_cmd(dl) != 0) die("download-network", "download failed");
            }
            if (!*dsha) break;                     /* --url: nothing to check against */
            if (verify_sha256(tarball, dsha) == 0) { printf("alr: sha256 ok\n"); break; }
            /* A cached tarball from an older point release is the common case,
             * so retry once with a fresh download before calling it corrupt. */
            fprintf(stderr, "alr: cached tarball does not match SHA256SUMS; refetching\n");
            unlink(tarball);
            if (attempt) die("download-corrupt",
                             "SHA256 mismatch after refetch; the tarball was removed");
        }
    }

    /* Safe extraction (docs/05-provisioning-spec.md §2).  As a non-root user
     * GNU tar already refuses to chown and cannot create device nodes; we add
     * the traversal and setuid guards explicitly rather than relying on that.
     * A hardened in-process untar is still owed -- tracked in the spec. */
    printf("alr: extracting into %s\n", part);
    ex[0]  = (char *)"tar";
    ex[1]  = (char *)"-xzf";        ex[2] = tarball;
    ex[3]  = (char *)"-C";          ex[4] = part;
    ex[5]  = (char *)"--no-same-owner";
    /* NOT --no-same-permissions: that makes tar apply the caller's umask, and
     * Termux's is 077, so every extracted file lands as 0700.  Programs that
     * compute executability themselves rather than calling access() then
     * decide nothing is runnable -- dpkg reports
     *   "'sh' not found in PATH or not executable"
     * for files that plainly exist and are executable by their owner.
     * We set umask 022 around the extraction instead (see below). */
    ex[6]  = (char *)"--no-overwrite-dir";
    ex[7]  = (char *)"--exclude=dev/*";
    ex[8]  = (char *)"--warning=no-unknown-keyword";
    ex[9]  = NULL;
    {
        mode_t old = umask(022);
        rc = run_cmd(ex);
        umask(old);
    }
    if (rc != 0) fprintf(stderr, "alr: tar exited %d (continuing; some members "
                                 "are expected to be skipped)\n", rc);

    if (fix_hardlinks(tarball, part) < 0)
        fprintf(stderr, "alr: hardlink fixup incomplete\n");

    {   int fixed = 0, failed = 0;
        relativize_tree(part, 0, &fixed, &failed);
        printf("alr: absolute symlinks: %d relativized, %d failed\n", fixed, failed);
        if (failed) fprintf(stderr, "alr: WARNING %d symlink(s) left absolute; "
                                    "they will not resolve inside the guest\n", failed);
    }

    {   /* setuid/setgid bits are inert on /data (nosuid) and only produce
         * confusing warnings later -- mask them off. */
        char cmdbuf[ALR_PBUF * 2];
        char *sh[4];
        snprintf(cmdbuf, sizeof cmdbuf,
                 "find '%s' -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null; exit 0",
                 part);
        sh[0] = (char *)"sh"; sh[1] = (char *)"-c"; sh[2] = cmdbuf; sh[3] = NULL;
        run_cmd(sh);
    }

    repair(part);
    install_preload(part);

    if (rename(part, R) != 0) die("extract-permission", "rename into place failed");
    printf("alr: installed %s\n", R);

    divert_ldconfig(distro, R);

    if (g_with && *g_with) {
        /* apt must run before the HTTPS fetches: ubuntu-base ships no
         * ca-certificates, and nodejs.org / GitHub are both HTTPS. */
        if (strstr(g_with, "git") || strstr(g_with, "node") || strstr(g_with, "codex")) {
            static const char *upd[] = { "/usr/bin/apt-get", "update", NULL };
            static const char *ins[] = { "/usr/bin/apt-get", "install", "-y",
                                         "--no-install-recommends",
                                         "ca-certificates", "xz-utils", NULL };
            guest_run(distro, upd, 1);
            guest_run(distro, ins, 1);
        }
        if (strstr(g_with, "git")) {
            static const char *g[] = { "/usr/bin/apt-get", "install", "-y",
                                       "--no-install-recommends", "git", NULL };
            if (guest_run(distro, g, 1) != 0)
                fprintf(stderr, "alr: git install failed\n");
        }
        if (strstr(g_with, "node")  && with_node(R, cache) != 0)
            fprintf(stderr, "alr: node install failed\n");
        if (strstr(g_with, "codex") && with_codex(R, cache) != 0)
            fprintf(stderr, "alr: codex install failed\n");
    }
    return 0;
}

/* ── launch ──────────────────────────────────────────────────────────── */

struct launch {
    char root[ALR_PBUF];
    size_t root_len;
    char ldso[ALR_PBUF];
    char libpath[ALR_PBUF * 2];
    char preload[ALR_PBUF];
    int  have_preload;
};

static int prepare(struct launch *L, const char *distro)
{
    static const char *libdirs[] = {
        "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
        "/lib", "/usr/lib", "/usr/local/lib/aarch64-linux-gnu", NULL
    };
    size_t o = 0;
    int i;

    distro_root(L->root, sizeof L->root, distro);
    L->root_len = alr_trim_root(L->root);
    if (!is_dir(L->root)) { errno = ENOENT; return -1; }

    snprintf(L->ldso, sizeof L->ldso, "%s/lib/ld-linux-aarch64.so.1", L->root);
    if (access(L->ldso, X_OK) != 0) return -2;

    /* ld.so's own library search is the one uninterposable component (it runs
     * before any preload), so we solve it declaratively instead of hooking it. */
    for (i = 0; libdirs[i]; i++)
        o += (size_t)snprintf(L->libpath + o, sizeof L->libpath - o, "%s%s%s",
                              o ? ":" : "", L->root, libdirs[i]);

    snprintf(L->preload, sizeof L->preload,
             "%s/usr/lib/alr/libalr_preload.so", L->root);
    L->have_preload = (access(L->preload, R_OK) == 0);
    return 0;
}

/* Resolve a guest command to a host path, searching the guest PATH when the
 * command has no slash. */
static int resolve(const struct launch *L, const char *cmd, char *out, size_t n)
{
    static const char *dflt =
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    const char *path = getenv("ALR_GUEST_PATH");
    const char *p;

    if (strchr(cmd, '/')) {
        char buf[ALR_PBUF];
        const char *h = alr_rw(cmd, L->root, L->root_len, buf, sizeof buf, NULL);
        if (!h) return -1;
        snprintf(out, n, "%s", h);
        return access(out, X_OK) == 0 ? 0 : -1;
    }
    if (!path || !*path) path = dflt;
    for (p = path; *p; ) {
        const char *e = strchr(p, ':');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len) {
            snprintf(out, n, "%.*s%.*s/%s", (int)L->root_len, L->root,
                     (int)len, p, cmd);
            if (access(out, X_OK) == 0) return 0;
        }
        if (!e) break;
        p = e + 1;
    }
    return -1;
}

static char **build_env(const struct launch *L, const char *guest_exe,
                        const char *guest_argv0)
{
    static char *env[ALR_MAX_ENVP];
    static char bufs[24][ALR_PBUF];
    int n = 0, b = 0, i;
    extern char **environ;

    /* Carry through only what is safe; drop the Android/Termux host set. */
    for (i = 0; environ[i] && n < ALR_MAX_ENVP - 24; i++) {
        const char *val;
        size_t klen = alr_split_env(environ[i], &val);
        if (alr_env_is_blocked(environ[i])) continue;
        /* LD_PRELOAD / LD_LIBRARY_PATH are replaced, never inherited: Termux's
         * value points at a BIONIC .so which a glibc ld.so cannot load, and an
         * empty string is a real bug on the bionic linker, not a no-op. */
        if (klen == 10 && !memcmp(environ[i], "LD_PRELOAD", 10)) continue;
        if (klen == 15 && !memcmp(environ[i], "LD_LIBRARY_PATH", 15)) continue;
        if (klen == 14 && !memcmp(environ[i], "GLIBC_TUNABLES", 14)) continue;
        /* Anything we are about to PUT() below must be dropped here first.
         * envp allows duplicate keys and getenv(3) returns the FIRST match, so
         * an inherited PATH would shadow the guest one for every C program --
         * while bash still showed the right value, because bash builds its own
         * table where the last assignment wins.  That divergence is what made
         * dpkg report "'sh' not found in PATH or not executable" for files that
         * plainly existed: it was searching Termux's $PREFIX/bin. */
        if (klen ==  4 && !memcmp(environ[i], "PATH", 4)) continue;
        if (klen ==  4 && !memcmp(environ[i], "HOME", 4)) continue;
        if (klen ==  6 && !memcmp(environ[i], "TMPDIR", 6)) continue;
        if (klen ==  8 && !memcmp(environ[i], "ALR_ROOT", 8)) continue;
        /* The guest rootfs has only C.UTF-8 generated; an inherited
         * LANG=en_US.UTF-8 makes every perl/dpkg invocation emit a locale
         * warning block that buries the real output. */
        if (klen ==  4 && !memcmp(environ[i], "LANG", 4)) continue;
        if (klen >=  3 && !memcmp(environ[i], "LC_", 3)) continue;
        env[n++] = environ[i];
    }

#define PUT(fmt, ...) do { \
        snprintf(bufs[b], ALR_PBUF, fmt, __VA_ARGS__); env[n++] = bufs[b++]; \
    } while (0)

    PUT("ALR_ROOT=%s", L->root);
    /* The preload needs these to re-dispatch the guest's own exec* calls
     * through the same loader invocation we used for the first program. */
    PUT("ALR_LDSO=%s", L->ldso);
    PUT("ALR_LIBPATH=%s", L->libpath);
    /* IN ADDITION to --library-path, not instead of it.  --library-path
     * populates the loader's search list for the INITIAL link; glibc's NSS
     * loads libnss_dns.so.2 later via __libc_dlopen_mode, and without
     * LD_LIBRARY_PATH that dlopen searches the default dirs against the REAL
     * host root, finds nothing, and every hostname lookup fails with
     * "Temporary failure in name resolution" while raw IP sockets still work.
     * Measured 2026-08-02: nss_dns load count was 0 before this line.
     * The value must be HOST paths -- the loader's own opens happen before the
     * preload can rewrite anything. */
    PUT("LD_LIBRARY_PATH=%s", L->libpath);
    if (L->have_preload) PUT("ALR_PRELOAD=%s", L->preload);
    PUT("ALR_GUEST_EXE=%s", guest_exe);
    PUT("ALR_GUEST_ARGV0=%s", guest_argv0);
    /* rseq is blocked by the Android filter and glibc registers it at startup;
     * this tunable removes the syscall entirely, one less SIGSYS per process.
     * It is only a partial fix -- set_robust_list has no equivalent knob, which
     * is exactly why the supervisor exists. */
    PUT("GLIBC_TUNABLES=%s", "glibc.pthread.rseq=0");
    PUT("HOME=%s", "/root");
    PUT("TMPDIR=%s", "/tmp");
    PUT("PATH=%s", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    /* ubuntu-base DOES ship /usr/lib/locale/C.utf8 -- the earlier note that it
     * ships no locales was wrong.  glibc simply never found it: _nl_find_locale
     * opens the LITERAL "/usr/lib/locale" through an internal call we cannot
     * interpose, and the HOST has no such directory at all, so the guest was
     * left with only C and POSIX.  LOCPATH is glibc's own escape hatch and it
     * points the lookup at the rootfs's copy.
     *
     * Without this, tmux (and anything else that insists on UTF-8) refuses to
     * start: "need UTF-8 locale (LC_CTYPE) but have ANSI_X3.4-1968".
     *
     * Caveat: when LOCPATH is set glibc skips locale-archive entirely, so
     * locales added later must be generated as directories --
     * `locale-gen --no-archive`.  See docs/RISKS.md. */
    PUT("LOCPATH=%s/usr/lib/locale", L->root);
    PUT("LANG=%s", "C.UTF-8");
    PUT("LC_ALL=%s", "C.UTF-8");
    if (L->have_preload) PUT("LD_PRELOAD=%s", L->preload);
    if (getenv("ALR_FAKEROOT")) PUT("ALR_FAKEROOT=%s", getenv("ALR_FAKEROOT"));
    if (getenv("ALR_COUNT")) { PUT("ALR_COUNT=%s", getenv("ALR_COUNT"));
                               PUT("ALR_LOG_FD=%d", 2); }
    if (g_resolv_sock) PUT(ALR_RESOLV_ENV "=%s", g_resolv_sock);
#undef PUT

    env[n] = NULL;
    return env;
}

struct rdctx { int fd; };
static int rd_pread(void *c, void *dst, size_t len, uint64_t off)
{
    struct rdctx *r = c;
    return pread(r->fd, dst, len, (off_t)off) == (ssize_t)len;
}

/* Classify the target the way the preload does for guest-initiated execs.
 * Without this, `alr run npm ...` hands a #! script straight to ld.so, which
 * reports "file too short" -- npm, npx, and most language-tool entry points
 * are scripts, so this is the common case, not an edge case.
 * Resolves the interpreter in the GUEST namespace and recurses. */
static int shebang_resolve(const struct launch *L, char *host, size_t hostsz,
                           const char **pre, int *npre, int depth)
{
    unsigned char head[ALR_PROBE_BYTES];
    struct alr_shebang sb;
    struct rdctx ctx;
    char interp_host[ALR_PBUF];
    enum alr_exe_kind k;
    ssize_t n;
    int fd;

    if (depth > ALR_SHEBANG_MAX_DEPTH) { errno = ELOOP; return -1; }
    fd = open(host, O_RDONLY);
    if (fd < 0) return -1;
    n = read(fd, head, sizeof head);
    ctx.fd = fd;
    k = alr_classify(head, n < 0 ? 0 : (size_t)n, rd_pread, &ctx, &sb, NULL, 0);
    close(fd);

    if (k != ALR_EXE_SHEBANG) return 0;      /* ELF (or unsupported): as-is */

    if (resolve(L, sb.interp, interp_host, sizeof interp_host) != 0) {
        errno = ENOENT;
        return -1;
    }
    /* argv becomes [interp, (arg,) script, original args...]; the script keeps
     * its GUEST path because that is what the program will see in argv. */
    if (sb.has_arg && *npre < 4) pre[(*npre)++] = strdup(sb.arg);
    if (*npre < 4) {
        char *g = malloc(ALR_PBUF);
        if (g) { snprintf(g, ALR_PBUF, "%s", host + L->root_len);
                 pre[(*npre)++] = g; }
    }
    snprintf(host, hostsz, "%s", interp_host);
    return shebang_resolve(L, host, hostsz, pre, npre, depth + 1);
}

static int cmd_run(const char *distro, int argc, char **argv, int login_shell)
{
    struct launch L;
    char host[ALR_PBUF];
    char *av[ALR_MAX_ARGV];
    const char *guest_cmd;
    struct alr_sup_opts o;
    struct alr_sup_stats st;
    int n = 0, i, status = 0, rc;
    const char *pre[4];
    int npre = 0;

    rc = prepare(&L, distro);
    if (rc == -1) die("rootfs-missing", "rootfs not installed; run `alr install`");
    if (rc == -2) die("ldso-missing",
                      "guest ld-linux-aarch64.so.1 not found; rootfs looks corrupt");

    guest_cmd = login_shell ? "/bin/bash" : argv[0];
    if (resolve(&L, guest_cmd, host, sizeof host) != 0)
        die("boot-enoent", "command not found in the guest");
    if (shebang_resolve(&L, host, sizeof host, pre, &npre, 0) != 0)
        die("boot-enoent", "script interpreter not found in the guest");

    /* ADR 0002: the program argument MUST contain a '/' -- glibc's dl-load.c
     * treats a slash-free name as a LIBRARY name and searches the library path
     * for it, not $PATH.  We always pass an absolute host path. */
    av[n++] = L.ldso;
    av[n++] = (char *)"--library-path";
    av[n++] = L.libpath;
    /* Defensive: there is no /system/etc/ld.so.cache today, but if one ever
     * appeared it would silently poison every library resolution. */
    av[n++] = (char *)"--inhibit-cache";
    av[n++] = (char *)"--argv0";
    av[n++] = (char *)(login_shell ? "-bash" : argv[0]);
    if (L.have_preload) { av[n++] = (char *)"--preload"; av[n++] = L.preload; }
    av[n++] = host;
    for (i = 0; i < npre; i++) av[n++] = (char *)pre[i];   /* shebang arg + script */
    if (login_shell) av[n++] = (char *)"-l";
    else for (i = 1; i < argc && n < ALR_MAX_ARGV - 2; i++) av[n++] = argv[i];
    av[n] = NULL;

    if (g_log >= 2) {
        fprintf(stderr, "alr: exec %s\n", L.ldso);
        for (i = 0; i < n; i++) fprintf(stderr, "  argv[%d]=%s\n", i, av[i]);
    }

    /* Start the resolver bridge before the guest exists.  If it cannot start
     * we continue without it: the guest then uses glibc's own resolver, which
     * is correct on devices that do not have Private DNS or a VPN. */
    g_resolv_sock = alr_resolvd_start(getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
    if (g_log >= 1 && !g_resolv_sock)
        fprintf(stderr, "alr: resolver bridge unavailable; guest DNS may fail "
                        "on devices with Private DNS or a VPN (RISKS R15)\n");

    memset(&o, 0, sizeof o);
    o.path = L.ldso;
    o.argv = av;
    o.envp = build_env(&L, guest_cmd, av[5]);
    o.log_level = g_log;
    o.log_fd = -1;

    if (alr_supervise(&o, &status, &st) < 0) { alr_resolvd_stop(); die("boot-failed", "supervisor failed"); }
    alr_resolvd_stop();

    if (g_log >= 1)
        fprintf(stderr, "alr supervisor: pids=%lu sigsys=%lu emulated=%lu "
                        "path_traps=%lu syscall_stops=%lu\n",
                st.tracees_seen, st.sigsys_seen, st.sigsys_emulated,
                st.path_traps, st.syscall_stops);

    return alr_exit_code(status);
}

/* ── main ────────────────────────────────────────────────────────────── */

static void usage(void)
{
    fprintf(stderr,
        "usage: alr [-d distro] [-v] <command>\n"
        "  install [<distro>] [--url <tarball>] [--with git,node,codex]\n"
        "                                     provision a rootfs\n"
        "  run <cmd> [args...]                run one guest command\n"
        "  shell                              interactive guest shell\n"
        "  version                            version and preload identity\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *distro = getenv("ALR_DISTRO");
    const char *url = NULL;
    int i = 1;

    {   /* Must happen before any fork: see g_self. */
        ssize_t n = readlink("/proc/self/exe", g_self, sizeof g_self - 1);
        if (n > 0) g_self[n] = '\0';
        else snprintf(g_self, sizeof g_self, "%s", argv[0]);
    }
    if (!distro || !*distro) distro = "ubuntu-24.04";
    if (getenv("ALR_LOG")) g_log = atoi(getenv("ALR_LOG"));

    while (i < argc && argv[i][0] == '-' && argv[i][1] != '\0') {
        if (!strcmp(argv[i], "-d") && i + 1 < argc) { distro = argv[++i]; i++; }
        else if (!strcmp(argv[i], "-v")) { g_log++; i++; }
        else if (!strcmp(argv[i], "--url") && i + 1 < argc) { url = argv[++i]; i++; }
        else break;
    }
    if (i >= argc) usage();

    if (!strcmp(argv[i], "install")) {
        const char *d = (i + 1 < argc) ? argv[i + 1] : distro;
        int j;
        for (j = i + 1; j < argc; j++) {
            if (!strcmp(argv[j], "--url")  && j + 1 < argc) url = argv[j + 1];
            if (!strcmp(argv[j], "--with") && j + 1 < argc) g_with = argv[j + 1];
        }
        if (!strncmp(d, "--", 2)) d = distro;
        return cmd_install(d, url);
    }
    if (!strcmp(argv[i], "run")) {
        if (i + 1 >= argc) usage();
        return cmd_run(distro, argc - i - 1, argv + i + 1, 0);
    }
    if (!strcmp(argv[i], "shell"))
        return cmd_run(distro, 0, NULL, 1);
    if (!strcmp(argv[i], "version") || !strcmp(argv[i], "--version"))
        return cmd_version();

    usage();
    return 2;
}
