/* alr — SIGSYS emulation table.
 *
 * GENERATED FROM A REAL DEVICE by `alr doctor`, not from documentation.
 *   device   Samsung SM-X236N  (MediaTek MT8775 / mt6878)
 *   android  16 (SDK 36), SELinux Enforcing
 *   kernel   6.1.145-android14-11 aarch64
 *   context  uid=10297  u:r:untrusted_app_27:s0  Seccomp=2
 *   date     2026-08-02
 *   result   239 of 468 syscalls blocked (SIGSYS / SYS_SECCOMP)
 *
 * Regenerate with:  alr doctor            (see docs/06-cli-spec.md §3)
 * Rationale for the return values:  docs/03-supervisor-spec.md §5
 *
 * Only syscalls whose emulated return is NOT the default belong here.
 * The supervisor returns -ENOSYS for every other blocked syscall, because
 * glibc's "try the new syscall, fall back on ENOSYS" pattern keys on it.
 */
#ifndef ALR_SIGSYS_TABLE_H
#define ALR_SIGSYS_TABLE_H

#include <errno.h>

struct alr_sigsys_ent { long nr; long ret; const char *name; };

/* Default for anything blocked but absent from this table. */
#define ALR_SIGSYS_DEFAULT_RET (-ENOSYS)

static const struct alr_sigsys_ent alr_sigsys_tab[] = {
    /* --- credential drop: must SUCCEED, not fail ----------------------
     * A child lowering privilege via setgid(getgid()) before execve dies
     * here otherwise.  This is where apt's _apt sandbox and gpgv
     * grandchildren disappear.  MEASURED: 147 setresuid and 148/150
     * getres[ug]id are NOT blocked on this device, so they are absent. */
    {  99, 0,       "set_robust_list" },
    { 143, 0,       "setregid" },
    { 144, 0,       "setgid" },
    { 145, 0,       "setreuid" },
    { 146, 0,       "setuid" },
    { 149, 0,       "setresgid" },
    { 151, 0,       "setfsuid" },
    { 152, 0,       "setfsgid" },
    { 159, 0,       "setgroups" },

    /* --- privileged ops with no ENOSYS-keyed glibc fallback ----------- */
    {  39, -EPERM,  "umount2" },
    {  40, -EPERM,  "mount" },
    {  51, -EPERM,  "chroot" },
    { 112, -EPERM,  "clock_settime" },
    { 161, -EPERM,  "sethostname" },
    { 162, -EPERM,  "setdomainname" },
    { 170, -EPERM,  "settimeofday" },
    { 171, -EPERM,  "adjtimex" },
    { 266, -EPERM,  "clock_adjtime" },

    /* --- explicitly named -ENOSYS (same as the default; listed because
     *     these are the ones that actually fire in practice) ---------- */
    {  89, -ENOSYS, "acct" },
    { 100, -ENOSYS, "get_robust_list" },
    { 105, -ENOSYS, "init_module" },
    { 106, -ENOSYS, "delete_module" },
    { 116, -ENOSYS, "syslog" },
    { 224, -ENOSYS, "swapon" },
    { 225, -ENOSYS, "swapoff" },
    { 293, -ENOSYS, "rseq" },
    { 425, -ENOSYS, "io_uring_setup" },
    { 426, -ENOSYS, "io_uring_enter" },
    { 427, -ENOSYS, "io_uring_register" },
    { 449, -ENOSYS, "futex_waitv" },
};

#define ALR_SIGSYS_TAB_LEN (sizeof alr_sigsys_tab / sizeof alr_sigsys_tab[0])

/* Full measured blocked set (device ground truth, for regression diffing).
 * Entries not named above fall through to ALR_SIGSYS_DEFAULT_RET. */
#if 0
blocked = 18, 39, 40, 42, 51, 58, 89, 99, 100, 104, 105, 106, 112, 116, 143, 144,
145, 146, 149, 151, 152, 159, 161, 162, 170, 171, 180, 181, 182, 183, 184,
185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 202, 217,
218, 219, 224, 225, 234, 235, 236, 237, 238, 239, 244, 245, 246, 247, 248,
249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 262, 263, 264, 265,
266, 272, 273, 288, 289, 290, 292, 293, 294, 295, 296, 297, 298, 299, 300,
301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315,
316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330,
331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345,
346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360,
361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375,
376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390,
391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405,
406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420,
421, 422, 423, 425, 426, 427, 428, 429, 430, 431, 432, 433, 442, 443, 447,
449, 450, 451, 453, 454, 455, 456, 457, 458, 459, 460, 461, 467
#endif

#endif /* ALR_SIGSYS_TABLE_H */
