#!/usr/bin/env bash
# Build the guest-side glibc interposer.
#
# The 2.17 floor is deliberate and load-bearing: it makes the linker REFUSE any
# accidental *call* into the stat family (stat/fstatat are GLIBC_2.33+), which
# the interposer must only DEFINE.  If this build starts failing with an
# undefined reference to stat/fstatat, that is the guard working -- fix the
# call, do not raise the floor.
set -euo pipefail

ZIG=${ZIG:-zig}
ZIG_REQ=0.16.0
TARGET=aarch64-linux-gnu.2.17
OUT=${OUT:-build/libalr_preload.so}
SRC="src/preload/alr_preload.c src/common/alr_elf.c"

have=$("$ZIG" version)
if [ "$have" != "$ZIG_REQ" ]; then
    echo "zig $ZIG_REQ required, found $have." >&2
    echo "Reproducibility only holds under an exact pin: a zig upgrade changes" >&2
    echo "the bundled compiler-rt and LLVM codegen." >&2
    exit 1
fi

mkdir -p "$(dirname "$OUT")"

# -D_FORTIFY_SOURCE=0 is NOT optional: distro/CI default CFLAGS often add
# -D_FORTIFY_SOURCE=2, which would make this library call into the very
# __*_chk symbols it defines -- infinite self-recursion.
"$ZIG" cc --target="$TARGET" \
    -shared -fPIC -O2 -D_GNU_SOURCE \
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
    -fno-stack-protector -fvisibility=default \
    -Wall -Wextra -Werror \
    `# The nonnull-attributed params below ARE checked for NULL on purpose:` \
    `# glibc declares them nonnull, but real callers pass NULL anyway and a` \
    `# preload that segfaults is far worse than one returning EINVAL. Keeping` \
    `# the checks is deliberate, so the diagnostic is suppressed rather than` \
    `# the code weakened. docs/04-preload-spec.md §1 mandates -Werror.` \
    -Wno-pointer-bool-conversion \
    -I src/common \
    ${ALR_CFLAGS_EXTRA:-} \
    -o "$OUT" $SRC

if command -v shasum >/dev/null 2>&1; then _sha() { shasum -a 256 "$@"; }
else                                        _sha() { sha256sum "$@"; }; fi

sha=$(_sha "$OUT")
# docs/04-preload-spec.md §1 and docs/05-provisioning-spec.md §3.4 require
# source_sha256 -- a digest of the inputs, not the path list that used to be
# emitted here.  Without it a manifest cannot answer "was this .so built from
# THIS tree", which is the whole point of shipping one.
SRC_ALL="$SRC src/common/alr_elf.h src/common/alr_path_rule.h src/common/alr_resolv_proto.h"
srcsha=$(for f in $SRC_ALL; do _sha "$f"; done | LC_ALL=C sort | _sha)
cat > "${OUT%.so}.manifest.json" <<EOF
{
  "zig_version": "$have",
  "target": "$TARGET",
  "sources": "$SRC",
  "source_sha256": "${srcsha%% *}",
  "output_sha256": "${sha%% *}"
}
EOF

echo "built $OUT"
echo "  $(grep -oE 'GLIBC_[0-9.]+' "$OUT" | sort -uV | tr '\n' ' ')"
