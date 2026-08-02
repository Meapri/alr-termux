# 05 — 프로비저닝 스펙

`alr install <distro>` 가 하는 일. 모든 사실은 [01-platform-facts.md §E](01-platform-facts.md)에서 검증되었다.

## 1. 다운로드

### 1.1 Ubuntu (cdimage 경로 — 기본)

**`ubuntu-base-24.04-base-arm64.tar.gz`는 존재하지 않는다 (404).** 파일명은 포인트 릴리스로 붙고 `latest` 심링크가 없다.

```
1. GET https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/SHA256SUMS
2. 정규식 ^([0-9a-f]{64})\s+\*?(ubuntu-base-24\.04\.(\d+)-base-arm64\.tar\.gz)$
   → 세 번째 그룹이 가장 큰 줄 선택   (파일명 앞의 '*' 제거 주의)
3. 같은 디렉토리에서 그 파일명을 GET
4. 1의 해시로 검증
```

폴백 핀 (오프라인/에어갭): `ubuntu-base-24.04.4-base-arm64.tar.gz`, ~29.9 MB.

### 1.2 OCI 경로 (Debian 기본, Ubuntu 대체)

proot-distro는 v5.0.2(2026-05-17)부터 Python이고 OCI 이미지를 쓴다. tarball URL을 가진 셸 플러그인은 더 이상 없다.

익명 Docker Hub 풀 3단계:
```
1. GET https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/<img>:pull
2. GET https://registry-1.docker.io/v2/library/<img>/manifests/<tag>
   Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json
   → manifests[] 중 platform.architecture=="arm64" && platform.os=="linux" 선택
   → 그 digest로 다시 manifests GET → layers[] 획득
3. GET https://registry-1.docker.io/v2/library/<img>/blobs/<layer digest>
```

**같은 코드가 Ubuntu에도 동작하므로 다운로더 하나로 두 배포판을 커버한다.** cdimage 경로는 Ubuntu 전용 최적화다.

예산: Ubuntu ~30 MB, Debian ~50 MB.

## 2. 안전 추출

`src/cli/alr_untar.c`. 규칙:

| 규칙 | 이유 |
|---|---|
| 절대경로 멤버 거부 | traversal |
| `..` 컴포넌트 거부 | traversal |
| 심링크/하드링크 타깃이 추출 루트를 벗어나면 거부 | traversal |
| blk/chr/fifo/socket 멤버 **스킵** | 비루트에서 `mknod` 불가. (스톡 이미지엔 없지만 방어) |
| `chown`/`lchown` **절대 호출 안 함** | 비루트. 모든 파일이 Termux UID 소유가 된다 |
| setuid/setgid 비트 **마스킹** (`& ~07000`) | `/data`는 nosuid라 무의미. 12개 해당 바이너리는 필요도 원하지도 않는 것들 |
| xattr **스킵** | 스톡 이미지에 없음 |
| **하드링크 멤버는 tar가 실패해 파일이 아예 안 생긴다** — 추출 후 `fix_hardlinks()`로 복구 필수 | [§B6](01-platform-facts.md), [ADR 0004](adr/0004-link2symlink.md), [실측](evidence/2026-08-02-m3-first-boot.md) |
| 임베디드 NUL이 있는 이름 거부 | |
| 심링크 생성 실패는 치명적이 아님 (로깅) | |

추출 후 직접 생성: `/dev`, `/proc`, `/sys`, `/run`, `/tmp`(0777).

**원자성**: `<R>.part`에 추출 후 `rename`. 중단된 설치가 반쯤 된 rootfs를 남기지 않게.

## 3. 추출 후 수리 — 매우 짧다

### 3.1 반드시 써야 하는 것

둘 다 스톡 이미지에서 **0바이트**로 오며, 나중 이미지가 심링크로 줄 수 있으니 **먼저 `unlink`** 한다.

`<R>/etc/resolv.conf`:
```
nameserver 8.8.8.8
nameserver 8.8.4.4
```

`<R>/etc/hosts`:
```
127.0.0.1	localhost localhost.localdomain
::1	localhost localhost.localdomain ip6-localhost ip6-loopback
```

### 3.2 써야 하는 것

`<R>/etc/apt/apt.conf.d/99-alr-no-sandbox`:
```
APT::Sandbox::User "root";
```
> **첫 `apt update` 이전에 반드시.** 안 하면 apt가 `setgroups()`에서 즉사한다 — setuid 계열이 Android seccomp에 차단되어 있다 ([§A6](01-platform-facts.md)). apt 자체의 자동 저하는 접근성 검사에서만 발동하는데, Android에서는 `setgroups()`가 먼저 치명적이다. (슈퍼바이저가 setgroups를 0으로 에뮬레이션하므로 실제로는 살아남지만, 이 설정이 없으면 apt가 존재하지 않는 uid로 권한을 낮추려 해서 파일 접근이 깨진다. 둘 다 필요하다.)

`<R>/etc/dpkg/dpkg.cfg.d/99-alr`:
```
force-unsafe-io
```
> fsync 생략. Android 플래시에서 큰 속도 향상이자 안정성 향상.

`<R>/etc/passwd`, `<R>/etc/group`에 Termux UID/GID 줄 **추가** (덮어쓰기 아님):
```
alr:x:<uid>:<gid>:alr:/root:/bin/bash
```
게스트의 `ls -l`, `getpwuid()`가 해석되게.

### 3.3 절대 건드리지 말 것

- ❌ `<R>/etc/apt/sources.list.d/ubuntu.sources` — arm64 tarball이 이미 `ports.ubuntu.com/ubuntu-ports`와 noble/updates/backports/security, 올바른 `Signed-By` 키링을 갖고 온다. **덮어쓰면 오히려 망가진다.** 지리적 미러를 원할 때만 손댄다.
- ❌ `<R>/etc/passwd`, `<R>/etc/group` 본문 — 완비되어 있고 `_apt`(uid 42), `shadow`(gid 42)가 이미 있다.
- ❌ `<R>/etc/dpkg/dpkg.cfg.d/excludes` — 이미 있다.
- ❌ `<R>/etc/nsswitch.conf`, `<R>/etc/apt/sources.list`

### 3.4 alr 컴포넌트 배치

```
<R>/usr/lib/alr/libalr_preload.so
<R>/usr/lib/alr/libalr_preload.manifest.json   # 어느 빌드인지 기록
<R>/usr/lib/alr/manifest.json      {zig_version, target, source_sha256, output_sha256}
<R>/.alr/l2s/                      link2symlink 그림자 (활성화된 경우)
```

**rootfs 빌드타임 린트**: 모든 `.so`의 `PT_GNU_STACK`이 실행 불가인지 확인. RWX `PT_GNU_STACK`을 가진 `.so`는 `PROCESS__EXECSTACK` 미허용으로 **로드 실패**한다 ([§B3](01-platform-facts.md)).

## 4. 첫 부팅 검증

`alr install`은 끝나기 전에 다음을 순서대로 수행하고, 실패 시 rootfs를 남기되 명확히 보고한다.

```
INSTALL DOWNLOAD:        PASS
INSTALL VERIFY SHA256:   PASS
INSTALL EXTRACT:         PASS  (files=<n> skipped_special=<n> setuid_masked=<n>)
INSTALL REPAIR:          PASS
INSTALL LDSO PRESENT:    PASS  <R>/lib/ld-linux-aarch64.so.1
INSTALL LDSO OPTIONS:    PASS  argv0=yes preload=yes library-path=yes inhibit-cache=yes
INSTALL BOOT /bin/true:  PASS  exit=0 elapsed_ms=<n>
INSTALL BOOT /bin/echo:  PASS  stdout="alr"
INSTALL GLIBC VERSION:   2.39
```

`INSTALL LDSO OPTIONS`는 `ld.so --help`를 파싱한다. `--argv0`이 없으면(glibc < 2.33) **경고**하고 `argv0_leaks=true`를 상태에 기록한다 ([§C2](01-platform-facts.md)).

## 5. 패키지 부트스트랩 (`alr install --with git,node,codex`)

**순서가 중요하다.** ca-certificates 없이는 HTTPS가 안 된다.

```
1. §3의 수리 완료
2. apt-get update                         (plain http — 동작함)
3. apt-get install -y --no-install-recommends ca-certificates git xz-utils
4. Node (선택):
     GET https://nodejs.org/dist/index.json  → lts가 truthy인 첫 항목
     (폴백 v24.18.1)
     node-v<V>-linux-arm64.tar.xz 다운로드
     SHASUMS256.txt 로 검증
     <R>/opt/node 에 추출, <R>/usr/local/bin 에 node/npm/npx 심링크
5. Codex (선택):
     GET https://github.com/openai/codex/releases/download/rust-v<V>/codex-aarch64-unknown-linux-musl.tar.gz
     codex-package_SHA256SUMS 로 검증
     단일 실행파일 추출 → <R>/usr/local/bin/codex
     <R>/root/.codex/config.toml 작성 (§5.2)
```

### 5.1 왜 apt의 nodejs가 아닌가

Ubuntu 24.04 아카이브의 nodejs는 **18.19.1 (EOL)**. 반면:
- nodejs.org tarball은 단일 ~30 MB fetch, 루트 불필요, 현재 LTS, 공개 SHA256.
- 그리고 apt의 18.19는 libuv 1.44.2라 io_uring을 안 부른다 — **안전한 쪽**이다. 사용자가 20/22를 깔면 io_uring SIGSYS가 발생하는데, 슈퍼바이저가 `-ENOSYS`로 구제한다 ([§C8](01-platform-facts.md)). 두 경로 다 동작해야 한다.

**NodeSource는 MVP에서 배제** (3자 저장소 추가는 실패 표면만 늘린다).

### 5.2 Codex는 Rust다 — Node가 필요 없다

`openai/codex`는 Rust(`codex-rs`)이고 npm 패키지는 배포 shim일 뿐이다. 바이너리 직접 설치가:
- Codex 경로에서 Node를 완전히 제거 → io_uring 위험 소멸
- npm 경로(~129 MB 플랫폼 tgz + Node 런타임을 같은 바이너리 exec하려고 끌어옴) 회피

**`https://chatgpt.com/codex/install.sh | sh` 금지** — 루트 가능한 정상 Linux를 가정한다.

**Codex의 Linux 샌드박스는 반드시 꺼야 한다** — Landlock과 bubblewrap이 Android 앱 프로세스에서 동작하지 않는다 ([§D4](01-platform-facts.md)).

`<R>/root/.codex/config.toml`:
```toml
# alr: Landlock/bubblewrap이 Android 앱 프로세스에서 동작하지 않아 샌드박스를 끈다.
# 정확한 키 이름은 디바이스에서 `codex --help` 로 확인 후 확정할 것 (PENDING_DEVICE).
sandbox_mode = "danger-full-access"
```

> ⚠️ **PENDING_DEVICE**: 2026년 시점의 정확한 설정 키/플래그 철자를 확인하지 못했다. M7에서 디바이스의 `codex --help`로 확정하고 이 문서를 갱신한다. 확정 전까지 값을 추측해 하드코딩하지 말 것.

> ⚠️ **보안 고지**: Codex 샌드박스를 끄면 alr이 에이전트와 사용자 디바이스 사이의 유일한 방어선이 된다. `alr`은 보안 경계가 **아니다** ([00-product.md §5](00-product.md)). 이 사실을 설치 시 사용자에게 명시적으로 알린다.

### 5.3 fakeroot 사용

`apt`/`dpkg` 호출은 `ALR_FAKEROOT=1`로 실행한다. 비루트에서 `chown`/`mknod`가 `EPERM`이므로 필수다.

> **M6 결정 사항**: Android seccomp가 SysV IPC를 막지 않는다면 (`alr doctor` P2가 답한다) **업스트림 `fakeroot` 패키지를 그냥 쓰는 것**이 자체 shim보다 낫다. 자체 shim은 유지보수 부채다. A/B로 결정한다.

## 6. 재설치 / 삭제 / 목록

```
alr install ubuntu-24.04 --force     기존 rootfs 제거 후 재설치
alr remove ubuntu-24.04              rootfs + state 제거 (확인 프롬프트)
alr list                             설치된 배포판, 크기, glibc 버전, 마지막 doctor 결과
alr update-components ubuntu-24.04   libalr_preload.so 만 갱신
```

`alr update-components`가 중요하다 — `.so`를 고칠 때마다 rootfs를 다시 깔 이유가 없다.

## 7. 실패 분류

모든 프로비저닝 실패는 안정적 `reason=` 코드를 갖는다.

```
download-network          download-checksum-mismatch    download-404
extract-traversal-reject  extract-disk-full             extract-permission
repair-write-failed       ldso-missing                  ldso-option-unsupported
boot-failed               boot-sigsys                   boot-enoent
apt-update-failed         apt-install-failed            node-fetch-failed
codex-fetch-failed        unsupported-android-policy
```
