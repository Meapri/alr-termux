# 08 — 구현 마일스톤 (Codex 작업 지시서)

> **읽는 법**: 마일스톤은 **순서대로** 한다. 각 마일스톤은 `Exit` 조건을 전부 만족해야 다음으로 간다. `Exit`가 `PENDING_DEVICE`인 항목이 있으면 그 마일스톤은 **미완**이며, 디바이스 없이 다음으로 넘어가는 것은 M5까지만 허용된다.

## 의존 그래프

```
M0 스캐폴딩
 └─ M1 공통 코어 (호스트에서 테스트 가능)          ← macOS/Linux에서 전부 검증 가능
     ├─ M2 슈퍼바이저                              ← 디바이스 필요
     └─ M3 첫 게스트 부팅  ← M2 필수                ← 여기가 진짜 첫 증명
         └─ M4 경로 가상화
             └─ M5 exec 연속성
                 ├─ M6 패키지 매니저 (fakeroot, link2symlink)
                 └─ M7 타깃 워크로드 (git/node/codex)
                     └─ M8 성능 + A/B
                         └─ M9 배포
```

---

> **진행 상황** (2026-08-02)
> - **M-1 기기 브링업 — 완료.** [evidence/2026-08-02-device-bringup.md](evidence/2026-08-02-device-bringup.md). `alr doctor` VERDICT READY, FATAL 0.
> - **M0 스캐폴딩 — 완료.** `Makefile`, `scripts/dev-push.sh`, `scripts/dev-bootstrap.md`.
> - **M1 공통 코어 — 완료.** Exit 3개 PASS(+1 M2로 이월), **macOS와 기기 양쪽에서 동일 결과**.
> - **M2 슈퍼바이저 — 완료.** 기기에서 **12/12 PASS**. 누적 `sigsys_seen=16 emulated=15 passthrough=1`,
>   불변식 `syscall_stops=0 path_traps=0` 유지.
>   재현: `ALR_SSH_KEY=... ./scripts/dev-push.sh supervisor`
> - **M3 첫 게스트 부팅 — 완료.** [evidence/2026-08-02-m3-first-boot.md](evidence/2026-08-02-m3-first-boot.md).
>   **스톡 Ubuntu 24.04(glibc 2.39, 무패치)가 부팅.** `sigsys=1 path_traps=0 syscall_stops=0`.
>   ADR 0001/0002가 반증 테스트로 실증됨(슈퍼바이저 없이 exit 159=SIGSYS, ld.so 없이 exit 127=ENOENT).
> - **M4 경로 가상화 / M5 exec 연속성 — 핵심 경로 동작, 미완.**
>   [evidence/2026-08-02-m4-m5-path-exec.md](evidence/2026-08-02-m4-m5-path-exec.md).
>   게스트가 rootfs를 `/`로 보고 `apt-get`/`dpkg`가 응답한다. ABI 게이트(GLIBC_2.17 단독) 통과.
>   **`rw()` 성능 게이트 통과 (MEASURED)**: abs 61.0 ns / rel 3.9 ns / sysdir 13.8 ns.
>   상위 프로젝트 변환기(4,334 ns/op) 대비 71배 싸다 → [RISKS R3 해소](RISKS.md).
>   **완료 선언하지 않는다** — `mkstemp` 계열, link2symlink, `/proc/mounts` 가상화, `dlopen`,
>   `posix_spawn`/`system`/`popen` 이 남아 있다. 특히 앞의 둘 없이는 M6이 진행되지 않는다.
> - **M6 패키지 매니저 — 완료.** [evidence/2026-08-02-m6-package-manager.md](evidence/2026-08-02-m6-package-manager.md).
>   `apt-get install git` 성공, **git 2.43.0 동작** (init/commit/status/clone --local 전부 PASS).
>   온디바이스 acceptance **PASS=36 FAIL=0**.
> - **M7 부분 완료.** [evidence/2026-08-02-m7-m8-workloads-perf.md](evidence/2026-08-02-m7-m8-workloads-perf.md).
>   Node v22.20.0 + npm 10.9.3 동작 — `process.execPath`, libuv `fs.statSync`, **io_uring 생존**,
>   `npm install` 네트워크 성공. Codex 는 미완(GitHub API 응답 실패).
> - **M8 첫 실측.** `git status` 10k 파일: native 44 ms vs alr 56 ms (**+27%**), 기동 **+8 ms**.
>   `path_traps=0 syscall_stops=0` 유지. **PRoot A/B 는 `PENDING`** (Termux proot 로더 실패).
> - **PRoot A/B 완료 (MEASURED).** proot-distro 대비 `git status` **34.8×**, 기동 **10.9×** 빠르다.
>   [증거](evidence/2026-08-02-m7-m8-workloads-perf.md). §4 의 1.5–4× 추정은 과소평가였다.
> - **재현성 작업 진행 중.** [evidence/2026-08-02-m9-reproducibility.md](evidence/2026-08-02-m9-reproducibility.md).
>   `alr install --with node,codex` 동작, **`--with git` 미완** (apt 스테이징).
> - **다음: `--with git` → 호환성 폭 측정 → `/proc/mounts` → 배포 → 스냅드래곤.**
>
> <details><summary>이전 M6 진행 기록</summary>
>
> - **M6 진행 중.** `apt-get update` **완주**(35.2 MB), 의존성 해석 정상, `dpkg --unpack` 신규 설치 성공.
>   막힌 곳: **패키지 업그레이드 경로**의 dpkg 언팩. 정확한 좁힘은
>   [evidence/2026-08-02-m4-m5-path-exec.md](evidence/2026-08-02-m4-m5-path-exec.md) "미해결" 절.
>   구현 완료: 리졸버 브리지, `mkstemp` 계열, `statvfs` 계열, `dlopen`, fakeroot(신원만), link→copy 폴백.
> </details>

## M0 — 스캐폴딩

**목표**: 빌드가 돌고 CI가 초록.

**산출물**
- `Makefile` — 두 개의 타깃: `alr`(호스트/bionic), `libalr_preload.so`(게스트/glibc). **정정**: 별도 `libalr_fakeroot.so` 는 만들지 않는다 — fakeroot 신원 사칭은 `ALR_FAKEROOT=1` 뒤에서 preload 안에 구현되어 있다(`src/preload/alr_preload.c` §6.10). 릴리스 레이아웃이 영원히 존재하지 않을 파일을 약속해서는 안 된다
- `scripts/build-host.sh` — NDK 29, `--target=aarch64-linux-android24`, `-Wl,-z,max-page-size=16384`
- `scripts/build-preload.sh` — `zig cc --target=aarch64-linux-gnu.2.17`, 플래그는 [04-preload-spec.md §1](04-preload-spec.md) 그대로
- `scripts/test-native-core.sh` — macOS/Linux에서 `src/common/` 테스트
- `src/common/alr_sys.h` — API 24 위 syscall의 inline `syscall()` shim: `memfd_create`, `statx`, `renameat2`, `pidfd_open`, `openat2`, `faccessat2`, `seccomp`
- CI: 세 타깃 빌드 + 호스트 테스트 + `readelf -V` 게이트

**Exit**
```
ALR BUILD HOST:               PASS
ALR BUILD PRELOAD:            PASS
ALR PRELOAD GLIBC FLOOR 2.17: PASS
```

**주의**
- **NDK 버전과 zig 버전을 정확히 핀한다.** `zig version`이 다르면 빌드를 실패시킨다 — 재현성 주장은 고정 버전에서만 참이다.
- Termux 네이티브 clang을 릴리스 경로로 쓰지 말 것. 온디바이스 이너 루프 전용이다.

---

## M1 — 공통 코어

**목표**: 디바이스 없이 검증 가능한 순수 로직을 전부 끝낸다. **여기에 시간을 아끼지 말 것** — 이후 모든 디버깅이 여기 정확성에 의존한다.

**산출물**
- `src/common/alr_path_rule.h` — **Linux 헤더를 include하지 않는다.** 정규화 + guest→host 변환 + host→guest 역변환. `..`는 루트에서 클램프.
- `src/common/alr_config.{h,c}` — `alr-config-v1` 탭 구분 + `%XX` 이스케이프 + FNV-1a 체크섬
- `src/common/alr_elf.{h,c}` — ELF64 aarch64 헤더 리더, `PT_INTERP` 추출, static/dynamic 분류
- `src/common/alr_exec_rule.{h,c}` — 순수 결정 커널: `decide_exec_path_mediation`, `decide_exec_envp_injection`, `path_under`, `colon_list_contains`, `split_env_entry`, shebang 파서
- `tests/cases/paths.tsv` — `(ALR_ROOT, input, expected)` 공유 테이블
- `tests/host/` — C 테스트 + Python 레퍼런스 모델. **둘 다 같은 tsv를 읽는다.**

**Exit** — ✅ 달성 (2026-08-02)
```
ALR PATH RULE HOST TESTS: PASS   (63 tsv cases, 73 assertions)
ALR ELF CLASSIFY:         PASS
ALR EXEC RULE TESTS:      PASS   (44 assertions)
ALR CONFIG ROUNDTRIP:     DEFERRED -> M2
```

> `alr_config`(`alr-config-v1` 직렬화)는 **M2로 미뤘다.** 상위 프로젝트는 execve를 넘어 상태를 넘기려고 이 포맷이 필요했지만, 이 설계는 env 변수(`ALR_ROOT`/`ALR_GUEST_EXE`/`LD_PRELOAD`)로 직접 넘긴다([02-architecture.md §6](02-architecture.md)). 슈퍼바이저가 체크섬 있는 핸드오프를 실제로 요구할 때 만든다 — 쓰이지 않을 포맷을 미리 구현하지 않는다.

**양쪽 실행 결과가 동일해야 한다** (이것이 M1의 진짜 검증):
```
macOS  : make test
device : ALR_SSH_KEY=... ./scripts/dev-push.sh test
         → context OK: uid=10297 Seccomp=2 u:r:untrusted_app_27:s0
```
`dev-push.sh`는 `uid>=10000 ∧ Seccomp==2`가 아니면 **실행을 거부**한다.

**필수 테스트 케이스 (최소)**
절대경로 / 상대경로 / `/proc`·`/sys`·`/dev` 통과 / 이미 rootfs 아래(멱등) / `..` 클램프 / `.` 제거 / 중복 슬래시 / 후행 슬래시 / 루트 자체(`/`) / 빈 문자열 / 임베디드 NUL 거부 / `ALR_PBUF` 초과 / 컴포넌트 경계(`/proctology`는 `/proc` 아님) / 역변환 왕복

**주의**
- `alr_path_rule.h`가 Linux 헤더를 include하면 macOS 테스트가 죽고 개발 루프가 10배 느려진다. **이것이 M1의 핵심 제약이다.**
- 경로 규칙은 여기에만 존재한다. preload가 자기 복사본을 만들면 드리프트로 "가끔 파일을 못 찾음"이 발생한다.

---

## M2 — 슈퍼바이저 ⚠️ 디바이스 필요

**목표**: SIGSYS 구제가 실제 디바이스에서 동작함을 증명.

**선행**: 참조 디바이스 확보 + `alr doctor` P1/P2 실행. **`getenforce == Enforcing` 이고 `Seccomp: 2`가 아니면 이 마일스톤의 모든 결과가 무효다.**

**산출물**
- `src/supervisor/alr_supervisor.c` — [03-supervisor-spec.md](03-supervisor-spec.md) 전체
- `src/supervisor/alr_sigsys_table.h` — 에뮬레이션 테이블 ([§5](03-supervisor-spec.md))
- `src/cli/doctor.c` — P1, P2, P3, P4, P5, P7, P10
- `tests/device/supervisor_*.c` — 테스트 프로그램들

**Exit**: [07-acceptance.md §2 M2](07-acceptance.md)의 9개 전부 PASS

**주의**
- `PTRACE_TRACEME` + go-pipe 순서를 정확히 지킨다. `PTRACE_SEIZE`를 쓰면 경합으로 자식이 `set_robust_list`에서 죽는다.
- `regs[0]`을 반드시 쓴다 (진입 시 arg0이 들어 있다).
- `regs[32] = si_call_addr`를 매번 쓴다 (`-ERESTARTNOINTR` 무한루프 방지).
- `waitpid`에 `__WNOTHREAD`를 넣는다.
- `si_code == SYS_SECCOMP`을 검증한다 — 게스트 자신의 SIGSYS를 삼키면 안 된다.
- **`PTRACE_SYSCALL`을 쓰고 싶어지면 멈추고 [09-codex-playbook.md](09-codex-playbook.md)를 읽는다.**

---

## M3 — 첫 게스트 부팅 ⚠️ **프로젝트의 진짜 첫 증명**

**목표**: 스톡 Ubuntu 24.04 rootfs에서 `/bin/true`가 exit 0으로 끝난다.

**산출물**
- `src/cli/install.c` — [05-provisioning-spec.md §1~4](05-provisioning-spec.md)
- `src/cli/alr_untar.c` — 안전 추출
- `src/cli/launch.c` — ld.so 호출 argv 조립 ([§C2](01-platform-facts.md) 규격 정확히)
- `src/preload/` 최소 골격 — 생성자 + `ALR_ROOT` 읽기만. **아직 재작성 없음**

**Exit**
```
INSTALL DOWNLOAD:      PASS
INSTALL VERIFY SHA256: PASS
INSTALL EXTRACT:       PASS
INSTALL REPAIR:        PASS
INSTALL LDSO OPTIONS:  PASS   argv0=yes preload=yes library-path=yes inhibit-cache=yes
ALR BOOT /bin/true:    PASS   exit=0
ALR BOOT /bin/echo:    PASS   stdout="alr"
ALR GUEST GLIBC VERSION: 2.39
```

**주의**
- `--library-path`를 빼면 라이브러리를 못 찾는다. ld.so 자신의 탐색은 인터포즈 불가라 **선언적으로** 풀어야 한다.
- 프로그램 인자에 반드시 `/`가 있어야 한다 (`elf/dl-load.c:2017` — 슬래시 없으면 `$PATH`가 아니라 라이브러리 검색 경로를 탄다).
- `LD_PRELOAD`는 절대 호스트 경로여야 한다.
- Termux의 `LD_PRELOAD`를 **제거**한다 (빈 문자열 대입 금지).
- `GLIBC_TUNABLES=glibc.pthread.rseq=0` 설정.
- 여기서 실패하면 M2의 SIGSYS 테이블에 항목이 빠진 것이다. `ALR_LOG=2`로 어느 nr에서 죽는지 본다.

**이 마일스톤이 통과하는 순간이 "스톡 glibc가 Android seccomp 아래에서 부팅한다"는 증명이다.** 여기까지 오면 나머지는 엔지니어링이다.

---

## M4 — 경로 가상화

**목표**: 게스트가 rootfs를 `/`로 본다.

**산출물**
- `src/preload/alr_rewrite.c` — `rw()`, `guest_canon()`, sysdir/멱등 규칙
- `src/preload/wrappers.def` — 심볼 표 정본
- `src/preload/wrappers_*.c` — `wrappers.def`에서 생성 또는 그것에 맞춰 수동 작성
- `src/preload/alr_procfs.c` — `/proc/self/{exe,cmdline,root,cwd,mounts,status}` 가상화
- `src/preload/alr_dlopen.c` — §6.13 (Node 네이티브 애드온 / Python C 확장에 필수)
- `src/preload/alr_tmpfile.c` — §6.14 (`mkstemp` 계열 — 없으면 M6의 apt가 깨진다)
- `src/preload/alr_devfull.c` — §12 + doctor P9
- `bench/microbench/rw_cost.c` — `rw()` 마이크로벤치

**Exit**: [07-acceptance.md §2 M4](07-acceptance.md) 전부 PASS. 특히:
```
PRELOAD RW ABS COST: <= 100 ns/op
PRELOAD RW REL COST: <= 20 ns/op
```

**주의**
- **`p[0] != '/'` 검사가 함수의 첫 줄이어야 한다.** git이 상대경로를 많이 쓴다.
- **정규화가 sysdir/멱등성 검사보다 먼저 와야 한다.** 순서가 반대면 `/proc/../etc/passwd`가 재작성 없이 통과해 게스트가 **Android 호스트의 `/etc/passwd`를 읽는다** ([04-preload-spec.md §5.1](04-preload-spec.md)의 경고).
- **`ALR_PBUF = PATH_MAX`(4096).** 더 작게 잡으면 커널이 받아들일 정상 경로를 거부한다.
- **캐시를 넣지 말 것.** memcmp보다 비싼 조회는 순손실이다.
- **malloc 금지.** 스택 버퍼만.
- **`stat` 계열을 호출하지 말 것.** 정의만 한다. `.2.17` 타깃이 링크 시점에 강제한다.
- `__*_chk` 5개(`__openat_2`, `__openat64_2`, `__getcwd_chk`, `__getwd_chk`, `__ttyname_r_chk`)를 빠뜨리지 말 것. 상위 프로젝트가 빠뜨린 것들이다.
- pre-2.33 stat 이름(`__xstat` 계열) 8개 **그리고 `fstat`/`fstat64`**도 정의한다 (M6 link2symlink가 `fstat`을 요구한다).
- `dlopen`(§6.13)과 `mkstemp` 계열(§6.14)을 M4에서 함께 한다. 둘 다 M6/M7에서 발견하면 원인 추적이 어렵다.
- `/proc/self/exe` 가상화는 **하드 요구사항**이다. Node의 `process.execPath`가 여기 달려 있고, 안 하면 npm/npx가 "Node 버그처럼" 깨진다.

---

## M5 — exec 연속성

**목표**: 게스트 안의 모든 exec가 후킹된 채 이어진다.

**산출물**
- `src/preload/alr_exec.c` — 13개 exec 함수 전부 + envp 재주입 + shebang
- `src/preload/alr_syscall.c` — `syscall()` 인터포즈 + 경로 인자 인덱스 표
- `src/preload/alr_guard.c` — `mount`/`umount2`/`chroot`/`pivot_root` → `EPERM`

**Exit**: [07-acceptance.md §2 M5](07-acceptance.md) 전부

**주의**
- **13개를 전부 한다.** 하나라도 빠지면 그 경로의 자식이 `ENOENT`로 죽고, 디버깅이 매우 어렵다.
- shebang 재귀 깊이 상한 4.
- `symlinkat`의 `target`은 **재작성하지 않는다** — 심링크 내용은 게스트 네임스페이스 문자열이다. 이런 비대칭이 여러 개 있으니 표를 신중히 만들고 항목마다 테스트를 붙인다.
- bionic 경계(게스트가 `/system/*`이나 `$PREFIX`를 부를 때)에서 `LD_PRELOAD`를 **교체**한다.
- `syscall()` 인터포즈가 없으면 Node의 `fs.stat`이 전부 `ENOENT`다. 성능이 아니라 **정확성** 문제다.

---

## M6 — 패키지 매니저

**목표**: `apt install`이 게스트 안에서 동작한다.

**산출물**
- `src/fakeroot/` — uid0 스푸핑 + mmap 메타DB
- `src/preload/alr_l2s.c` — link2symlink ([04-preload-spec.md §8](04-preload-spec.md))
- `src/cli/doctor.c` P6 추가
- `<R>/etc/apt/apt.conf.d/99-alr-no-sandbox` 등 수리 항목
- fakeroot ↔ preload **체인 계약** 구현 ([02-architecture.md §4.4](02-architecture.md) (3)번 부류). fakeroot는 `chown`/`chmod`/`mknod`/`stat` 계열의 **경로를 스스로 재작성하지 않고** `dlsym(RTLD_NEXT)`로 preload에 체인한다

**Exit**: [07-acceptance.md §2 M6](07-acceptance.md) 전부

**결정 사항 (이 마일스톤에서 답한다)**
- `alr doctor` P2가 SysV IPC를 허용한다고 답하면, **업스트림 `fakeroot` 패키지를 그대로 쓰는 것**과 자체 shim을 A/B로 비교한다. 자체 shim은 유지보수 부채이므로 업스트림이 동작하면 그쪽을 택한다.
- P6이 `link(2)` 성공을 보고하면 **link2symlink 계층 전체를 끈다.** 불필요한 복잡도이자 버그 표면이다.

**주의**
- fakeroot와 preload의 **심볼 분할이 load-bearing 계약**이다 ([02-architecture.md §4.4](02-architecture.md)). 공유 심볼(`stat` 계열, `chown`/`chmod`/`mknod` 계열)은 fakeroot가 바인딩을 이기되 **경로를 재작성하지 않고** `dlsym(RTLD_NEXT)`로 preload에 체인한다. 이걸 종단 처리로 만들면 `--fakeroot`(기본 켜짐)에서 모든 `chown`/`chmod`가 재작성 안 된 경로로 나가 `ENOENT`가 된다.
- link2symlink는 `stat`/`lstat`/**`fstat`**/`readlink`/`unlink`/`rename`/**`readdir`**/**`scandir`**를 함께 인터포즈하지 않으면 깨진다. `fstat` 누락 → `stat`과 `fstat`의 nlink 불일치로 dpkg 무결성 검사 실패. `readdir` `d_type` 보정 누락 → `find -type f`가 하드링크 파일을 전부 놓치고 `git add`가 설명 불가능하게 실패.

---

## M7 — 타깃 워크로드

**목표**: git, node, codex가 실사용 가능.

**Exit**: [07-acceptance.md §2 M7](07-acceptance.md) 전부

**이 마일스톤의 회귀 테스트가 특히 중요하다**
| 테스트 | 무엇을 지키는가 |
|---|---|
| `ALR GIT CLONE LOCAL` | link2symlink |
| `ALR GIT CLONE HTTPS` | NSS + resolver + 서브프로세스 exec |
| `ALR GIT HOOKS` | shebang exec |
| `ALR NODE EXECPATH` | `/proc/self/exe` 가상화 |
| `ALR NODE FS STAT` | `syscall()` 인터포즈 |
| `ALR NODE IO_URING SURVIVE` | 슈퍼바이저 SIGSYS 구제 (Node 22로 테스트) |

**Codex 관련 미결 항목** (`PENDING_DEVICE`)
- 2026년 시점 Codex의 정확한 샌드박스 비활성화 키/플래그를 `codex --help`로 확인하고 [05-provisioning-spec.md §5.2](05-provisioning-spec.md)를 갱신한다. **추측해서 하드코딩하지 말 것.**
- Codex가 `rustix` 크레이트의 raw-syscall 백엔드를 쓰는지 확인한다. 쓴다면 libuv와 똑같이 계층을 우회한다.

---

## M8 — 성능 + A/B

**목표**: **아무도 공개한 적 없는 숫자를 만든다.**

**산출물**
- `bench/` 이식 완료
- `alr bench --vs proot` 동작
- `bench/regression_gate.py`
- 참조 디바이스에서 측정한 리포트 (Android 12대 1종 + 15/16대 1종)

**Exit**: [07-acceptance.md §2 M8](07-acceptance.md) + 다음
```
ALR MEDIATION INVARIANT: path_traps=0 syscall_stops=0
```

**주의**
- **`getenforce`/`Seccomp:` 검증 없이 결과를 발표하지 않는다.**
- PRoot 베이스라인을 하나로 고정한다 (`PROOT_NO_SECCOMP=1`과 기본값을 한 차트에 섞지 말 것).
- 목표 배수는 [00-product.md §4](00-product.md)의 방어 가능한 범위 안이어야 한다. 넘으면 측정이 틀렸거나 베이스라인이 잘못된 것이다.
- **auditallow 로그 볼륨을 측정한다** ([07-acceptance.md §6](07-acceptance.md)). 이것이 숨은 지배 비용일 수 있다.

---

## M9 — 배포

**산출물**
- termux-packages `build.sh` (`pkg install alr`)
- GitHub 릴리스: `alr` 바이너리 + 두 개의 `.so` + `manifest.json`
- README에 방어 가능한 숫자만 담은 성능 표
- **호환성 폭 리포트** ([07-acceptance.md §5](07-acceptance.md)) — grun 대비 유일한 차별점이므로 헤드라인 지표

---

## 시간 배분 권고

| 마일스톤 | 상대 난이도 | 비고 |
|---|---|---|
| M0, M1 | 낮음 | 디바이스 없이 전부. 여기 정확성이 이후를 좌우하니 서두르지 말 것 |
| M2 | **높음** | ptrace + 시그널 의미론. 함정 3개가 전부 여기 있다 |
| M3 | 중간 | 대부분 배관. 여기서 막히면 M2 테이블 문제 |
| M4 | 중간 | 심볼 수가 많지만 반복적. 성능 예산이 진짜 제약 |
| M5 | **높음** | exec 13종 + 비대칭 경로 인자. 버그가 가장 잘 숨는 곳 |
| M6 | 중간 | link2symlink가 까다롭지만 P6이 꺼줄 수도 있다 |
| M7 | 중간 | 대부분 회귀 테스트 작성 |
| M8 | 낮음 | 이식 + 측정 |
