# 07 — Acceptance 및 벤치마크

## 1. Acceptance 문자열 규약

상위 프로젝트에서 이식한다. 모든 테스트는 정확히 한 줄을 낸다:

```
<TEST NAME>: PASS
<TEST NAME>: FAIL
<TEST NAME>: SKIP
<TEST NAME>: KNOWN_FAIL:<reason>
<TEST NAME>: PENDING_DEVICE
```

**다섯 가지 상태만 존재한다.** "대체로 동작함"이나 "환경 문제"는 없다. 실패는 안정적 `reason=` 코드를 갖는다.

| 상태 | 의미 |
|---|---|
| `PASS` | 통과 |
| `FAIL` | 실패. 고쳐야 한다 |
| `SKIP` | **이 환경에 해당 없음** (판정 불필요, 영구적) |
| `KNOWN_FAIL:<reason>` | 알려진 미해결 실패. 안정적 reason 코드 보유 |
| `PENDING_DEVICE` | 참조 디바이스가 없어 아직 판정 불가. **PASS도 FAIL도 아니다** |

`PENDING_DEVICE`는 pass-rate 분모에서 제외한다. 다만 [08-milestones.md](08-milestones.md)의 읽는 법에 따라 `Exit` 항목에 `PENDING_DEVICE`가 하나라도 남아 있으면 **그 마일스톤은 미완이다** — 분모 제외가 마일스톤 통과를 뜻하지 않는다.

`grep`으로 집계 가능해야 하므로 문자열을 임의로 바꾸지 않는다. 문자열 변경은 이 문서를 함께 고치는 것으로만 허용된다.

## 2. 마일스톤별 acceptance

### M1 — 호스트 스캐폴딩
```
ALR BUILD HOST:                   PASS
ALR BUILD PRELOAD:                PASS
ALR PRELOAD GLIBC FLOOR 2.17:     PASS
ALR PATH RULE HOST TESTS:         PASS   (tests/cases/paths.tsv N cases)
ALR CONFIG ROUNDTRIP:             PASS
ALR ELF CLASSIFY:                 PASS
```

### M2 — 슈퍼바이저
```
SUPERVISOR TRACEME HANDSHAKE:     PASS
SUPERVISOR SIGSYS SET_ROBUST_LIST:PASS
SUPERVISOR SIGSYS ENOSYS DEFAULT: PASS
SUPERVISOR SIGSYS RESTART LOOP GUARD: PASS
SUPERVISOR SIGSYS PASSTHROUGH:    PASS
SUPERVISOR CHILD TRACKING:        PASS
SUPERVISOR NO SYSCALL STOPS:      PASS
SUPERVISOR SIGNAL FORWARD:        PASS
SUPERVISOR EXIT CODE:             PASS
```

### M3 — 첫 게스트 부팅
```
ALR LDSO INVOKE:                  PASS
ALR BOOT /bin/true:               PASS  exit=0
ALR BOOT /bin/echo:               PASS  stdout="alr"
ALR BOOT /bin/bash -c true:       PASS
ALR GUEST GLIBC VERSION:          2.39
ALR SUPERVISOR SIGSYS COUNT:      <n>   (기록만. 보통 1~3)
```
> **M3이 이 프로젝트의 진짜 첫 증명이다.** 여기가 통과하면 `set_robust_list` 문제가 실제로 풀린 것이다.

### M4 — 경로 가상화
```
PRELOAD PATH ABS:                 PASS
PRELOAD PATH REL:                 PASS
PRELOAD PATH SYSDIR:              PASS
PRELOAD PATH IDEMPOTENT:          PASS
PRELOAD DOTDOT CLAMP:             PASS
PRELOAD NORMALIZE BEFORE SYSDIR:  PASS
PRELOAD PBUF PATH_MAX:            PASS
PRELOAD PROC SELF EXE:            PASS
PRELOAD PROC SELF CMDLINE:        PASS
PRELOAD DLOPEN ABS PATH:          PASS
PRELOAD DLOPEN ORIGIN TOKEN:      PASS
PRELOAD MKSTEMP:                  PASS
PRELOAD DEV FULL ENOSPC:          PASS
PRELOAD CHK SYMBOLS PRESENT:      PASS
PRELOAD NO MALLOC IN REWRITE:     PASS
PRELOAD RW ABS COST:              61.0 ns/op  (게이트: <= 100)  MEASURED
PRELOAD RW REL COST:               3.9 ns/op  (게이트: <= 20)   MEASURED
PRELOAD RW SYSDIR COST:           13.8 ns/op  (게이트: <= 40)   MEASURED
PRELOAD RW MICROBENCH:            PASS
```

### M5 — exec 연속성
```
PRELOAD EXEC DYNAMIC:             PASS
PRELOAD EXEC SHEBANG:             PASS
PRELOAD EXEC SHEBANG RECURSION:   PASS
PRELOAD EXEC STATIC:              KNOWN_FAIL:unhooked-static-binary
PRELOAD EXEC ENVP IDEMPOTENT:     PASS
PRELOAD EXEC ALL 13 VARIANTS:     PASS
PRELOAD SYSCALL REWRITE:          PASS
PRELOAD SYMLINKAT ASYMMETRY:      PASS
ALR BASH INTERACTIVE:             PASS
ALR PIPELINE:                     PASS   (echo | grep | wc)
```

### M6 — 패키지 매니저
```
PRELOAD LINK2SYMLINK BASIC:       PASS
PRELOAD LINK2SYMLINK NLINK:       PASS
PRELOAD LINK2SYMLINK FSTAT NLINK: PASS
PRELOAD LINK2SYMLINK DTYPE:       PASS
PRELOAD LINK2SYMLINK UNLINK:      PASS
ALR DPKG VERSION:                 PASS
ALR DPKG ARCH:                    PASS   arm64
ALR APT VERSION:                  PASS
ALR APT UPDATE:                   PASS
ALR APT INSTALL git:              PASS
ALR DPKG LOCAL INSTALL:           PASS
ALR FAKEROOT IDENTITY:            PASS   uid=0 gid=0
```

### M7 — 타깃 워크로드
```
ALR GIT VERSION:                  PASS
ALR GIT CLONE LOCAL:              PASS   ← link2symlink 회귀 테스트
ALR GIT CLONE HTTPS:              PASS   ← NSS + resolver + git-remote-https 서브프로세스
ALR GIT STATUS 10K:               PASS   elapsed_ms=<n>
ALR GIT HOOKS:                    PASS   ← shebang exec
ALR NODE VERSION:                 PASS
ALR NODE EXECPATH:                PASS   ← process.execPath가 게스트 경로여야 함
ALR NODE FS STAT:                 PASS   ← libuv raw syscall 회귀 테스트
ALR NODE IO_URING SURVIVE:        PASS   (Node 22)  ← SIGSYS 구제 회귀 테스트
ALR NPM CI:                       PASS   elapsed_ms=<n>
ALR CODEX VERSION:                PASS
ALR CODEX SANDBOX DISABLED:       PASS
ALR PTY TMUX:                     PASS
```

### M8 — 성능
```
ALR BENCH GIT STATUS vs PROOT:    <ratio>x
ALR BENCH NPM CI vs PROOT:        <ratio>x
ALR BENCH NODE COLD vs PROOT:     <ratio>x
ALR BENCH EXEC THROUGHPUT:        <n> exec/s  (native/alr/proot)
ALR MEDIATION INVARIANT:          path_traps=0 syscall_stops=0
```

## 3. Regression gate

`bench/regression_gate.py`. CI와 온디바이스 스위트가 모두 실행한다.

**하드 불변식 — 어기면 즉시 실패:**
```
supervisor.syscall_stops == 0
supervisor.path_traps    == 0
preload.rw_abs_ns        <= 100
preload.rw_rel_ns        <= 20
preload.malloc_calls     == 0
preload.glibc_verneed_max <= "2.17"
```

`syscall_stops != 0`은 누군가 `PTRACE_SYSCALL`을 도입했다는 뜻이고, **그 순간 이 제품은 PRoot다.** 성능 주장 전체가 무효화되므로 가장 중요한 게이트다.

**소프트 게이트 (경고 후 기록):**
```
git_status_10k_ms   <= 이전 최고 * 1.10
npm_ci_ms           <= 이전 최고 * 1.10
sigsys_per_process  <= 8
```

## 4. 벤치마크 하네스

`alr bench`. 상위 프로젝트의 `bench/`를 이식한다 (APK 비의존이라 거의 그대로 온다).

### 4.1 필수 워크로드

| ID | 워크로드 | 비교 대상 |
|---|---|---|
| `hello` | `/bin/true` × 100 | native Termux / proot-distro / alr |
| `sh_true` | `/bin/sh -c true` × 100 | 동일 |
| `stat_storm` | 1,000회 `stat` | 동일 |
| `open_storm` | 1,000회 `open/read/close` | 동일 |
| `spawn` | 자식 100개 spawn | 동일 |
| **`git_status_10k`** | 10k 파일 저장소의 `git status` | 동일 ← **히어로** |
| **`npm_ci`** | 중간 크기 프로젝트의 `npm ci` | 동일 ← **히어로** |
| `node_cold` | `node -e 0` | 동일 (디엠퍼사이즈) |
| `exec_throughput` | execve/s | 동일 ← [§D2](01-platform-facts.md), 오버헤드가 드러나는 곳 |
| `dpkg_arch` | `dpkg --print-architecture` | 동일 |

### 4.2 리포트 스키마

```
backend        native | proot-distro | alr
device         <model>
soc            <chipset>
android_sdk    <n>
kernel         <version>
selinux        Enforcing | Permissive      ← Permissive면 결과 INVALID
seccomp_mode   2 | 0                       ← 2가 아니면 결과 INVALID
distro         ubuntu-24.04
workload       <id>
iterations     <n>
elapsed_ms     <n>
stddev_ms      <n>
relative_to_proot  <ratio> | PENDING_DEVICE
evidence       MEASURED | MODELED
result         PASS | FAIL | KNOWN_FAIL:<reason>
```

### 4.3 측정 규율

1. **`MEASURED`와 `MODELED`를 절대 섞지 말 것.** A/B 실측 전에는 `relative_to_proot=PENDING_DEVICE`.
2. **PRoot 베이스라인을 하나로 고정한다.** `PROOT_NO_SECCOMP=1`(모든 syscall 트랩)은 필드에서 흔한 워크어라운드지만 기본 설정과 **완전히 다른 베이스라인**이다. 한 차트에 섞지 말 것. 기본은 seccomp 켜진 proot-distro 기본값.
3. **워밍업 후 측정.** 콜드 페이지 캐시가 결과를 지배한다. 3회 워밍업 + 5회 측정, 중앙값 보고.
4. **동일 디바이스, 동일 세션, 동일 온도.** thermal throttling이 2배를 만든다.
5. **`getenforce`와 `Seccomp:` 검증 없이는 결과를 발표하지 않는다.** permissive 디바이스는 zygote 필터가 아예 없어 모든 문제가 사라져 보인다.

### 4.4 미측정 항목 — 반드시 채울 것

상위 프로젝트가 **PRoot vs ALR A/B를 한 번도 측정하지 못했다** (SELinux가 APK의 rootfs 실행을 막아서). **Termux는 이 측정을 처음으로 가능하게 한다.** 이것이 M8의 핵심 산출물이고, 이 프로젝트가 상위 프로젝트에 되돌려줄 수 있는 가장 큰 증거다.

추가로 아직 아무도 공개하지 않은 숫자들:
- `git status`의 proot vs native 격차 (정성적 보고만 존재)
- V8 JIT + W^X mmap churn의 proot 오버헤드 분리
- Node cold start의 proot 비용

## 5. 호환성 폭 (compatibility breadth)

[00-product.md §4](00-product.md)의 포지셔닝이 성립하려면 **속도가 아니라 호환성**을 숫자로 방어해야 한다.

`alr bench --breadth`:
```
상위 M개 Ubuntu noble 패키지 중:
  설치 성공        N / M
  실행 성공        N / M
  KNOWN_FAIL 분류  N / M   (reason별 집계)
```

M = 100으로 시작 (curated 목록: 빌드 툴체인, 언어 런타임, CLI 유틸). 이 숫자가 grun 대비 유일한 차별점이므로 **공개 발표의 헤드라인 지표**가 된다.

## 6. 숨은 비용 — 발표 전 반드시 측정

[§B1/§B3](01-platform-facts.md): `untrusted_app_27` 도메인은 `execute`와 `execute_no_trans` 양쪽에 `auditallow`가 걸려 있다. **게스트의 모든 execve와 모든 `.so` 매핑이 logd에 감사 레코드를 남긴다.** Node 프로세스 하나가 시작 시 `.so` ~40개를 매핑하면 레코드 ~40개다.

exec 집약 워크로드(`git rebase`, npm postinstall)에서 `logcat -b events` 볼륨을 측정한다. **이것이 PRoot 대비 이 설계의 지배적 숨은 비용일 수 있다.** 오버헤드 주장을 발표하기 전에 수치를 확보한다.
