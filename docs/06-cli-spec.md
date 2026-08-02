# 06 — CLI 스펙

바이너리: `$PREFIX/bin/alr`. 언어: C11 + C++17, NDK 29 / `--target=aarch64-linux-android24` 크로스 빌드.

## 1. 서브커맨드

```
alr install <distro> [--with git,node,codex] [--force] [--offline <tarball>]
alr remove  <distro>
alr list
alr update-components [<distro>]

alr run [옵션] <command> [args...]     단일 명령 실행
alr shell [옵션]                       게스트 로그인 셸 (기본 bash -l)
alr exec [옵션] -- <command> [args...] run과 동일하나 옵션 파싱 모호성 없음

alr doctor [--json] [--full]           디바이스 능력 진단
alr bench [--vs proot] [--json]        벤치마크
alr version
alr config get|set <key> [<value>]
```

### 1.1 `run` / `shell` / `exec` 공통 옵션

| 옵션 | 기본 | 설명 |
|---|---|---|
| `-d, --distro <name>` | 설정의 `default_distro` | 사용할 rootfs |
| `-w, --workdir <guest path>` | `/root` 또는 매핑된 cwd | 게스트 cwd |
| `-e, --env KEY=VAL` | — | 게스트 env 추가 (반복 가능) |
| `--fakeroot` / `--no-fakeroot` | 설정값 | uid 0 스푸핑 |
| `--log <0\|1\|2>` | 0 | 진단 상세도 |
| `--no-supervisor` | off | **위험**. 슈퍼바이저 없이 실행 (디버깅 전용, 대개 부팅 실패) |

### 1.2 cwd 매핑

- **현재 디렉토리가 `<R>` 아래면**: 대응하는 게스트 경로로 매핑.
- **그 밖이면**: `/root`로 폴백하고 경고를 낸다.

### 1.3 v1에는 바인드 매핑이 없다

**v1에서 게스트에게 보이는 것은 `<R>` 아래뿐이다.** `--bind`도, `$HOME` 자동 바인드도 없다.

> **왜 뺐는가**: 바인드는 [04-preload-spec.md §5.1](04-preload-spec.md)의 `rw()`가 **단일 무조건 접두사 붙이기**라는 설계와 양립하지 않는다. 바인드를 지원하려면 (a) 게스트 env로 바인드 테이블을 전달하는 변수, (b) `rw()`의 핫패스에 테이블 조회(≤100 ns 예산 위협), (c) `guest_canon()`의 역매핑 — 없으면 `getcwd`/`realpath`/`/proc/self/cwd`가 생 호스트 경로를 반환하고 다음 절대 open이 그것을 다시 접두사 붙여 이중 경로가 된다 — 이 셋이 모두 필요하다. 어느 것도 M1~M8에 마일스톤·acceptance·테스트가 없다.
>
> **Termux 홈의 프로젝트에서 작업하려면** 그 디렉토리를 rootfs 안으로 옮기거나(`<R>/root/` 아래), rootfs 안에서 클론한다. 이것이 v1의 워크플로다.

**v1.1 후보**: 바인드를 다시 넣으려면 위 (a)(b)(c)를 하나의 설계로 묶어 ADR을 쓰고, `rw()` 예산을 재측정하고, 역매핑 테스트를 acceptance에 추가한 뒤에 한다. 부분 구현은 조용한 경로 손상을 만든다.

## 2. 설정 파일

`$PREFIX/etc/alr/config.toml` (전역) → `$HOME/.alr/config.toml` (사용자) 순으로 병합.

```toml
default_distro = "ubuntu-24.04"

[runtime]
fakeroot   = true        # apt/dpkg에 필요
supervisor = true        # false로 두지 말 것 — 부팅이 안 된다
log        = 0

[paths]
root = "$PREFIX/var/lib/alr"

# [binds] 는 v1 에 없다 — §1.3 참조

[env]
# 게스트에 통과시킬 추가 변수
passthrough = ["TERM", "COLUMNS", "LINES", "http_proxy", "https_proxy", "no_proxy"]

[network]
mirror = ""              # 비우면 tarball 기본값 사용 (권장)
```

## 3. `alr doctor`

**설치 후 1회 필수.** 결과를 `state/<distro>/doctor.json`에 캐시하고 런타임이 읽는다.

[01-platform-facts.md §G](01-platform-facts.md)의 P1~P12를 전부 실행한다.

### 3.1 출력 형식

```
alr doctor — device capability report

  host
    android_sdk        35
    selinux            Enforcing                    [P1] PASS
    seccomp_mode       2                            [P1] PASS
    termux_build       f-droid (targetSdk 28)       [P3] PASS
    abi                arm64-v8a
    page_size          4096

  execution
    exec app_data_file                              [P3] PASS
    anon mmap RW→RX                                 [P4] PASS
    file-backed PROT_EXEC mmap (rootfs)             [P5] PASS
    getrandom                                       [P10] PASS
    memfd_create                                    [P10] PASS

  filesystem
    link(2) same-dir                                [P6] FAIL EACCES  → link2symlink 활성화
    /dev/full                                       [P9] FAIL EACCES  → 에뮬레이션 활성화
    /dev/{null,zero,urandom,tty,ptmx}               PASS
    posix_openpt/grantpt/unlockpt                   [P8] PASS

  namespaces
    unshare(CLONE_NEWUSER)                          [P7] EINVAL (예상됨)

  seccomp blocked syscalls                          [P2]
    99   set_robust_list      → emulate 0
    100  get_robust_list      → emulate -ENOSYS
    293  rseq                 → emulate -ENOSYS
    437  openat2              → emulate -ENOSYS
    439  faccessat2           → emulate -ENOSYS
    ... (총 N개, 에뮬레이션 테이블에 없던 것 M개는 ⚠️ 로 표시)

  rootfs scan                                       [P11]
    raw svc sites outside libc/ld.so: 3 binaries
      /usr/bin/gh          (Go — 경로 가상화 미적용, 동작 불가할 수 있음)
      ...

  process budget                                    [P12]
    live descendants 1 / phantom limit 32

  VERDICT: READY   (link2symlink=on, devfull_emu=on)
```

### 3.2 실패 등급

| 등급 | 의미 | 예 |
|---|---|---|
| `FATAL` | 제품이 동작 불가 | P3 exec 거부, P5 file-backed exec 거부, P10 getrandom 차단 |
| `MITIGATED` | 기능이 켜져서 해결됨 | P6 link → link2symlink, P9 /dev/full → 에뮬 |
| `EXPECTED` | 정상 | P7 EINVAL |
| `WARN` | 사용자가 알아야 함 | P11 Go 바이너리, P12 프로세스 예산 |
| `INVALID` | 측정 결과를 신뢰할 수 없음 | P1 permissive 디바이스 |

**`INVALID`면 `alr bench`가 결과에 무효 표시를 붙인다** ([00-product.md §6.6](00-product.md)).

### 3.3 P2 (syscall 스윕) 구현 주의

`PTRACE_SECCOMP_GET_FILTER`는 `CAP_SYS_ADMIN`이 필요해 쓸 수 없다. 대신:
- 자식 프로세스를 fork하고 SIGSYS 핸들러를 설치
- syscall 0..460을 **무해한 더미 인자로** 호출 (부작용 있는 것은 스킵 목록으로 제외: `exit`, `execve`, `kill`, `reboot`, `unlink` 등)
- SIGSYS가 오면 차단, `ENOSYS`면 미구현, 그 외면 허용으로 분류
- 각 syscall마다 자식을 새로 fork하는 것이 안전하다 (하나가 프로세스를 망가뜨려도 격리)

**Android 12 디바이스와 Android 15/16 디바이스 양쪽에서 돌려야 한다** — allowlist가 릴리스마다 늘었다 (365 → 392줄).

## 4. `alr bench`

[07-acceptance.md](07-acceptance.md) 참조.

## 5. 출력 규약

- **stdout은 게스트 것이다.** alr의 진단은 전부 stderr 또는 `ALR_LOG_FD`로.
- 종료 코드는 게스트의 것을 그대로 전파 (`WIFSIGNALED` → `128 + sig`).
- alr 자신의 실패는 `125`를 쓴다 (`env`/`nice`의 관례와 일치, 게스트 코드와 충돌 최소화).
- `--json`이 있으면 stdout에 JSON 한 덩어리, 사람용 출력 없음.

## 6. 시그널 처리

`alr`이 받는 시그널을 게스트 프로세스 그룹으로 포워딩한다:

| 시그널 | 동작 |
|---|---|
| `SIGINT`, `SIGTERM`, `SIGQUIT`, `SIGHUP` | `kill(-leader_pgid, sig)` |
| `SIGWINCH` | 포워딩 (터미널 크기 변경) |
| `SIGTSTP`, `SIGCONT` | 포워딩 (잡 컨트롤) |
| `SIGCHLD` | 슈퍼바이저 루프가 처리 |

**터미널 소유권**: `alr shell`은 게스트를 포그라운드 프로세스 그룹으로 만들어야 한다 (`tcsetpgrp`). Android에 제약은 없다 ([§B8](01-platform-facts.md)).

## 7. 에러 메시지 품질

사용자가 볼 실패는 **원인과 다음 행동**을 담는다. 예:

```
alr: 게스트 실행 실패
  reason=ldso-missing
  <R>/lib/ld-linux-aarch64.so.1 가 없습니다.
  rootfs가 손상되었을 수 있습니다. `alr install ubuntu-24.04 --force` 로 재설치하세요.
```

```
alr: Play Store 버전 Termux는 지원하지 않습니다
  reason=unsupported-android-policy
  이 Termux는 targetSdk >= 29 라 앱 데이터 경로의 실행이 SELinux에 의해 거부됩니다.
  F-Droid 또는 GitHub 릴리스 버전을 설치하세요: https://github.com/termux/termux-app/releases
```

```
alr: 게스트 프로세스가 상태 없이 사라졌습니다
  reason=android-phantom-process-kill
  Android가 앱당 백그라운드 프로세스를 32개로 제한합니다 (현재 자손 31개).
  Termux 알림에서 wake lock 을 켜거나 동시 프로세스를 줄이세요.
```
