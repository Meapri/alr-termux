# RISKS — 미해결 리스크 및 디바이스 검증 대기

> 이 문서는 **알려진 미지수의 등록부**다. 항목이 해결되면 [01-platform-facts.md](01-platform-facts.md)로 옮기고 여기서 지운다. 조용히 지우지 않는다.

## 1. 제품을 끝낼 수 있는 리스크 (Fatal)

### ~~R1. `getrandom` 또는 `memfd_create` 차단~~ — **해소됨** ✅

두 syscall 모두 glibc 폴백이 없어 차단되면 제품이 성립하지 않았다.

**2026-08-02 실측 (SM-X236N, Android 16, `untrusted_app_27`, `Seccomp=2`): 둘 다 `allowed`.**
근거: [evidence/2026-08-02-device-bringup.md](evidence/2026-08-02-device-bringup.md).

`alr doctor` P10이 계속 검사하며, 차단된 기기를 만나면 여전히 **크게 실패**한다. Android 12~15 기기에서 재확인 필요하나 Fatal 등급에서는 내린다.

### R2. targetSdk 28 앱의 설치 자체가 막힘 — **이미 현실화됨** ⚠️

두 개의 별개 위협이다. 하나는 아직 멀었고, **하나는 이미 도착했다.**

**R2a — 플랫폼 하드 블록 (장기, 수년)**
Android가 `MIN_INSTALLABLE_TARGET_SDK`를 29로 올리면 F-Droid Termux 설치가 불가능해지고 `untrusted_app_27` 도메인의 exec 허용도 사라진다. 릴리스당 +1씩(23→24) 올라왔으므로 아직 멀다. 이것이 제품을 끝내는 유일한 플랫폼 변화다.

**R2b — Google Play Protect 차단 (지금 일어남)** — `MEASURED`

2026-08-02, SM-X236N / Android 16(SDK 36)에서 `adb install`이 **Play Protect에 의해 차단**되었다. 대화상자 원문:

```
Google Play 프로텍트
안전하지 않은 앱 차단됨
Termux
이 앱은 Android 이전 버전에 맞게 개발되었으며 최신 개인 정보 보호 기능을 포함하지 않습니다.
[세부정보 더보기]  [확인]
```

`pm path com.termux`는 비어 있었고 `mCurrentFocus`는 `com.android.vending/...PlayProtectDialogsActivity`였다. 즉 **설치가 완료되지 않았다.**

성격:
- 플랫폼 차단이 아니라 **Play Protect(GMS) 차단**이다. 우회 가능하지만 **사용자가 기기에서 직접 눌러야 한다** (`세부정보 더보기` → `무시하고 설치`).
- 기본 대화상자에는 진행 버튼이 없다. `확인`은 설치를 **취소**한다.
- GMS가 있는 모든 소비자 기기에서 발생한다 → **모든 사용자가 이 마찰을 겪는다.**

**제품에 대한 함의 (설계가 아니라 배포 문제)**:
1. 설치 안내에 이 대화상자를 **스크린샷과 함께** 명시해야 한다. 예상 못 하면 "Termux가 안 깔린다"로 이탈한다.
2. 이것은 `alr`이 고칠 수 없다 — Termux 앱의 targetSdk 문제이고 상류에서만 해결된다.
3. 자동화(CI, 기기 팜)에서는 `adb install` 전에 Play Protect 검증을 꺼야 하는데, 이는 **보안 설정 변경**이라 사용자 동의 없이 해서는 안 된다.
4. R2a의 선행 지표가 하나 더 생겼다: Play Protect의 차단이 "경고 후 우회 가능"에서 "우회 불가"로 바뀌는 시점.

**해결**: 특정 Android 버전에 마이그레이션 계획을 걸지 않는다. 첫 실행 때 스크래치 ELF execve를 프로브하고(`alr doctor` P3) `EACCES`면 크게 실패한다. `MIN_INSTALLABLE_TARGET_SDK`와 Play Protect 정책 양쪽을 릴리스마다 추적한다.

### ~~R3. `rw()` 성능 예산 초과~~ — **해소됨** ✅ `MEASURED`

2026-08-02, SM-X236N 온디바이스 (`bench/microbench/rw_cost.c`, 2M iterations):

| 케이스 | ns/op | 예산 | bare syscall 대비 |
|---|---|---|---|
| abs hit (deep, 최악) | **61.0** | ≤100 | 0.26× |
| abs hit (typical) | 37.3 | — | 0.16× |
| rel miss (git 핫패스) | **3.9** | ≤20 | 0.02× |
| sysdir 통과 | **13.8** | ≤40 | 0.06× |
| 교정: bare `getppid` | 233.9 | — | 1.00× |

**상위 프로젝트의 변환기는 cold 4,334 ns/op였다 — 우리는 61 ns로 71배 싸다.** 캐시를 넣지 않은 것이 옳았다(캐시 조회가 memcmp보다 비쌌을 것이다).

`git status` 10k 파일 모델(13,500회 재작성): 재작성 총비용 **0.82 ms**. PRoot는 같은 호출들에 5~20 µs의 ptrace 왕복을 내므로 67~270 ms다. 성능 논지가 큰 여유를 두고 성립한다.

> 아직 `MODELED`인 부분: 13,500이라는 호출 수는 문헌 추정이다. M8에서 `strace -c -f git status`로 실측해 확정한다.

## 2. 큰 재작업을 유발할 수 있는 리스크 (Major)

### ~~R15. 게스트 DNS가 동작하지 않는다~~ — **해결됨** ✅ (리졸버 브리지 구현)

아래는 진단 기록이다. 해결: `src/cli/alr_resolvd.c`(Termux측 bionic 리졸버 스레드) + preload의 `getaddrinfo`/`freeaddrinfo` 인터포즈. 검증: `apt-get update`가 35.2 MB를 받고 완주.

### R15 (원 진단). 게스트 DNS가 동작하지 않는다 — Private DNS / VPN 환경 — `MEASURED`

**2026-08-02 실측 (SM-X236N).** 게스트에서 이름 해석이 전부 실패한다:

```
게스트  getent hosts ports.ubuntu.com   → (빈 결과)
게스트  bash /dev/tcp/ports.ubuntu.com  → Temporary failure in name resolution
게스트  8.8.8.8:53 로 원시 DNS 질의     → 타임아웃 (응답 없음)
게스트  TCP 1.1.1.1:53 핸드셰이크       → OK       ← 네트워크 자체는 정상
Termux  ping ports.ubuntu.com           → 91.189.91.102  ← 호스트는 정상
```

**원인은 alr이 아니라 기기 네트워크 구성이다.** `dumpsys connectivity`:
- `UsePrivateDns: true`, `PrivateDnsServerName: 6cf6a6f2.d.adguard-dns.com` (DNS-over-TLS)
- VPN 인터페이스 `tun0` (`com.adguard.android`)가 사실상 모든 IPv4 경로를 잡고 있음

Android는 앱이 **netd를 통해** 해석하기를 기대한다. bionic의 `getaddrinfo`는 netd로 가므로 DoT/VPN을 존중하고 정상 동작한다. **glibc의 리졸버는 netd를 모르고 `/etc/resolv.conf`의 서버로 직접 UDP/TCP 53을 쏘는데, 그 경로가 막혀 있다.**

`nss_dns` 로드 카운트가 0인 것은 **정상**이다 — glibc 2.34+는 `files`/`dns` NSS를 libc에 내장해 dlopen하지 않는다. (초기 가설은 틀렸다.)

**영향 범위**: VPN이나 Private DNS를 쓰는 모든 사용자. 광고 차단기 사용자가 많으므로 드문 구성이 아니다. `apt update`, `git clone https://`, `npm install` 이 전부 막힌다 — **M6/M7의 하드 블로커**.

**해결책 후보**

| 안 | 내용 | 평가 |
|---|---|---|
| A. 사용자가 VPN/Private DNS를 끈다 | — | ❌ 사용자의 보안 설정이다. 제품이 요구할 수 없다 |
| B. `/etc/hosts` 정적 채움 | 필요한 호스트만 | ❌ 확장 불가 |
| C. `nameserver 127.0.0.1` + 로컬 프록시 | Termux에서 DNS 프록시 | ❌ 53 포트 바인딩에 `CAP_NET_BIND_SERVICE` 필요, 앱은 불가. `resolv.conf`는 포트 지정 불가 |
| **D. `getaddrinfo` 인터포즈 + 리졸버 브리지** | preload가 `getaddrinfo`/`gethostbyname`/`getnameinfo`를 가로채 Unix 소켓으로 Termux측 `alr-resolvd`에 위임. 그쪽은 **bionic `getaddrinfo`**를 쓰므로 netd·DoT·VPN을 그대로 존중 | ✅ **권장.** 유일하게 사용자 설정을 건드리지 않으면서 모든 환경에서 동작 |

**D안 주의점**: `getaddrinfo`는 `struct addrinfo` 링크드 리스트를 malloc으로 반환하므로 preload의 R1(no-malloc)이 이 경로에는 적용될 수 없다 — 핫패스가 아니므로 예외로 명시한다. `freeaddrinfo`도 함께 인터포즈해야 짝이 맞는다. `res_*` 계열을 직접 쓰는 프로그램(dig, nslookup)은 여전히 못 잡는다.

**우선순위**: M6 착수 전 필수. 현재 `apt update`가 이것 때문에 진행되지 않는다.

### R4. SIGSYS ptrace 왕복 비용이 예상보다 큼 — `PENDING_DEVICE`

설계는 "프로세스당 몇 번뿐"을 전제한다. 실제로 어떤 워크로드가 차단 syscall을 반복 호출하면(예: 어떤 라이브러리가 `faccessat2`를 루프에서 부름) 비용이 누적된다.

**해결**: 슈퍼바이저가 프로세스당 SIGSYS 수를 집계한다. 소프트 게이트 `sigsys_per_process <= 8`. 초과하면 원인을 조사하고, 정말 필요하면 [ADR 0001](adr/0001-signal-only-ptrace-supervisor.md)의 옵션 (C)(부팅 창에서만 ptrace 후 detach + in-process 핸들러)를 재검토한다.

### R5. exec 오버헤드가 히어로 벤치를 잡아먹음 — `PENDING_DEVICE`

`LD_PRELOAD` DSO가 execve마다 하나 더 매핑·재배치되고 전역 심볼 스코프가 커진다. `npm ci`는 라이프사이클 스크립트로 프로세스를 대량 생성한다. **`npm ci`가 히어로 벤치인데 오버헤드가 드러나는 곳도 exec다.**

여기에 명시적 ld.so 호출(argv 조립 + 파일 분류를 위한 open/read)이 더해진다.

**해결**: M8에서 `exec_throughput`를 native/alr/proot 3자 비교로 측정한다. `npm ci` 비율이 1.5배 미만이면 히어로 벤치에서 내리고 `git status`만 남긴다.

### R6. `auditallow` 로그 볼륨 — `PENDING_DEVICE`

`untrusted_app_27`은 `execute`와 `execute_no_trans` 양쪽에 `auditallow`가 걸려 있다. 게스트의 모든 execve와 모든 `.so` 매핑이 logd에 감사 레코드를 남긴다. Node 하나가 시작 시 `.so` ~40개 → 레코드 ~40개.

**이것이 PRoot 대비 이 설계의 지배적 숨은 비용일 수 있다.** PRoot는 게스트 바이너리를 직접 exec하지 않으므로 이 비용이 없다.

**해결**: M8에서 exec 집약 워크로드(`git rebase`, npm postinstall)의 `logcat -b events` 볼륨을 측정한다. **오버헤드 주장을 발표하기 전에 수치를 확보한다.**

### R7. Codex의 `rustix` raw-syscall 백엔드 — `PENDING_DEVICE`

Codex CLI는 Rust다. Rust std는 libc 래퍼를 쓰지만, `rustix` 크레이트는 raw syscall 백엔드를 선택할 수 있다. 그 경로를 쓰면 libuv와 똑같이 경로 가상화를 우회한다.

**해결**: M7에서 `strace -f`로 확인. 우회하면 `syscall()` 인터포즈로는 못 잡으므로(인라인 asm) 정적 링크 musl 바이너리의 특성상 대응이 어렵다. 최악의 경우 Codex를 게스트가 아니라 **Termux에서 직접** 실행하는 것을 권장한다 (musl 정적 링크라 rootfs가 필요 없다).

### R8. Codex 샌드박스 비활성화 키 미확정 — `PENDING_DEVICE`

2026년 시점의 정확한 설정 키/플래그 철자를 확인하지 못했다.

**해결**: M7에서 디바이스의 `codex --help`로 확정하고 [05-provisioning-spec.md §5.2](05-provisioning-spec.md)를 갱신한다. **추측해서 하드코딩하지 말 것.**

**부수 보안 이슈**: 샌드박스를 끄면 alr이 에이전트와 사용자 디바이스 사이의 유일한 방어선이 된다. alr은 보안 경계가 아니다. 설치 시 사용자에게 명시적으로 고지한다.

### ~~R14. preload SIGSEGV~~ — **근본 원인 확정 및 수정** ✅

**원인: preload의 생성자는 먼저 실행되지 않는다.**

glibc `_dl_init()`은 `l_initfini`를 **내림차순**으로 순회하고, preload는 인덱스 1(메인 맵 바로 뒤)에 놓인다. 따라서 **libc와 다른 모든 DSO보다 늦게** 초기화된다. 그동안 73개 래퍼는 이미 인터포즈 중이므로, 다른 라이브러리의 생성자가 래핑된 심볼을 건드리면 아직 NULL인 `real_*`로 점프해 `main()` 전에 죽는다.

- `libselinux`의 `init_lib()` → `fopen("/proc/filesystems")`
- `libgcrypt`의 자체 무결성 검사 → `/proc/self/maps` open

**이것이 `cat`/`true`/`readlink`는 되고 `ls`/`find`/`apt-get`은 죽은 이유다.** 앞 그룹은 libc만 링크하는데, libc 자신의 초기화는 인터포즈 불가능한 내부 별칭(`__openat_nocancel`, `__fstatat64_time64`)을 쓴다.

> `__attribute__((constructor(101)))`은 **도움이 되지 않는다.** 생성자 우선순위는 **한 오브젝트 안의** `.init_array` 항목만 정렬하며, 이 `.so`에는 항목이 하나뿐이라 완전한 no-op다. [04-preload-spec.md §3](04-preload-spec.md)이 반대로 적었고 **그것이 틀렸다.**

**"미바인딩 심볼 0개"는 이 가설의 반증이 아니라 예측이었다.** `g_missing`은 dlsym이 *실패한* 심볼만 기록한다. 여기서의 NULL 창은 어휘적(심볼이 없음)이 아니라 **시간적**(호출이 생성자보다 먼저 도착)이다. 모든 심볼은 나중에 정상 해석된다.

**수정: 생성자 의존을 버리고 최초 사용 시 초기화(lazy init).** `ensure_init()`을 모든 래퍼 진입점(`rw()`, `NEED`, `NEEDN`, fakeroot 게터)에 넣고, `dlsym` 재진입은 thread-local `g_in_init`으로 막아 그동안은 패스스루로 동작시킨다. 생성자는 최적화로만 남긴다.

**NULL 가드만으로는 부족했던 이유**: 가드는 크래시를 막지만 그 창에서 `g_root_len`이 0이라 `alr_rw()`가 **패스스루 모드**였다. 초기 생성자 경로의 호출들이 rootfs가 아니라 **Android 네임스페이스**를 조용히 건드리고 있었다. 10/10 안정은 운이었다(프로브성 초기화 코드가 실패를 "기능 없음"으로 처리).

함께 수정한 것:
- `exec_path_search()`의 무가드 `real_access()` 호출 (파일 내 유일하게 남아 있던 것)
- `readlink()` 역매핑의 잠재 스택 오버플로: `tmp[ALR_PBUF]`가 호출자의 `sz`로만 경계 지어져 있었다

## 3. 관리 가능한 리스크 (Minor)

### R9. SysV IPC 가용성 — `PENDING_DEVICE`

Android seccomp가 SysV IPC(`shmget`/`semget`/`msgget` 계열)를 막는지 확인되지 않았다. 막지 않는다면 **업스트림 `fakeroot` 패키지를 그대로 쓰는 것**이 자체 shim보다 낫다 (유지보수 부채 감소).

**해결**: `alr doctor` P2가 답한다. M6에서 A/B 결정.

### R10. 하드링크가 일부 디바이스에서는 동작할 수 있음 — `PENDING_DEVICE`

`link(2)` `EACCES`는 Android 11/12에서 직접 관찰되었고 10~16 정책 검토로 확인되었다. 그러나 OEM/커널 차이 가능성이 있다.

**해결**: `alr doctor` P6이 실제로 테스트한다. **성공하면 link2symlink 계층 전체를 끈다** — 불필요한 복잡도이자 버그 표면이다.

### R11. phantom process 32개 한도 — `SOURCE`, 완화만 가능

Node + Codex + 언어 서버 + git 서브프로세스가 32에 도달할 수 있다.

**해결**: 자손 수 추적, ~24에서 경고, wake lock 권장, 자손이 상태 없이 사라지면 `reason=android-phantom-process-kill`로 분류. `device_config put activity_manager max_phantom_processes <N>`은 adb가 필요한 파워유저용 탈출구다.

### R12. `--argv0` 없는 구형 rootfs — `SOURCE`

Ubuntu 20.04 / Debian 11(glibc 2.31)에는 `--argv0`이 없어 argv[0]이 호스트 경로로 샌다.

**해결**: Ubuntu 24.04만 v1 타깃. 구형 지원을 추가하려면 `ld.so --help`를 파싱해 지원 옵션 집합을 캐시하고, `argv0_leaks=true`를 상태에 기록한다.

### R13. PTY 슬레이브 ioctl 화이트리스트 — `SOURCE`, 완화 가능

13개만 허용. `FIONREAD`가 없는 것이 가장 아프다 (readline/ncurses가 쓴다).

**해결**: [04-preload-spec.md §11](04-preload-spec.md)의 번역 계층. 생 `EACCES`를 그대로 돌려주면 안 된다.

## 4. 명시적으로 수용한 한계 (리스크 아님)

이것들은 해결하지 않기로 **결정한** 것이다. 다시 논의하지 않는다.

| 한계 | 근거 |
|---|---|
| Go 컴파일 바이너리 (`gh`, docker CLI, hugo 등) | 인라인 `svc`. `LD_PRELOAD`로 원리적 불가. `alr doctor` P11이 경고 |
| 하드링크의 `st_nlink` 정확성 | 복사 폴백 + inode 신원 테이블로 대체. 프로세스 단위·1024개 제한(링크당 2 엔트리). 프로세스를 넘는 nlink 검사는 진실을 본다 ([M6 증거](evidence/2026-08-02-m6-package-manager.md)) |
| `ld.so.cache` | 로더를 항상 `--inhibit-cache`로 호출하므로 소비자가 없다. `ldconfig`은 no-op으로 대체하고, **`dpkg-divert` 로 등록**해 libc-bin 업그레이드에도 살아남게 한다 (아래 주석) |
| 그룹 멤버 64명 초과 | NSS `files` 백엔드가 잘라내고 `ALR_LOG` 에 기록한다. 조용한 절단이 아니다 |
| `initgroups()` | 미구현. `setgroups` 가 seccomp 로 차단되어 보조 그룹 설정 자체가 불가능하다 |
| 로케일 아카이브 | `LOCPATH` 를 rootfs 로 지정하므로 glibc 가 `locale-archive` 를 건너뛴다. 추가 로케일은 `locale-gen --no-archive` 로 디렉토리 생성해야 한다 (아래 주석) |
| `/dev/full` | **영구 비목표.** 서빙하려면 프로세스에서 가장 뜨거운 syscall 인 `write()` 를 인터포즈해야 하는데, 대상 워크로드 중 이 디바이스 노드를 쓰는 것이 없다. 게다가 stdio 심볼(`puts`/`putchar`/`fwrite_unlocked`/`dprintf`/…)을 하나라도 빠뜨리면 **성공한 쓰기로 조용히 통과**한다 — 열거 가능하고 요란하게 실패하는 `mkstemp`(9개)·NSS(15개) 계열과 다르다. `KNOWN_FAIL:non-goal-devfull` |
| §11 `ioctl` 번역 | **구현됨** ([M14](evidence/2026-08-03-m14-ioctl-php.md)). 실측이 스펙 전제를 반박했다 — `FIONREAD` 는 네이티브로 허용되어 마스터 fd 에뮬레이션이 애초에 불필요했다. `TIOCSTI` 만 의도적으로 계속 거부(`neverallowxperm`) |
| `php-cli` abort 재발 가능성 | 출하 빌드에서는 동작하나 **원인 미규명**. preload 심볼 테이블 크기에 민감(경계 ~152). 심볼을 덜어내면 재발할 수 있고 범인은 그 변경이 아니다. `breadth.sh` 가 회귀를 잡지만 오귀속 주의 |
| Ubuntu 26.04 의 uutils coreutils | **원리적으로 불가.** 26.04 는 GNU coreutils 를 uutils(Rust 멀티콜)로 교체했는데, 이 바이너리는 **inline `svc` 로 raw syscall 을 발행한다**(74개 확인. 일반 Rust 바이너리와 GNU coreutils 는 0개). `LD_PRELOAD` 는 libc 를 거치는 호출만 볼 수 있으므로 경로 가상화가 닿지 않고, 자기 이름을 `/proc/self/exe` raw syscall 로 읽어 로더를 본다. **위의 "Go 컴파일 바이너리" 와 동일한 한계이며 alr 의 결함이 아니다.** proot 는 syscall 마다 ptrace 를 걸어 이것을 잡지만, 그 비용을 내지 않는 것이 이 프로젝트의 존재 이유다([ADR 0001](adr/0001-signal-only-ptrace-supervisor.md)). 26.04 의 나머지(`bash`·`apt`·`dpkg`·`find`·`grep`·`sed`·`awk`·`tar`·`getent`)는 정상 동작하며, `alr install` 이 설치 시점에 이 사실을 경고한다 ([M15](evidence/2026-08-03-m15-cmdline-2604.md)) |
| `/proc/self/cmdline` | **합성됨** ([M15 §1](evidence/2026-08-03-m15-cmdline-2604.md)). 이전에는 로더 호출 전체와 모든 호스트 경로가 노출됐다. 단, 이것은 **자기 프로세스에 한한다** — `ps` 처럼 다른 pid 의 `/proc/<pid>/cmdline` 을 읽는 쪽은 여전히 로더 호출을 본다. 그 프로세스 밖에서는 고칠 수 없다 |
| `/proc/stat` 시간 필드 | Android 가 `/proc/stat` 을 앱 uid 에 `EACCES` 로 막는다. CPU **개수**는 `sched_getaffinity` 로 진짜 값을 얻어 합성하지만(`nproc`=8 과 일치), **시간 필드는 전부 0** 이다. 델타로 CPU 사용률을 계산하는 도구는 항상 0% 를 본다. `/proc/cpuinfo` 는 읽히므로 건드리지 않는다 |

> **`LOCPATH` 를 왜 쓰는가.** glibc 의 `_nl_find_locale` 은 리터럴 `/usr/lib/locale` 을 내부 호출로 열고, Android 호스트에는 그 디렉토리가 아예 없다. 그래서 게스트는 rootfs 가 `C.utf8` 을 배포하고 있는데도 `C`/`POSIX` 밖에 못 봤고, `tmux` 는 "need UTF-8 locale (LC_CTYPE) but have ANSI_X3.4-1968" 로 거부했다. `LOCPATH` 는 glibc 자신의 탈출구다. 대가는 `locale-archive` 를 못 읽는 것인데, 호스트에 로케일이 전무한 현 상태보다는 확실히 낫다.

> **`ldconfig` no-op 은 파일을 덮어쓰는 것만으로는 부족하다.** `libc-bin` 업그레이드가 진짜 래퍼를 복원하고, 그 래퍼가 정적 링크된 `ldconfig.real` 을 실행해 실패한다. 그 실패는 `libc-bin` 을 half-configured 로 남기므로 **이후의 모든 `apt install` 이 함께 죽는다** — 호환성 폭 측정에서 96개 패키지가 전부 "설치 불가" 로 보이는 형태로 드러났다. `alr` 이 매번 셰임을 다시 쓰는 것으로도 부족하다: 게스트 안에서 `alr` 을 거치지 않고 apt 를 돌리면 재발한다. 그래서 `alr install` 이 `dpkg-divert --local --rename --add /sbin/ldconfig` 를 등록한다. 이후 dpkg 는 새 버전을 `/sbin/ldconfig.distrib` 에 쓰고 우리 no-op 을 건드리지 않는다.
| 정적 링크 게스트 바이너리 | `LD_PRELOAD` 원리적 불가. `KNOWN_FAIL:unhooked-static-binary` |
| **`codex` 가 바로 그 사례다** | 배포 바이너리에 `INTERP` 도 `NEEDED` 도 없다(ET_EXEC, 269 MB). 실행은 되지만 **경로 가상화가 전혀 적용되지 않아** Android 파일시스템을 본다. 시작 시의 `could not create PATH aliases: Read-only file system` 이 그 증거다. `codex --version` 통과를 "게스트 안에서 동작함" 으로 읽으면 안 된다. 수용 테스트 `ALR CODEX LINKAGE` 가 추적한다 |
| Play Store Termux | [ADR 0005](adr/0005-play-store-unsupported.md) |
| setuid 의미론 / `sudo` | `/data`는 nosuid, setuid 계열은 seccomp 차단 |
| 보안 격리 | alr은 샌드박스가 아니다. 경로 재작성은 방어 경계가 아니다 |
| 커널 네임스페이스 | `unshare(CLONE_NEWUSER)` = `EINVAL`. 커널에 기능 없음 |
| GUI / GPU | 상위 프로젝트의 영역 |
| grun 대비 속도 우위 | 무승부에 가깝다. 차별점은 스톡 rootfs 호환성 |

## 5. 검증 우선순위

디바이스를 확보하면 **이 순서로** 확인한다. 앞의 것이 실패하면 뒤는 의미가 없다.

```
1. P1  getenforce == Enforcing && Seccomp: 2     (모든 측정의 전제)
2. P3  $PREFIX 스크래치 ELF execve                (설계 전체의 전제)
3. P5  rootfs 파일 file-backed PROT_EXEC mmap     (ld.so 동작의 전제)
4. P10 getrandom / memfd_create                   (R1 — Fatal)
5. P2  syscall 0..460 스윕                        (에뮬레이션 테이블 확정)
6. P4  익명 mmap RW→RX                            (Node JIT)
7. P6  link(2)                                    (R10 — link2symlink 필요 여부)
8. P8  posix_openpt / grantpt                     (PTY)
9. P9  /dev/full                                  (에뮬 필요 여부)
10. P7 unshare(CLONE_NEWUSER)                     (EINVAL 확인)
11. P11 rootfs raw svc 스캔                       (Go 바이너리 목록)
```

**Android 12대 디바이스 1종 + Android 15/16대 디바이스 1종**에서 각각 돌린다. bionic allowlist가 릴리스마다 늘었다 (365 → 392줄).
