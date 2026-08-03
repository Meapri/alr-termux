# M19 — 참조 기기 #2 (Snapdragon): 차단 집합은 SoC·커널과 무관하다

- **날짜**: 2026-08-03
- **기기**: Samsung SM-S937N (Galaxy S25 Edge), Snapdragon 8 Elite SM8750 (`ro.board.platform=sun`)
- **OS**: Android 16, SELinux Enforcing, 커널 `6.6.98-android15-8-pd6ff1cd-abogkiS937NKSS9CZG3-4k`
- **컨텍스트**: `uid=10447  u:r:untrusted_app_27:s0  Seccomp=2`
- **목적**: 이 저장소가 가장 오래 달고 있던 `PENDING_DEVICE` — [§A6](../01-platform-facts.md)의 "차단 239개는 이 기기의 집합인가, Android의 집합인가"

참조 #1은 SM-X236N / MediaTek MT8775 / 커널 6.1.145-android14 다. 두 기기는 **SoC 벤더와 커널 major.minor가 모두 다르고**, Android 릴리스만 같다.

## 0. 측정 자격부터

```
uid       : 10447
seccomp   : 2
selinux   : u:r:untrusted_app_27:s0:c191,c257,c512,c768
```

`uid>=10000 ∧ Seccomp=2` 가 아니면 이 문서의 모든 숫자가 허구다. Android 앱 seccomp 필터는 zygote가 uid≥10000으로 띄운 프로세스에만 설치되고, `adb shell`은 `Seccomp: 0`으로 나온다. 하네스가 게이트를 들고 있으며([`scripts/dev-push.sh`](../../scripts/dev-push.sh) `assert_context`), 통과 후에만 진행했다.

## 1. §A6 — 차단 집합 239개가 완전히 동일하다

| | 참조 #1 | 참조 #2 |
|---|---|---|
| SoC | MediaTek MT8775 | **Qualcomm** SM8750 |
| 커널 | 6.1.145-**android14** | **6.6.98-android15** |
| 차단 | 468개 중 **239** | 468개 중 **239** |

개수만이 아니라 **집합이 같다**:

```
$ scripts/diff-sweep.sh docs/evidence/sweeps/mediatek-mt8775-android16-k6.1.txt \
                        docs/evidence/sweeps/snapdragon-8elite-android16-k6.6.txt
  shared: 239
ALR SWEEP DIFF: IDENTICAL (239 syscalls, both devices)
```

### 1.1 결정적인 부분은 개수가 아니라 음성 주장이다

`alr_sigsys_table.h`는 참조 #1에서 **차단되지 않는다**고 명시적으로 단언한 세 개를 갖고 있다 — `setresuid`(147), `getresuid`(148), `getresgid`(150). 참조 #2에서도 셋 다 차단되지 않는다.

이게 왜 중요한가: 차단되는 자격증명 계열은 143·144·145·146·149·151·152다. 147/148/150은 **그 사이에 끼어 있다.** 만약 두 기기가 "대충 비슷한 범위를 막는" 서로 다른 필터를 갖고 있었다면 이 셋 중 하나는 갈렸을 것이다. 갈리지 않았다는 것은 두 필터가 같은 목록에서 생성됐다는 뜻이다 — 개수 일치의 우연이 아니라 **지문 일치**다.

### 1.2 그래서 무엇이 확정되고 무엇이 남았나

**확정**: `alr_sigsys_table.h`를 릴리스에 동봉하는 현재 방식이 옳다. 표는 기기별 생성물이 아니라 **기본값**이다. OEM·SoC·커널 버전은 무관하다.

**남음**: 두 기기 모두 **Android 16**이다. 갈린 축(SoC 벤더, 6.1→6.6, android14→android15)은 전부 무관했는데, **정작 allowlist가 실제로 따라가는 축은 갈리지 않았다** — bionic의 allowlist는 릴리스마다 커졌다(android12 365줄 → android16 392줄). 즉 이 결과는 "OEM은 상관없다"의 강한 증거이지 "Android 버전도 상관없다"의 증거가 아니다. Android 12~15 한 대가 남은 전부다.

### 1.3 하마터면 "비교 불가"로 끝날 뻔했다

diff를 시작할 때 `alr_sigsys_table.h`에서 `{ N, ... }` 표 행을 grep해 **30개**를 얻었다. 참조 #2는 239개다. 여기서 *"큐레이션된 예외만 남기고 원본 스윕은 폐기됐다 — 전체 diff는 참조 #1을 다시 손에 넣어야 가능하다"* 로 결론 내리고, 그 문장을 헤더에 커밋까지 했다.

틀렸다. 전체 239개는 **같은 파일 끝의 `#if 0` 블록**에 처음부터 있었고, [§A6](../01-platform-facts.md)이 그렇게 적어 두기까지 했다("그 헤더 끝의 `#if 0` 블록이 기기 ground truth이며, 회귀 diff의 기준선이다"). 내 grep이 표 행 문법만 찾았을 뿐이다.

**이 세션 다섯 번째 "부재 오독"이고, 앞선 넷과는 결이 다르다.** [M18 §5](2026-08-03-m18-codex-config.md)의 넷은 전부 *출력을 자르는 명령*(`head`·`grep -c`·`wc -l`)이 원인이었다. 이번엔 자르지 않았다 — **한 가지 문법으로만 찾고 못 찾자 없다고 했다.** 처방도 다르다: 부재를 주장하기 전에 **그 사실이 있다면 어디에 적혀 있을 문서를 먼저 읽는다.** §A6에 답이 있었고 나는 그것을 읽지 않은 채로 파일을 grep했다.

원본 스윕은 이제 [`docs/evidence/sweeps/`](sweeps/)에 한 줄에 하나씩 들어간다. 다음 비교는 `scripts/diff-sweep.sh` 한 줄이다.

## 2. ADR 0006 — SUD는 커널 6.6에서도 없다

[ADR 0006](../adr/0006-raw-syscall-binaries.md)은 raw `svc` 바이너리를 네이티브 속도로 가로챌 방법이 없다고 결론지었고, 근거 중 하나가 커널 6.1에서 `PR_SET_SYSCALL_USER_DISPATCH`가 arm64에 없다는 것이었다. 커널이 올라간 기기에서 다시 쟀다:

```
SUD      : UNAVAILABLE (range=Invalid argument empty=Invalid argument)
NOTIF    : LISTENER fd=3
FILTER   : INSTALLED
```

인자 두 형태 모두 `EINVAL`. **커널 6.6.98에서도 arm64 SUD는 없다.** seccomp user notification은 여기서도 붙지만, 그 비용은 이미 재 놓았다 — 154 µs/syscall([M-노티프 측정](../adr/0006-raw-syscall-binaries.md)). ADR 0006은 두 기기에서 유효하다.

## 3. ADR 0005 — Play 스토어 빌드를 처음으로 실측했다

[ADR 0005](../adr/0005-termux-github-build.md)는 GitHub 빌드(`targetSdk=28`)를 요구한다. Play 빌드가 왜 안 되는지는 **추론**이었고 실물을 잰 적이 없었다. 이 기기는 Play 빌드가 깔린 채로 왔다:

| | Play 빌드 | GitHub 빌드 |
|---|---|---|
| `versionName` | `googleplay.2026.06.21` | `0.118.3` |
| `targetSdk` | **37** | **28** |
| `minSdk` | 32 | 24 |
| `installerPackageName` | `com.android.vending` | `null` |

**ADR 0005의 전제가 `MEASURED`가 됐다** — Play 빌드는 실제로 `targetSdk=37`을 싣는다.

**결론은 여전히 추론이다.** Play 빌드에서 `alr`이 못 도는 것까지 잰 것은 아니다 — GitHub 빌드를 설치하려면 서명이 달라 Play 빌드를 **먼저 지워야** 했고(`INSTALL_FAILED_UPDATE_INCOMPATIBLE ... signatures do not match`), 지운 뒤에는 잴 대상이 없다. `targetSdk>=29`의 W^X 규칙에서 앱 데이터 디렉토리 실행이 막힌다는 플랫폼 사실로부터의 연역이 근거의 전부다.

교체 자체도 기록해 둔다: GitHub 빌드는 디버그 서명이라 `run-as com.termux`가 통하고, 그 덕에 UI를 거의 건드리지 않고 `authorized_keys`·`openssh`·`clang`을 넣을 수 있었다. Play 빌드에서는 이 경로가 없다.

## 4. 기능 — 두 기기가 같은 결과를 낸다

| | 참조 #1 (MediaTek) | 참조 #2 (Snapdragon) |
|---|---|---|
| `alr install --with git` | 2m27s | **2m29s** |
| 수용 시험 | 78 PASS / 0 FAIL / 2 KNOWN_FAIL | **78 PASS / 0 FAIL / 2 KNOWN_FAIL / 0 SKIP** |
| 호환성 폭 | 설치 96/96, 실행 96/96 | **설치 96/96, 실행 96/96** |
| 슈퍼바이저 자체시험 | 12/12 | **12/12** |
| `path_traps` / `syscall_stops` | 0 / 0 | **0 / 0** |
| preload 심볼 | 165 | **165** |

KNOWN_FAIL 2건도 같다: `PRELOAD DEV FULL ENOSPC`(영구 비목표)와 `ALR CODEX LINKAGE`(정적 musl이라 후킹 불가).

`--with git,node,codex` 조합이 이 기기에서 처음 한 번에 돌았다 — node v24.18.1, codex rust-v0.146.0, git 2.43.0.

### 4.1 ldconfig 다이버전이 진짜 업그레이드를 견뎠다

게스트에 `libc6-dev make python3 gcc`를 넣는 과정에서 `libc-bin`이 **2.39-0ubuntu8.7 → 8.8**로 올라갔다. 다이버전은 살아 있다:

```
local diversion of /usr/sbin/ldconfig to /usr/sbin/ldconfig.distrib
```

참조 #1에서는 이 경로를 억지로(강제 unpack) 밟게 해서 확인했다. 여기서는 **평범한 apt 업그레이드가 자연히 밟았고** 결과가 같았다.

## 5. 87/96은 기기 차이가 아니라 내 하네스 충돌이었다

첫 breadth 실행은 `install=87/96 run=87/96`으로 나왔다. 9개 실패의 dpkg 상태가 `triggers-pending`·`unpacked`·`absent`로 제각각이라 기기 차이를 의심할 만했다. apt 로그를 열자 원인이 하나였다:

```
108 E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 15272 (apt-get)
```

**앞서 10분 타임아웃으로 끊은 breadth 실행이 기기에서는 계속 돌고 있었다.** 타임아웃은 SSH 클라이언트를 죽였을 뿐 원격 프로세스를 죽이지 않는다. 그 상태에서 두 번째 실행을 띄웠고, 배치 12개가 전부 락에 막힌 뒤 개별 재시도로 87개만 겨우 붙은 것이다.

정리 후(고아 없음 확인 → `dpkg --configure -a` → 파손 0건) 단독으로 재실행하니 **96/96, 락 에러 0건**이었다.

교훈 두 개:

- **오래 도는 기기 작업은 분리해서 띄우고 폴링한다.** 클라이언트 타임아웃은 취소가 아니다.
- 이 저장소가 반복해 온 규칙이 또 맞았다 — **이상한 수치를 만나면 대상이 아니라 계측기를 먼저 본다.** 여기서는 apt 로그가 한 줄로 답했다.

## 6. 성능 — A/B

### 6.1 히어로 벤치 — `git status` 10k, **양쪽 git 2.53.0**

M8 의 `git status` 비교에는 약점이 있었고 문서가 그렇게 적어 두었다: 세 실행의 git 빌드가 달랐다(2.55/2.43/2.53). 여기서는 그것을 없앴다. proot-distro 가 제공하는 ubuntu 는 **26.04**(git 2.53.0)뿐이므로, alr 쪽도 26.04 게스트를 깔아 **같은 배포판·같은 git 버전**으로 맞췄다.

| | git | `git status --porcelain` (10,000 파일, 7회 중앙값) |
|---|---|---|
| native (Termux) | 2.55.0 | **37 ms** |
| **alr** | 2.53.0 | **39 ms** |
| proot-distro | 2.53.0 | **947 ms** |

**alr 은 네이티브와 2 ms 차이이고, proot 대비 24.3배다.**

native 다리만 여전히 다른 빌드다(Termux 의 git 2.55.0). alr/proot 쌍은 동일 버전이므로 **24.3배 쪽이 엄밀한 수치**이고, native 대비 1.05배는 근사치로 읽어야 한다.

양성 대조를 먼저 돌렸다. 첫 시도에서 alr 16 ms / proot 239 ms 라는 좋아 보이는 숫자가 나왔는데, **저장소가 아예 만들어지지 않은 상태였다** — 26.04 의 `mkdir` 은 uutils 라 동작하지 않았고, 나는 없는 디렉토리에 대해 git 이 에러 내는 시간을 재고 있었다. 파일 수를 찍어 둔 덕에 걸렸다. 최종 측정 전에 확인한 것:

```
tracked 파일 : alr 10000 / proot 10000
파일 하나 수정 후: alr " M f4242" / proot " M f4242"     <- 실제로 10k 를 훑는다
```

파일 트리는 **Termux 호스트가** 만들었고 git 만 게스트에서 돌렸다. 26.04 게스트에서 git 은 정상 동작한다([ADR 0006 추가 실측](../adr/0006-raw-syscall-binaries.md)).

### 6.2 하네스 A/B (24.04 게스트)

```
ALR BENCH NODE COLD vs PROOT:      5.23x  MEASURED  alr 61 / proot 319 ms  (identical node binary)
ALR BENCH EXEC THROUGHPUT:         330 exec/s  MEASURED  alr 330 / proot 133 exec/s
ALR MEDIATION INVARIANT:           PASS  path_traps=0 syscall_stops=0  MEASURED
```

node 는 게스트의 `/opt/node` 를 proot rootfs 로 통째로 복사해 **바이트 단위로 동일한 바이너리**임을 `cmp` 로 확인한 뒤 쟀다.

### 6.3 배수는 기기마다 다르다 — 인용할 때 기기를 붙인다

| | 참조 #1 (MediaTek) | 참조 #2 (Snapdragon) |
|---|---|---|
| `node -e 0` 콜드 | 6.60× (alr 55 / proot 363 ms) | **5.23×** (alr 61 / proot 319 ms) |
| exec 처리량 | 351 exec/s (proot 135) | **330 exec/s** (proot 133) |
| `git status` 10k | 34.8× (git 빌드 3종 상이) | **24.3×** (git 동일 버전) |

**alr 쪽 절대값은 두 기기가 거의 같고**(55→61 ms, 351→330 exec/s), 배수 차이는 대부분 **분모(proot)** 에서 온다. [M17 §3](2026-08-03-m17-bench-ab.md) 이 콜드 스타트에 대해 한 말이 여기서도 그대로다 — 큰 배수는 "alr 이 빠르다"가 아니라 "proot 가 느리다"는 진술이다.

`git status` 의 34.8× → 24.3× 하락은 기기 차이와 **git 버전 통일** 이 섞여 있어 분리되지 않는다. 더 엄밀한 쪽이 24.3× 이므로 앞으로는 이쪽을 인용한다.

`tests/device/bench.sh` 말미의 안내가 "MediaTek MT8775" 를 하드코딩하고 있었다. 이제 실행 기기를 `getprop` 으로 찍고, 같은 워크로드가 기기에 따라 6.60×/5.23× 로 갈린다는 사실을 함께 출력한다.

## 7. 남은 것

- **Android 12~15** — §A6를 완전히 닫는 마지막 변수. 기기 없음.
- **Play 빌드에서의 실패 실측** — 되돌리려면 GitHub 빌드를 지워야 해서 이 기기로는 사실상 불가.
- **R6 귀속**(auditallow가 측정 비용의 몇 %인가) — root 필요, 여전히 미해결([M16 §2.2](2026-08-03-m16-ipc-audit.md)).
- **php-cli 근본 원인** — 두 기기 모두 동작하지만 이유는 여전히 모른다([M14](2026-08-03-m14-ioctl-php.md)).
