# ADR 0006 — raw-syscall 바이너리를 어떻게 할 것인가

- **상태**: 채택 (2026-08-03)
- **관련**: [ADR 0001](0001-signal-only-ptrace-supervisor.md), [00-product.md §5](../00-product.md), [M15](../evidence/2026-08-03-m15-cmdline-2604.md)

## 배경

`LD_PRELOAD` 인터포저는 **libc 를 거치는 호출만** 볼 수 있다. inline `svc` 로 커널에 직접 가는 바이너리는 경로 가상화가 닿지 않는다. 해당하는 것:

- Go 로 컴파일된 모든 바이너리 (처음부터 비목표로 문서화)
- **uutils coreutils** — Ubuntu 26.04 가 GNU coreutils 를 대체해 채택한 것. 실측 inline `svc` **74개** ([M15 §3](../evidence/2026-08-03-m15-cmdline-2604.md))

즉 26.04 에서는 `ls`·`cat`·`echo` 가 통째로 동작하지 않는다.

## 이전 판단이 틀렸다

이 프로젝트는 "seccomp user notification 은 zygote 필터가 자리를 차지해 불가능" 이라고 기록해 왔다. **틀렸다.**

두 가지를 잘못 알고 있었다.

**1. 액션 우선순위.** 스택된 seccomp 필터에서 커널은 **수치가 낮은** 액션을 택한다. `SECCOMP_RET_USER_NOTIF` 는 `0x7fc00000`, `SECCOMP_RET_ALLOW` 는 `0x7fff0000` 이므로, **zygote 가 ALLOW 하는 syscall 에 대해서는 우리 USER_NOTIF 가 이긴다.** 자리를 빼앗기지 않는다. (zygote 가 `RET_TRAP`(0x30000) 으로 막는 것은 여전히 TRAP 이 이긴다 — 그건 이미 SIGSYS 로 처리 중이다.)

**2. EPERM 의 원인.** 필터 설치가 `EPERM` 으로 실패한 것은 정책이 아니라 **`no_new_privs` 가 0이었기 때문**이다. Android 앱 프로세스는 그것을 켜지 않는다. 우리가 직접 켜면 된다:

```
status   : NoNewPrivs: 0  Seccomp: 2
set NNP  : ok
NOTIF    : LISTENER fd=3        ← 설치됨
FILTER   : INSTALLED
```

`tests/device/probe_intercept.c`.

## 그래서 쓸 수 있는가 — 비용을 쟀다

`bench/microbench/notif_cost.c`, 같은 프로세스·같은 syscall(`getppid`, 인자 없음 → 순수 가로채기 비용):

| | ns/call |
|---|---|
| 베이스라인 (필터 없음) | 438 |
| `RET_ALLOW` 필터 추가 | 266 |
| `USER_NOTIF` + supervisor 응답 | **154,270** |

두 가지가 동시에 읽힌다.

**필터 평가 자체는 공짜다.** ALLOW 필터를 얹어도 베이스라인과 차이가 없다(266 vs 438 은 주파수 스케일링 잡음 수준). 즉 **몇 개 syscall 만 notify 하고 나머지는 ALLOW 하는 필터는 나머지에 아무 비용도 물리지 않는다.**

**하지만 알림 왕복은 154 µs 다** — 베이스라인의 352배. 그리고 이건 supervisor 가 같은 프로세스의 **스레드**인 하한값이다. 실제 구현은 별도 프로세스여야 한다(자기 supervisor 와 데드락하지 않으려면).

비교: proot-distro 의 `git status`(10k 파일) 전체가 1,704 ms 였다. 경로 syscall 을 3만 번쯤 하는 워크로드에 154 µs 를 물리면 **가로채기만으로 4.6초** 다. PRoot 보다 느리다.

> 이 수치는 유휴 CPU 깨우기 지연에 지배될 가능성이 있다(폰의 idle exit + big.LITTLE 마이그레이션). 바쁜 supervisor 로 재보려 했으나 벤치마크가 걸려 측정하지 못했다 — **UNVERIFIED**. 다만 결론을 뒤집으려면 30배 이상 빨라져야 하는데, 그 정도는 기대하기 어렵다.

## 값싼 길은 이 커널에 없다

`PR_SET_SYSCALL_USER_DISPATCH` (SUD) 는 정확히 이 문제를 위한 기능이다. 지정한 PC 범위 **밖에서** 발행된 syscall 을 **같은 스레드에서** SIGSYS 로 잡는다 — tracer 도, 컨텍스트 스위치도 없다. 스레드별 바이트 하나로 켜고 끄므로 우리 자신의 libc 호출은 전속력을 유지한다.

```
SUD      : UNAVAILABLE (range=Invalid argument empty=Invalid argument)
kernel   : 6.1.145-android14
```

인자를 두 형태로 시도해 **인자 실수가 아님을 확인**했다. arm64 SUD 는 이 커널에 없다.

## 결정

**1. 기본 경로는 바꾸지 않는다.** `LD_PRELOAD` + signal-only supervisor 가 그대로 v1 이다. 실측 96/96 패키지가 이 경로로 동작하고, 경로 계층 총비용은 `git status` 49 ms 중 약 40 µs 다.

**2. raw-syscall 바이너리는 계속 비목표로 둔다.** 다만 근거를 정정한다 — "원리적으로 가로챌 수 없다" 가 아니라 **"가로챌 수는 있으나 그 비용이 이 프로젝트의 존재 이유를 지운다"** 이다.

**3. 선택적 적용은 열어 둔다 (미구현).** 필터 평가가 공짜라는 것이 설계 여지를 만든다:

- `alr` 은 이미 exec 시점에 바이너리를 분류한다(`alr_classify`). 여기에 inline `svc` 스캔을 더할 수 있다.
- `svc` 를 가진 바이너리에 대해서만, 그 자식 프로세스에 한해, **경로를 나르는 syscall 에만** USER_NOTIF 필터를 건다.
- 그 바이너리는 PRoot 급(혹은 그 이하) 속도로 **동작은 한다**. 나머지 시스템은 아무 영향도 받지 않는다.

이걸 하려면 먼저 답해야 할 것들이 있고, 전부 미검증이다:

- supervisor 가 죽으면 notify 대상 syscall 이 `ENOSYS` 로 실패한다. 필터는 제거할 수 없다 — 신뢰성 설계가 필요하다.
- `no_new_privs` 는 되돌릴 수 없고 setuid 의미론을 죽인다. 이미 비목표라 수용 가능하지만 게스트 의미론의 실제 변경이다.
- 경로 인자 재작성은 `SECCOMP_IOCTL_NOTIF_ADDFD` 로 fd 를 주입하거나 `/proc/pid/mem` 을 쓰는 방식이 필요하다. 후자는 TOCTOU 가 있는데, **alr 은 보안 경계가 아니므로**([00-product.md §5](../00-product.md)) 그 자체는 결격 사유가 아니다.
- 바쁜 supervisor 로 154 µs 가 얼마나 줄어드는지.

**4. 26.04 는 v1 대상이 아니다.** 설치는 되고 coreutils 를 제외한 나머지는 동작하며, `alr install` 이 그 사실을 경고한다.

## 다시 볼 조건

- **arm64 SUD 를 지원하는 커널이 흔해지면** 이 결정을 뒤집어야 한다. SUD 는 프로세스 안에서 처리되므로 알림 왕복이 없고, raw-syscall 바이너리를 native 에 가까운 비용으로 지원할 수 있는 유일한 알려진 길이다.
- Ubuntu 가 26.04 이후로도 uutils 를 유지하고 사용자가 최신 LTS 를 요구하면, 위 3번(선택적 적용)이 "느리지만 동작" 과 "아예 안 됨" 중 하나를 고르는 문제가 된다.
