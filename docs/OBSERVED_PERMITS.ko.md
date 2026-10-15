# 네이티브 observed permit

`--features observed-authentication`으로 빌드한 `pumgye`에서
`--observed-permits`를 명시하면 기존 mTLS gRPC 리스너에
`ObservedProjectionPermits/Issue`, `/Observe`가 추가된다. 기존 decision 자격증명이
네이티브 집행 호출자를 인증한다. `--grpc-listen`, `--permit-key`,
`--authentication-trust`, `--authentication-live`, `--network-live`, `--route-live`,
`--projection-live` 리소스가 필요하다. 인증 live JSON의 `observed_clock_rates`는 strict 파서에는 선택 항목이지만 observed
활성화에는 필수다. `{"source_ppm":50,"receiver_ppm":75}`처럼 각각 0 이상
1,000,000 미만의 명시적 오차 범위를 설정해야 한다. 기본값이나 묵시적 equal-rate
가정은 없다. source 범위는 모든 고정 auth/network/route/plan 원격 소유자를,
receiver 범위는 로컬 BOOTTIME을 포괄해야 한다. 비밀은 기존처럼 참조로만 로드한다.
기존 strict RPC와 HTTP 결정의 동작은 유지된다. observed 소유자가 설정되지 않았거나
지원하지 않는 peer이면 거부하며 strict 검증으로 대체하지 않는다.

`--observed-authority`는 안정적인 소유자 base를 설정한다. 기본값은 `pumgye`이며
`A-Za-z0-9_.:-`의 1~64바이트만 허용한다. 시작 시 독립 CSPRNG 128비트 프로세스
nonce와 Linux BOOTTIME 시계를 만든다. permit의 서명된 `binding.authority_epoch`와
보고의 `clock_domain`은 정확히 `pobs1:<소문자 16진수 32자리 nonce>:<base>`이다.
처음 두 콜론만 구분자로 해석하고 나머지를 base로 보존한다. 최대 103바이트이며
공백, 대문자 16진수, 별도 정규화를 허용하지 않는다. 재시작하면 domain이 바뀌며,
서명 키가 같더라도 이전 domain permit은 거부한다. 인증 identity epoch는 Hopae
계보로 남으며 permit 시계로 사용하지 않는다. 실제 고정 소유자로 라우팅해야 하며
복제본 자동 탐색이나 다른 domain으로의 갱신은 지원하지 않는다.

운영 서비스는 기존 Authority의 동일한 DB/Kubernetes `Arc<View>`와 compiled policy를
캡처한다. 정책 복사본이나 별도 정책 엔진을 만들지 않는다. health, 호출자, 정확한
publication 세대가 계속 유효해야 한다. Kubernetes 수집에는 Authority BOOTTIME
틱을 사용하고 원래 수집 결과의 `valid_until_ms`를 publication 트랜잭션 전에 비공개
`LocalDeadline`에 묶는다. 수집, 컴파일, 영속 커밋, RPC, 콜백, 서명, 호스트 suspend가
모두 이 원래 예산을 소비한다. source evidence가 없거나 만료/폐기되면 인가를 거부한다.
strict 결정과 readiness도 같은 원래 publication 수명을 사용하며 `Instant` 구제는 없다.

발급에는 고정 Hopae SDK 클라이언트의 실제 `CheckedObservedService`, Sumunjang의
Enforce Allow, 실제 route/plan 소유자 관찰, 정책 Allow가 모두 필요하다. 기존
network/route/plan 클라이언트는 실제 인증 RPC 전후 Pumgye BOOTTIME을 샘플링한다.
원격 TTL/remaining 기간은 RPC 전에 고정한 로컬 시작점에 최대 1000ms로 묶이며,
원격 UTC expiry와 섞지 않는다. 인증 refresh는 이전 관찰을 소비하고 원래 가장 짧은
기한을 보존한다. route와 plan은 최초, 서명 전, 서명 후 다시 조회하며 scope와 revision이
일치해야 한다. 재조회가 원래 기한을 늘리지 않는다. 정책/인증 remaining은 콜백보다 먼저
캡처한 로컬 시작점에 묶는다. 모든 기한과 작업 최초 1000ms 상한을 교차하고 내림 및
1ms 여유를 적용한다. 원격 상대 TTL은 명시적으로 설정한 비대칭 시계 오차 범위와 SDK 구간 산술로 먼저
축소하고 RPC 전 원래 시작점을 보존해 내림한다. 추가 여유는 최종 source 틱의 양자화를
포괄한다. 시계 읽기 실패는 해당 source를
영구 폐기한다. 가짜 UTC now를 사용하지 않는다.

`Issue`는 별도 `ObservedProjectionPermitReply` 안에 기존 형태의 서명 permit과 인증된
시간 보고를 반환한다. `Observe`는 `PermitValidationRequest`의 정확한 요청/서명/domain을
검증하고 모든 실제 소유자와 정책을 다시 확인한다. 대체 permit을 발급하지 않는다.
보고는 새 request correlation, 정확한 receipt SHA-256, process domain, 자체 진행 시계
`owner_now_ms`, 서명 binding과 일치하는 policy/network/route/plan revision을 포함한다.
`cache_ttl_ms`는 항상 0이다. `proof_remaining_ms`는 해당 샘플의 전체 서명 수명 잔여량으로,
수신자의 replay 보존 상한 계산용이며 admission이 아니다. `remaining_ms`는 모든 현재
prerequisite와 proof로 제한한 별도 admission 하한 기간이다. 수신자는 endpoint와 서명을
검증하고 자신의 BOOTTIME 요청 전후 샘플 및 명시적 시계 오차 범위로 두 값을 변환해야 한다.
갱신 시 이전의 짧은 admission과 긴 retention을 보존해야 한다. 숫자 자체는 권한이나 lease가
아니며 서로 다른 domain의 raw expiry 최소값을 계산하면 안 된다.

엔드포인트는 공유 predecode admission, 8192바이트 요청/3072바이트 응답 제한,
decision-role 인증, 별도 작업 semaphore를 사용한다. snapshot guard나 writer lock을
콜백/RPC 동안 유지하지 않는다. 서명 결과는 서명 후 실제 소유자 재조회와 최종
호출자/publication/인증/network/시간 검사를 통과할 때까지 비공개다. 마지막 조회 이후의
원격 변경은 point-in-time 한계로 남으며 replay 소비와 최종 credential 출력은 downstream
소유자의 책임이다.

검증에는 실제 생성 mTLS auth/network/route/plan 및 observed permit RPC fixture,
독립 인증/Pumgye 시계 offset, digest/호출자 거부, 서명 후 route 세대 변경, publication 교체,
BOOTTIME Kubernetes readiness 만료, 기존 strict 테스트가 포함된다. 배포된 전체
projector/dispatch 경로의 적격성 검증을 뜻하지 않는다.
