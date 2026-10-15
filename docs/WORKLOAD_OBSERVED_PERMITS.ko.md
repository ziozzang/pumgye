# 네이티브 Workload observed projection permit

`observed-authentication` 기능의 새 `WorkloadObservedProjectionPermits.Issue/Observe`는 kind3/AAL0, 정규 `wobs1` 인증 epoch와 동일 네이티브 컴파일 정책의 `workload_users`만 사용한다. 기존 Service RPC(kind2/users), wire와 기본 동작은 유지한다. 두 map 또는 strict UTC/observed 시간 사이 fallback은 없으며 Human 세션을 Workload로 변환하지 않는다.

고정 서버 설정과 실제 인증된 Hopae Workload ObserveTime 응답에서만 비공개 `CheckedObservedWorkload`를 만든다. 서명된 인증 증명만으로 권한을 주지 않는다. 같은 DB/Kubernetes `Arc<View>`의 단일 컴파일러가 리소스·동작·네트워크·정보등급·역할·AAL을 모두 평가하고 실제 네트워크 Allow, route, plan owner를 확인한다. grant 삭제, 정확한 View 교체, readiness 상실, 원천 record 누락이나 원래 만료는 거부한다.

callback 이전 BOOTTIME anchor와 원래 prerequisite 만료를 유지한다. refresh는 기존 admission deadline과 교집합을 취하며 TokenReview 이전 최대 1초 원천 수명을 갱신하지 않는다. 서명 뒤 RPC/인증 refresh와 최종 owner/time 검사를 통과하기 전에는 서명을 출력하지 않는다. 서로 다른 process tick과 UTC의 숫자 최소값을 사용하지 않는다.

기존 envelope/tag를 재사용한다. permit epoch와 report domain은 발급 Pumgye의 `pobs1:<32자리 소문자 hex nonce>:<authority>`와 일치한다. `owner_now_ms`는 해당 process의 suspend 포함 tick이다. `proof_remaining_ms`는 전체 서명 수명의 replay 보존 상한 근거이고, `remaining_ms`는 prerequisite로 단축된 admission 예산이다. 소비자는 인증과 권한을 독립 검증하고 기존 paired replay ledger를 사용해야 한다. RPC/kind별 별도 nonce namespace를 만들면 안 된다.

빌드 시 기능을 켜고 `--workload-observed-permits --workload-authentication-live workload-live.json` 및 기존 trust/permit/network/route/plan/mTLS 옵션을 제공한다. live JSON은 고정 endpoint, 인증서/키 파일 경로, token 환경변수 참조와 명시적 `observed_clock_rates`의 `source_ppm`/`receiver_ppm`이 필요하다. Service와 Workload를 모두 활성화하면 각각의 live 설정이 필요하다. 지원되는 BOOTTIME가 없으면 observed 활성화를 거부한다.

테스트는 실제 Pumgye 컴파일러/owner/서명 경계/mTLS RPC와 인증된 fixture peer를 사용한다. 같은 subject의 class 충돌, grant 삭제, AAL/정보등급/network/resource, scope/revision floor, callback과 서명 뒤 owner 교체 및 최종 만료를 검증한다. 이는 실제 K8s TokenReview부터 소비 projection/Root backend까지의 전체 경로, 외부 Pod/SA 철회 지연, browser, 운영 배포나 성능 검증을 뜻하지 않는다. 기존 legacy prerequisite/cache의 시간 가정을 전체 BOOTTIME 보장으로 확대하지 않는다. 상세 계약은 영문 문서를 따른다.
