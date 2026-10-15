# 네이티브 Human observed permit — 통합 후보

이 구현은 아직 공개·운영 Human 인가 완료를 뜻하지 않습니다. 실제 Hop Human source/RPC/SDK 검증과 정확한 source scope fingerprint pin이 최종 수용 조건입니다. 기존 Service/Workload 기본 동작과 RPC는 유지합니다. Human contract4 projection과 Root 최종 실행은 다음 단계입니다.

기존 `observed-authentication` feature로 빌드합니다. `--human-observed-permits --human-authentication-live human-live.json`을 명시하고 기존 authentication-trust/permit-key/network-live/route-live/projection-live와 필수 mTLS gRPC 설정을 함께 제공해야 합니다. Human 활성화가 없으면 해당 서비스는 등록하지 않습니다. 사용자 헤더로 클래스를 선택하거나 TLS 검증을 끄거나 기존 인증으로 fallback하지 않습니다.

관리자 소유의 bounded JSON은 기존 endpoint/CA/certificate/key/token_env/observed_clock_rates를 담는 `transport`, 명시적인 source/application/key-registry 최소 revision, `scopes`로 구성합니다. scope는 service/audience/app_id/route_id/route_revision/32바이트 destination_sha256/header_policy_revision/header_names/reserved_names를 고정합니다. 요청에서 endpoint·비밀 참조를 승격하지 않습니다. source/app/key floor는 publication 소유권용이며 서로 다른 사용자·세션 revision에 전역 최댓값을 적용하지 않습니다.

PEP는 공개 SDK의 실제 본문 기반 H1 v2 preparation으로 최종 요청을 결합합니다. Pum은 context/proof/digest/route reference를 받고 실제 Hop ObserveTime을 고정 peer SDK로 독립 호출합니다. opaque Observation만 private Human 증거를 만듭니다. DTO의 subject/AAL/IP/digest만으로 권한을 만들지 않으며 빈 본문을 조작하지 않습니다. 필수 source report fingerprint는 공개 SDK가 검증합니다. Pum은 opaque Observation::scope()의 route/revision/destination을 실제 route owner와 비교하며 같은 service/audience의 다른 설정 scope나 전역 source revision으로 대체하지 않습니다.

HumanObservedProjectionPermits Issue/Observe는 실제 Authority/View, 같은 human_users 정책, Sum 네트워크 증거, route/plan owner를 사용합니다. 실제 AAL1/2를 plan과 정책에 동일하게 전달합니다. AAL0/3, API-context Human, 클래스 간 grant fallback, metadata만으로 TOTP 승격은 거부합니다. 기존 role/network/resource 요건과 AAL3 거부를 유지합니다. 정책은 기존 Document CAS/DB로 게시하며 새 사용자 저장소를 만들지 않습니다.

전송 ingress에서 caller callback/decode보다 먼저 원래 BOOTTIME admission과 policy/authentication generation을 고정합니다. private one-shot extension을 소비하며 헤더나 decode 후 재샘플로 대체하지 않습니다. 회수·교체·관측 record miss·재시작·만료는 거부합니다. 관측/refresh는 원래 수명을 연장하지 않습니다. current 관측은 시점 확인이며 분산 회수 lease나 비동기 snapshot 엔진이 아닙니다.

서명 permit 전체 잔여 수명과 prerequisite로 짧아진 admission을 구분합니다. Pum 자체 pobs1 clock과 정확한 proof hash, TTL0를 사용합니다. 외부 tick을 UTC나 다른 clock의 expiry와 직접 비교하지 않습니다. 최종 credential 출력과 paired replay는 후속 Hop/Root contract4가 담당하며 기존 모든 클래스·모드와 같은 canonical nonce transaction을 사용해야 합니다.

wire 서명/DTO 거부 테스트만으로 네이티브 완료를 주장하지 않습니다. 실제 OIDC/LDAP와 실제 TOTP, Hop RPC, opaque SDK 관측, Pum permit 및 회수/ABA/취소/재시작/만료/final fence 검증이 필요합니다. 실제 네 서비스 backend0/1·재사용 검증은 다음 단계입니다. 성능·100k 검증을 주장하지 않습니다.

`HumanResourceAuthorization.Decide(ResourceDecisionRequest)`도 Human 명시적 활성화 때만 등록합니다. 같은 현재 Authority/View에 고정 PEP의 Human subject/AAL1·2 metadata를 평가하고 TTL0를 반환합니다. Hop을 호출하지 않으며 인증·서명 permit·freshness lease·최종 credential을 만들지 않습니다. preliminary Allow만으로 독립 ObserveTime이나 최종 permit을 생략할 수 없습니다. 실제 바이너리 fixture는 preliminary의 Source RPC 0회, 잘못된 신원/AAL 거부, Human grant 삭제 후 legacy users fallback 거부, 기본 시작에서 두 Human 서비스 미등록을 검사합니다.

외부 runtime 검증은 `tests/human_observed_permit.rs`의 `human_native_runtime::actual_native_hop_sdk_to_pum_authority_human_permit`입니다. 별도로 준비한 native portal driver와 정확한 Hop 실행 파일이 필요하므로 일반 workspace 실행에서는 ignored입니다. `--ignored --exact`, `OWNED_HUMAN_RUNTIME_FIXTURE`, `OWNED_HOPAE_BINARY`, 고정 `OWNED_HUMAN_PROVIDER=oidc|ldap`로 명시 실행합니다. `OWNED_HUMAN_LDAP_STARTTLS=1`은 LDAPS 대신 필수 StartTLS를 선택합니다. 준비물이 없으면 실패하며 metadata 서명 peer로 Hop을 대체하지 않습니다. 비공개 evidence 디렉터리를 보존하고 실제 본문 SDK preparation, native 로그아웃 직후 원래 proof 예산이 남아 있는 상태의 거부, 실제 Pum 실행 파일/SQLite 정책 CAS를 검사합니다. Sum/route/plan peer는 protocol fixture이므로 실제 4-core/H4/Root 전체 체인이나 모든 provider의 Human MFA를 입증하지 않습니다.
