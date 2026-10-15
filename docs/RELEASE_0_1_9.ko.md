# Pumgye 0.1.9 후보 — 운영 미적용

이번 후보는 명시적 Kubernetes API 문맥, 기존 grants와 같은 compiler의 정확한 server-owned 매핑, strict v1 SubjectAccessReview decoder, 기본-off 인증 persistent HTTP1 SAR listener를 포함한다. [문맥](KUBERNETES_API_CONTEXT.ko.md)·[매핑](KUBERNETES_AUTHORIZATION_MAPPING.ko.md)·[wire](KUBERNETES_SAR_WIRE.ko.md)·[서버](KUBERNETES_SAR_SERVER.ko.md) 계약을 따른다. 기존 Service/Workload 및 network/guard 기본 의미를 분리 유지하며 SAR에서 가짜 IP/Sum/AAL 또는 Human/Workload 인증 증명을 만들지 않는다.

로컬 실제 검증mTLS 같은 연결 Allow/Deny/Allow, caller 분리, Pending TLS flush 중 View 철회/취소 테스트를 갖지만 버전 변경 자체가 실제 API-server·운영·고속처리 완료를 뜻하지 않는다. 부모 소유 실제 API-server/artifact gate 전 서명·공개·적용은 보류한다. 기존 공개0.1.8 자산/운영 설정은 그대로다.

0.1.9 운영 후보는 실제0.1.8과 동일하게 `--features pumgye-server/observed-authentication`으로 빌드해 기존 RPC를 보존한다. 동결 raw마다 build feature를 기록해야 한다. 기본 feature는 SAR/strict native API를 포함하지만 observed-authentication의 Service/Workload observed permit RPC는 포함하지 않는다. 기존0.1.8 운영 raw는 pumgye-server/observed-authentication을 켜서 빌드했다. 따라서 기본-only SAR 후보로 기존 observed chain을 몰래 대체하면 안 된다. 별도 observed-feature raw는 독립 hash/provenance/gate가 필요하며 compile 포함도 runtime owner 자동 활성화를 의미하지 않는다.

적용 전 전용 API-server에서 v1/fixed caller/cacheAuthorizedRequests:false/cacheUnauthorizedRequests:false/failurePolicyDeny/authorizer순서/system:masters 제외/원천·grant철회/장애·재시작·rotation과 Root core/adminUI 문맥 호환을 검증한다. 기존 main K3s authorizer 변경을 허용하는 문서가 아니다. raw send-boundary 검사로 kernel 수락 응답이나 이미 허용된 작업·stream을 회수하지 못한다. persistent H1 구현과 별개로 H2 owner분리·극단적 처리량은 미완이다. native clock 미지원 시 opt-in SAR만 거부하고 legacy를 약화하지 않는다.
