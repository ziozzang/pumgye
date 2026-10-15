# Pumgye 0.1.9 — 검증된 릴리스 준비

명시적 Kubernetes API 문맥, 기존 grants와 같은 compiler의 정확한 server-owned 매핑,
strict v1 SubjectAccessReview decoder, 기본-off 인증 persistent HTTP1 SAR listener를
추가한다. [문맥](KUBERNETES_API_CONTEXT.ko.md)·[매핑](KUBERNETES_AUTHORIZATION_MAPPING.ko.md)·
[wire](KUBERNETES_SAR_WIRE.ko.md)·[서버](KUBERNETES_SAR_SERVER.ko.md) 계약을 따른다.
기존 Service/Workload 및 network/guard 기본 의미는 분리 유지하며 가짜 IP/Sum/AAL이나
Human/Workload 인증 증명을 만들지 않는다.

## 정확한 runtime 검증

runtime source는 `435f138927fa78a1256e8a29a442eba399b971b6`, Linux amd64 정적 SHA256은
`a450084ea8d7c1a04c261a0e145317ad85a5a8fc47ce4d7fa91dfa61afc2c32f`이다.
`--features pumgye-server/observed-authentication`으로 기존0.1.8 운영 observed RPC를
보존했다. 기본-only 빌드는 이를 제외하므로 대체하면 안 되며 compile 포함도 owner를
자동 활성화하지 않는다. 문서 commit이 이후여도 Rust/lock/protocol/raw는 이 runtime이다.
기본127/전체기능136 및 양쪽 strictClippy가 통과했고 동결 raw의 실제 검증mTLS 같은
HTTP1 연결 native CAS Allow/Deny/Allow를 확인했다. 실제 client-go의 `?timeout=3s`
요청을 지원해 재현한404를 수정했지만 원래1초 BOOTTIME 예산은 바꾸지 않았다.

## 실제 Kubernetes 검증 완료 범위

소유 disposable API-server/etcd에서 이 정확한 raw와 pinned image로18검사가 통과했다.
ordinary 요청자는 system:masters가 아니며 고정 mTLS leaf+별도Bearer/v1 상호운용,
양쪽 authorization cache 비활성/failurePolicyDeny를 적용했다. named ConfigMap
GET/PATCH, 미매핑 신원·리소스, role AAL·정보등급 거부, native grant 회수,
허용 PATCH 변경→회수 PATCH403·backend 불변→복구 변경, Pum 장애/새 Pod 복구를
검증했다. Pum DB-native 정책을 써 자기 webhook API의 RBAC import 순환을 피했으며
기존 main K3s authorizer는 변경하지 않았다.

같은 Pum raw가 실제 네 코어 Service/Any 및 Workload 체인도 통과했다. Workload는
공개 SDK subject→typed grant→contract3→backend, 같은 pair replay 거부,
grant/map/audience/realm/reviewer 회수, 재시작/held proof 거부, PodUID 교체·SA 회수를
검사했고 실행 중6개 image identity를 확인했다. API 전파 지연은 proof 수명이 아니며
원래 예산은 유지했다. 재시작 후 held proof 거부에는 원래 만료도 영향을 줄 수 있다.
cleanup 후 원래12 PodUID와 두 노드 Ready를 보존했다.

이전 SAR filecap/이른 port-forward·loopback advertise·query404 실패와 Workload
 timeout/503/parser 증거는 남겼다. 최종 Workload 통과는 정확한 artifact 검증이며
이전 실패의 인과적 제품 수정이라고 주장하지 않는다. Human/Workload 관리자UX/
성능 검증 완료를 뜻하지 않는다.

## 공개·운영과 남은 제한

로컬 릴리스 자산은 서명·독립 검증하지만 공개/운영 반영이나 SAR 활성화는 별도다.
기존0.1.8 공개 자산은 불변이다. 고정 cluster/caller와 API authorizer 순서를 검토해
명시적으로 활성화해야 하며 이 문서로 기존 master 변경을 지시하지 않는다.
실제 v1 상호운용은 raw envelope 캡처나 webhook 연결 재사용 관측을 뜻하지 않는다.
같은 H1 연결 재사용은 로컬 mTLS fixture에서 직접 검증했다. 실제 API gate는 named
GET/PATCH 범위이며 모든 verb/admission/CNI 의미가 아니다. native Kubernetes 정책
원천과 SAR adapter는 별도 owner다. source lease는 native capture 테스트이지 새로운
실제 socket 만료 검증은 아니다. kernel 수락 응답·이미 허용된 작업/stream을 회수하지
못하며 H2 owner분리·극단적 처리량·분산 source/cache 검증은 남아 있다. clock 미지원은
opt-in SAR를 거부하며 legacy를 약화하지 않는다.
