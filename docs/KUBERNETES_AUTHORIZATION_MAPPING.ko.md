# Kubernetes API 매핑 코어 선행 단계

이번 변경은 선택적인 `Policy.kubernetes_authorization` version 1 메타데이터를 기존 grants와 같은 `Policy.compile()` 및 불변 `CompiledPolicy`에 포함한다. listener, 인증된 caller, Human/Workload 증명, receipt, 별도 grant 저장소·캐시, Kubernetes 배포는 추가하지 않는다. 필드가 없거나 null이면 직렬화에서 생략한다. 실제 어댑터는 mTLS API-server를 인증해 고정 cluster를 별도로 전달하고, 같은 authority View의 원천수명·publication·deadline을 응답까지 검사해야 한다. 과거 compiled snapshot은 자동 철회되지 않는다.

`principals`와 `routes`는 각각 최대 4096개다. principal은 cluster, 정확한 user, uid의 명시적 absent/exact 모드, required_groups, required_extra, subject를 갖는다. cluster는 콜론 없는 1~64 ASCII 영숫자/밑줄/하이픈이며 subject는 정확한 `k8sapi:<cluster>:` 아래의 비어 있지 않은 native assignment label이다. 이는 인증 증명이나 capability가 아니다. group-only/username-prefix 추론과 Service/Workload fallback은 없다.

필수 그룹은 부분집합 제약이며 필수 extra key의 값은 순서와 무관한 정확한 집합이어야 한다. 추가 bounded 그룹/extra key는 권한을 추가하지 않는다. UID 없음과 정확한 UID는 구분한다. 정확히 하나의 principal만 매칭되어야 하며 같은 subject의 중복 매칭도 거부한다. 그룹/extra 값 및 extra key 중복, 동일 설정 binding 중복은 거부한다. anonymous와 system:unauthenticated는 거부한다. user/UID/그룹/extra 문자열은 제어문자 없는 1~256 bytes, 그룹 64개, extra key 32개, key당 값 8개, (cluster,user) 후보 64개로 제한한다.

route는 정확한 속성을 기존 native service/catalog resource/action으로 연결하며 동일 cluster/속성 중복은 컴파일 시 거부한다. 대상은 명시적 kubernetes_api 문맥이어야 하고 기존 users/roles/permissions/class/AAL 규칙만 권한을 부여한다. AAL은 항상 0이며 가짜 IP나 Sum 증거를 만들지 않는다. 같은 recompilation에서 grant 철회·class 변경·AAL 조건 변경이 즉시 계산에 반영된다.

resource는 kind=resource와 group/version/resource/subresource/namespace/name/verb를 모두 명시한다. 빈 group은 core API이며 wildcard가 아니다. 이름과 namespace가 있는 get/update/patch/delete만 지원하며 subresource는 빈 값/status/scale만 허용한다. create/list/watch, cluster-scoped, wildcard, escalation, proxy/exec/connect, selector 및 미지원 subresource는 거부한다. nonresource는 kind=non_resource의 정확한 path/verb만 사용하며 ASCII 영숫자와 /_.- 경로, 선두 slash를 요구한다. percent/query/double-slash/dot-segment/prefix/glob/정규화는 지원하지 않는다. unknown 필드도 거부한다. 전체 SAR wire/API 지원을 주장하지 않는다.

순수 evaluate_kubernetes_request 입력 생성은 caller를 인증하지 않는다. 실제 transport/body/중복 SAR wire 검사, mTLS, overload, serialization 이후 source/current View fence, API-server failurePolicy와 Allow cache 비활성화는 후속 단계다. 이미 허용된 API 작업/stream 회수나 처리량 달성을 주장하지 않는다.
