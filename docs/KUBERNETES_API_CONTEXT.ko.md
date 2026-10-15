# 명시적 Kubernetes API 정책 문맥 (core 선행 단계)

네이티브 service의 `authorization_context: "kubernetes_api"`는 같은 `CompiledPolicy`의 기존 users/roles/permission/정보등급/resource grant를 사용한다. 명시적 network-free API 문맥이므로 compiler는 `require_guard: false`, 빈 networks/workload_users와 `k8sapi:` 이름공간의 subject를 요구한다. IP나 Sumunjang EnforcedAllow를 만들어 넣지 않는다.

필드 생략 시 기존 network_and_guard 의미와 직렬화 바이트를 유지한다. 기존 service/resource/scoped-resource/Workload 진입점은 API 문맥을 거부하고, 새 `evaluate_kubernetes_api_resource`는 일반 문맥을 거부한다. 기존 network/guard 조건을 새 메서드 선택으로 우회할 수 없다.

`KubernetesApiSubject`는 문법만 검증한 metadata이며 인증 주체나 receipt/capability가 아니다. 호출자가 API-server 인증과 server-owned 매핑을 먼저 수행해야 한다. 입력에는 IP/guard/AAL이 없고 AAL0으로 고정되어 native role/resource가 AAL1 이상이면 거부한다. Human/Service/Workload 인증으로 변환하지 않는다. grant 삭제는 새 compiled publication에 반영되며 서버의 정확한 View/원천수명 검사는 별도로 필요하다.

이 단계에는 SAR listener/parser/매핑 저장소/클러스터 배포가 없다. 추후 adapter는 같은 View 안에서 매핑과 권한을 평가하고 인증된 bounded ingress, default deny, source-owner fence와 API-server cache/failure/순서 검증을 구현해야 한다. 원요청 network 강제나 MFA를 보장한다는 뜻이 아니다. 테스트는 core 문맥 격리·기존 network/guard·권한/등급/AAL·철회 후 재컴파일·기존 직렬화 바이트를 검증하며 실제 webhook/클러스터 완료를 의미하지 않는다.
