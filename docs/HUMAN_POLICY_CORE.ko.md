# Human 정책 메타데이터 코어 선행 단계

선택적 human_users는 human1:+소문자64hex 주체를 기존 역할에 할당하며 같은
Policy컴파일러를 사용합니다. 빈 맵 직렬화는 기존과 같고 users/workload_users와
fallback하지 않습니다. HumanSubject파싱은 메타데이터 검증일 뿐 인증·권한이 아닙니다.

전용 scoped평가는 실제 인증된 AAL1/2를 호출자가 전달해야 하는 순수 함수입니다.
잘못된/미등록 주체는 Guest, 다른 AAL은 AssuranceDenied, 다른 서비스/API컨텍스트는
UnknownService입니다. 기존 리소스/액션/정보등급/네트워크/Guard를 모두 유지합니다.
사용자별 역할 floor와 네트워크/리소스 요구치를 결합하며 전역floor는 추가하지 않습니다.
요구AAL3은 초기 Human에서 만족할 수 없습니다. 세 맵은 총65536할당 제한을 공유합니다.

KubernetesApi는 Human할당을 금지하고 두 버전 K8s매핑 템플릿도 기존 Human권한을
거부합니다. 기존 Service/Workload RPC나 매핑 출력은 변경하지 않습니다.
Human RPC·신뢰된 SDK원천·서명·permit·원장·라우트 활성화는 없습니다.
오래된 strict정책 소비자 갱신 전 새 필드를 발행하면 안 됩니다.
삭제는 새 컴파일 스냅샷에 반영되며 오래된 순수 스냅샷 자체는 폐기되지 않습니다.
서버의 정확한 View/현재원천 fence와 이후 H2기반 네이티브 권한/실제 전체체인 검증이 필요합니다.
