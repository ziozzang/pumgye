# Kubernetes 원천 연결기

[English](KUBERNETES.md)

품계 서버에 제한된 읽기 전용 RBAC 검사 명령을 추가했습니다.

```sh
pumgye --inspect-kubernetes-rbac rbac-list.json --kubernetes-cluster example-cluster
```

입력은 Role/ClusterRole/RoleBinding/ClusterRoleBinding을 포함한 `v1/List`이며
각 리소스는 `rbac.authorization.k8s.io/v1`이어야 합니다. 참조하는 역할을 같은
목록에 포함하고 저장된 UID/resourceVersion 및 ServiceAccount subject의 명시적
namespace를 제공합니다. 최대 4 MiB·4096 객체입니다. Secret이나 모든 리소스를
덤프하지 말고 RBAC 객체만 수집합니다. 출력에는 역할·subject 등 권한 메타데이터가
있으므로 취급에 주의합니다.

이 명령은 DB·리스너를 열기 전에 종료하며 관리자/판정 토큰을 요구하지 않습니다.
클러스터 식별자·UID·불투명 resourceVersion·원본 규칙·집계 선택자·역할 참조·
subject를 보존하고 결정적 순서로 출력합니다. 알 수 없는 규칙 필드/API/종류,
중복 객체·UID, 잘못된 참조 범위, 해결되지 않은 역할은 검사 전체를 거절합니다.
resourceVersion을 숫자로 해석하지 않습니다.

출력은 Kubernetes 전역 원자 스냅샷이나 API 인가 판정이 아닙니다. 집계 메타데이터는
보존만 하며 실제 집계는 API 관찰이 필요합니다. 오프라인 목록으로 워크로드 신원이나
토큰을 검증하지 않습니다. 앱 권한을 게시하거나 기존 DB·메모리 정책을 바꾸지 않습니다.

후속 구현은 인증된 list/watch·완전한 재조회·명시적 앱 권한 매핑·원천별 게시·
TokenReview·회수/복제본 fence·실제 클러스터 검증입니다. 이 목록을 allow 판정으로
사용하지 않습니다. 공통 책임과 의미는 [ADR 0015](https://github.com/ziozzang/hangang-zerotrust/blob/main/docs/ko/0015-kubernetes-iam-authority.md)에 있습니다.
