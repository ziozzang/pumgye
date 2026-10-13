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

## 실제 HTTPS 읽기 전용 수집

```sh
pumgye --observe-kubernetes-rbac --kubernetes-cluster example-cluster \
  --kubernetes-api https://kubernetes.example.test \
  --kubernetes-namespace example \
  --kubernetes-ca /run/secrets/kubernetes-ca.pem \
  --kubernetes-token /run/secrets/kubernetes-token
```

별도 관찰 명령이며 권한 DB·판정 리스너를 열지 않습니다. 네 RBAC 종류를 수집해
줄별 JSON을 출력합니다. namespace는 Role/RoleBinding에 적용하고 ClusterRole/
ClusterRoleBinding은 명시적 클러스터 읽기 권한이 필요합니다. namespace 생략 시
모든 namespace를 수집합니다. Secret은 읽지 않습니다. 별도 읽기 전용 계정을
사용하며 Ingress 컨트롤러의 인증 정보를 무조건 재사용하지 않습니다.

설정 CA로 검증되는 HTTPS origin만 허용하며 기본 공개 root·리다이렉트·환경
프록시를 사용하지 않습니다. 제한된 토큰·CA 파일을 매 수집 주기 다시 읽습니다.
요청당 3초·전체 15초 기한, 종류당 32페이지·전체 4096 객체·응답 4 MiB 제한입니다.
continue를 URL 인코딩하고 순환·페이지간 collection resourceVersion 변경을 거절합니다.
만료된 continue(HTTP 410)를 포함한 실패는 다음 주기 전체 재조회로 복구합니다.
부분 상태를 게시하지 않습니다. 종류별 버전은 독립이므로 전역 원자 스냅샷이 아닙니다.

불변 ArcSwap 관찰 상태는 프로세스 내부 revision, 네 collection 버전, inventory,
프로세스 상대 valid_until_ms를 갖습니다. 삭제·내용·원천 버전 변경은 revision을
올리고 동일한 관찰은 유지합니다. 수집 전 기존 상태를 비우며 실패 시 available:false를
출력합니다. 수집 완료 후 신선도는 최대 1초입니다. 진단 출력은 권한 receipt가 아니며
워크로드 검증·앱 매핑·권한 부여를 포함하지 않습니다. revision은 재시작 시 초기화하며
영속 인가 floor로 사용할 수 없습니다.

완전 조회 사이에 1초를 기다리는 초기 읽기 전용 폴링입니다. 확장 가능한 watch
구현은 아직 아닙니다. 모든 운영 복제본에 폴링을 켜 watch/reconcile을 대신하지
않습니다. bookmark·종류별 resume·원천 게시·복제본 복구·실제 API 서버 검증이
필요합니다. 현재 운영 정책과 설정은 그대로입니다.

```sh
python3 tools/kubernetes_source_smoke.py --binary target/debug/pumgye
```

격리 HTTPS fixture는 페이지/불투명 버전, 동일 상태 revision, 삭제, 버전·범위·
리다이렉트 오류, HTTP 410 복구, 토큰·CA 교체, 프록시 격리, DB 미생성·비밀 미출력을
검증합니다. 공식 API 근거는 대응 영문 문서에 링크했습니다.

## 명시적인 앱 권한 매핑 후보

검사 또는 관찰 명령에 `--kubernetes-mapping`으로 관리자 소유 설정을 제공합니다.
가상 예제는 다음 명령으로 확인합니다.

```sh
pumgye --inspect-kubernetes-rbac examples/kubernetes-rbac-list.json \
  --kubernetes-cluster example-cluster \
  --kubernetes-mapping examples/kubernetes-mapping.json
```

기존 사용자 권한 없는 네이티브 정책 템플릿과 명시적인 service/앱 역할/native
subject 참조, Kubernetes subject, Role/Binding kind·namespace·name·UID를 지정합니다.
동명 객체가 재생성되면 기존 UID pin으로 활성화하지 않습니다. API group/resource
(서브리소스 포함)·verb·리소스 namespace·선택적 이름의 모든 조건이 정확히 맞아야
합니다. RoleBinding으로 cluster/다른 namespace 권한을 얻지 않습니다. 원천 wildcard를
명시적 규칙에 자동 대응하지 않으며 매핑 조건의 wildcard, bind/escalate/impersonate,
서비스 계정 토큰 발급 변환은 거절합니다. Group·집계 역할 변환은 검증된 membership/
reconcile이 필요해 미지원입니다. 리소스 namespace는 관리자 명시 제약이며 실제
API discovery·네이티브 authorizer 검증으로 리소스 범위를 확인하는 단계가 남았습니다.

클러스터가 정확히 일치해야 합니다. 객체 삭제/재생성·roleRef 변경·subject/규칙 삭제·
이름 제한 불일치는 비활성 매핑이 되고 후보 사용자 배정을 없앱니다. 매번 빈 사용자
템플릿부터 다시 계산해 이전 권한을 남기지 않습니다. 후보는 네이티브 코어로 다시
컴파일하며 IP 권한과 수문장 집행 근거가 필요합니다. 여러 일치는 명시적으로 선택한
앱 역할만 합칩니다. 설정 최대 64 KiB·256 매핑·매핑당 16 규칙입니다.

출력은 candidate_only, 설정 원문 SHA-256, 후보 정책, 매핑별 active/reason을 포함합니다.
실시간 출력은 원천을 source에 담고 후보 계산/직렬화 후 신선도를 다시 확인합니다.
매핑 파일은 시작 시 한번 읽으며 수정 시 새 프로세스·검토된 digest가 필요합니다.
DB·운영 권한·권위 revision을 바꾸지 않습니다. 영속 원천 게시와 전역 reconcile
fence가 없으므로 진단 후보를 운영 API에 자동 게시하지 않습니다. native_subject는
운영자가 제공한 연관 관계이며 인증 증명이 아닙니다. 호패가 실제 요청의 신원과
클러스터/issuer/audience/바인딩 객체를 검증해야 합니다. 예제 신원·UID는 가상입니다.

격리 HTTPS fixture의 --mapping 옵션은 후보 생성과 원천 삭제 후 배정 제거,
오류 복구·인증 파일 교체를 같이 검증합니다.
