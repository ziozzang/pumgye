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
요청당 3초·전체 1초 기한, 종류당 32페이지·전체 4096 객체·응답 4 MiB 제한입니다.
continue를 URL 인코딩하고 순환·페이지간 collection resourceVersion 변경을 거절합니다.
만료된 continue(HTTP 410)를 포함한 실패는 다음 주기 전체 재조회로 복구합니다.
부분 상태를 게시하지 않습니다. 종류별 버전은 독립이므로 전역 원자 스냅샷이 아닙니다.

불변 ArcSwap 관찰 상태는 프로세스 내부 revision, 네 collection 버전, inventory,
프로세스 상대 valid_until_ms를 갖습니다. 삭제·내용·원천 버전 변경은 revision을
올리고 동일한 관찰은 유지합니다. 수집 전 기존 상태를 비우며 실패 시 available:false를
출력합니다. 신선도는 수집 시작 후 최대 1초이며 통신·정규화·해시 시간도 소비합니다. 진단 출력은 권한 receipt가 아니며
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

## 실제 API 검증

검증된 typed RBAC collection 내부 항목에서 kind/apiVersion이 생략되면 해당
collection의 알려진 종류/API를 보완합니다. 명시적으로 모순된 종류/버전은 거절하며
오프라인 혼합 List 검사를 완화하지 않습니다. 실제 typed list는 항목 TypeMeta를
생략할 수 있고 kubectl은 합친 출력에 이를 채웁니다. 소유 v1.37.0 API에서 이 차이를
발견하고 검증했습니다.

```sh
python3 tools/kubernetes_real_cluster.py --binary target/debug/pumgye \
  --state-dir /private/owned-kind-qualification
```

고정된 소유 kind 클러스터·비공개 kubeconfig에 제한하며 고유 namespace와 읽기 전용
계정을 사용합니다. namespace Role/Binding과 cluster Role/Binding 조회 권한을
분리합니다. 실제 조회/후보 매핑·Binding 삭제 후 배정 제거·동명 재생성 UID 거절·
인증 실패/복구·정책 DB 미생성을 검증하고 fixture RBAC/namespace를 제거합니다.
Python PyYAML·클러스터 내 kubectl이 필요합니다. native subject는 명시적 가상 참조이며
호패 워크로드 연관·자동 권위 게시·운영 활성화를 주장하지 않습니다. v1.37.0을
검증했고 다른 버전·확장 watch는 별도 단계입니다.


## Kubernetes 원천 권위 판단

`--authorize-kubernetes-rbac`는 동일 수집기·명시적 매핑을 서버 정책의 유일한
작성자로 사용합니다. 관찰 연결 옵션과 `--kubernetes-mapping`, 일반 서버의 DB·
초기 정책·관리/판단 인증·TLS 옵션을 함께 지정합니다. 별도 DB를 사용하며 검사·
관찰·권위 모드는 동시에 선택할 수 없습니다.

매핑 정책을 컴파일하고 정책·revision·감사를 한 트랜잭션으로 커밋한 뒤 메모리에
설치합니다. 정책 변경만 영속 revision을 높이며 동일 정책 갱신은 감사 기록을
추가하지 않습니다. Binding 삭제·UID 교체는 재수집 시 배정을 제거합니다.
관리자 `PUT /v1/policy`는 409를 반환합니다. DB에 원천 소유 표시를 저장하여
플래그를 빠뜨려 네이티브 작성자로 재시작하는 것도 거절합니다. 원천 변경은
별도 명시적 마이그레이션이 필요합니다.

기존 SQLite 허용 정책이 있어도 프로세스 시작 시 판단은 사용할 수 없습니다.
매번 완전 수집 전에 판단을 철회하며 HTTP·매핑·컴파일 실패는 이전 허용을
재사용하지 않습니다. 스냅샷은 수집 시작 시점의 1초 만료를 따르며 컴파일·커밋 시간도 포함합니다. 저장 불확실성은 재시작까지 차단합니다. 수집 간 대기는
500ms입니다. `/healthz`와 인증된 `/v1/status`는 원천 가용성을 표시하고 관리
정책 조회는 마지막 영속 정책 점검에 사용할 수 있습니다. HTTP·PPG1 모두
같은 원천 검사를 적용하며 요청마다 DB를 읽지 않습니다.

보수적 polling이므로 수집 중에는 사용 불가 구간이 있습니다. 고가용성 watch·
follower 구현이나 종류 간 전역 원자적 관찰을 의미하지 않습니다. native_subject는
여전히 관리자 명시 연관이며 호패의 검증된 워크로드와 자동으로 연결되지는
않습니다. 비공개 매핑 파일·UID 핀·권한 변환을 검토하고 미검증 클라이언트
헤더를 신원으로 사용하지 않습니다. fixture는 운영 원천 모드를 활성화하지 않습니다.

```sh
python3 tools/kubernetes_real_cluster.py --binary target/debug/pumgye \
  --state-dir /private/owned-kind-qualification --authority
```

실제 API fixture는 격리 DB에서 네이티브 HTTP 허용/거절, 삭제의 영속 revision,
작성자 배제, 인증 실패/복구와 재시작 시 캐시 권한 거절까지 검증합니다.
호패의 검증된 신원 자동 연관·watch·한강 전체 연결 검증은 후속 단계입니다.


## 호패 워크로드 신원 연관

grant는 불투명 native_subject 참조 대신 workload를 사용할 수 있습니다.
[가상 워크로드 매핑](../examples/kubernetes-workload-mapping.json)은 issuer,
namespace, ServiceAccount 이름/UID와 Pod 이름/UID를 고정합니다. mapping의 cluster는
호패 cluster_id와 같습니다. 정확히 같은 문자열로 호패 Workload 신원을 계산하여
해시를 수동 복사하지 않아도 됩니다. namespace/계정은 RBAC ServiceAccount 대상과
일치해야 하며 두 형식을 함께 지정하면 거절합니다. 다른 신원 종류는 기존 명시적
native 참조를 사용합니다.

이것은 신원 주소 계산이며 인증이 아닙니다. issuer/audience·신뢰 TokenReview·현재
객체 UID/삭제·기한 검증은 호패가 담당하고 한강은 신뢰된 네이티브 인증 경로로
신원을 받아야 합니다. issuer/cluster·두 UID가 신원을 구분하므로 같은 계정의
다른 Pod나 재생성 객체가 이 고정 권한을 상속하지 않습니다. 매핑은 관리자 소유이고
프로세스 동안 고정합니다. 실시간 자동 발견·원천 편집·UID 재고정·분산 watch는
후속 작업입니다.

호패 기존 알고리즘과 일치합니다. hopae:kubernetes:pod-subject:v1 뒤 NUL과
namespace/계정 이름·UID/Pod 이름·UID를 각각 big-endian u32 바이트 길이와 UTF-8로
연결하여 SHA-256한 뒤 w_와 전체 소문자 hex로 만듭니다. 종류 바이트 2 뒤
issuer/cluster/워크로드 문자열을 각각 big-endian u64 길이와 UTF-8로 연결하여
SHA-256하고 첫 24바이트를 s_와 소문자 hex로 만듭니다. 해시는 정책 컴파일 시만
계산하며 서명 영수증이나 인증 근거를 대신하지 않습니다.

```sh
python3 tools/kubernetes_real_cluster.py --binary target/debug/pumgye \
  --state-dir /private/owned-kind-qualification --authority \
  --hopae-driver /path/to/hopae/target/debug/examples/qualify_kubernetes_tokenreview
```

소유 실제 v1.37.0 fixture에서 서명된 Pod-bound TokenRequest 토큰을 네이티브 호패
TokenReview·현재 객체 검증으로 인증합니다. 품계가 계산한 신원과 호패 출력이
일치하고 mTLS HTTP/지속 PPG1로 매핑 권한을 허용해야 합니다. 같은 계정의 다른
실제 검증된 Pod는 guest이며 첫 Pod 삭제는 토큰을 거절합니다. Binding 삭제/재생성·
원천 실패·작성자 배제·재시작 fence도 계속 검사합니다. 두 네이티브 모듈 연관
검증이며 한강 전체 요청/스트림 연결 검증을 완료한 것은 아닙니다.


## 네 네이티브 모듈 요청 검증

소유 워크로드 검증에 실제 실행 파일 세 개를 추가합니다.

```sh
python3 tools/kubernetes_real_cluster.py --binary /path/to/pumgye \
  --state-dir /private/owned-kind-qualification --authority \
  --hopae-driver /path/to/qualify_kubernetes_tokenreview \
  --gateway-binary /path/to/hangang --hopae-binary /path/to/hopae \
  --sumunjang-binary /path/to/sumunjang
```

kubernetes_gateway.py는 품계 원천 권위 옆에 실제 한강·호패·수문장 프로세스를
새 DB·설정·인증키로 시작합니다. 공개 요청은 HTTPS이고 앱 허용 포트는 실제
fixture TLS 포트와 일치합니다. HOP1·PPG1·HGD1은 고정 mTLS·분리된 앱 인증을
사용하고 호패는 실제 Pod-bound Kubernetes 토큰을 검증합니다. 네이티브 TLS
옵션이 없는 오래된 한강 바이너리는 거절하며 미인증 프로토콜 peer로 대체하지 않습니다.

매핑된 Pod만 백엔드에 도달합니다. 다른 실제 인증된 Pod·미인증 신원 헤더 위조는
실패합니다. 백엔드 신원은 canonical Workload·AAL 0·일치하는 service이며 원래
Authorization 토큰은 전달하지 않습니다. 실제 수문장의 observe는 필수 Guard
조건을 만족하지 않고 명시적 IP 차단은 거절하며 제거 후 회복합니다. Binding 삭제는
후속 요청을 막고 원천 자격 실패는 사용 불가, Pod 삭제는 인증 거절입니다. 거절된
경우 백엔드 요청이 없음을 확인합니다. 한강 위임 정책/상태 API도 Kubernetes
소유 표시를 전달하고 올바른 관리자·두 revision 조건으로도 원천 정책 덮어쓰기를
거절합니다.

프로세스·고유 Kubernetes 자원을 정리하고 운영 설정/이미지는 보존합니다. 실제
요청 집행 검증이며 스트림 인증 회수·Kubernetes Pod 패키징/Ingress 소유·분산 watch/
follower 가용성·CNI 전체 네트워크 보호·전체 성능 완료를 뜻하지 않습니다. 보수적
polling의 수집 중 사용 불가 구간도 남아 있습니다. 모두 후속 완료 조건입니다.


## 실제 호패 워크로드 갱신

네 모듈 명령에 --qualify-renewal을 추가합니다. 일반 Kubernetes 원천 권위의
Binding/원천/재시작 검사를 마친 뒤 이전 검증 후보로 별도 native 품계 DB를
초기화합니다. 고정 정책으로 인증 갱신과 polling 중 사용 불가를 의도적으로
분리하며 fallback·운영 원천 전환이 아니고 RBAC watch 연속성을 검증하지 않습니다.

실제 호패·한강·수문장·별도 품계 프로세스가 native mTLS를 사용합니다. 스트림은
실제 서명 Pod-bound 토큰과 auth.renew_native_evidence로 heartbeat를 2.2초 넘게
유지합니다. 실제 Pod 삭제 후 소유 fixture의 삭제 완료 기준 1.5초 안에 닫히고
후속 인증은 401입니다. 백엔드 신원/AAL/service·인증 토큰 제거 검사도 유지합니다.
별도 DB/프로세스/자원을 정리하며 운영은 그대로입니다.

비공개 보고서는 고정 정책 분리와 RBAC watch 연속성 미검증을 명시합니다. 인증과
권한 원천 freshness를 같은 것으로 취급하지 않으면서 실제 프로바이더 갱신 검증을
진전시킵니다. 분산 watch·장애 토폴로지·대규모 처리량은 추가 완료 조건입니다.


수집 시작 1초 안에만 원천 스냅샷을 사용할 수 있습니다. 느린 완전 수집은 완료 뒤
새 수명을 부여하지 않고 거절합니다. 전체 수집 timeout·정규화 후 나이 검사로
네트워크/CPU 지연을 제한하고 시계 overflow도 거절합니다. 소유 HTTPS 1.2초 지연은
사용 불가를 출력한 뒤 다음 성공 수집에서 회복해야 합니다. 컴파일·커밋도 같은
시작 시각 예산을 소비합니다. 종류 간 전역 원자성이나 watch 지속 가용성은 아닙니다.
큰/느린 원천은 확장형 재조정 구현 전까지 사용 불가이고 오래된 권한을 게시하려고
예산을 조용히 늘리지 않습니다.


## 원천 전송 풀 재사용

실제 CA/토큰 자료의 fingerprint가 같으면 고정 HTTPS 클라이언트를 유지합니다.
파일은 매 주기 다시 읽어 검증하고 Authorization 헤더는 민감 값으로 새로 구성합니다.
자료 변경은 이전 신뢰 풀을 먼저 폐기하고 잘못된 CA는 기존 풀로 fallback하지
않습니다. 진단 fingerprint/출력에 원래 자격을 넣지 않습니다. 원천당 idle 연결은
최대 2개·idle 만료는 10초이며 전송 재사용이지 권한 캐시가 아닙니다. 원천 freshness는
여전히 수집 시작 1초입니다.

소유 HTTP/1.1 HTTPS fixture가 TLS 연결을 세어 두 번의 동일 완전 pagination 수집이
한 연결을 사용하고 자격 변경/복구가 새 연결을 여는 것을 확인합니다. 기존 CA
오류/복구·redirect·HTTP 410·느린 수집·삭제 검사와 실제 Kubernetes/네 프로세스·격리
갱신도 통과합니다. 반복 handshake 비용을 줄이며 전체 처리량·확장 watch 완료를
의미하지 않습니다.

## 통합 관리 상태

인증된 `/v1/status` 응답은 `source_state`로 `native`, `starting`, `collecting`,
`fresh`, `expired`, `collection_failed`, `candidate_rejected`,
`persistence_failed`를 구별합니다. `source_lease_remaining_ms`는 응답 시점의
프로세스 내부 유효기간이며 재사용 가능한 권한 영수증이 아닙니다.
`source_writable`은 자체 정책 게시 API가 쓰기를 받는 원천 모드인지를 표시하며
저장소 정상이나 Kubernetes 수정 권한을 보장하지 않습니다.
`policy_revision`은 마지막 적용 로컬 리비전입니다. 원천 장애 중에도 저장된
정책을 조회할 수 있지만 유효한 권한으로 취급하지 않습니다. 오류는 제한된
분류로만 반환하며 프로바이더 응답·주소·자격 경로는 노출하지 않습니다.
한강은 이 상태를 표시하고 외부 원천 정책의 자체 편집을 비활성화합니다.
Kubernetes 원천 수정이나 전체 패키지 배포 구현 완료를 의미하지 않습니다.

## 한강 월드 배포 구성요소

`deploy/kubernetes`는 한강 월드 통합 패키지의 품계 구성요소입니다. Kustomize
렌더링과 실제 API 서버의 dry-run을 통과했으나 실제 Pod 배포 및 네 모듈 통합은
미검증입니다. 의도적으로 실행 불가능한 이미지 참조를 검증한 이미지 digest로
교체한 overlay를 사용합니다.

자체 원천 기준 설정은 SQLite 단일 작성자, Recreate 전략, 영속 상태와 초기
전체 거부 정책을 사용합니다. 이 SQLite 배포를 scale하지 않습니다. 분산
follower·백본은 별도 검증이 필요하며 bootstrap 수정은 기존 DB를 덮어쓰지
않습니다. 패키지 overlay에서 StorageClass와 보존·복구 정책을 지정합니다.
Delete 회수 정책의 PVC 삭제는 저장소를 삭제할 수 있습니다. `pumgye-tls`의
`tls.crt`, `tls.key`, `ca.crt`와 `pumgye-credentials`의 서로 다른 `admin-token`,
`decision-token`을 별도로 공급합니다. 예제 자격은 만들지 않습니다. 클라이언트는
인증서의 품계 Service DNS를 검증해야 합니다.

관리 9084와 PPG1 9085는 mTLS 및 역할별 자격을 유지합니다. 선택적
`--readiness-listen`은 `GET /-/ready`에 본문 없는 200/503과 no-store만
반환하며 정책·상태·감사·판단 API는 제공하지 않습니다. 9086은 Service에
노출하지 않습니다. readiness는 판단과 같은 메모리 신선도 경계를 사용하므로
Kubernetes 시작·만료·영속화 실패 시 거부합니다. liveness 소켓 검사는 정책
사용 가능을 보장하지 않습니다. probe 포트는 패키지 네트워크 정책으로 제한합니다.
자체 원천 기준에는 API 토큰이나 RBAC 권한이 없습니다. Kubernetes 원천에는
명시적 매핑, 제한된 projected token, CA와 Namespace·클러스터 RBAC 조회 권한이
필요하며 자체 원천으로 자동 fallback하지 않습니다.

정적 바이너리를 빌드하고 네이티브 fixture를 통과한 뒤 이미지로 묶습니다.

```sh
CARGO_INCREMENTAL=0 cargo build --locked --release --target x86_64-unknown-linux-musl -p pumgye-server
docker build -f deploy/Dockerfile -t pumgye:QUALIFIED_VERSION .
kubectl kustomize deploy/kubernetes
```

설정된 클러스터 wrapper로 검증·배포합니다. 이 절차 자체는 릴리즈 게시나
기존 설치 덮어쓰기를 의미하지 않습니다.

### 실제 Pod 검증

명시한 실제 클러스터 wrapper와 미리 적재한 이미지로 배포 구성요소를 검증합니다.

```sh
python3 tools/kubernetes_pod_smoke.py --kubectl /path/to/cluster-kubectl \
  --image pumgye:QUALIFIED_VERSION
```

전용 Namespace에 하루짜리 TLS 신원과 합성 자격·정책만 생성합니다. 관리하는
manifest로 nonroot Pod를 실행하여 mTLS HTTP/PPG1, 클라이언트 인증서 없는
호출의 거부, 역할별 자격, readiness의 관리 API 비노출, 회수 후 실제 정책 거부,
Pod UID 교체 후 PVC의 정책·리비전 보존 및 같은 거부를 검사합니다. 사용 불가
응답으로 정책 거부 검사를 대신 통과하지 못합니다. finally에서 Namespace와
자격을 정리하지만 Retain PV·데이터는 기존 보존 정책에 따라 남고 별도로
보고합니다. 이 fixture는 보존된 저장소를 삭제하지 않습니다. 자체 정책 원천과
합성된 신뢰 호출자 근거를 사용하는 검사이며 Kubernetes 원천 신선도와 네 모듈
전체 통합 패키지는 별도 검증 대상입니다.
