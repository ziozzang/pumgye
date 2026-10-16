# 관리자 설명(explain)·가정(what-if)·후보 차이(diff) API (미릴리스)

[English](EXPLAIN.md)

품계는 permit 발행·판정 카운트·정책 변경 없이 *이 요청이 왜 허용/거부되었는지, 초안
정책에서는 어떻게 되는지*에 답합니다. ADR 0019(판정 이벤트·시뮬레이션), ADR 0020(콘솔
시뮬레이터), ADR 0021(explain·후보 diff, P0)이 사용하는 품계 권한 서버 API입니다.
who-can/what-can 조회는 ADR 0021 P1이며 구현하지 않았습니다.

버전: `/v1/explain*` 경로는 정책 버전 1 모델용입니다. ADR 0021 v2 모델은 자체 단계(그룹,
명시적 거부, 존, clearance, 유효 기간)를 가진 `/v2/...` explain 경로를 추가하며, `/v1`은
v1 문서용으로 유지합니다.

## 보장 사항

- **같은 함수.** 모든 집행 진입점(HTTP `/v1/decision`·`/v1/resource/decision`, PPG1,
  gRPC, Workload/Human 자원 경로, Kubernetes API/SAR 경로)은 `Tracer`에 대해 제네릭인
  하나의 평가 함수를 사용합니다. 운영 경로는 크기 0인 `NoTrace`(빈
  `#[inline(always)]` 메서드)로 인스턴스화되어 추적 코드가 컴파일 단계에서 사라지고,
  explain은 제한된 `VecTrace`(이벤트 ≤ 32, 할당 1회)를 사용합니다. explain 판정은 그
  함수의 반환값이며 재구현이 아닙니다. 네트워크 규칙 인덱스는 기존 패딩에 저장되어
  컴파일된 항목 크기가 변하지 않음을 컴파일 시점에 검사합니다.
- **핫 패스 무할당 유지.** `crates/pumgye-core/tests/no_alloc.rs`가 전역 할당기로 모든
  진입점·모든 `Decision` 변형에서 힙 할당 0회를 요구합니다.
- **동등성.** `crates/pumgye-core/tests/explain.rs`가 5만 건 이상의 코퍼스로 모든
  진입점·모든 사유 코드에 대해 explain과 운영 호출을 비교하고, 서버 테스트가 같은
  스냅샷에서 `/v1/explain`과 `/v1/decision`·`/v1/resource/decision` 응답을 비교합니다.
- **읽기 전용.** permit·receipt·세션·정책 쓰기가 없고 `decision_queries` 카운터를 건드리지
  않으며 응답은 `Cache-Control: no-store`입니다. 후보 문서는 `PUT /v1/policy`와 똑같이
  검증·컴파일되지만 저장되지 않습니다.
- **감사.** 수락된 시뮬레이션마다 별도 `simulation_audit` 테이블에 `kind=simulation`
  행(행위자, 선택적 위임 행위자, 작업, 스냅샷 원천/리비전, 후보 digest, 요청 본문
  SHA-256, 집계)을 결과 반환 *전에* 기록합니다. 기록에 실패하면 결과 없이 503을
  반환하며 집행은 차단하지 않습니다. 기록할 때마다 `--simulation-audit-retention-days`
(기본 30, 범위 1–3650)보다 오래된 행을 지우고 최신 100,000행까지만 보존합니다. 게시 감사는
지우지 않습니다.

## 인증·수용·제한

모든 endpoint는 기존 인증 리스너(루프백 외에는 mTLS)에서 `Authorization: Bearer
<관리자 자격>`이 필요합니다. 판정 자격은 요청 게이트와 핸들러에서 모두 401로
거부됩니다. `/v1/policy`·`/v1/status`·`/v1/audit`과 관리 수용 게이트(동시 4, 5초
기한)를 공유하고, 프로세스 전체 시뮬레이션 토큰 버킷(용량 1024, 초당 256 보충;
비용 = 케이스 수, 후보 비교 시 ×2, 후보 컴파일당 +64)을 추가로 적용합니다. 버킷이
비면 `Retry-After: 1`과 함께 429를 반환합니다.

| 제한 | 값 | 상태 |
| --- | --- | --- |
| 요청 본문 | 1 MiB + 256 KiB | 413 |
| 후보 문서(재직렬화) | 1 MiB, 저장 정책과 동일 | 413 |
| 배치 케이스 | 1–256, `trace: true`이면 1–32 | 413 / 400 |
| diff 페이지 | `limit` 1–500, 기본 100 | 400 |
| 식별자 | `[A-Za-z0-9_.:-]` 1–128바이트(label ≤ 64) | 400 |
| `on_behalf_of` | `[A-Za-z0-9_.:@-]` 1–128바이트 | 400 |

### 오류

이 endpoint들의 400·409·413·422·429는 구조화된 본문을 반환합니다(다른 품계 endpoint는
상태 코드만 유지). 401·415·503은 인증 전 정보나 저장소 정보를 드러내지 않도록 본문이 없습니다.

```json
{"error": {
  "code": "pumgye.error.candidate_invalid",
  "message_key": "pumgye.error.candidate_invalid",
  "details": [{"path": "snapshot.policy.services.orders.users.u_reader",
               "code": "pumgye.validation.unknown_assigned_role",
               "message_key": "pumgye.validation.unknown_assigned_role"}],
  "current_revision": 7
}}
```

`current_revision`은 409에만 있습니다. `details`(최대 32개)는 요청 경로로 원인을 가리키며
코드는 메시지 키이기도 하고 en/ko 카탈로그에 있습니다.

| 상태 | `code` | 상세 코드 / 경로 |
| --- | --- | --- |
| 400 | `pumgye.error.malformed_request` | 요청 경로의 JSON/스키마 오류(`case.subject.kind`, 최상위는 `$`) |
| 400 | `pumgye.error.invalid_case` | 잘못된 모든 케이스: `pumgye.case.*`, 경로 `case.<필드>` / `cases[i].<필드>` |
| 400 | `pumgye.error.invalid_delegated_actor`, `empty_batch`, `invalid_page`, `invalid_cursor` | `on_behalf_of`, `cases`, `limit`/`cursor`, `after_id` |
| 409 | `pumgye.error.revision_conflict` | `snapshot.revision`, `snapshot.base_revision`, `base_revision`. `current_revision`으로 다시 불러와 재시도 |
| 413 | `pumgye.error.payload_too_large`, `batch_too_large`, `candidate_too_large` | 본문, `cases`, 후보 문서 |
| 422 | `pumgye.error.candidate_invalid` | 검증기의 구체적 실패: `pumgye.validation.schema`(모르는 필드·형식 오류) 또는 `unknown_assigned_role`, `role_cycle`, `network_host_bits`, `resource_permission` 등 컴파일 코드(`pumgye_core::VALIDATION_CODES`)와 가장 구체적인 문서 경로 |
| 429 | `pumgye.error.rate_limited` | — (`Retry-After: 1`) |

## 케이스

```json
{
  "label": "case-1",
  "subject": {"id": "u_writer", "kind": "user"},
  "service": "orders",
  "permission": "write", "information_class": "internal",
  "ip": "192.0.2.1", "aal": 2, "guard": "enforced_allow",
  "minimum_revision": 0
}
```

대상은 `permission`+`information_class` 또는 `resource`+`action` 중 정확히 하나입니다.
`guard`는 *모의* 수문장 증거(`enforced_allow`, `deny`, `observe`, `unavailable`)입니다.

| `subject.kind` | 조회 맵 | 모의 진입점 | 대상 | 네트워크 증거 | AAL |
| --- | --- | --- | --- | --- | --- |
| `user` | `users` | `/v1/decision`, PPG1, gRPC / `/v1/resource/decision` | 둘 다 | 필수 | 0–3 |
| `workload` | `workload_users` | Workload 자원 경로 | 자원 | 필수 | 0만 |
| `human` | `human_users` | Human 자원 경로 | 자원 | 필수 | 0–3(허용은 1–2만) |
| `kubernetes_api` | `kubernetes_api` 서비스의 `users` | SAR | 자원 | 금지 | 0만 |

집행과 똑같이 맵은 서로 대체되지 않습니다(두 맵의 같은 `s_` 문자열은 서로 다른 주체).

## 스냅샷 선택자

```json
{"source": "published"}
{"source": "published", "revision": 7}
{"source": "candidate", "base_revision": 7, "policy": { ...정책 문서 v1... }}
```

생략하면 현재 게시 스냅샷입니다. 고정 `revision`이나 후보 `base_revision`이 현재
리비전과 다르면 409(`If-Match` 게시와 같은 CAS 규칙)입니다. 후보는 게시 시 받을
리비전(`base_revision + 1`)으로 평가하며, 모든 후보 결과에 같은 케이스의 게시 스냅샷
결과를 함께 보고합니다.

게시 스냅샷이 서비스 중이 아니거나(비정상, Kubernetes 원천 lease 만료) 케이스의
`minimum_revision`보다 낮으면 집행과 똑같이 `decision: null`,
`reason_code: pumgye.unavailable`, 결정 단계 `fence`로 보고합니다.

## `POST /v1/explain`

요청: `{"snapshot"?, "case", "trace"?(기본 true), "on_behalf_of"?}`. 응답 형식은
[영문 문서](EXPLAIN.md#post-v1explain)의 예시와 같습니다. `decision`은
`pumgye_core::Decision` 변형 이름(카탈로그 경로에서는 `UnknownResource`/`UnknownAction`)이며
판정 API의 `reason`과 동일합니다. 후보를 쓰면 `"comparison": {"published": <outcome>,
"changed": true|false}`가 추가됩니다. `AssuranceDenied`이면 단계 상향을 위한
`obligations.required_aal`을 반환합니다.

### 단계

단계는 실제 평가 순서로 보고하며 진입점마다 다릅니다. 마지막 `pass`/`deny` 항목이
결정 단계이고 이후 단계는 `not_evaluated`입니다. 수문장 거부는 모든 권한보다 우선하므로
신원보다 먼저 검사합니다. 역할 확장은 컴파일 시점에 계산되며 그 결과(주체 ∩ 네트워크
권한)가 사용되는 위치에 보고합니다.

| 진입점 | 순서 |
| --- | --- |
| 권한(`user`) | fence → service → context → guard → subject → network → role_expansion → permission → information_class → assurance |
| 자원(`user`, `workload`) | fence → resource → service_scope → action → context → guard → subject → network → role_expansion → permission → information_class → assurance |
| 자원(`human`) | fence → resource → service_scope → context → principal_format → principal_assurance → action → guard → subject → network → role_expansion → permission → information_class → assurance |
| `kubernetes_api` | fence → resource → service_scope → context → action → subject → role_expansion → permission → information_class → assurance |

권한·정보등급 단계는 모르는 이름, 어떤 할당 역할도 부여하지 않음(`*_missing_subject`),
주체는 가졌지만 일치한 네트워크 규칙이 제거함(`*_removed_by_network`)을 구분하고 양쪽에서
부여하는 역할(`granted_by_subject_roles`, `granted_by_network_roles`)을 나열합니다.
네트워크 단계는 선택된 규칙(정확한 호스트가 prefix보다 우선)과 가려진 덜 구체적인 규칙을
최대 8개 보고합니다. 수문장 단계는 `guard_denied`, `guard_not_enforced`(`require_guard`
서비스에서 observe/unavailable), `guard_enforced_allow`, `guard_not_required` 중 하나입니다.

### 사유 코드와 메시지 키

등록된 최종 코드(ADR 0019 `pumgye.*` 네임스페이스): `pumgye.allow`, `unknown_service`,
`guest`, `network_guest`, `permission_denied`, `class_denied`, `assurance_denied`,
`guard_denied`, `guard_unavailable`, `unknown_resource`, `unknown_action`, `unavailable`.
각각 `pumgye.reason.<접미사>`(문장)와 `pumgye.hint.<접미사>`(조치) 키가 있습니다. 모든
단계 상세 코드(`pumgye.detail.*`, `pumgye_core::explain::DETAIL_CODES`)는 그 자체가 메시지
키이고 각 단계에는 `pumgye.stage.<단계>` 키가 있습니다. 카탈로그는
`crates/pumgye-core/messages/en.json`·`ko.json`이며 ICU 매개변수 이름은 단계 `detail`
필드 이름과 같습니다. 계약 테스트가 두 카탈로그의 키 집합이 등록 키와 정확히 같은지
검사합니다. 코드를 추가하려면 스키마 minor 버전, 두 카탈로그 항목, 테스트가 필요합니다.

## `POST /v1/explain/batch`

요청: `{"snapshot"?, "cases": [...], "trace"?(기본 false), "on_behalf_of"?}`. 배치
전체에 스냅샷 하나를 사용합니다. 응답은 요청 순서의 `results`(`label` 반환)와
`summary`(`cases`, `allowed`, `denied`, `unavailable`, 후보일 때 `changed`,
`allow_to_deny`, `deny_to_allow`)입니다. ADR 0019 영향(what-if) 분석의 기본 연산이며,
한강은 보존된 과거 문맥을 배치로 보내 변경된 결과를 집계합니다. 잘못된 케이스가 하나라도
있으면 배치 전체를 거부(400)하므로 부분 감사가 생기지 않습니다.

## `POST /v1/explain/diff`

요청: `{"base_revision", "policy", "cursor"?(0), "limit"?(100), "on_behalf_of"?}`.
현재 스냅샷과 후보의 역할 확장된 컴파일 권한을 이름 기준으로 비교합니다(어휘 순서 변경은
변경이 아님). 항목은 결정적 순서로 `information_classes`, 서비스별(정렬) `service`(컨텍스트,
`require_guard`, 권한 어휘), 맵·주체별 `assignment`, CIDR별 `network`, 마지막으로
`resource`입니다. 각 항목은 `change`(`added`/`removed`/`modified`), `before`/`after`,
`delta`(추가/제거된 권한·정보등급, 최소 AAL 변화)를 가집니다. cursor는 이 순서의
오프셋이며 같은 후보·기준 리비전에서 안정적입니다.

## `GET /v1/audit/simulations?after_id=N`

관리자 전용. ID 순서로 최대 100행을 반환합니다. `actor`는 전송 계층 신원(클라이언트
인증서 SHA-256 또는 루프백)이며 요청 필드가 아닙니다. `on_behalf_of`는 호출자가 선언한
신뢰하지 않는 값으로 한강 콘솔 감사와의 상관을 위해서만 기록합니다. `revision`은 게시
시뮬레이션에서는 게시 리비전, 후보에서는 기준 리비전입니다.

## 한강 콘솔 브로커 계약(한강 미구현)

한강은 브라우저에서 직접이 아니라 호스트 API 브로커를 통해 콘솔 플러그인에 노출해야 합니다.

| 콘솔 작업 | 브로커 경로 | 품계 호출 |
| --- | --- | --- |
| 단일 요청 시뮬레이션 | `POST /v1/pumgye/explain` | `POST /v1/explain` |
| 다건/영향 분석 | `POST /v1/pumgye/explain/batch` | `POST /v1/explain/batch` |
| 초안 영향 diff | `POST /v1/pumgye/explain/diff` | `POST /v1/explain/diff` |
| 시뮬레이션 감사 | `GET /v1/pumgye/audit/simulations` | `GET /v1/audit/simulations` |

- 브로커는 품계 관리자 자격과 클라이언트 인증서를 서버 측에 보관하고, 콘솔 행위자와
  권한(예: `policy:simulate`)을 재검증하며, `on_behalf_of`를 브라우저가 아닌 인증된
  세션에서 채우고, 위 제한 안에서 본문을 그대로 전달합니다.
- 브로커는 품계의 프로세스 전체 버킷보다 먼저 콘솔 행위자별로 속도를 제한하고 429/503을
  콘솔 재시도 상태로 매핑합니다. 409는 초안 기준 리비전이 오래되었음을 뜻합니다.
- 콘솔은 `message_key`/`hint_key`/`code`/`label_key`를 EN/KO 카탈로그(품계 카탈로그에서
  시작)로 표시하고 모든 결과에 `snapshot.source`·`snapshot.revision`과 함께
  *시뮬레이션* 표시를 붙입니다.
- 브로커는 `audit_id`를 참조하는 한강 `simulation` 판정 이벤트(ADR 0019)를 기록합니다.
  품계는 판정 이벤트를 직접 발행하지 않습니다.

## 핫 패스 성능

추적 제네릭 리팩터링을 `0409a7a`(ADR 0021 회귀 기준)와 `849ca90`(이 변경의 부모)에 대해
리비전별 release 빌드 1회씩, 같은 측정 루프로 비교했습니다. 단일 고정 코어에서 사용자
65,536명과 `/32` 네트워크 규칙 65,536개로 `CompiledPolicy::evaluate`를 실행당 2천만 회
호출했습니다. *allow*는 전부 허용, *mixed*는 허용/권한/등급/수문장 거부를 순환합니다. 값은
판정당 ns 중앙값이며 공유 호스트(16코어에서 load average ≈ 7)라 실행 간 편차가 ±20 %였습니다.

| 패턴 | `0409a7a` | `849ca90` | 이 브랜치 |
| --- | --- | --- | --- |
| sequential, allow (5회) | 367.6 | 283.2 | 282.1 |
| sequential, mixed (5회) | 330.9 | 264.4 | 222.4 |
| shuffled, allow (5 + 9회) | 1242.9 | 506.9 / 599.4 | 619.6 / 581.6 |
| shuffled, mixed (5 + 9회) | 881.1 | 405.5 / 545.6 | 417.6 / 471.2 |

모든 구성에서 `0409a7a`보다 느리지 않고, `849ca90` 대비 차이는 실행 간 잡음 범위입니다(교차
실행 9회의 두 번째 shuffled 측정에서는 이 브랜치가 중앙값·최솟값 모두 빠름: allow 최소 520 vs
529 ns, mixed 417 vs 495 ns). 결정적 보증은 `no_alloc.rs`가 유지합니다. 코어 단독 수치이며
[PERFORMANCE.ko.md](PERFORMANCE.ko.md)의 mTLS 요청 체인 수치와 비교할 수 없습니다.

## 제약

- 정책 모델은 버전 1입니다. ADR 0021 v2 단계(그룹, 명시적 거부, 존, clearance, 유효 기간)는
  v2 구현 시 같은 추적에 추가합니다.
- who-can/what-can(ADR 0021 P1)과 저장된 후보 ID는 없습니다. 후보는 요청마다 인라인으로 보냅니다.
- explain 결과에 서명하지 않습니다(ADR 0019 미결 질문 6).
- 수문장 증거는 모의 입력이며 explain은 수문장을 조회하지 않습니다. 한강이 조율하는
  시뮬레이션이 수문장을 별도로 조회합니다.
