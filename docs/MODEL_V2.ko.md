# 정책 모델 버전 2 (ADR 0021 P0, 미릴리스)

[English](MODEL_V2.md)

버전 2는 서비스별 주체 맵과 역할을 Hopae 소유 주체·그룹, 전역 역할 템플릿, 수명 주기
메타데이터를 가진 명시적 허용·거부 **바인딩**, 카탈로그 clearance 레이블, 수문장 네트워크
존으로 바꿉니다(Hangang ADR 0021). 운영자가 설명되지 않은 불일치 0건인 섀도 관찰 기간 뒤에
컷오버를 승인할 때까지 버전 1이 권한을 가지며, 롤백은 버전 1을 다시 게시합니다. 컴파일된
스냅샷은 비트셋 기반이고 핫 패스는 할당 없이 동작합니다.

## 문서

예시는 [영문 문서](MODEL_V2.md#document)와 같고, 전체 fixture는
[examples/v2/policy.json](../examples/v2/policy.json), 위치 지정 거부가 기대값으로 붙은
적대적 fixture 21개는 [examples/v2/adversarial](../examples/v2/adversarial)에 있습니다.
`pumgye_core::v2`의 serde 모델(모든 곳에 `deny_unknown_fields`)이 규범이며, 설명용 JSON
Schema는 [docs/schema/policy-v2.schema.json](schema/policy-v2.schema.json)입니다.

| 요소 | 규칙 |
| --- | --- |
| 주체 | `{kind, ref}`: `human` = `human1:` + 64 hex, `service` = `s_` + 48 hex, `workload` = `wk2:` + 64 hex(레거시 Pod 기반 `s_`는 사용 중단 경고와 함께 허용). 종류가 키의 일부이므로 같은 문자열도 종류가 다르면 다른 주체입니다. |
| GroupRef | `grp1:` + `0123456789abcdefghjkmnpqrstvwxyz` 26자, 바이트 단위 비교(대소문자 접기 없음). 멤버십은 서명된 Hopae projection에서만 오며 요청에는 그룹 필드가 없습니다. |
| 템플릿 | 전역. `permissions`(추상 이름, 서비스별 `permission_map`으로 매핑, 기본은 동일 이름), `inherits`(최대 8, 비순환), `clearance_ceiling`(`{level, compartments}` 또는 `null` = clearance 없음), `minimum_aal`(상속 체인 최댓값). |
| 서비스 | `permissions`(최대 256), `permission_map`, `network_ceiling`(`{zone, max}`, `max`는 템플릿·템플릿 목록·`"guest"`), `require_guard`(기본 true), 컨텍스트는 `network_and_guard`만(Kubernetes API 서비스는 v1 유지, ADR 0022). |
| 바인딩 | 고유한 `bnd_…` ID, `effect` `allow`(`role` 필요) 또는 `deny`(`permissions` 목록 또는 `"all"` 필요), 주체 1–64개, `scope.services` 목록 또는 `"all"`, `conditions`의 `zones`(목록 또는 `"any"`)·`minimum_aal`·`not_before`/`expires_at`(RFC 3339, 권한 서버 시각). |
| 메타데이터 | `reason`, `approval_ref`, `source`(`native`, `kubernetes:<uid>`, `jit:<id>`, `migrated:v1`)와 서버가 찍는 `granted_by`, `created_at`, `revision`(본문 값은 무시). |
| 카탈로그 | 카탈로그 소유자의 읽기 전용 가져오기: 순서 있는 `levels`, `compartments`, 리소스 레이블과 동작 → 권한. |
| 존 | 읽기 전용 가져오기(`source: sumunjang`과 수문장 리비전, 또는 `local` CIDR 대체). |

한도(컴파일 시 검사, 위치가 지정된 `pumgye.validation.*` 거부): 서비스 4,096, 템플릿 1,024,
바인딩·주체 1,048,576, 스냅샷당 참조 그룹 256(projection 샤드 1개), 존 64·prefix 65,536,
서비스당 권한 256, 수준 16, compartment 64, 서비스당 주체별 grant 64, 상한당 템플릿 8.

## 평가(ADR 0021 순서)

1. **펜스**(권한 서버): 정상·최신 스냅샷, `minimum_revision`, 그룹을 참조하는 스냅샷이면 staleness
   한도 안의 검증된 멤버십 projection. 아니면 판정 불가(guest-to-allow 없음).
2. 알 수 없는 서비스 → `UnknownService`, 컨텍스트 불일치 → `PermissionDenied`.
3. 수문장 `deny` → `GuardDenied`, `require_guard`인데 강제 허용이 아니면 `GuardUnavailable`.
4. 카탈로그: 리소스/동작 → 권한과 레이블. 알 수 없는 리소스/동작/권한/등급은 거부. 권한형
   진입점의 등급은 수준 또는 compartment 이름(참고용 레이블)이며 리소스 진입점의 레이블은
   카탈로그 값입니다.
5. 주체: 종류별 조회와 projection 그룹(Human). 바인딩이 없으면 `Guest`.
6. **명시적 거부**: 주체 또는 그룹·서비스·권한·존이 맞는 유효 거부 → `ExplicitDenied`. 거부는
   모든 허용보다 우선합니다.
7. 허용 집합: 유효 기간 안이고 존 조건이 요청 존과 겹치는 허용. 유효한 것이 없으면 `Guest`,
   존이 맞는 것이 없으면 `NetworkGuest`.
8. **네트워크 상한**: 가장 구체적인 상한 prefix(정확한 호스트 우선, v1 최장 prefix와 동일).
   없으면 `NetworkGuest`, `guest`는 아무것도 허용하지 않습니다.
9. 권한: 유효 허용 템플릿과 상한이 모두 부여해야 함 → 아니면 `PermissionDenied`.
10. **권한을 부여한 템플릿별 clearance**: 바인딩 템플릿과 상한 템플릿 모두에서 레이블 수준 ≤
    템플릿 수준이고 compartment ⊆ 템플릿 compartment → 아니면 `ClassDenied`.
    `reader@public` + `admin@internal`은 internal 템플릿이 `read`를 부여하지 않는 한
    `read@internal`이 되지 않습니다.
11. 보증 수준: 제시 AAL ≥ 가장 유리한 부여 쌍의 max(템플릿 체인, 바인딩 조건, 상한, 리소스) →
    아니면 `obligations.required_aal`과 함께 `AssuranceDenied`.
12. `Allow`.

`ExplicitDenied`는 변경되지 않은 v1 와이어 상대(PPG1, `/v1/decision`, gRPC)에는
`PermissionDenied`로 전달되고, `/v2/explain`과 섀도 보고서에는 정확한 변형이 나옵니다.

**AAL 정렬.** AAL0은 기계 증거, 1–3은 Hopae가 발급하는 NIST SP 800-63B 수준이며 service·
workload 케이스는 0이어야 합니다. projection `max_aal`보다 높은 AAL을 요구하는 템플릿·바인딩·
리소스는 `pumgye.warning.unsatisfiable_assurance`(상태·explain)와 함께 컴파일되며 절대 낮춰지지
않습니다(Hopae는 이제 opt-in 애플리케이션에만 AAL3을 발급).

**유효 기간.** `not_before`/`expires_at`은 모든 판정에서 권한 서버 시각과 정수 비교로
적용되며, `/v2/status`가 만료된 바인딩과 다음 경계를 보여 줍니다.

## Hopae 소유자 입력

`--hopae-owner owner.json`은 Hopae admin mTLS 리스너로 가는 인증된 HTTPS 클라이언트 하나를
설정합니다(고정 CA, 클라이언트 인증서, Hopae 서비스 자격, `x-hopae-audience`,
`x-hopae-admin-request: 1`). 설정 예시는 [영문 문서](MODEL_V2.md#hopae-owners)를 참조하세요.
`token_file`(권장) 또는 `token_env`에 자격을 두고, `audience`는 `x-hopae-audience`로 보내며,
선택적 `connect_address`는 콘솔 호스트가 해석될 주소를 고정합니다(Host 헤더와 TLS 서버 이름은
그대로 콘솔 호스트).

**호출자 자격.** 품계는 Hopae의 **경로 범위가 제한된 읽기 전용 서비스 자격**(Hopae
`docs/SERVICE_CREDENTIALS.md`)을 사용합니다: `Bearer hsc1.<id>.<secret>`이며 Hopae admin mTLS
리스너에서만, 고정된 클라이언트 인증서(SPKI SHA-256 및/또는 SAN)와 함께, Hopae audience에 대해서만,
preset `pumgye-v2` 경로(`/v1/groups/projection/snapshot`, `/v1/groups/projection/changes`,
`/v1/subjects/lifecycle`, `/v1/subjects/lifecycle/snapshot`)에서만 받아들여지고 쓰기 경로는
`403 service_route_forbidden`으로 거부됩니다. `hopae admin service-credentials create pumgye-v2
--preset pumgye-v2 --client-spki-sha256 <품계 인증서 SPKI> [--client-san <품계 SPIFFE ID>] --config …`로
발급해 출력된 토큰을 비공개 파일에 두고, `rotate` → 다음 토큰 배포 → `promote`로 교체합니다.
관리자 세션이나 위임 키는 절대 쓰지 마세요.

**멤버십 projection**(Hopae `docs/GROUPS.md`). 게시된 스냅샷의 관련 그룹 어휘를 보내고
계약대로 모든 페이지를 검증합니다: envelope 형식, 고정된 `(issuer_ref, key_epoch)` 키(envelope의
키는 절대 사용하지 않음), 파싱 전에 `"hangang-zerotrust:hopae-membership-projection:v1\0" ||
payload 바이트`에 대한 엄격한 Ed25519 검증, 그다음 `kind`·issuer/epoch·`audience`·
`vocabulary_sha256`·신선도(`issued_at`이 `max_age_secs` 이내, 60초 넘게 미래가 아님). snapshot
페이지는 요청 cursor와 첫 페이지 watermark를 되돌려야 하고, feed는 watermark부터 `from`이 요청
리비전과 같고 `next_cursor`가 뒤로 가지 않는 경우에만 적용합니다. 다른 `store`, 연속성 파괴,
`410 cursor_expired`는 새 snapshot을 받습니다. null 주체와 비활성 항목은 무시하고,
`member_removed`(정지된 멤버십 포함)·`member_added`/`restored`·`group_deleted`는 집합 연산입니다.
어휘 밖이거나 정규 소문자가 아닌 GroupRef는 페이지를 거부합니다. projection의 `max_aal`은 AAL3
경고에 쓰입니다. 갱신에 성공하면 `max_staleness_secs` 동안 멤버십이 유효하고, 그 뒤에는 그룹
권한이 fail closed 됩니다. 키 교체: 다음 `(issuer_ref, key_epoch)`를 먼저 추가하고 Hopae를 바꾼 뒤
이전 키를 제거합니다.

**주체 수명 주기**(Hopae `docs/SUBJECT_DIRECTORY.md`). reconcile snapshot과 feed를 주기적으로
적용합니다(보고된 status를 적용). 삭제된 주체는 컴파일 시 바인딩 주체에서 제외되고, 모든 주체가
삭제된 바인딩은 **고아**가 되어 컴파일에서 빠지며 문서에는 읽기 전용으로 남고 관리자가 제외하고
다시 게시할 때까지 `/v2/status`에 표시됩니다. 비활성 주체는 권한 변경 없이 `subject_disabled`로
표시됩니다. 수명 주기 snapshot이 완전하면 삭제되었거나 알 수 없는 Human을 지정하는 새·변경
바인딩 게시는 거부됩니다(`pumgye.validation.subject_deleted` / `subject_unresolved`).

## Kubernetes workload 주체(Hopae ServiceAccount 신원)

Hopae는 Kubernetes workload를 **ServiceAccount**로 인증합니다(Hopae `docs/KUBERNETES_WORKLOAD.md`):
주체 `wk2:<64 hex>`(ServiceAccount UID 한 세대), SPIFFE ID `spiffe://<trust-domain>/ns/<ns>/sa/<sa>`
(이름), 집행이 싣는 wire 주체 `s_<48 hex>`. 버전 2 바인딩은 workload를 `{kind: "workload", ref}`로
`wk2:` 주체(UID 고정) 또는 SPIFFE ID(설계상 재생성에도 유지)로 지정할 수 있으며, 레거시 Pod 기반
`s_` 주체는 사용 중단 경고와 함께 계속 허용합니다.

- 품계는 `include_workloads: true`로 수명 주기 feed를 읽습니다. `workload_observed`는 wire 주체 →
  (주체, SPIFFE ID) 별칭을 추가하고, `workload_retired`(ServiceAccount 삭제 또는 재생성)는 주체를
  영구 폐기하며, `workload_legacy_mapped`는 Pod 기반 주체 → 주체 매핑을 기록합니다. workload 기록은
  저장되며(Hopae snapshot에는 없음) 매 reconcile snapshot 전에 이전 cursor부터 feed를 비웁니다.
- 평가: workload wire 주체는 자기 주체와 SPIFFE ID의 권한도 가집니다(그룹 멤버십 옆의 할당 없는 별칭
  인덱스). SPIFFE ID로 직접 지정된 호출자(한강 SVID 리스너)는 SVID에 UID가 없으므로 이름 바인딩만
  적용됩니다. 폐기된 주체와 그 wire 주체는 바인딩을 고아로 만들고, 폐기된 주체에 대한 새 바인딩 게시는
  거부됩니다(`pumgye.validation.subject_retired`). explain은 별칭을 보여 줍니다.
- Pod 기반 권한 이전: `GET /v2/workloads`는 주체, Hopae 레거시 매핑, **보고 전용 재부여 제안**(매핑된
  레거시 주체를 지정한 각 바인딩을 ServiceAccount 주체로 옮긴 사본)을 나열하고,
  `POST /v2/workloads/regrants/apply {base_revision, proposals, reason, approval_ref?}`는 선택한 제안을
  CAS 게시로 적용합니다(`source: migrated:legacy-pod`, 행위자 기록). 레거시 바인딩은 명시적으로
  폐기할 때까지 남습니다. 이전 미리보기도 v1 `workload_users`의 관측된 매핑을 보고합니다.

## AAL3

Hopae는 opt-in 애플리케이션에만 AAL3을 표시하고 receipt에 봉인합니다(Hopae ADR-0018 결정 3, 11).
품계는 수준을 숫자로 비교하고 Human AAL3을 **Hopae가 봉인한 증거에서만** 받아들입니다: 검증된 인증
receipt, 권한 context, 관측 Human permit(`SealedAssurance`). 어댑터가 주장하는 수준(서명 없는 Human
리소스 진입점)은 AAL1–2로 유지합니다. 버전 2 템플릿·바인딩·리소스는 3을 요구할 수 있고, projection이
`max_aal ≥ 3`을 알리기 전까지 충족 불가 경고와 함께 컴파일되며 절대 낮춰지지 않습니다. explain은
`presented`/`required`와 `obligations.required_aal: 3`을 보고하며, v1 explain 케이스는
`assurance_evidence: "sealed"`로 봉인된 AAL3을 모의합니다.

## 수문장 존 계약(수문장이 존을 내보내기 전까지 CIDR 대체)

존의 소유자는 수문장입니다. 수문장이 `NetworkZone`과 존 snapshot export를 제공하기 전까지 문서는
`"source": "local"` 존을 사용합니다(변환기의 `legacy.<service>.<n>` 존은 수문장에 대한 제안).
수문장이 존을 내보낼 때 품계가 소비하는 계약:

- 리비전이 있는 snapshot `{"revision": N, "zones": {"<이름>": {"prefixes": ["CIDR", …]}}}`,
  이름은 `[A-Za-z0-9_.:-]{1,128}`, 정규 prefix(호스트 비트 없음), 품계 스냅샷당 존 64개·prefix
  65,536개 이하.
- 문서에 `"zones": {"source": "sumunjang", "revision": N, …}`로 가져와 일반 CAS 경로로
  게시하므로 판정 리비전이 존 리비전을 펜스합니다. 품계가 서명된 snapshot을 직접 가져오는 것은
  ADR 0021 P1(PPG2/HGD)입니다.
- 존 조건과 상한은 이름만 참조합니다. 품계는 "이 IP가 허용되는가"에 답하지 않으며 수문장 거부가
  여전히 우선합니다(3단계).

## 관리 API(`/v2`, 관리자 자격, 관리 수용 게이트)

| Endpoint | 용도 |
| --- | --- |
| `GET /v2/policy` / `PUT /v2/policy` | `{revision, policy}` 조회·게시. `If-Match: "<v2 리비전>"`(첫 문서는 `"0"`). 새 리비전은 지금까지 발급된 모든 리비전보다 하나 큽니다(v1·v2가 하나의 리비전 순서와 `document: v1|v2`가 붙은 하나의 게시 감사를 공유). `current_revision`이 있는 409, 위치 지정 422, 413. Kubernetes 소유 모드에서는 거부. |
| `GET /v2/status` | 권한 모델, 리비전, 경고, 고아·비활성·만료 바인딩, 다음 경계, projection·수명 주기 상태, 멤버십 신선도, 섀도 게이트. |
| `POST /v2/explain`, `/v2/explain/batch` | v2 explain(아래). |
| `POST /v2/candidates/diff` | `{base_revision, policy, cursor?, limit?}` → (주체, 서비스)별 권한 변경: 추가·제거된 권한과 거부, 조건 변경, 전후 grant. |
| `POST /v2/migration/preview` | 현재 v1 문서 변환(`{workload_mapping?}`), 저장하지 않음. |
| `GET /v2/shadow` | 판정 쌍 행렬, 최근 불일치(최대 64), 설명, 게이트. |
| `POST /v2/shadow/explanations` | `{service?, v1_decision?, v2_decision?, reason}`: 이후 불일치를 설명됨으로 분류(규칙 최대 64, 행위자와 함께 감사). |
| `POST /v2/shadow/reset` | `{reason}`: 새 관찰 기간 시작. |
| `POST /v2/cutover` | `{approval_ref, reason}`: 게이트 필요. v2 문서를 새 리비전으로 다시 게시하고 한 트랜잭션에서 모델을 전환. |
| `POST /v2/rollback` | `{reason}`: 보관된 v1 문서를 새 리비전으로 다시 게시하고 되돌림. |
| `GET /v2/model/history` | 행위자·승인 참조·사유·게이트 증거가 있는 모델 전환 기록. |

오류는 explain API의 구조화된 본문(`pumgye.error.*`, 위치 상세)을 사용합니다.

## 섀도 평가와 컷오버

v2 문서가 게시되어 있으면 모든 PPG1·HTTP·gRPC·리소스 판정을 v2로도 평가해(같은 요청, 종류는
typed 증거 또는 일반 진입점의 정규 prefix) 할당 없이 비교합니다: (v1, v2) 판정 쌍별 건수, 결과
불일치(허용 ≠ 거부), 사유만 다른 drift, 설명됨/설명되지 않음, 제한된 샘플 링. 카운터는 30초마다
저장되어 리비전 쌍이 같으면 재시작 후 이어지고, 어떤 게시든 새 관찰 기간을 시작합니다.
**게이트**는 관찰 기간(`--shadow-window-days`, 기본 7)이 지났고 판정이 관찰되었으며 **설명되지
않은** 결과 불일치가 0일 때 충족됩니다. 설명은 기록 시점부터 적용되고 기간 재시작은 명시적입니다.
컷오버 뒤에는 v2가 판정하고 v1이 섀도로 비교되며 응답에는 v2 리비전이 실립니다. 롤백은 v1을
모든 발급 리비전보다 높게 다시 게시하므로 클라이언트 리비전 하한은 뒤로 가지 않습니다.

## 이전(`pumgye --migrate-v1-to-v2 policy.json`)

결정적이고 fail closed이며 DB를 건드리지 않고 `{document, report}`를 출력합니다. 역할은 템플릿
`<service>.<role>`이 되고 서비스 간 동일 역할은 병합 후보로 보고합니다. `users`는 소유자 조회로
분류(오프라인은 prefix, preview endpoint는 Human이 수명 주기 feed에 알려져 있어야 함)하며 확인할
수 없는 주체는 보고하고 **이전하지 않습니다**. `human_users` → `human`, `workload_users` →
`workload`(`wk2:`는 관리자가 확인한 매핑으로만, 그 외에는 사용 중단 레거시 주체). 네트워크는 역할
집합별 로컬 존 `legacy.<service>.<n>`과 상한이 되며 상한 AAL과 바인딩 조건이 v1의 합집합 AAL을
재현합니다. 모든 역할의 등급 집합이 v1 어휘 순서에서 하향 폐쇄이면 순서 있는 수준으로, 아니면 하나의
기본 수준 아래 compartment로(템플릿별로 v1 소속을 정확히 재현) 변환하고 카탈로그 소유자를 위한 검토
항목을 남깁니다. v1이 허용하던 역할 간 등급 합집합은 보고합니다(`pumgye.migration.class_union`).
Kubernetes API 서비스와 RBAC 매핑은 v1에 남습니다.

동등성 테스트는 v1 qualification 코퍼스를 변환해 모든 판정을 비교하며, 설명되지 않은 허용/거부
불일치는 0이고 남은 차이는 보고서가 나열한 주체와 합집합뿐입니다.

## Explain v2

`POST /v2/explain {snapshot?, case, trace?}`와 `/v2/explain/batch {snapshot?, cases, trace?}`는
기록용 tracer로 같은 평가 함수를 실행합니다. 케이스: `{subject: {kind, id}, service,
resource+action | permission+information_class, ip, aal, guard, minimum_revision?, at?,
hypothetical_groups?}` — `at`은 권한 서버 시각을 모의하고 `hypothetical_groups`는 Human 케이스
하나에 대해 projection을 대체합니다. 단계: `fence, service, context, guard, catalog, principal,
explicit_deny, allow_set, network_ceiling, permission, clearance, assurance`, 각각 등록된
`pumgye.detail.*` 코드가 있고 거부·기여 허용 바인딩은 출처(`id`, role, 조건, `reason`,
`granted_by`, `approval_ref`, `source`, `revision`)와 함께 보고합니다. 후보 스냅샷은 게시본과의
비교를 추가합니다. 모든 호출은 `explain_v2`/`explain_v2_batch`/`diff_v2`로 감사합니다.

## 성능

release 빌드, 고정 코어 1개, 직접 바인딩이 하나씩 있는 service 주체 65,536개와 `/32` 상한 prefix
65,536개, 같은 카디널리티의 v1과 같은 프로세스에서 교차 측정(판정당 ns, 공유 호스트 load ≈ 5에서
6라운드 최솟값):

| 케이스(순차 주체) | v1 | v2 |
| --- | --- | --- |
| allow | 256 | 271 |
| permission denied | 237 | 258 |
| class denied | 246 | 258 |
| 수문장 observe | 21 | 16 |
| shuffled allow | 462–475 | 443–461 |
| shuffled mixed | 351–355 | 357–371 |

단일 경로 케이스는 v1 대비 +4–11 % 이내이며 ADR의 `0409a7a` 회귀 기준(같은 루프·같은 호스트에서
순차 allow ≈ 368 ns, shuffled allow ≈ 1,243 ns)보다 빠릅니다. 평가는 할당이 없습니다
(`tests/no_alloc.rs`가 v2 모든 결과를 검사).

**잔여 차이(미결).** *순차* 주체(작업 집합 전체가 캐시에 상주, 판정당 순수 CPU ≈ 200 ns)에서 네
결과를 매 요청 번갈아 섞는 패턴은 집중 최적화(무조건 단일 grant용 직선 fast path와 일반 경로 분리,
상한·clearance 통합 루프, 압축 상한 인덱스, FNV 어휘) 뒤에도 v1보다 +20–28 % 느립니다. 분석: v2는
ADR 순서상 4단계에서 모든 요청의 권한 비트와 카탈로그 레이블을 모두 해석하고 템플릿별로 상한과
clearance를 평가하는 반면, v1은 등급을 지연 해석하고 첫 합집합 검사 실패에서 멈춥니다. 결과가 매
요청 바뀌면 추가 해시 조회와 템플릿별 clearance 분기가 메모리 대기 뒤에 숨지 않습니다. 절대 차이는
≈ 40 ns이며, 캐시 미스가 나는 *shuffled* 혼합(주체 65,536)에서는 동등(391–397 vs 400–415 ns),
측정된 mTLS 요청 체인(판정당 ≈ 7 µs)에서는 1 % 미만입니다. 이를 없애려면 ADR 단계 순서를 버리거나
(레이블 지연 해석) (주체, 서비스, 권한)별 결과를 캐시해야 하며 둘 다 P0에서는 채택하지 않았습니다.

## ADR 0021 P0 수용 기준 상태

| 게이트 | 상태 |
| --- | --- |
| v2 스키마, 유효·적대적 예시 | 완료(serde 모델, JSON Schema, fixture 1 + 21) |
| 컴파일러·평가기(거부, 그룹, 템플릿, 존, clearance, 유효 기간) | 완료 |
| Explain `NoTrace`/`VecTrace` 동등성 | 완료(코퍼스 동등성 테스트) |
| 후보 diff | 완료 |
| v1 → v2 변환기와 섀도 모드 | 완료 |
| 속성 테스트(거부 단조성, 상한은 줄이기만, 바인딩 없이 권한 없음, 종류 격리, 만료) | 완료(결정적 생성기) |
| 적대적 fixture(헤더를 통한 그룹 위조, 고아, AAL3 충족 불가, 등급 헤더 불일치) | 완료: 어떤 요청에도 그룹 입력이 없고(모르는 필드 거부) projection 위조는 거부, 고아 처리, 낮추지 않는 AAL3 경고, 클라이언트 등급은 권한 경로에서 참고용이며 리소스 경로에서는 받지 않음 |
| qualification 코퍼스에서 v1/v2 섀도 동등성 | 테스트로 완료, 운영 7일 관찰은 운영 게이트 |
| `0409a7a` 대비 10 % 이내 성능 | ADR 기준 충족. 현재 v1 대비 단일 경로 +4–11 %, 캐시 상주 교차 혼합 +20–28 %(위 잔여 분석) |
| Hopae 멤버십 projection·수명 주기 소비 | 완료: 서명 페이지 단위 테스트와 Hopae 서비스 자격을 쓰는 로컬 상호 운용 도구로 실제 검증(workload 주체 포함 31/31) |
| 수문장 `NetworkZone` export | 계약 정의, 수문장 제공 전까지 로컬 CIDR 대체 |
| 원격 k3s 실제 4개 구성 요소 체인(ADR 0022) | 이 변경에서 실행하지 않음 |

## 로컬 상호 운용 검증(opt-in)

`tools/hopae_v2_interop.py`는 클러스터나 OIDC 제공자 없이 실제 Hopae와 실제 품계를 루프백
프로세스로 실행합니다.

```sh
python3 tools/hopae_v2_interop.py --hopae <hopae 바이너리> --pumgye target/debug/pumgye [--workdir DIR] [--keep] [--skip-workloads]
```

Hopae에 projection 키, `human1:` 주체에 필요한 네이티브 Human receipt 발급자(Hopae mTLS gRPC
리스너 필요), admin mTLS 리스너, `admin.service_audience`, 정적 JWKS를 쓰는 `kubernetes_workload`
프로필, 도구의 운영자 쓰기용 unified 위임 키를 설정하고, Hopae 시나리오 테스트처럼 사람을 SQL로
저장소에 넣은 뒤 그룹·멤버십·비활성화는 Hopae의 실제 admin API로 수행합니다. 품계 서비스 자격은
`hopae admin service-credentials create --preset pumgye-v2`로 발급하고, 품계의 `--hopae-owner`는
투명한 TCP 장애 주입기(TLS는 그대로 통과, 장애 모의 전용)를 거쳐 admin mTLS 리스너를 **직접**
호출합니다. 검사(31): 서비스 자격의 쓰기 경로·다른 클라이언트 인증서·다른 audience 거부, 서명된
snapshot과 feed 소비, 그룹 허용, 명시적 거부 우선, feed 제거 회수, Hopae 접근 불가 시 fail closed와
복구, 비활성화 → `subject_disabled`, 저장소 삭제 → 고아 바인딩과 새 바인딩 거부, journal 정리 →
`410 cursor_expired` → 재snapshot과 수렴, Hopae가 오프라인 검증한 ServiceAccount 토큰(rollout에도
같은 주체)이 `workload_observed`로 들어오고 wire 주체가 `wk2:` 바인딩을 상속하며 SPIFFE 이름 거부가
적용되고 SPIFFE ID로 지정된 SVID 호출자는 이름 바인딩만 받음. Python 3.11+와 `cryptography`
패키지가 필요합니다. 마지막 실행: Hopae `feat/scoped-service-credentials`(`b318922`)와
`feat/k8s-workload-identity`(`c6fb27a`)의 로컬 병합(푸시하지 않음) 대상 31/31. workload 신원이 없는
빌드는 `--skip-workloads`를 사용합니다.

## Hopae 의존성

버전 2는 다음 Hopae 기능을 사용합니다(`ziozzang/hopae` PR 번호).

| 기능 | Hopae 출처 | 용도 |
| --- | --- | --- |
| 서명 멤버십 projection, 그룹 | #5 `feat/groups`(`integrate/identity-platform` 포함) | 그룹 바인딩 |
| 주체 디렉터리, 수명 주기 feed와 reconcile snapshot | #4 `feat/subject-resolve` | 고아, 게시 검사 |
| 경로 범위 읽기 전용 서비스 자격(`hsc1`, preset `pumgye-v2`) | #10 `feat/scoped-service-credentials` | owner 클라이언트 인증 |
| Kubernetes workload 신원(`wk2:`, SPIFFE, `include_workloads`) | #9 `feat/k8s-workload-identity` | workload 주체와 재부여 |
| opt-in 애플리케이션 receipt의 AAL3 봉인 | ADR-0018(`feat/admin-api-gaps`) | `SealedAssurance` |

**Hopae에 필요한 것: workload snapshot.** workload 주체는 수명 주기 feed에만 나타납니다
(`workload_observed`는 Hopae 프로세스당 한 번). `410 cursor_expired`나 품계 DB 손실 뒤에는 새
watermark 이전에 보고된 주체가 새 Hopae 프로세스가 다시 인증할 때만 복구됩니다. 품계는 본 것을
저장하고 매 reconcile snapshot 전에 feed를 비우지만, 완전한 복구에는 Hopae가 현재 workload 주체를
나열해야 합니다(예: `/v1/subjects/lifecycle/snapshot`의 `include_workloads`, `principal`·
`subject_ref`·`spiffe_id`·`status`). 그전까지는 feed 보존 기간을 품계의 최장 중단 시간보다 길게 두세요.

**호패 SDK의 재적재 TLS (ziozzang/hopae#15).** 이제 `hopae-grpc`는
`ReloadableEndpointConfig`를 받습니다. 이 구성의
`Arc<dyn Fn() -> Arc<rustls::ClientConfig>>`는 새 연결을 만들 때마다 읽습니다.
`EndpointConfig` PEM 생성자는 이전과 같이 동작합니다. 품계의 `observed-*` 소유자는
`tls_reload::Reloading<ClientConfig>`를 넘기므로 인증서를 교체한 뒤에 재시작할 필요가
없습니다.

품계는 `hopae-grpc`를 #15 커밋(`74bb829`, #14 `feat/live-reload` 기반)에 고정합니다.
#14와 #15가 병합되면 고정을 병합된 `integrate/identity-platform` 리비전으로 옮기십시오.

**Hopae #9와 #10 병합.** 두 브랜치는 추가 목록에서만 충돌합니다. 상호 운용 검증에 쓴 로컬 해결(푸시하지
않음)은 양쪽을 모두 유지했습니다.

- `src/event/types.rs`: `EventKind`에 `AdminServiceCredential`(#10)과 `WorkloadPrincipalObserved`,
  `WorkloadPrincipalRetired`, `WorkloadLegacySubjectMapped`, `WorkloadKeysRotated`,
  `WorkloadRevocationStale`(#9)을 모두 추가하고 `EventKind::ALL`은 `[EventKind; 57]`(51 + 1 + 5)이
  됩니다. 나머지 충돌 hunk(`ALL` 항목, wire 이름, required/diagnostic 분류)는 같은 순서로 양쪽의
  합집합입니다.
- `src/telemetry/counters.rs`: `ADMIN_SERVICE_CREDENTIALS_TOTAL`과 모든 `WORKLOAD_*` 상수를 유지합니다.
- `CHANGELOG.md`, `docs/THREAT_MODEL.md`, `docs/ko/THREAT_MODEL.md`: 양쪽 항목을 모두 유지합니다
  (#9의 TM-70..TM-74, #10의 TM-75..TM-77).
- 마이그레이션은 충돌하지 않습니다(`0015_service_credentials.sql`이 유일한 0015).

## 제약

- JIT 접근 요청, 접근 검토, who-can/what-can, PPG2는 P1/P2입니다.
- 그룹 권한은 Human 주체에만 적용됩니다(projection이 `human1:` 주체를 실음).
- v2 모드의 permit 소유자는 v1 형태 카탈로그 메타데이터를 받습니다(수준을 정보 등급으로 사용,
  compartment는 아직 permit에 싣지 않음).
- 관련 그룹 256개를 넘는 projection 샤딩은 P1입니다.
- workload 그룹 권한은 P1입니다(workload 주체 자체는 아래처럼 지원).
- workload 주체는 Hopae feed에서만 알 수 있으므로(snapshot에는 없음) 품계가 저장합니다. 수명 주기
  cursor가 만료되면 새 watermark 이전 변경은 Hopae가 그 주체를 다시 보고할 때(새 Hopae 프로세스의
  다음 인증)만 복구됩니다.
