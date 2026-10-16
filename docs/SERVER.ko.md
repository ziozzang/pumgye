# 독립 품계 서버와 PPG1

[English](SERVER.md)

`pumgye --database /private/pumgye.sqlite3 --policy examples/policy.json`은 빈 DB를
리비전 1로 초기화합니다. 이후 시작은 DB를 복구하며 초기 파일은 무시합니다.
`PUMGYE_ADMIN_TOKEN`, `PUMGYE_DECISION_TOKEN`은 서로 다른 제한된 값으로 비공개
서비스 환경에 공급하며 명령 인자에 넣지 않습니다.

원격 배포는 `--listen 0.0.0.0:9084 --decision-listen 0.0.0.0:9085`와 함께
`--tls-cert`, `--tls-key`, `--client-ca`를 모두 설정합니다. 모든 원격 연결은 신뢰된
클라이언트 인증서를 제시해야 합니다. HTTPS는 역할별 bearer도 검증하고 PPG1은 TLS
이후 판단 자격 증명을 연결당 한 번 검증합니다. 평문 루프백은 신뢰된 로컬 프로세스 경계에만
사용할 수 있으며 원격 인증을 의미하지 않습니다.

`GET /v1/policy`는 관리자 인증이 필요합니다. `PUT /v1/policy`는 `{revision, policy}`와
`If-Match: "<revision>"`을 받고 본문 리비전도 일치해야 합니다. 조건 누락은 428,
본문 불일치는 400, 오래된 리비전은 409, 정책 오류는 422, 과부하·저장 불확실성은 503입니다.
서버가 리비전을 증가시킵니다. 승인된 게시 작업은 HTTP 취소와 독립적으로 완료됩니다.
타임아웃 후에는 롤백을 추정하지 말고 서버 상태를 다시 읽습니다. 정책·리비전·해시 감사
기록을 함께 커밋하며 저장 오류는 복구까지 상태·판단을 차단합니다.

`POST /v1/decision`은 판단 자격 증명이 필요하고 JSON을 2KiB로 제한합니다.
`service_id`, `subject`, `ip`, `permission`, `information_class`, `aal`, `guard`와 선택적
`minimum_revision`을 받습니다. Guard 값은 `enforced_allow`, `deny`, `observe`,
`unavailable`입니다. 판단 불가·리비전 미달은 503이며 응답은 리비전·allow·reason·
`ttl_ms: 0`입니다. 일반 판단은 SQLite에 쓰지 않습니다.

`GET /v1/status`는 관리자에게 상태·정책 리비전·판단 건수·결과 TTL 0을 제공합니다.
`GET /v1/audit?after_revision=N`은 리비전 순서의 감사 기록을 최대 100개 반환합니다.
HTTPS 게시 actor는 전송 계층이 검증한 클라이언트 인증서의 SHA-256 지문이며 요청
헤더로 주장한 신원을 사용하지 않습니다. 로컬 평문은 loopback actor를 기록합니다.
Hangang 관리자 개인별 위임은 추가 통합 항목입니다.

## 전송 계약

정수는 네트워크 바이트 순서입니다. TLS ALPN은 `ppg1`, early data는 비활성화합니다.
클라이언트는 `PPG1`, u16 자격 증명 길이(16–4096), 자격 증명 바이트를 보냅니다.
판단 자격 증명만 허용하며 서버는 `PPA1`을 응답하거나 연결을 닫습니다.

요청마다 u16 payload 길이(40–552)를 앞에 붙입니다.

| 위치 | 내용 |
| --- | --- |
| 0 | 버전 1 |
| 1 | IP family 4 또는 6 |
| 2 | AAL 0–3 |
| 3 | Guard: enforce allow 0, deny 1, observe 2, unavailable 3 |
| 4–11 | u64 요청 ID |
| 12–19 | u64 최소 리비전 |
| 20–35 | IPv6 또는 IPv4 뒤 12개 0 바이트 |
| 36 이후 | 서비스·신원·권한·등급: 각 u8 길이 뒤 UTF-8 바이트 |

식별자는 비어 있지 않고 128바이트 이하이며 제어 문자가 없어야 합니다. 후행·잘린 바이트,
버전·주소·근거·UTF-8 오류는 연결을 닫습니다. 응답은 32바이트로, 위치 0 버전, 1 판단 코드,
2–3 예약 0, 4–11 요청 ID, 12–19 리비전, 20–31 예약 0입니다. 코드 0–8은 allow,
서비스 없음, guest, 네트워크 guest, 권한 거부, 등급 거부, 보증 수준 거부, Guard deny,
Guard 판단 불가입니다. 255는 판단 불가·리비전 미달이며 허용할 수 없습니다. 예약 바이트는
결과 TTL 0을 포함하며 이 버전은 양수 캐시 lease를 발급하지 않습니다.

서버는 현재 불변 정책으로 요청을 평가하고 순서대로 최대 64개 준비된 응답을 묶습니다.
클라이언트는 최대 64개 요청을 묶고 ID·구조·설정 및 관측한 단조 증가 리비전 하한을 검증합니다.
취소·타임아웃·잘못된 응답은 연결을 폐기하며 익명·서명 생략·오래된 허용으로 대체하지 않습니다.
클라이언트 풀은 1–1024, 기한은 풀 대기·핸드셰이크 포함 1ms–5s입니다. 서버는 네이티브
4096 연결, HTTPS 2048 연결, HTTP 요청 4096, 관리 요청 4로 제한합니다. TLS/토큰
핸드셰이크는 3s, 네이티브 유휴 읽기 30s, frame 완료/쓰기 5s, 연결 수명 300s입니다.
클라이언트는 수명 240s/유휴 20s까지 연결을 재사용합니다.

복제본 게시, authority 재생성 식별자 고정, 자격 증명 회전/재로드, 위임 관리자 개인별 감사,
fleet 회수 lease는 추가 통합 항목입니다. 리비전 하한만으로 quorum 일관성을 보장하지 않습니다.
이 서버/클라이언트 검증은 전체 스택 100k HTTP 요청/초를 의미하지 않습니다.

네이티브 클라이언트 주소는 제한된 `host:port` Service DNS와 IPv4/IPv6 주소를
받습니다. `localhost`도 DNS이면 mTLS가 필수이며 DNS 발견은 신원 증명이
아닙니다. 기존 판단 기한 안에서 새 pooled 연결마다 조회하고 설정된 TLS
서버 이름·CA와 호출 자격을 검증합니다. 기존 연결의 폐기 기한은 유지하며
복제본 멤버십이나 원천 리비전 일관성을 구현한 것은 아닙니다.

## 네이티브 허용 결과 게시 경계 (미릴리스)

판정은 `authorize_then` 경계를 공유합니다. 실제 컴파일한 소유자 Allow에서만
비공개 후속 작업을 호출하고 거부/사용 불가에서는 호출하지 않습니다. 작업 전후
같은 활성 불변 snapshot·원천 lease/준비 상태·영속 저장 건강을 확인합니다.
교체된 snapshot의 후보 결과는 버리고 사용 불가를 반환합니다. 일반 HTTP/native/
gRPC 판정도 이 최종 경계를 사용합니다. 성공 반환 전 외부 출력이나 되돌릴 수
없는 효과를 발생시키는 callback은 허용하지 않습니다.

snapshot 교체/거부 시 발행 미호출 회귀 검사·workspace 30개 테스트·엄격한
Clippy·실제 네 서버 native/gRPC 영속 요청 체인이 통과했습니다. 후속 서명의
소유자 경계이며 권한 receipt API가 아닙니다. 네이티브 자원/catalog 매핑·
인증/네트워크 receipt 검증·서명 키 수명주기·변환 단계 재사용 방지는 아직 남아 있습니다.

## 자원 판정 HTTP API (미릴리스)

`POST /v1/resource/decision`은 decision 자격과 기존 인증 리스너 경계를
사용합니다(관리자 자격으로 질의하지 못합니다). 최대 2 KiB JSON에는 `resource`·
`action`·`subject`·`ip`·`aal`·`guard`와 선택 `minimum_revision`만 넣습니다.
서비스·권한·정보등급은 호출자가 지정하지 않으며 모르는 필드는 거부합니다.
신원/인증 수준/네트워크 근거는 신뢰한 집행 어댑터만 전달해야 합니다.

응답은 version/revision/allow/reason과 TTL 0입니다. 원천·리비전·필수 수문장
근거를 사용할 수 없으면 503, 자원/행위 부재·권한/인증 수준 부족은 거부 판정입니다.
평가 전후 활성 소유자 snapshot·원천 lease를 검사하고 판정 중 SQL을 호출하지 않습니다.

`cargo build -p pumgye-server && python3 tools/resource_catalog_smoke.py`로
실제 격리 프로세스·자격 역할 분리·정보등급 주입 거부·자원 인증 수준·CAS 회수·
재시작 후 bootstrap 미복구·정책 복구를 확인했습니다. 라우터/workspace 33개
검사와 엄격한 Clippy가 통과했습니다. 서명 없는 판정 API이며 인증 receipt 검증·
권한 발행은 아닙니다. 자원 gRPC·한강 UI/집행·서명 기반 자격 전달은 남아 있습니다.

미릴리스 자원 endpoint는 `service_id`가 필수이며 다른 서비스의 자원을 거부합니다. 서비스 범위는 신뢰한 집행 문맥에서 얻으며 애플리케이션 주장을 사용하지 않습니다.

## 관리자 설명 API (미릴리스)

`POST /v1/explain`·`POST /v1/explain/batch`·`POST /v1/explain/diff`·
`GET /v1/audit/simulations`는 관리자 자격이 필요하며(판정 자격 거부) 관리 수용 게이트를
공유합니다. 집행 평가 함수를 추적 sink로 실행해 게시 스냅샷 또는 저장하지 않는 후보를
평가하고, 등록된 `pumgye.*` 사유 코드와 en/ko 메시지 키가 있는 순서형 단계 추적을
반환하며, 모든 호출을 읽기 전용 `simulation`으로 감사합니다. [설명 API 계약](EXPLAIN.ko.md)을
참조하세요.

## 정책 모델 버전 2 (미릴리스)

`/v2/policy`, `/v2/status`, `/v2/explain*`, `/v2/candidates/diff`, `/v2/migration/preview`,
`/v2/shadow*`, `/v2/cutover`, `/v2/rollback`, `/v2/model/history`는 관리자 자격이 필요합니다.
버전 1·2 게시는 하나의 리비전 순서와 하나의 감사(`document: v1|v2`)를 공유하므로 v1
`PUT /v1/policy`도 다음 전역 리비전을 발급합니다. 승인된 컷오버 전까지 판정은 v1이 합니다.
[MODEL_V2.ko.md](MODEL_V2.ko.md)를 참조하세요.

## TLS 인증서 교체 (미릴리스)

품계는 재시작하지 않고 mTLS 인증서를 다시 읽으므로 cert-manager 갱신을 그대로
따라갑니다. `--tls-reload-interval-secs`초마다(기본 10초, 범위 1–3600) 각 TLS
사용처의 인증서·키·CA 파일을 읽어 내용의 SHA-256 다이제스트를 비교합니다.
호스트의 inotify 감시 개수가 부족하므로 inotify는 쓰지 않습니다. 내용이 바뀌면
새 rustls 설정을 만들어 원자적으로 교체합니다.

다시 읽는 대상:

- 리스너: HTTP(`http listener`), PPG1(`ppg1 listener`), gRPC(`grpc listener`),
  SAR(`sar listener`). 새 핸드셰이크부터 새 인증서와 CA를 씁니다. 이미 맺은
  연결은 닫힐 때까지 수락 당시 설정을 그대로 씁니다. gRPC TLS를 교체할 수 있도록
  tonic이 아니라 품계의 acceptor가 종료합니다.
- 외부로 나가는 mTLS 클라이언트:
  - 수문장/호패 live 클라이언트: `route_live`, `projection_live`,
    `network_live`, `authentication_live`. 재적재되는 tonic 커넥터를 쓰므로 새
    HTTP/2 연결은 현재 클라이언트 인증서와 CA를 쓰고, 기존 채널은 연결을
    유지합니다.
  - 호패 소유자 클라이언트(`hopae_owner client`). 새 인증서로 HTTP 클라이언트를
    다시 만듭니다.

새 인증서가 유효하지 않으면(PEM 파싱 실패, 인증서와 맞지 않는 키) 이전 설정을 계속
씁니다. 이때 해당 리스너나 클라이언트는 `failing: true`와 `last_error`를 보고하고,
`GET /v1/status`의 `tls_reload_failing`이 `true`가 됩니다. 이 필드에 경보를 거십시오.
거부한 파일 내용은 한 번만 로그에 남기고, 파일이 다시 바뀔 때까지 재시도하지
않습니다. 지금 쓰는 인증서로 되돌려도 경보가 풀립니다. 원자적이지 않은 쓰기
도중처럼 파일을 잠시 읽을 수 없으면 계속 서비스하고 다음 폴링에서 다시
확인합니다.

`GET /v1/status`의 `tls`는 리스너와 클라이언트마다 항목 하나씩을 담은 목록입니다.
각 항목에는 `name`, `leaf.serial`(16진수), `leaf.sha256`(DER 지문), `loaded_at`,
`reloads`, `failures`, `failing`, `last_error`가 있습니다. 변경이 있을 때마다 stderr에
JSON 한 줄을 남깁니다.

```json
{"event":"tls_reloaded","name":"grpc listener","serial":"1002","sha256":"…"}
{"event":"tls_reload_refused","name":"grpc listener","error":"…","serving_serial":"1001"}
```

Kubernetes API 소스(`--kubernetes-ca`, `--kubernetes-token`)는 relist할 때마다 CA와
토큰 파일을 다시 읽으므로 폴러를 쓰지 않습니다. 두 파일 중 하나라도 내용이
바뀌면 HTTP 클라이언트를 새로 만들고 이전 신뢰 풀은 더 쓰지 않습니다. 서버
인증서와 맞지 않는 CA는 닫힌 쪽으로 실패합니다. 소스 관측이 만료되고, 유효한
인증서로 다음 relist를 하면 회복합니다. 이런 변경 횟수는
`pumgye_kubernetes_credential_reloads_total` 메트릭으로 셉니다.

`observed-*` 소유자(관측 인증, workload, Human)도 다시 읽습니다
(`authentication_observed client`, `workload_observed client`,
`human_observed client`). 이 소유자들은 호패 SDK에 재적재되는 TLS 소스
(`hopae-grpc`의 `ReloadableEndpointConfig`)를 넘기고, SDK는 새 연결을 만들 때마다 현재
클라이언트 설정을 읽습니다.

`hopae-grpc` 의존성은 ziozzang/hopae#15(`feat/grpc-reloadable-tls`, `74bb829`) 커밋에
고정되어 있습니다. #14와 #15가 병합되면 이 고정을 병합된 `integrate/identity-platform`
리비전으로 옮겨야 합니다.

제약: 새 인증서가 반영되기까지 최대 폴링 주기 한 번만큼 걸립니다.

## Prometheus 메트릭 (미릴리스)

`GET /metrics`는 Prometheus 텍스트 형식(`text/plain; version=0.0.4`)으로 응답합니다.
주 HTTPS 관리 리스너에 있으므로 스크레이프하려면 리스너의 mTLS 클라이언트
인증서와 bearer 자격 증명이 필요합니다.

- 관리자 자격 증명, 또는
- 읽기 전용 스크레이프 전용 자격 증명. `--metrics-token-env`(기본
  `PUMGYE_METRICS_TOKEN`)가 가리키는 환경 변수에서 읽습니다. 16–4096자의 보이는
  ASCII 문자여야 하고 관리자·판정 자격 증명과 달라야 합니다. 이 자격 증명으로는
  `/metrics`만 열 수 있습니다.

평문 readiness 리스너는 메트릭을 제공하지 않습니다. Prometheus Operator
`ServiceMonitor` 엔드포인트 예시는 다음과 같습니다.

```yaml
endpoints:
  - port: management   # 9084, HTTPS 관리 리스너
    scheme: https
    path: /metrics
    bearerTokenSecret: {name: pumgye-metrics, key: token}
    tlsConfig:
      ca: {secret: {name: pumgye-tls, key: ca.crt}}
      cert: {secret: {name: pumgye-scrape-client, key: tls.crt}}
      keySecret: {name: pumgye-scrape-client, key: tls.key}
      serverName: pumgye.pumgye.svc
```

판정 경로에서의 기록은 relaxed 원자 증가 몇 번뿐입니다. 메모리를 할당하지 않고
(`tests/metrics_no_alloc.rs`) 잠금도 쓰지 않습니다. 주체, IP 주소, 서비스, 자원을
담는 레이블이 없으므로 시계열 개수가 고정됩니다. 예외는 TLS `name` 레이블 하나이며,
그 값은 정해진 리스너·클라이언트 이름입니다.

| 메트릭 | 형식 | 레이블 |
| --- | --- | --- |
| `pumgye_decisions_total` | counter | `context`(`permission`, `resource`, `workload_resource`, `human_resource`), `outcome`(`allow`, `deny`, `unavailable`), `reason`(판정 사유 코드, `unknown_resource`, `unknown_action`, `unavailable`) |
| `pumgye_request_duration_seconds` | histogram | `transport`(`http`, `ppg1`, `grpc`, `sar`) |
| `pumgye_policy_revision` | gauge | `model`(`v1`, `v2`) |
| `pumgye_policy_v2_authoritative`, `pumgye_available` | gauge | — |
| `pumgye_policy_publications_total` | counter | `model`, `outcome`(`applied`, `conflict` = If-Match CAS 충돌, `rejected`) |
| `pumgye_shadow_decisions_total`, `pumgye_shadow_reason_drift_total` | counter | — |
| `pumgye_shadow_mismatches_total` | counter | `explained`(`true`, `false`) |
| `pumgye_shadow_window_start_timestamp_seconds` | gauge | — |
| `pumgye_hopae_last_success_timestamp_seconds`, `pumgye_hopae_staleness_seconds` | gauge | `feed`(`projection`, `lifecycle`). 첫 동기화 전 staleness는 `-1` |
| `pumgye_hopae_sync_failures_total`, `pumgye_hopae_cursor_expired_total` | counter | `feed` |
| `pumgye_simulation_audit_rows` | gauge | —(보존된 행 수) |
| `pumgye_simulation_audit_rows_appended_total` | counter | — |
| `pumgye_observed_permits_total` | counter | `kind`(`service`, `workload`, `human`), `outcome`(`issued`, `permission_denied`, `unavailable`, `invalid_argument`, `unauthenticated`, `other`) |
| `pumgye_tls_reloads_total`, `pumgye_tls_reload_failures_total` | counter | `name` |
| `pumgye_tls_reload_failing` | gauge | `name` |
| `pumgye_tls_leaf_expiry_seconds` | gauge | `name`(`notAfter`까지 남은 초. 만료되면 음수) |
| `pumgye_kubernetes_credential_reloads_total` | counter | — |

권장 경보:

- `pumgye_tls_reload_failing == 1`
- `pumgye_tls_leaf_expiry_seconds < 7 * 86400`
- `pumgye_hopae_staleness_seconds`가 projection의 `max_staleness_secs`보다 클 때
- `pumgye_shadow_mismatches_total{explained="false"}`가 늘어날 때
- `pumgye_available == 0`
