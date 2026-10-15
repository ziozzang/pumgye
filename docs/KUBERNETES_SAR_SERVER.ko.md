# 선택적 인증 SAR persistent listener

새 `--kubernetes-authorization-config <file>`은 기본-off이며 기존 Authority/Policy/CompiledPolicy/View와 grants를 그대로 사용한다. Kubernetes API assertion을 Hop Human/Service/Workload 증명으로 승격하거나 receipt를 만들지 않는다. 기존 management/native/gRPC listener, network/guard 기본 의미는 바꾸지 않는다. 명시적 kubernetes_api 문맥, 고정AAL0만 사용하며 가짜 IP/Sum은 없다.

JSON은 version1/listen/고정cluster/정확한HTTPauthority/certificate·key·client_ca 파일참조/client_sha256(leaf DER SHA256 소문자64hex1~16개)/caller_token_env만 허용한다. Config64KiB/TLS1MiB/token32~4096 graphic bytes 제한, 기존 admin/decision credential과 구분한다. mTLS CA 검증만으로 신뢰하지 않고 정확한 leaf와 요청별 단일 Bearer를 모두 검사한다. 요청 필드가 cluster를 고르지 못한다. `--check-kubernetes-authorization`는 config/TLS/credential/BOOTTIME를 검사하고 DB/listener를 열지 않는다. Linux BOOTTIME가 없으면 opt-in만 거부하며 fallback은 없다. TLS tickets/session storage/early data는 끄지만 연결 자체는 재사용한다. 변경은 감독된 listener 재시작으로 기존 generation을 철회한다.

단일 task의 strict HTTP1.1 순차 keepalive다. ALPN http/1.1 또는 ALPN 없음만 허용하며 H2/h2c/upgrade는 거부한다. 연결128/활성요청128/idle30초/연결300초/연결당4096요청, drain5초 뒤 runtime소유 task를 취소한다. 종료/오류/serve취소 모두 generation을 철회한다. 요청은 정확한 POST 경로·Host,16KiB/64headers, 단일 canonical Content-Length1~32768과 application/json을 요구한다. TE/chunked/Expect/trailer/upgrade/중복 auth·framing/모호한 길이/Connection nomination은 거부·close한다. Body 전에 caller/admission을 검사한다. JSON 잘못된 envelope/중복은400, 유효 envelope의 미지원/unknown/철회/native deny는200 deniedtrue이며 no-opinion이 아니다. API-server failurePolicyDeny가 필수다.

원래1초 BOOTTIME budget은 첫 byte를 성공적으로 받는 poll 직전에 시작하며 이후 await/auth/body/decoder/evaluation/serialization/write로 옮겨도 갱신하지 않는다. Pending은 입장·Arc할당을 만들지 않고 idle은 별도 원래 budget이다. Clock failure/reversal/expiry는 비가역 거부한다. source-owned policy는 원래 source_lifetime을 검사하며 socket 재사용·sampling으로 연장하지 않는다. 동일 Arc<View>의 매핑/grants만 평가하고 같은 revision의 snapshot 교체도 철회한다.

raw TCP 아래 guard가 TLS의 scalar/vectored write·flush·shutdown과 read 오류 alert까지 검사한다. 모든 시간 의존성 뒤 listener-active를 다시 읽는다. 같은 owner로 전체 write_all+TLSflush+대기 출력 없음+최종 current를 확인한 다음에만 다음 요청 owner로 바꾼다. Pending/실패/cancel 뒤 옛 Allow ciphertext를 새 owner로 내보내지 않는다. detached Hyper writer가 없으며 실패 연결은 재사용하지 않는다. 보호 buffer zeroize는 TLS/parser/kernel 전체 복사본 소거를 뜻하지 않는다.

검증 범위는 매 poll send-boundary 관측이며 분산 원자적 철회·원격 수신/ACK·이미 kernel에 수락된 bytes/완료 작업의 회수 보장이 아니다. 실제 로컬 mTLS 같은 연결 Allow/Deny/Allow, native CAS publication, body 없는 caller 거부, 실제 binary main/CLI/종료, Pending TLS flush 중 교체·shutdown·cancel·queued next request의 추가 전송0을 검증한다. 실제 Kubernetes API-server/고속처리 완료 주장은 아니다. Bytewise header 읽기는 명시적 최적화 후속이다.

운영 전 별도 승인된 전용 API-server에서 v1 envelope/실제 H1재사용/cacheAuthorizedRequests:false/cacheUnauthorizedRequests:false/failurePolicyDeny/authorizer순서/system:masters 제외/철회·장애·재시작·credential rotation을 검증해야 한다. 현재 main K3s authorizer를 바꾸지 않는다. Root core pin 및 context-aware Pum UI가 전체 policy/API metadata를 보존하고 부적절한 network/Workload 편집을 막아야 하며 현재 Kubernetes 관리화면 완료를 주장하지 않는다. 기존 transport pooling은 그대로이며 H2 owner분리/처리량은 후속이다.


## 실제 client-go advisory timeout 호환

실제 Kubernetes98e9 NewGenericWebhook 클라이언트의 로컬 httptest POST에서
`/v1/kubernetes/subjectaccessreviews?timeout=3s`를 관측했다. 이전 query 없는 경로만
허용한 frozen5817 정적 binary는 실제 검증 mTLS에서404를 반환했다. 이제 정확한
기존 경로에 query 없음 또는 단일 timeout만 허용한다. 양수 canonical Go Duration
URI이며 최대30s: ns1..999, `%C2%B5s` micro1..999(소수3자리), ms1..999(소수6자리),
s1..30(소수9자리)만 허용한다. 소수 끝0/선행0/영음수/overflow/추가·중복·미지원query/
경로percent/다른escape/fragment는 거부한다. 이 값은 advisory로 버리며 원래1초
BOOTTIME 예산이나 원천 수명을 절대 연장·재구성하지 않는다.

fixtures의 Go probe는 실제 POST 캡처 및 실제 REST URL 생성 증거를 재현한다.
subsecond URL 생성은 짧은 네트워크 deadline 성공 증거가 아니다. 실제 mTLS 같은
연결 Allow/Deny/Allow와 child CLI에 캡처한3s target을 적용했다. 실제 API-server/
K3s는 새 source/static으로 재검증해야 하며 이전 후보의 결과를 상속하지 않는다.
