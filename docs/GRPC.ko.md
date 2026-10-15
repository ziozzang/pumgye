# 추가 gRPC 판정 전송

서비스 네 종류는 공용 unary ingress 바깥에서 최초 호출자 메타데이터를
인증하며 생성된 protobuf 디코딩보다 먼저 실행합니다. Bearer는 최초 헤더에
있어야 합니다. 핸들러 검사와 생성된 Prost 메시지 제한을 유지합니다.

모든 서비스와 연결은 핸들러 4096개 슬롯과 별도로 ingress 64개 슬롯을
공유합니다. 소진 시 본문을 poll하지 않고 즉시 거부합니다. 슬롯은 디코딩과
핸들러 future 전체를 포함하며 완료·오류·취소 때 반환됩니다. 비압축 unary
메시지 한 프레임만 허용하고 실제 DATA를 메서드 payload 제한+5바이트로
제한합니다. payload는 기존 2048/2048/4096/8192바이트이며 응답 제한도 유지합니다.

용량 계획은 요청당 64 KiB를 추산합니다. 최대 8 KiB payload의 약 8배를
소유 문자열/바이트 버퍼·scalar/message 저장·할당 여유에 배정합니다. 스키마에
반복 메시지 컬렉션은 없습니다. 64개 슬롯의 계획 예산은 4 MiB이며 HTTP/2
버퍼·응답·백엔드 작업·기타 프로세스 메모리는 별도입니다. 실측 할당 상한이나
처리량 검증이 아니며 느린 백엔드도 슬롯을 점유합니다. 핸들러는 ingress
세마포어를 다시 획득하지 않습니다.

[English](GRPC.md)

상태: 품계 서비스 매트릭스 판정을 구현하고 로컬 실제 프로세스로 검증했습니다.
운영 배포나 네 모듈 Kubernetes 통합 검증은 아직 아닙니다. 범용 자원 메타데이터·
집행 의무 및 호패·수문장·한강 gRPC 연동은 남았습니다. 순수 코어와 PPG1은 유지합니다.

`pumgye-grpc`는 버전별 protobuf 계약과 Rust client/server를 제공합니다. 빌드에는
`protoc`가 필요합니다. 선택적 `--grpc-listen`은 loopback에서도 기존 `--tls-cert`,
`--tls-key`, `--client-ca`를 요구하며 클라이언트 인증서가 필수입니다. 신뢰 호출자는
별도 판단 자격을 authorization Bearer metadata로 보내야 합니다. 관리자 자격은
이 API에 사용할 수 없습니다. 신뢰된 집행 호출자만 신원·IP 근거를 전달하며,
사용자가 주장한 subject·guard 결과 자체를 인증하는 API가 아닙니다.

`hangang.pumgye.v1.Authorization/Decide`는 동일한 메모리 Authority를 호출합니다.
request ID·최소 revision·4/16바이트 IP·AAL 0–3·guard와 제한된 비어 있지 않은
식별자의 네이티브 의미를 유지합니다. 미지정 guard는 거부합니다. allow·deny·
unavailable를 구별하고 미지정 verdict를 권한으로 취급하지 않습니다. native_reason은
PPG1과 같으며 cache_ttl_ms는 0입니다. 판단을 캐시하거나 전송 오류를 허용으로
취급하지 않습니다.

연결 2048개, 연결별 stream/동시성 64개, 공유 요청 슬롯 4096개, metadata header
8192바이트, 디코딩 메시지 2048바이트, 응답 1024바이트, TLS handshake 3초와
서버 요청 1초를 제한합니다. 압축은 활성화하지 않습니다. 요청 경로에 DB 조회·
JSON 변환·별도 정책 엔진을 추가하지 않습니다. 관리·정책 쓰기는 기존 인증된
관리 인터페이스에 유지합니다.

검증은 생성된 Python grpcio stub으로 소유한 실제 프로세스를 호출합니다.

```sh
python3 -m venv /tmp/pumgye-grpc-env
/tmp/pumgye-grpc-env/bin/pip install grpcio grpcio-tools
cargo build --locked -p pumgye-server
cargo build --locked --release -p pumgye-client --example qualify
/tmp/pumgye-grpc-env/bin/python tools/server_smoke.py \
  --binary target/debug/pumgye --client target/release/examples/qualify --grpc
```

임시 CA·서버·클라이언트 신원과 합성 자격으로 의미 일치·즉시 정책 회수·역할
분리·잘못된 CA/이름·클라이언트 인증서 부재·잘못되거나 큰 입력·최소 revision
사용 불가를 검증합니다. unit 검사에는 중복 metadata·용량·원천 만료가 포함됩니다.
부하 수치·Kubernetes 역방향 webhook·PostgreSQL 어댑터를 입증하는 검사는 아닙니다.
gRPC를 활성화하지 않아도 기존 네이티브 전송을 사용할 수 있습니다.

## ResourceAuthorization 서비스 (미릴리스)

같은 필수 mTLS 리스너에 기존 `Authorization/Decide`와 별도로
`ResourceAuthorization/Decide`를 등록합니다. 입력은 요청 ID·최소 소유자
리비전·검증된 IP/AAL/수문장 근거·자원/행위·신원이며 서비스/권한/등급을
덮어쓰는 필드는 없습니다. IP는 정확히 4/16 bytes·인증 수준은 0..3·범위
식별자는 제한되며 양 서비스는 decision 역할 인증·전체 처리 용량을 공유합니다.

자원 RPC·HTTP는 동일한 네이티브 불변 소유자 판정/신선도 경계를 사용합니다.
제한된 응답은 요청 ID·소유자 리비전·Allow/Deny/Unavailable·사유·TTL 0을
포함합니다. 핸들러에서 등급·인증 수준·역할/용량 분리·IP 누락·오래된 리비전/
observe 거부를 확인하고 workspace 36개 검사·엄격한 Clippy가 통과했습니다.
소유한 실제 mTLS 소켓으로 허용·관리자 자격 거부·클라이언트 인증서 부재 거부와
같은 연결에서 카탈로그 인증 수준/리비전 변경을 검증했습니다. 이 변경은
인메모리 게시이며 DB 영속성은 별도의 HTTP 카탈로그 smoke 검사로 확인합니다.
한강 집행/UI 연결은 남아 있으며 서명 permit 또는 검증된 인증 receipt가 되는
것은 아닙니다.

자원 요청은 신뢰한 게이트웨이 라우트/인증 문맥의 `service_id`가 필수입니다. 신원이 다른 서비스의 권한을 갖고 있어도 자원 소속 서비스가 다르면 거부합니다. 누락/빈 범위는 잘못된 요청입니다. 미릴리스 계약이므로 소비자 재빌드가 필요하며 기존 Authorization은 유지합니다.

## 네이티브 자원 서명 경계 (미릴리스)

자원 HTTP/gRPC 판정은 `resource_authorize_then`을 공유합니다. 실제 범위 소유자의
Allow만 비공개 콜백을 호출하고 불변 소유자 자원 메타데이터와 리비전을 전달합니다.
콜백 뒤에도 같은 스냅샷·준비/원천 lease·건강 상태가 현재여야 하며 회수된 결과는
폐기합니다. 콜백은 성공 전까지 후보 서명을 비공개로 유지하고 되돌릴 수 없는
외부 효과를 피해야 합니다. 낮거나 잘못된 인증 수준·다른 서비스/행위·최소 리비전·
후보 생성 중 같은 리비전 스냅샷 교체와 건강 상태 회수를 검사합니다. 품계 서명
경계의 준비이며 호패 receipt 검증과 서명 permit 발급은 아직 없습니다. 자원
HTTP의 네이티브 서비스 문법도 gRPC와 같은 기준으로 검증합니다.


[네이티브 observed permit](OBSERVED_PERMITS.ko.md)에서 opt-in BOOTTIME permit RPC를 설명한다.
