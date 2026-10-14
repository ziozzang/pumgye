# 추가 gRPC 판정 전송

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
