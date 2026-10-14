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
