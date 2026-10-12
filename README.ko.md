# 품계 (Pumgye)

Hangang의 결정적 서비스 권한 관리자다. 호패가 신원과 세션을, 수문장이 네트워크
근거를 소유하고 품계는 서비스별 역할·권한·정보등급을 관리한다.

불변 비트셋과 수문장의 압축 IP 트라이를 사용한다. 사용자와 네트워크 모두의
권한을 만족해야 한다. 미배정 사용자는 guest다. 네트워크 차단이 우선하며,
필수 집행 설정에서 observe 또는 근거 불가는 거부한다.

게이트웨이 집행·설정 CAS 게시·관리자 매트릭스는
[Hangang에 통합되었습니다](https://github.com/ziozzang/hangang/pull/5).
격리된 HOP1/HGD1 근거와 배포된 Linux 바이너리를 검증했습니다.
종단간 HTTP 10만 QPS를 입증했다고 주장하지 않습니다. 호출자는 검증된 신원·전송 IP·수문장 근거를 전달해야 한다.
이 라이브러리의 enum 자체가 상대 서버를 인증하는 것은 아니다.

`cargo test`, `cargo clippy --all-targets -- -D warnings`로 검증한다.

`python3 tools/hangang_smoke.py --gateway-binary /path/to/hangang`으로 실제 격리 프로세스의 guest/observe/차단 거부·CAS 게시·스트림 철회를 검증합니다. 운영 자격 증명은 사용하지 않습니다.
