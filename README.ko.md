# Pumgye (품계)

[English](README.md)

품계는 서비스별 역할·권한·정보등급·사용자/IP 매트릭스와 결정적 권한 판단을 담당합니다.
호패는 검증된 신원·세션을, 수문장은 네트워크 근거를 소유하고 Hangang이 결과를 집행합니다.

네 패키지를 분리합니다.

- `pumgye-core`: 제한된 정책 컴파일·판단. HTTP·TLS·비동기 런타임·DB 의존성이 없습니다.
- `pumgye-server`: 독립 `pumgye` 서버, SQLite 저장·트랜잭션 감사·HTTP/PPG1 리스너.
- `pumgye-protocol`: 크기가 제한된 PPG1 코덱, 문자열을 복사하지 않는 요청 해석과 고정 응답.
- `pumgye-client`: 인증된 지속 연결, 제한된 풀·기한·배치, 요청 상관 검증과 단조 증가 리비전 하한.

네이티브 모드의 정책 원본은 SQLite입니다. 시작 시 커밋된 정책을 복구·컴파일하고, CAS 게시 시 정책·
리비전·감사를 한 트랜잭션으로 저장한 뒤 불변 `ArcSwap` 메모리 스냅샷을 교체합니다.
일반 판단은 DB를 읽지 않습니다. 정책 스냅샷은 다음 게시까지 유지하며 1–5초짜리 판단
결과 캐시와 다릅니다. 현재 판단 결과 TTL은 0입니다. HTTP 요청 취소가 승인된 게시의
완료를 중단하지 않습니다. 저장 결과가 불확실하면 복구/재시작 전까지 판단을 차단합니다.
DB마다 런타임 소유자는 하나이며, SQLite 직접 수정 대신 품계 API로 정책을 변경합니다.

권한·정보등급 비트셋과 수문장의 압축 prefix trie를 사용합니다. 사용자와 네트워크 권한이
모두 요청을 허용해야 합니다. 미할당 신원은 guest이고 네트워크 deny가 우선합니다.
필수 집행은 observe/판단 불가 근거를 거부합니다. 호출자는 인증된 신원·신뢰된 출발 IP·
검증된 근거를 제공해야 하며, 전송된 enum만으로 사실이 검증되지는 않습니다.

원격 리스너는 명시적으로 공급한 클라이언트 CA의 mTLS와 별도 관리자/판단 자격 증명을
필수로 적용합니다. 평문은 루프백에서만 허용합니다. 네이티브 클라이언트는 고정 endpoint·
서버 이름·CA를 검증하고 클라이언트 인증서를 제시합니다. [서버 계약](docs/SERVER.ko.md)을 참조하세요.

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --release --workspace
cargo build --locked --release -p pumgye-client --example qualify
python3 tools/server_smoke.py --binary target/release/pumgye --client target/release/examples/qualify
```

독립 프로세스 fixture는 mTLS 거부, 역할별 자격 증명, HTTP/네이티브 일치, 지속 파이프라인,
리비전 하한, CAS 경쟁, 게시 후 권한 회수, 감사, DB 소유권과 재시작 복구를 검증합니다.
`--benchmark 1000000`을 추가하면 합성 네이티브 전송을 측정합니다. 이 결과는 전체
Hangang/호패/수문장 HTTP 처리량이나 복제본 검증을 의미하지 않습니다.

이전 내장 게이트웨이·매트릭스 구현은 [Hangang #5](https://github.com/ziozzang/hangang/pull/5)에서
검증했습니다. 독립 Hangang 클라이언트·관리 위임 연결, 복제본 lease·회수, 사람/기계 혼합 인증은
계속 구현해야 합니다. 패키지 존재만으로 전체 제로트러스트 완성을 의미하지 않습니다.

이전 게이트웨이 기준 구현 검증은
`python3 tools/hangang_smoke.py --gateway-binary /path/to/hangang`으로 수행합니다.

[네이티브 측정](docs/PERFORMANCE.ko.md)에 mTLS 10초 측정 3회의 범위·제약을 기록했습니다.

[Kubernetes 원천 연결기](docs/KUBERNETES.ko.md): 제한된 검사·HTTPS polling·명시적 매핑·단일 작성자 원천 권위 판단을 구현하고 소유 실제 API에서 검증했습니다. 확장형 watch와 검증된 신원 자동 연관은 후속 단계입니다.

[추가 gRPC 판정](docs/GRPC.ko.md)은 같은 코어·스냅샷을 사용합니다. 선택적 mTLS 리스너를 로컬 검증했으며 운영/Kubernetes 및 모듈 간 통합은 남았습니다. workspace 빌드에 `protoc`가 필요합니다.

네이티브·관리 TCP 리스너는 고정한 hangang-runtime 0.1.2의 연결 제한과 태스크
소유권을 사용합니다(네이티브 4,096개, 관리 2,048개). 리스너 소유 태스크가
취소되면 연결도 취소하며 분리된 태스크로 남기지 않습니다. PPG1, TLS/ALPN,
인증서 감사 신원과 메모리 권한 판정은 품계가 소유합니다. OS 종료 신호의
새 드레인 처리나 감독 실행 리스너 인계까지 구현했다는 의미는 아닙니다.

Linux 릴리즈 준비 기본은 정적 amd64 musl입니다. tools/prepare_release.py에
--output·--signer·--seed를 지정하면 바이너리·문서 아카이브·고정 공개키·서명
manifest·체크섬을 준비합니다. 비공개 seed는 저장소 밖에 보존합니다. ELF·버전·
서명 신원을 검사하고 OpenSSL로 실제 Ed25519 서명을 독립 검증하며 payload를
정확한 자산에 묶습니다. 릴리즈 키는 다른 한강 월드 원천과 독립적입니다.
검증 가능한 설치 자산이며 런타임 자동 업데이트 구현을 의미하지 않습니다.

## 정상 종료 (미릴리스)

서버는 SIGTERM·SIGINT를 처리하고 새 연결 수락을 중단하며 네이티브·HTTP 연결
작업을 최대 5초 동안 정리합니다. gRPC에도 정상 종료를 전달하고 전체 종료는
6초로 제한합니다. 다음 시작에서도 영속 정책을 사용합니다. 격리 프로세스 검증은
`cargo build -p pumgye-server` 후 `python3 tools/shutdown_smoke.py`로 실행합니다.
이 검사는 실제 SIGTERM·정상 종료·유휴 네이티브 소켓 닫힘을 확인하며 진행 중인
gRPC 스트림 완료나 운영·K8s 반영까지 검증하지는 않습니다.

v0.1.1 후보는 workspace 테스트·엄격한 Clippy·정적 ELF·실제 SIGTERM 및
영속 재시작을 포함한 실제 네 프로세스 native/gRPC 요청 체인을 통과했습니다.
후보 서명·공개·운영 반영을 마치기 전까지 공개 v0.1.0이 운영 릴리즈입니다.

품계 [v0.1.1](https://github.com/ziozzang/pumgye/releases/tag/v0.1.1)을
da45832에서 Linux amd64 musl 서명 자산 5개로 공개했습니다. 내부 운영 반영은
격리 DB 복사본·영속 정책 완전 보존·실제 mTLS 관리/native 거부·서명 바이너리
digest·두 번째 서비스 재시작을 통과했습니다. 비공개 복구 백업을 보존합니다.
이 버전의 K8s 반영과 진행 중인 gRPC 완료는 아직 검증하지 않았습니다.

이후 원격 K8s에서 v0.1.1의 네 모듈 기능 검사와 실제 관리자 브라우저 흐름이
통과했습니다. 판정 Pod 교체·즉시/영속 권한 및 인증 회수·오래된 관리자 CAS
거부·거부 시 backend 미전달·네트워크 판정 서버 장애 거부를 확인하고 전용
네임스페이스를 정리했습니다. 검사한 gRPC 배포의 근거이며 모든 K8s 전송·
진행 중인 gRPC 종료·권한 webhook·분산 snapshot 복제의 검증은 아닙니다.
