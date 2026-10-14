# 품계 네이티브 성능 검증

[English](PERFORMANCE.md) · [원시 측정](native-performance.json)

2026-10-13 소스 `25a50474fb1a87d5027c71072bf6929f1f947998`을 Rust release로 빌드해
독립 서버·Rust 부하 생성기 fixture를 검증했습니다. Ryzen 7 8745HS(8코어/16논리CPU)
한 시스템에서 별도 프로세스로 실행하며 원격 지원 리스너에 loopback PPG1/mTLS로 연결합니다.
정책은 서비스·역할·신원·IPv4 prefix·권한 각 1개와 등급 2개이며 네트워크 근거는 합성
enforce-allow입니다. 모든 응답의 요청 ID·리비전·allow를 검증합니다. 판단은 컴파일된
메모리를 읽고 SQLite를 조회/갱신하지 않습니다. 작은 hot-policy 워크로드입니다.

| 회차 | 시간(s) | 검증된 판단 | 판단/초 | 배치 p50 / p99(µs) |
| --- | --- | --- | --- | --- |
| 1 | 10.003 | 43,316,352 | 4,330,543 | 228 / 382 |
| 2 | 10.002 | 44,921,536 | 4,491,178 | 222 / 359 |
| 3 | 10.003 | 41,890,688 | 4,187,998 | 239 / 367 |

동시 worker 16개가 연결을 재사용하고 64개 배치로 회차마다 최소 10초 실행합니다.
지연은 개별 요청이 아닌 배치 단위입니다. Closed-loop 측정이므로 open-loop 도착 부하·
포화·tail 동작을 증명하지 않습니다. 바이너리 해시와 정확한 건수는 JSON에 기록합니다.

```sh
cargo build --locked --release --workspace
cargo build --locked --release -p pumgye-client --example qualify
python3 tools/server_smoke.py --binary target/release/pumgye --client target/release/examples/qualify --benchmark 1000000
```

같은 fixture에서 HTTP/네이티브 일치·신원/토큰 거부·권한 회수·CAS·감사·재시작도
검증합니다. 전체 Hangang/호패/수문장 HTTP 처리량·외부 프로바이더·복제본 lease/증감·
물리 네트워크 지연·큰 정책 규모의 증거는 아닙니다. 이 항목은 별도 통과 조건으로 남으며
네이티브 여유는 메모리·지속 연결 설계의 근거입니다.

## 단일 요청 mTLS 검증 — 2026-10-14

[원시 측정](native-single-request-performance.json)은 batch **1**, native 연결 16개로
10초씩 3회 측정합니다. 같은 8코어/16스레드 Ryzen 7 8745HS에서 서버와 Rust 생성기를
분리합니다. 작은 hot 정책은 검증 판단 138,790~142,300건/초·p99 177~182µs입니다.
사용자/IP /32 prefix 각 4096개를 순환하면(기본 적합성 사용자/prefix 하나 별도)
129,080~134,344건/초·p50 115~119µs·p99 183~195µs입니다. 여기의 batch 지연은
판단 한 건 완료 시간입니다.

```sh
cargo build --locked --release -p pumgye-client --example qualify
python3 tools/server_smoke.py --binary target/release/pumgye --client target/release/examples/qualify --benchmark 1000000 --benchmark-batch 1 --benchmark-cardinality 4096
```

생성기는 신원과 주소를 모두 바꾸고 모든 허용/correlation/revision 하한을 검사합니다.
주변 fixture는 신뢰/토큰 거절·CAS·즉시 회수·감사·재시작도 검사합니다. 서비스/역할/
권한은 하나, 등급은 둘이며 assurance/수문장 근거는 합성입니다. 이 조건에서 native
품계 10만건/초 이상의 여유를 보인 결과이며 전체 한강/호패/수문장 처리량은 아닙니다.
closed-loop·loopback·warm 정책과 도착률 overload 미주입의 한계를 명시합니다.
운영 서비스를 부하 대상으로 쓰지 않습니다.
