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
