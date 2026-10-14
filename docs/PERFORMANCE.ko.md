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

## 실제 네 모듈 HTTPS 체인 — 2026-10-14

[원시 측정·해시](native-chain-performance.json)는 실제 한강·호패·품계·수문장 프로세스
결과입니다. 호패 native API key·수문장 enforce·품계 신원/네트워크/권한·한강 HTTPS와
지속 mTLS HOP1/PPG1/HGD1을 사용합니다. Go origin이 canonical service 신원/AAL/
service·Authorization 미전달을 검사하고 모든 성공 응답은 200·정확한 ok 본문입니다.

같은 Ryzen 7 8745HS에서 10초씩 3회 closed-loop 결과입니다.

| Workers | 검증 응답/초 | p50 (µs) | p99 (µs) | 실패 |
| --- | --- | --- | --- | --- |
| 16 | 11,081~11,657 | 1,339~1,422 | 2,041~2,091 | 0 |
| 32 | 10,365~10,914 | 2,890~3,024 | 4,238~5,642 | 0 |

Python origin 예비 3초 측정은 7,791~8,214/s이고 같은 검증을 하는 Go origin으로
fixture 비용 일부를 줄였습니다. 동시성을 늘려도 이 조건의 처리량은 증가하지
않았습니다. 제어된 조건의 1만/s 하한 검증이며 전체 10만/s는 달성하지 못했습니다.
품계 단독 결과로 대체하지 않습니다. 서비스/키/역할 하나·warm 고정 정책·작은 응답·
loopback이며 외부 공급자/TokenReview 비용은 없습니다. open-loop 포화·거절 mix·
장기 갱신 부하·대형 앱 정책·물리/fleet 네트워크는 별도입니다. 운영 부하는 없습니다.

```sh
go build -o /tmp/owned-https-chain-load tools/https_chain_load.go
python3 tools/native_chain_benchmark.py --pumgye /path/to/pumgye --gateway /path/to/hangang --hopae /path/to/hopae --sumunjang /path/to/sumunjang --generator /tmp/owned-https-chain-load --fast-origin --seconds 10 --workers 16
```

부하 전 미인증/잘못된 자격·observe·IP 차단도 거절합니다. 인증 프로토콜 대역이
없고 별도 상태/키/프로세스를 정리합니다. 실패/status를 숨기거나 성공 처리량으로
계산하지 않습니다.
