# Native Pumgye qualification

[한국어](PERFORMANCE.ko.md) · [Raw measurements](native-performance.json)

On 2026-10-13, source `25a50474fb1a87d5027c71072bf6929f1f947998` was built in
Rust release mode and qualified with the owned server/client fixture. Server and
Rust load generator were separate processes on one Ryzen 7 8745HS (8 cores,
16 logical CPUs), using authenticated PPG1/mTLS over loopback with remote-capable
listeners. The fixture has one service, role, subject, IPv4 prefix and permission,
two information classes and synthetic enforce-allow network evidence. Every reply's
correlation, revision and allow result is checked. Decisions use the compiled memory
view; they do not read/write SQLite. This is a small hot-policy workload.

| Trial | Duration (s) | Verified decisions | Decisions/s | Batch p50 / p99 (µs) |
| --- | --- | --- | --- | --- |
| 1 | 10.003 | 43,316,352 | 4,330,543 | 228 / 382 |
| 2 | 10.002 | 44,921,536 | 4,491,178 | 222 / 359 |
| 3 | 10.003 | 41,890,688 | 4,187,998 | 239 / 367 |

Sixteen concurrent workers reuse connections and send batches of 64 for at least
10 seconds per trial. Latency is per batch, not per individual request. These are
closed-loop measurements and do not demonstrate open-loop arrival/saturation/tail
behavior. Binary hashes and exact counters are recorded in the JSON report.

```sh
cargo build --locked --release --workspace
cargo build --locked --release -p pumgye-client --example qualify
python3 tools/server_smoke.py --binary target/release/pumgye --client target/release/examples/qualify --benchmark 1000000
```

The same fixture also verifies HTTP/native parity, trust/token rejection, policy
revocation, CAS, audit and restart. It does not qualify Hangang/Hopae/Sumunjang
end-to-end HTTP throughput, external providers, replica leases/churn, physical
network latency or large-cardinality policies. Those remain separate acceptance
work; native headroom is evidence for the memory/connection design only.

## Single-request mTLS qualification — 2026-10-14

[Raw measurements](native-single-request-performance.json) record three ten-second
trials with batch size **one** and 16 persistent native connections. The same
8-core/16-thread Ryzen 7 8745HS runs separate server and Rust generator processes.
The small hot policy reaches 138,790–142,300 verified decisions/s with p99
177–182 µs. With 4096 varying users and IPv4 /32 prefixes (plus one base conformance
user/prefix), round-robin lookups reach 129,080–134,344 decisions/s, p50 115–119 µs
and p99 183–195 µs. Batch latency here measures one completed decision.

```sh
cargo build --locked --release -p pumgye-client --example qualify
python3 tools/server_smoke.py --binary target/release/pumgye --client target/release/examples/qualify --benchmark 1000000 --benchmark-batch 1 --benchmark-cardinality 4096
```

The cardinality generator varies both subjects and addresses, and checks every
allow result, correlation and revision floor. The surrounding fixture still checks
trust/token rejection, CAS, immediate revocation, audit and restart recovery.
There is one service/role/permission, two information classes and synthetic
assurance/Guard evidence. This demonstrates native Pumgye headroom above 100k/s
under these conditions, not Hangang/Hopae/Sumunjang end-to-end capacity. Closed-loop
load, loopback, cache warmth and lack of arrival-rate overload injection limit
interpretation. No operational service is used for this load test.

## Actual four-component HTTPS chain — 2026-10-14

[Raw measurements and hashes](native-chain-performance.json) cover **actual**
Hangang, Hopae, Pumgye and Sumunjang processes. Hopae uses a native API key;
Sumunjang is enforce mode; Pumgye requires matching identity/network/permission;
Hangang accepts HTTPS and uses pooled mTLS HOP1/PPG1/HGD1. An owned Go origin
verifies canonical service identity/AAL/service and absence of Authorization;
every successful client response must have status 200 and exact body `ok`.

Three ten-second closed-loop trials on the same Ryzen 7 8745HS yield:

| Workers | Verified responses/s | p50 (µs) | p99 (µs) | Failed replies |
| --- | --- | --- | --- | --- |
| 16 | 11,081–11,657 | 1,339–1,422 | 2,041–2,091 | 0 |
| 32 | 10,365–10,914 | 2,890–3,024 | 4,238–5,642 | 0 |

The Python-origin preliminary three-second fixture measured 7,791–8,214/s;
changing only the validated origin removes some fixture overhead. More client
concurrency does not improve this host/workload's result. This establishes the
lower 10k/s target under these controlled conditions; **100k/s full-chain capacity
is not achieved**. Component-only Pumgye numbers cannot be substituted for it.
There is one service/key/role, a warm fixed policy, tiny response, loopback networking
and no external issuer or TokenReview cost. Open-loop saturation, denied mix,
long-lived renewal load, large application cardinality and physical/fleet networks
remain separate work. The test does not touch operational services.

```sh
go build -o /tmp/owned-https-chain-load tools/https_chain_load.go
python3 tools/native_chain_benchmark.py --pumgye /path/to/pumgye --gateway /path/to/hangang --hopae /path/to/hopae --sumunjang /path/to/sumunjang --generator /tmp/owned-https-chain-load --fast-origin --seconds 10 --workers 16
```

The fixture also refuses missing/invalid credentials, observe evidence and explicit
IP blocking before load. No authentication protocol peer is mocked. Owned state,
keys and processes are discarded at completion; errors/response statuses remain
visible rather than counted as throughput success.


The request-local Guard evidence variant records 11,764–12,492/s with 16 workers,
p50 1,256–1,328 µs, p99 1,862–2,110 µs and zero failed replies in three ten-second
trials. Its issued proof remains bound to authority/IP/revision/deadline; expired
or unusable proof re-queries. Raw variant source/hash is included above. This is
an observed result, not a guaranteed percentage improvement or a 100k/s claim.
