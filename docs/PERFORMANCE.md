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
