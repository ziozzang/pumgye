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
