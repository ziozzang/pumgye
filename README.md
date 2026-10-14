# Pumgye (품계)

[한국어](README.ko.md)

Pumgye owns deterministic service roles, permissions, information classes and
user/IP authorization matrices. Hopae owns verified identity and sessions;
Sumunjang supplies network evidence; Hangang enforces the combined decision.

The workspace separates four packages:

- `pumgye-core`: bounded policy compilation and deterministic evaluation. No HTTP, TLS, runtime or database dependencies.
- `pumgye-server`: the independent `pumgye` policy authority, SQLite persistence, transactional audit and HTTP/PPG1 listeners.
- `pumgye-protocol`: bounded PPG1 codec, with borrowed query identifiers and fixed replies.
- `pumgye-client`: authenticated persistent connections, bounded pools/deadlines, batches, correlation and monotonic revision floors.

Native mode uses SQLite as the policy source of truth. Startup recovers and compiles its committed
policy; successful CAS publication atomically commits policy, revision and audit,
then replaces an immutable `ArcSwap` memory snapshot. Decisions never read the DB.
The snapshot remains until the next publication; it is not a 1–5 second decision
result cache. Results currently have zero cache TTL. HTTP cancellation does not
interrupt an admitted durable publication. Persistence uncertainty fences decisions
until restart/recovery. One runtime owns each database; edit policies through its
API rather than changing SQLite directly.

Rights use permission/class bitsets and Sumunjang's compressed prefix trie.
User and network rights must both permit a request. Unassigned subjects are guests,
network deny dominates and required enforcement rejects observe/unavailable evidence.
Callers must supply authenticated identity, trusted source IP and verified evidence;
wire enums do not themselves verify those facts.

Remote listeners require mTLS with an explicitly provisioned client CA, plus separate
admin/decision credentials. Plaintext is limited to loopback. The native client pins
an endpoint, server name and CA and presents its client certificate. See
[server and protocol contracts](docs/SERVER.md).

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --release --workspace
cargo build --locked --release -p pumgye-client --example qualify
python3 tools/server_smoke.py --binary target/release/pumgye --client target/release/examples/qualify
```

The owned process fixture covers mTLS rejection, role-separated credentials,
HTTP/native parity, persistent pipelining, revision floors, CAS races, publication
revocation, audit, DB ownership and restart recovery. To measure the synthetic native
transport, append `--benchmark 1000000`; this is not full Hangang/Hopae/Sumunjang HTTP
throughput or replica qualification.

The earlier embedded gateway/matrix implementation is qualified in
[Hangang #5](https://github.com/ziozzang/hangang/pull/5). Independent Hangang client
and delegated administration integration, replica leases/revocation, and mixed
human/machine authentication remain implementation gates. The presence of these
packages does not establish completion of the full zero-trust stack.

Qualify the earlier owned gateway baseline with
`python3 tools/hangang_smoke.py --gateway-binary /path/to/hangang`.

[Native transport measurements](docs/PERFORMANCE.md) record three 10-second mTLS trials and their exact scope/limitations.

[Kubernetes source adapter](docs/KUBERNETES.md): bounded inspection, HTTPS polling, explicit mapping and sole-writer source-authoritative decisions are implemented and qualified against an owned real API. Scalable watches and automatic verified identity association remain pending.

[Additional gRPC decisions](docs/GRPC.md) use the same core and snapshots. Optional mTLS listener, locally qualified; production/Kubernetes and cross-component integration remain pending. Workspace builds now require `protoc`.

Native and management TCP listeners use pinned hangang-runtime 0.1.2 connection
admission and task ownership (4,096 native; 2,048 management connections).
Cancelling the listener owner aborts its connection tasks instead of detaching
them. PPG1 framing, TLS/ALPN, peer certificate audit identity and in-memory
authorization remain Pumgye owned. This is task lifecycle ownership, not a new
graceful OS-signal shutdown or supervisor handover implementation.

Linux release preparation defaults to static amd64 musl.
`tools/prepare_release.py --output /secure/dist --signer /secure/offline-signer
--seed /secure/private-seed` stages the binary, documentation archive, pinned
public key, signed manifest and checksums. The private seed remains outside this
repository. Preparation checks ELF/version/signing identity, verifies the actual
Ed25519 signature with OpenSSL and binds the payload to the exact artifact.
The release key is independent of other Hangang World authorities. This supplies
verified installation assets; it does not implement automatic runtime updates.

## Graceful termination (unreleased)

The server handles SIGTERM and SIGINT, stops accepting new connections, and
drains native/HTTP connection tasks for up to five seconds. gRPC receives graceful
shutdown, with a six-second overall shutdown bound. Independent readers can keep
using the durable policy on the next start. Validate an isolated process with
`cargo build -p pumgye-server` and `python3 tools/shutdown_smoke.py`. The smoke
checks actual SIGTERM, clean exit and idle native socket closure; it does not
qualify in-flight gRPC stream completion or production/Kubernetes rollout.

The v0.1.1 candidate passed the complete workspace tests and strict Clippy,
static ELF and actual SIGTERM checks, and actual four-process native/gRPC
request chains with durable restart. The published v0.1.0 remains the operating
release until candidate signing, publication and rollout are completed.

Pumgye [v0.1.1](https://github.com/ziozzang/pumgye/releases/tag/v0.1.1) is now
published at da45832 with five independently verified Linux amd64 musl assets.
Internal adoption passed an isolated policy DB clone, exact durable policy
preservation, live mTLS management/native refusal, signed binary digest checks
and a second service restart. Private rollback backups are retained. Kubernetes
rollout of this version and in-flight gRPC completion remain unqualified.

Subsequent remote Kubernetes qualification of v0.1.1 passed the maintained
four-component functional fixture and real administrator browser flow, including
authority Pod replacement, immediate/durable permission and authentication
revocation, stale administrator CAS refusal, backend non-dispatch on denial,
and network-authority outage refusal. The exact owned namespace was removed.
This qualifies the tested gRPC deployment; it does not qualify all Kubernetes
transports, in-flight gRPC shutdown, authorization webhooks or fleet replication.
