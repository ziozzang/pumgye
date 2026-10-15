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

## Current local performance evidence

[Raw measurements](docs/current-static-performance.json) separate complete request
chains from pure-core evaluation. With the current signed static releases, three
10-second closed-loop runs at 16 concurrent workers verified 11.4k–11.9k HTTPS
requests/second, zero failures and p99 1.90–2.06 ms. These runs include actual
Hangang/Hopae/Sumunjang/Pumgye native mTLS calls and a validated Go origin.

`cargo run --release -p pumgye-core --example decision_benchmark -- 1000000`
measures a warmed compiled policy with 65,536 users and 65,536 IPv4 /32 entries.
Three single-thread samples took 295–319 ns/decision. This synthetic sequential
workload excludes compilation, SQL and transport; it does not establish server
throughput, random-key latency or full-chain 100k QPS capacity. Host contention
and loopback locality limit extrapolation. No Kubernetes load test was run.

The [paired access-order measurement](docs/core-access-performance.json) uses
the same core executable and precomputed sequential/shuffled permutations of
all 65,536 assignments. Run the second mode with
`cargo run --release -p pumgye-core --example decision_benchmark -- 1000000 shuffled`.
Three sequential samples took 243–268 ns/decision; shuffled samples took
753–930 ns/decision. The difference demonstrates sensitivity to cache locality.
The fixed shuffled order repeats, uses one role/service and is not an adversarial
or production traffic model. These core samples cannot establish server QPS.

### Exact-host lookup optimization (unreleased)

Compiled policies now index IPv4 /32 and IPv6 /128 assignments in a separate
canonical-address HashMap; broader CIDRs retain the compressed radix trie. Exact
host assignments are always most specific, including guest overrides. Mapped IPv4
identities share the canonical host entry and duplicate canonical host rules are
refused. Request lookups remain allocation-free and snapshots remain immutable.

[Candidate measurements](docs/core-host-index-performance.json) took 175–187 ns
sequentially and 300–323 ns with the same fixed shuffled maximum-assignment
fixture. This is promising for host-heavy policies, but broader CIDR-only policies,
additional memory, full-chain performance and operational adoption still require
qualification. Current signed v0.1.1 artifacts are unchanged.

## v0.1.2 publication and internal adoption

[v0.1.2](https://github.com/ziozzang/pumgye/releases/tag/v0.1.2), source d3092ff,
publishes the canonical exact-host index as five independently verified Linux
amd64 musl assets. Workspace tests (29), strict Clippy, five release boundary
tests, actual SIGTERM and both four-process native/gRPC durable chains passed.
Downloaded signatures, hashes and version/target/URL binding were verified.

The internal authority now runs this exact signed executable. An isolated copy
of its durable policy passed preflight; live mTLS management/native refusal,
unchanged durable policy and a second restart passed. Private binary/DB/config
rollback backups remain available. Kubernetes qualification of v0.1.2, mixed-policy
memory/CIDR costs, full-chain 100k QPS and fleet replication remain open.

## Native resource catalog (unreleased)

Policy `resources` owns resource ID → service, information class, action/permission
mapping and minimum AAL. [Example](examples/resource-catalog.json). The pure core
`evaluate_resource` accepts resource/action and verified identity/network evidence;
its caller cannot select a lower information class. User/network role intersection,
guard requirements and the maximum of role/resource assurance still apply.
Unknown resources/actions refuse; unknown service/class/permission relations or
invalid assurance reject compilation before publication. Limits: 65,536 resources,
64 actions per resource and 65,536 total actions. Decisions query immutable memory
without SQL or request allocations.

An empty catalog is omitted from serialization, preserving legacy policy shape.
Nonempty catalogs require upgraded typed consumers; old strict consumers reject
unknown fields. Existing service-level decision APIs retain their semantics and
do not implicitly use resource classification. Resource query RPC, administrator
UI, catalog-aware permit signing, DBMS adapters and operational qualification
remain unfinished. No direct PostgreSQL access hook is enabled by this example.

## v0.1.3 publication and internal adoption

The native owner resource catalog defines service membership, information class,
action-to-permission mapping and minimum authentication assurance. New authenticated
HTTP and mandatory-mTLS gRPC resource decisions require a trusted native service
scope, retain immutable snapshot/revision/source freshness fences and have zero
cache TTL. Existing service decision protocols remain supported. Policy JSON
persists the catalog atomically without a separate database schema migration.
Hangang resource dispatch and the integrated catalog view passed actual local
four-server and remote Kubernetes/browser candidate qualification, including owner
changes, deletion, revocation and Pod replacement. [v0.1.3](https://github.com/ziozzang/pumgye/releases/tag/v0.1.3) is published at
b8e972b with five independently verified static signed assets. All downloaded
assets match the originals. Internal adoption passed isolated real-DB-clone
preflight, private binary/database/configuration rollback backups, exact policy
preservation, live management/native mTLS denial and a second durable restart.
The catalog is available without automatically enabling new gateway resource gates;
full provider/fleet/projection and automatic-update work remains open.

## v0.1.4 publication and internal adoption

This candidate adds server-owned service receipt verification and signed permit
candidates, reference-only signing/trust configuration, durable key retirement
and scope revision floors, and explicit owner-lock release after SQLite closes.
Receipt/permit RPC activation and live distributed owner checks remain open;
loading these resources alone does not grant access. Existing resource decision
APIs and independent static server deployment remain supported. See
[receipt boundaries](docs/AUTHENTICATION_RECEIPTS.md). [v0.1.4](https://github.com/ziozzang/pumgye/releases/tag/v0.1.4) is published at
`89e5987cfee934f2fb6b9f007064bc6525999715`. All 55 workspace tests, strict
all-target Clippy and five release-boundary tests passed. Exact static artifacts
passed actual HTTP/PPG1/gRPC mTLS, role isolation, revocation/restart and catalog
CAS qualification. Downloaded assets matched original hashes and pinned Ed25519
signature. Internal deployment passed private operating-DB clone preflight,
exact policy preservation and two restarts; the unified console still returns 200.
Private consistent backup and binary rollback material are retained. This version
has not yet been qualified in the remote K3s world fixture.

## v0.1.5 release preparation

This increment adds native authenticated resource decisions backed by Hopae live
receipt validation and Sumunjang Enforce observations, pinned mTLS startup
resources and bounded persistent clients. Candidate static three-authority tests
passed; exact newly versioned artifacts must pass before signed publication.
Signed permit, route/projection ownership, Hangang dispatch and distributed
restore/fleet qualification remain open. GitHub Actions remains disabled.

[v0.1.5](https://github.com/ziozzang/pumgye/releases/tag/v0.1.5) is now
published at `c490bc5f4389051161bfcd872d5c3a1f716713a3`. Exact newly versioned static three-authority endpoint
qualification, source regression/Clippy and release boundary checks passed.
All downloaded assets matched originals; pinned signatures, version/target/URL
bindings and static ELF were independently verified. Internal adoption and
Kubernetes combined-endpoint qualification remain subsequent gates.

### 0.1.5 Internal adoption — 2026-10-15

Internal deployment passed signed-artifact verification, isolated operating DB
clone preflight, private consistent backup, exact policy preservation, actual
mTLS management/PPG1 refusal and two restarts. Native receipt/live resources
remain unconfigured in this existing deployment; the new endpoint fails closed.

### Combined-observation permit candidates

`permit::Signer::issue_combined` requires opaque actual Hopae and Sumunjang
observations in addition to verified authentication. It derives Enforce evidence
and network expiry from that observation, refuses a mismatched network revision
or IP, and rechecks both observations before and after owner fences. The signed
candidate cannot outlive the network observation or authentication receipt.
Clock reversal and retirement during the final callback discard the private
candidate. No policy decision performs SQL.

The owned `authenticated_resource_smoke.py --combined-permit` fixture requires
a participating client; use `hopae_live_qualification`, `--live-validation`,
`--grpc-decisions` and `--nonempty-entity` to exercise actual live authorities,
network refusal/restoration, identity withdrawal/restoration and outage. Its
route/projection owners are local synthetic fixture state. This is not a permit
RPC, distributed owner discovery, downstream replay consumption or production
activation. The low-level `issue` API still requires native caller-owned facts.

### Native gateway route observations (source integration)

`--route-live` loads reference-only native route resources using the same fields
as network authority configuration: address, server_name, ca, certificate, key
and token_env. Only a fixed HTTPS authority is accepted, with no userinfo, path
or query. Construction validates TLS lazily to avoid a gateway/authority startup
cycle; actual queries still require a verified mTLS exchange within one second.

When configured, authenticated resource decisions require a 32-byte native route
reference and destination digest. Owner-derived scope/IP must match the checked
receipt and requested resource/action. The server queries the actual owner both
before and after identity/network/policy evaluation; missing configuration or
references, mismatches, expiry and failure refuse without fallback. The reply's
`route_observed` marker distinguishes this path from legacy zero-TTL observations.
These observations are not signed permission or distributed leases.

The client has private observation constructors, bounded admission/decoding,
correlation and scope checks, monotonic exchange-time accounting and configured
client identity binding. Source workspace tests and strict Clippy pass. Actual
gateway reference delivery, end-to-end route qualification, release and operating
adoption remain the next integration gate. Existing deployments are unchanged.
