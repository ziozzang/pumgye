# Additional gRPC decision transport

[한국어](GRPC.ko.md)

Status: implemented and locally qualified for Pumgye service-matrix decisions.
Not deployed to production or qualified as the four-component Kubernetes package.
Generic resource metadata/obligations and Hopae/Sumunjang/Hangang gRPC integration
remain pending. The pure authorization core and PPG1 transport are unchanged.

`pumgye-grpc` provides the versioned protobuf contract and generated Rust client/server.
Builds require `protoc`. The server's optional `--grpc-listen` requires the existing
`--tls-cert`, `--tls-key`, `--client-ca`, including on loopback. Client certificates
are mandatory; a trusted client also supplies the distinct decision credential as
`authorization: Bearer …` metadata. Administrator credentials do not authorize this
endpoint. Only the trusted enforcement caller may assert identity and IP evidence;
this API does not authenticate an end-user's self-reported subject or guard result.

`hangang.pumgye.v1.Authorization/Decide` invokes the same in-memory Authority evaluator.
Request IDs, minimum revision, IP bytes (4/16), assurance (0–3), guard evidence and
bounded nonempty identifiers preserve native semantics. Unspecified guard evidence
is rejected. Replies explicitly distinguish allow, deny and unavailable; unspecified
verdicts must never grant access. `native_reason` matches PPG1. `cache_ttl_ms` is zero;
clients must not cache the decision or treat transport errors as permission.

The listener bounds connections (2048), streams/concurrency per connection (64),
request capacity (the shared 4096 slots), metadata headers (8192 bytes), decoded
messages (2048 bytes), encoded replies (1024 bytes), TLS handshake (3 seconds) and
server request duration (1 second). Compression is not enabled. No database lookup,
JSON conversion or second policy engine is introduced on the decision path.
Management/policy writes stay on the existing authenticated management interface.

Qualification uses generated Python grpcio stubs against an owned actual process:

```sh
python3 -m venv /tmp/pumgye-grpc-env
/tmp/pumgye-grpc-env/bin/pip install grpcio grpcio-tools
cargo build --locked -p pumgye-server
cargo build --locked --release -p pumgye-client --example qualify
/tmp/pumgye-grpc-env/bin/python tools/server_smoke.py \
  --binary target/debug/pumgye --client target/release/examples/qualify --grpc
```

The fixture generates temporary CA/client/server identities and synthetic credentials,
checks native/gRPC parity, immediate policy revocation, role isolation, bad server CA/name,
missing client certificate, invalid/oversized input and unavailable revision floors.
Unit tests additionally check duplicate metadata, capacity and expired source fences.
No load result, inbound Kubernetes webhook or PostgreSQL adapter is established by
these checks. Existing native transport remains available without enabling gRPC.

## ResourceAuthorization service (unreleased)

The same mandatory-mTLS listener registers `ResourceAuthorization/Decide`
separately from legacy `Authorization/Decide`. Input contains correlation,
minimum owner revision, verified IP/AAL/guard evidence, resource/action and
subject; there is no service/permission/class override. IP must contain exactly
4 or 16 bytes, assurance 0..3 and scope identifiers are bounded. Only the
authenticated decision role may call either service; both share global admission.

Resource RPC and HTTP use the same native immutable owner evaluation/freshness
fence. The bounded reply contains correlation, owner revision, Allow/Deny/
Unavailable, reason and zero TTL. Handler tests cover native classification,
assurance denial, role/capacity isolation, missing IP and stale/observe refusal.
Workspace tests (36) and strict Clippy pass. An owned actual mTLS socket test
checks Allow, administrator-credential refusal, missing-client-certificate refusal
and catalog assurance/revision changes on the same channel. Those changes are
in-memory publications; database durability is covered separately by the HTTP
catalog smoke test. Hangang dispatch/UI adoption remains open; this unsigned
result is not a signed permit or verified authentication receipt.

Resource requests now require `service_id` from trusted gateway route/authentication context. The owner refuses a catalog entry belonging to another service even when the principal has grants there. Omitted/empty scopes are invalid. This unreleased contract requires rebuilding consumers; legacy Authorization is unchanged.
