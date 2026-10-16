# Independent authority and PPG1

[한국어](SERVER.ko.md)

`pumgye --database /private/pumgye.sqlite3 --policy examples/policy.json` bootstraps
an empty DB at revision 1. Later starts recover that DB and ignore the initial file.
Set distinct bounded `PUMGYE_ADMIN_TOKEN` and `PUMGYE_DECISION_TOKEN` through private
service environment configuration; do not put credentials in command arguments.

Remote deployment configures `--listen 0.0.0.0:9084 --decision-listen 0.0.0.0:9085`
with all of `--tls-cert`, `--tls-key` and `--client-ca`. Every remote connection must
present a trusted client certificate. HTTPS additionally checks its role bearer;
PPG1 authenticates a decision credential once after TLS. Loopback-only plaintext is
available for an explicitly trusted local process boundary. It is not remote auth.

`GET /v1/policy` requires admin auth. `PUT /v1/policy` accepts the document
`{revision, policy}`, requires `If-Match: "<revision>"`, and requires its body revision
to agree. Missing preconditions return 428, body disagreement 400, stale revision 409,
invalid policy 422, overload/storage uncertainty 503. The server increments revision.
Admitted publication continues independently of HTTP cancellation; after a timeout,
read authoritative state rather than assuming rollback. Policy, revision and digest
receipt commit together. Persistence failure fences health/decisions until recovery.

`POST /v1/decision` requires the decision credential, bounds JSON to 2 KiB and accepts
`service_id`, `subject`, `ip`, `permission`, `information_class`, `aal`, `guard` and
optional `minimum_revision`. Guard is `enforced_allow`, `deny`, `observe` or
`unavailable`. Unavailable/stale authority returns 503. Responses contain revision,
allow, reason and `ttl_ms: 0`. No ordinary query writes to SQLite.

`GET /v1/status` requires admin auth and exposes health, current policy revision,
query count and zero result-cache TTL. `GET /v1/audit?after_revision=N` returns up
to 100 revision-ordered receipts for admin callers. On HTTPS, the publication actor
is the SHA-256 fingerprint of the verified client certificate, supplied by the
transport rather than a request header. Local plaintext records a loopback actor;
individual Hangang administrator delegation remains an integration gate.

## Wire contract

Integers use network byte order. TLS ALPN is `ppg1`; early data is disabled.
The client sends `PPG1`, a u16 credential length (16–4096), and credential bytes.
Only the decision credential is accepted. The server replies `PPA1` or closes.

Each query is preceded by u16 payload length (40–552). Payload offsets:

| Offset | Content |
| --- | --- |
| 0 | Version 1 |
| 1 | IP family 4 or 6 |
| 2 | AAL 0–3 |
| 3 | Guard: enforce allow 0, deny 1, observe 2, unavailable 3 |
| 4–11 | Request ID u64 |
| 12–19 | Minimum revision u64 |
| 20–35 | IPv6 bytes, or IPv4 bytes followed by 12 zero bytes |
| 36 onward | Service, subject, permission, class: four u8 lengths followed by UTF-8 bytes |

Identifiers are nonempty, at most 128 bytes, without control characters. Trailing,
truncated, invalid-version/address/evidence/UTF-8 frames close the connection.
Each reply is 32 bytes: version at 0, decision code at 1, zero reserved bytes at
2–3, echoed request ID at 4–11, revision at 12–19, and zero bytes at 20–31. Decision
codes 0–8 are allow, unknown service, guest, network guest, permission denied, class
denied, assurance denied, Guard deny, Guard unavailable. Code 255 means unavailable
or below the requested revision; it must never allow. Reserved reply bytes include
zero cache TTL; no positive cache lease is issued in this version.

The server evaluates each frame against the current immutable view and replies in
order, batching at most 64 ready replies. The client batches at most 64 requests,
checks IDs/shape and enforces the configured and observed monotonic revision floor.
Cancellation, timeout or malformed/mismatched response discards the connection;
there is no unsigned/anonymous/stale allow fallback. Client pools are 1–1024,
deadlines 1 ms–5 s (including acquisition/handshake); native server capacity is
4096 connections, HTTPS capacity 2048, HTTP request capacity 4096, management 4.
TLS/token handshake is limited to 3 s, native idle reads 30 s, frame completion/write
5 s and connection lifetime 300 s. Clients recycle by 240 s age/20 s idle.

Replica publication, authority incarnation pinning, credential rotation/reload,
individual delegated admin actors and fleet revocation leases are additional
integration gates. A revision floor alone is not quorum consistency. Native client
and server tests do not establish whole-stack 100k HTTP requests per second.

Native client endpoints accept bounded `host:port` Service DNS names and literal
IPv4/IPv6 socket addresses. DNS names always require mTLS, even `localhost`; DNS
discovery does not establish peer identity. The client resolves on each new pooled
connection under the existing decision deadline and validates the configured TLS
server name/CA and client credential. Existing pooled connections keep their normal
retirement bounds; this is not replica membership or source-revision coherence.

## Native Allow publication fence (unreleased)

Authority evaluation now shares an `authorize_then` boundary. Only an actual
compiled owner Allow can invoke private follow-up work; denial/unavailability
never invokes it. The same active immutable snapshot is checked before and after
that work, including source lease/readiness and persistence health. Retirement
discards the candidate and returns unavailable. Normal HTTP/native/gRPC decisions
also use this final fence. Callbacks must not publish output or perform irreversible
external effects before successful return.

The snapshot-replacement/denied-signer regression, 30 workspace tests, strict
Clippy and actual four-process native/gRPC durable request chains passed. This
is the owner boundary for future signing, not a permission-receipt API: native
resource/catalog mapping, authentication/network receipt verification, signer
key lifecycle and downstream projection replay admission remain unfinished.

## Resource decision HTTP API (unreleased)

`POST /v1/resource/decision` requires the decision credential (administrator
credentials do not authorize it) and the existing authenticated listener policy.
Its bounded 2 KiB JSON contains `resource`, `action`, `subject`, `ip`, `aal`,
`guard` and optional `minimum_revision`. There is no caller-selected service,
permission or information class; unknown fields are refused. Only a trusted
enforcement adapter may supply identity/assurance/network evidence here.

The response contains version/revision/allow/reason and zero TTL. Missing/stale
authority or required guard evidence returns 503. Resource/action absence and
insufficient rights/assurance return a denied decision. Active owner snapshot and
source lease are fenced around evaluation, and no SQL runs per decision.

`cargo build -p pumgye-server && python3 tools/resource_catalog_smoke.py`
qualifies the actual isolated process, role isolation, class injection refusal,
resource assurance, CAS catalog revocation, restart without bootstrap resurrection
and restoration. Router/workspace tests (33) and strict Clippy pass. This is an
unsigned decision API, not authentication-receipt verification or permission
issuance; resource gRPC, Hangang UI/dispatch and signed projection remain open.

The unreleased resource endpoint requires `service_id` and rejects a resource owned by another service. Service scope comes from trusted enforcement context, never an application claim.

## Administrative explain API (unreleased)

`POST /v1/explain`, `POST /v1/explain/batch`, `POST /v1/explain/diff` and
`GET /v1/audit/simulations` require the administrator credential (the decision
credential is refused) and share management admission. They run the enforcement
evaluator with a trace sink against the published snapshot or an unpublished
candidate (never stored), return an ordered stage trace with registered
`pumgye.*` reason codes and en/ko message keys, and audit every call as a
read-only `simulation`. See [the explain contract](EXPLAIN.md).

## Policy model version 2 (unreleased)

`/v2/policy`, `/v2/status`, `/v2/explain*`, `/v2/candidates/diff`,
`/v2/migration/preview`, `/v2/shadow*`, `/v2/cutover`, `/v2/rollback` and
`/v2/model/history` require the administrator credential. Version 1 and version 2
publications share one revision sequence and one audit (`document: v1|v2`); the v1
`PUT /v1/policy` therefore issues the next global revision. Decisions stay on v1 until
an approved cutover. See [MODEL_V2.md](MODEL_V2.md).

## TLS certificate rotation (unreleased)

Pumgye reloads mTLS material without a restart, so it keeps up with cert-manager
renewals. Every `--tls-reload-interval-secs` seconds (default 10, range 1–3600)
it reads the certificate, key and CA files of each TLS user and compares a
SHA-256 digest of their contents. It does not use inotify, because host inotify
watches are scarce. When the contents change, it builds a new rustls
configuration and swaps it in atomically.

Reloaded:

- Listeners: HTTP (`http listener`), PPG1 (`ppg1 listener`), gRPC
  (`grpc listener`) and SAR (`sar listener`). New handshakes use the new
  certificate and CA. Established connections keep the configuration they were
  accepted with until they close. gRPC TLS is terminated by Pumgye's own
  acceptor, not by tonic, so that it can be swapped.
- Outbound mTLS clients:
  - Sumunjang/Hopae live clients: `route_live`, `projection_live`,
    `network_live` and `authentication_live`. They use a reloading tonic
    connector, so new HTTP/2 connections use the current client certificate and
    CA, and existing channels keep their connection.
  - The Hopae owner client (`hopae_owner client`). Its HTTP client is rebuilt
    from the new material.

When new material is invalid (unparsable PEM, or a key that doesn't match the
certificate), the previous configuration stays in service. The
listener or client then reports `failing: true` and `last_error`, and
`GET /v1/status` sets `tls_reload_failing: true`. Alert on that field. Pumgye
logs each rejected file content once and doesn't retry it until the files
change again. Reverting to the served material also clears the alert. If files
can't be read briefly, for example during a non-atomic write, Pumgye keeps
serving and checks again on the next poll.

`GET /v1/status` includes `tls`, a list with one entry per listener or client:
`name`, `leaf.serial` (hex), `leaf.sha256` (DER fingerprint), `loaded_at`,
`reloads`, `failures`, `failing` and `last_error`. Pumgye logs each change to
stderr as a JSON line:

```json
{"event":"tls_reloaded","name":"grpc listener","serial":"1002","sha256":"…"}
{"event":"tls_reload_refused","name":"grpc listener","error":"…","serving_serial":"1001"}
```

The Kubernetes API source (`--kubernetes-ca`, `--kubernetes-token`) reads its CA
and token files again on every relist, so it does not use the poller. When the
content of either file changes, Pumgye builds a new HTTP client and stops using
the old trust pool. A CA that doesn't match the server's certificate fails
closed: the source observation expires, and the next relist with valid material
recovers it. The `pumgye_kubernetes_credential_reloads_total` metric counts
these changes.

Limitations: the longest delay before new material is used is one polling
interval. The outbound clients of the `observed-*` features pass fixed PEM bytes
to the Hopae gRPC SDK (`hopae-grpc`), so they still need a restart after
rotation. Fixing this is a Hopae SDK follow-up: `hopae-grpc` needs an API that
accepts a reloadable connector or client configuration (see
`docs/MODEL_V2.md`, "Hopae dependencies").

## Prometheus metrics (unreleased)

`GET /metrics` serves the Prometheus text format (`text/plain; version=0.0.4`).
It is on the main HTTPS management listener, so a scrape needs the listener's
mTLS client certificate and a bearer credential:

- the administrator credential, or
- a dedicated read-only scrape credential, read from the environment variable
  named by `--metrics-token-env` (default `PUMGYE_METRICS_TOKEN`). It must be
  16–4096 visible ASCII characters and differ from the administrator and decision
  credentials. It opens only `/metrics`.

The plaintext readiness listener does not serve metrics. A Prometheus Operator
`ServiceMonitor` endpoint looks like this:

```yaml
endpoints:
  - port: management   # 9084, the HTTPS management listener
    scheme: https
    path: /metrics
    bearerTokenSecret: {name: pumgye-metrics, key: token}
    tlsConfig:
      ca: {secret: {name: pumgye-tls, key: ca.crt}}
      cert: {secret: {name: pumgye-scrape-client, key: tls.crt}}
      keySecret: {name: pumgye-scrape-client, key: tls.key}
      serverName: pumgye.pumgye.svc
```

Recording on the decision path is a few relaxed atomic increments. It doesn't
allocate (`tests/metrics_no_alloc.rs`) and doesn't take locks. No label carries a
subject, IP address, service or resource, so the number of series is fixed. The
only exception is the TLS `name` label, whose values are the fixed listener and
client names.

| Metric | Type | Labels |
| --- | --- | --- |
| `pumgye_decisions_total` | counter | `context` (`permission`, `resource`, `workload_resource`, `human_resource`), `outcome` (`allow`, `deny`, `unavailable`), `reason` (decision reason code, `unknown_resource`, `unknown_action`, `unavailable`) |
| `pumgye_request_duration_seconds` | histogram | `transport` (`http`, `ppg1`, `grpc`, `sar`) |
| `pumgye_policy_revision` | gauge | `model` (`v1`, `v2`) |
| `pumgye_policy_v2_authoritative`, `pumgye_available` | gauge | — |
| `pumgye_policy_publications_total` | counter | `model`, `outcome` (`applied`, `conflict` = If-Match CAS conflict, `rejected`) |
| `pumgye_shadow_decisions_total`, `pumgye_shadow_reason_drift_total` | counter | — |
| `pumgye_shadow_mismatches_total` | counter | `explained` (`true`, `false`) |
| `pumgye_shadow_window_start_timestamp_seconds` | gauge | — |
| `pumgye_hopae_last_success_timestamp_seconds`, `pumgye_hopae_staleness_seconds` | gauge | `feed` (`projection`, `lifecycle`); staleness is `-1` before the first sync |
| `pumgye_hopae_sync_failures_total`, `pumgye_hopae_cursor_expired_total` | counter | `feed` |
| `pumgye_simulation_audit_rows` | gauge | — (retained rows) |
| `pumgye_simulation_audit_rows_appended_total` | counter | — |
| `pumgye_observed_permits_total` | counter | `kind` (`service`, `workload`, `human`), `outcome` (`issued`, `permission_denied`, `unavailable`, `invalid_argument`, `unauthenticated`, `other`) |
| `pumgye_tls_reloads_total`, `pumgye_tls_reload_failures_total` | counter | `name` |
| `pumgye_tls_reload_failing` | gauge | `name` |
| `pumgye_tls_leaf_expiry_seconds` | gauge | `name` (seconds until `notAfter`; negative once expired) |
| `pumgye_kubernetes_credential_reloads_total` | counter | — |

Suggested alerts:

- `pumgye_tls_reload_failing == 1`
- `pumgye_tls_leaf_expiry_seconds < 7 * 86400`
- `pumgye_hopae_staleness_seconds` above the projection's `max_staleness_secs`
- an increase in `pumgye_shadow_mismatches_total{explained="false"}`
- `pumgye_available == 0`
