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
