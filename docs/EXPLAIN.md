# Administrative explain, what-if and candidate diff (unreleased)

[한국어](EXPLAIN.ko.md)

Pumgye answers *why was this request allowed or denied, and what would happen
under a draft policy* without issuing permits, counting decisions or changing
policy. This is the Pumgye authority API that ADR 0019 (decision events,
simulation), ADR 0020 (console simulator) and ADR 0021 (explain/candidate diff,
P0) consume. Who-can/what-can queries are ADR 0021 P1 and are not implemented.

Versioning: these `/v1/explain*` paths serve the policy version 1 model. The ADR 0021
v2 model will add `/v2/...` explain paths with its own stages (groups, explicit deny,
zones, clearance, validity); `/v1` remains for v1 documents.

## Guarantees

- **Same function.** Every enforcement entrypoint (HTTP `/v1/decision`,
  `/v1/resource/decision`, PPG1, gRPC, Workload/Human resource paths, the
  Kubernetes API/SAR path) delegates to one evaluator generic over a `Tracer`.
  Production instantiates it with the zero-sized `NoTrace` sink whose method is an
  empty `#[inline(always)]` function, so the trace compiles away; explain uses a
  bounded `VecTrace` (≤ 32 events, one allocation). The explain decision is the
  return value of that function, not a re-implementation. Network rule indexes
  live in former padding (compiled entry size is asserted unchanged).
- **Hot path stays allocation-free.** `crates/pumgye-core/tests/no_alloc.rs`
  counts heap allocations with a global allocator across every entrypoint and every
  `Decision` variant and requires zero.
- **Parity.** `crates/pumgye-core/tests/explain.rs` compares explain with the
  production call over a >50,000 case corpus covering every entrypoint and every
  reason code; server tests compare `/v1/explain` with `/v1/decision` and
  `/v1/resource/decision` responses on the same snapshot.
- **Read-only.** No permit, receipt, session or policy write; decision counters
  (`decision_queries`) are untouched; results are `Cache-Control: no-store`.
  Candidate documents are validated and compiled exactly like `PUT /v1/policy` but
  are never stored.
- **Audited.** Each accepted simulation appends one `kind=simulation` row to a
  separate `simulation_audit` table (actor, optional delegated actor, operation,
  snapshot source/revision, candidate digest, request body SHA-256, counts) *before*
  the result is released. If the row cannot be written the request returns 503 and
  no result; enforcement is not fenced. Every insert trims rows older than
  `--simulation-audit-retention-days` (default 30, range 1–3650) and keeps at most
  the newest 100,000 rows. Publication audit is never trimmed.

## Authentication, admission and limits

All endpoints require `Authorization: Bearer <admin credential>` on the existing
authenticated listener (mTLS outside loopback). The decision credential is refused
(401) by the request gate and again in the handler. Requests share the management
admission gate (4 concurrent, 5 s deadline) with `/v1/policy`, `/v1/status` and
`/v1/audit`, plus a process-wide simulation token bucket (capacity 1024, refill
256/s; cost = cases, ×2 when compared with a candidate, +64 per candidate
compilation). An exhausted bucket returns 429 with `Retry-After: 1`.

| Bound | Value | Status |
| --- | --- | --- |
| Request body | 1 MiB + 256 KiB | 413 |
| Candidate document (re-serialized) | 1 MiB, same as stored policy | 413 |
| Batch cases | 1–256; 1–32 with `trace: true` | 413 / 400 |
| Diff page | `limit` 1–500, default 100 | 400 |
| Identifiers | 1–128 bytes of `[A-Za-z0-9_.:-]` (labels ≤ 64) | 400 |
| `on_behalf_of` | 1–128 bytes of `[A-Za-z0-9_.:@-]` | 400 |

### Errors

400, 409, 413, 422 and 429 from these endpoints carry a structured body (other
Pumgye endpoints keep status-only errors). 401, 415 and 503 stay bare so they
reveal nothing before authentication or about storage:

```json
{"error": {
  "code": "pumgye.error.candidate_invalid",
  "message_key": "pumgye.error.candidate_invalid",
  "details": [{"path": "snapshot.policy.services.orders.users.u_reader",
               "code": "pumgye.validation.unknown_assigned_role",
               "message_key": "pumgye.validation.unknown_assigned_role"}],
  "current_revision": 7
}}
```

`current_revision` appears only on 409. `details` (≤ 32) locate the cause by
request path; codes double as message keys and are in the en/ko catalogs.

| Status | `code` | Detail codes / paths |
| --- | --- | --- |
| 400 | `pumgye.error.malformed_request` | JSON/schema error at the request path (`case.subject.kind`, `$` for the root) |
| 400 | `pumgye.error.invalid_case` | every invalid case: `pumgye.case.{invalid_name, invalid_label, ambiguous_target, missing_network_evidence, unexpected_network_evidence, assurance_out_of_range, unsupported_combination, revision_out_of_range}` at `case.<field>` / `cases[i].<field>` |
| 400 | `pumgye.error.invalid_delegated_actor`, `empty_batch`, `invalid_page`, `invalid_cursor` | `on_behalf_of`, `cases`, `limit`/`cursor`, `after_id` |
| 409 | `pumgye.error.revision_conflict` | `snapshot.revision`, `snapshot.base_revision` or `base_revision`; reload `current_revision` and retry |
| 413 | `pumgye.error.payload_too_large`, `batch_too_large`, `candidate_too_large` | body, `cases`, candidate document |
| 422 | `pumgye.error.candidate_invalid` | the validator's failure: `pumgye.validation.schema` (unknown field, wrong type) or a compile code such as `unknown_assigned_role`, `role_cycle`, `network_host_bits`, `resource_permission` (`pumgye_core::VALIDATION_CODES`), at the most specific document path (`snapshot.policy.services.<s>.roles.<r>`, `….networks[i]`, `….resources.<r>.actions.<a>`) |
| 429 | `pumgye.error.rate_limited` | — (`Retry-After: 1`) |

## Case

```json
{
  "label": "case-1",
  "subject": {"id": "u_writer", "kind": "user"},
  "service": "orders",
  "permission": "write", "information_class": "internal",
  "ip": "192.0.2.1", "aal": 2, "guard": "enforced_allow",
  "minimum_revision": 0
}
```

The target is exactly one of `permission`+`information_class` or
`resource`+`action`. `guard` is *simulated* Sumunjang evidence:
`enforced_allow`, `deny`, `observe` or `unavailable`.

| `subject.kind` | Map consulted | Entrypoint simulated | Target | Network evidence | AAL |
| --- | --- | --- | --- | --- | --- |
| `user` | `users` | `/v1/decision`, PPG1, gRPC / `/v1/resource/decision` | either | required | 0–3 |
| `workload` | `workload_users` | Workload resource path | resource | required | must be 0 |
| `human` | `human_users` | Human resource path | resource | required | 0–3 (only 1–2 can allow) |
| `kubernetes_api` | `users` of a `kubernetes_api` service | SAR | resource | forbidden | must be 0 |

Maps never fall back to each other (the same `s_` string in two maps is two
subjects), exactly as enforcement.

## Snapshot selector

```json
{"source": "published"}
{"source": "published", "revision": 7}
{"source": "candidate", "base_revision": 7, "policy": { ...policy document v1... }}
```

Omitted means the current published snapshot. A pinned `revision` or a candidate
`base_revision` that is not the current revision returns 409 (the same
compare-and-swap rule as `If-Match` publication). A candidate is evaluated as the
revision it would receive (`base_revision + 1`) and every candidate result also
reports the published outcome for the same case.

If the published snapshot is not serving (unhealthy, or Kubernetes source lease
expired) or is below a case's `minimum_revision`, explain reports what enforcement
does: `decision: null`, `reason_code: pumgye.unavailable`, deciding stage `fence`.

## `POST /v1/explain`

Request: `{"snapshot"?, "case", "trace"? (default true), "on_behalf_of"?}`.

```json
{
  "version": 1, "kind": "simulation", "audit_id": 42,
  "snapshot": {"source": "published", "revision": 7, "serving": true},
  "result": {
    "outcome": {
      "decision": "AssuranceDenied", "allow": false,
      "reason_code": "pumgye.assurance_denied",
      "message_key": "pumgye.reason.assurance_denied",
      "hint_key": "pumgye.hint.assurance_denied",
      "deciding_stage": "assurance",
      "detail_code": "pumgye.detail.assurance_below_required"
    },
    "obligations": {"required_aal": 2},
    "trace": [
      {"stage": "fence", "result": "pass", "code": "pumgye.detail.fence_satisfied",
       "label_key": "pumgye.stage.fence", "detail": {"revision": 7, "minimum_revision": 0, "serving": true}},
      {"stage": "service", "result": "pass", "code": "pumgye.detail.service_found", "...": "..."},
      {"stage": "subject", "result": "pass", "code": "pumgye.detail.subject_assigned",
       "detail": {"map": "users", "subject": "u_writer", "roles": ["writer"],
                  "rights": {"permissions": ["read", "write"], "information_classes": ["public", "internal"], "minimum_aal": 2}}},
      {"stage": "network", "result": "pass", "code": "pumgye.detail.network_matched",
       "detail": {"ip": "192.0.2.1", "matched": {"index": 0, "cidr": "192.0.2.0/24", "roles": ["writer"]},
                  "shadowed": [{"index": 3, "cidr": "192.0.0.0/16", "roles": ["reader"]}]}},
      {"stage": "role_expansion", "result": "pass", "code": "pumgye.detail.roles_intersected",
       "detail": {"subject_roles": [{"role": "writer", "permissions": ["write"], "information_classes": ["internal"], "minimum_aal": 2},
                                    {"role": "reader", "inherited_from": "writer", "...": "..."}],
                  "network_roles": ["..."], "subject": {}, "network": {}, "effective": {}}},
      {"stage": "assurance", "result": "deny", "code": "pumgye.detail.assurance_below_required",
       "detail": {"presented": 1, "required": 2, "role_minimum": 2, "resource_minimum": 0}}
    ]
  }
}
```

`decision` is the exact `pumgye_core::Decision` variant name (or `UnknownResource`
/ `UnknownAction` on catalog paths), identical to the `reason` field of the decision
APIs. With a candidate the result also has
`"comparison": {"published": <outcome>, "changed": true|false}`.

### Stages

Stages are reported in actual evaluation order, which differs per entrypoint. The
deciding stage is the last `pass`/`deny` entry; later stages are listed as
`not_evaluated`. A Sumunjang denial is checked before identity because it dominates
every grant; role expansion is resolved at compile time and is reported where its
result (subject ∩ network rights) is used.

| Entrypoint | Order |
| --- | --- |
| permission (`user`) | fence → service → context → guard → subject → network → role_expansion → permission → information_class → assurance |
| resource (`user`, `workload`) | fence → resource → service_scope → action → context → guard → subject → network → role_expansion → permission → information_class → assurance |
| resource (`human`) | fence → resource → service_scope → context → principal_format → principal_assurance → action → guard → subject → network → role_expansion → permission → information_class → assurance |
| `kubernetes_api` | fence → resource → service_scope → context → action → subject → role_expansion → permission → information_class → assurance |

Permission and class stages distinguish an unknown name, a right no assigned role
grants (`*_missing_subject`) and a right the subject holds but the matched network
rule removes (`*_removed_by_network`), and list the roles that grant it on each
side (`granted_by_subject_roles`, `granted_by_network_roles`). The network stage
reports the winning rule (exact host entries win before prefixes) and up to 8
shadowed less-specific rules. Guard reports `guard_denied`, `guard_not_enforced`
(observe/unavailable on a `require_guard` service), `guard_enforced_allow` or
`guard_not_required`.

### Reason codes and message keys

Registered final codes (ADR 0019 namespace `pumgye.*`): `pumgye.allow`,
`unknown_service`, `guest`, `network_guest`, `permission_denied`, `class_denied`,
`assurance_denied`, `guard_denied`, `guard_unavailable`, `unknown_resource`,
`unknown_action`, `unavailable`. Each has `pumgye.reason.<suffix>` (sentence) and
`pumgye.hint.<suffix>` (remediation) keys. Every stage detail code
(`pumgye.detail.*`, listed in `pumgye_core::explain::DETAIL_CODES`) is its own
message key, and every stage has `pumgye.stage.<stage>`. The catalogs are
`crates/pumgye-core/messages/en.json` and `ko.json`; ICU parameters are named after
fields of the stage `detail` object. A contract test requires both catalogs to
contain exactly the registered keys. Adding a code requires a schema minor
version, both catalog entries and a test (ADR 0019).

## `POST /v1/explain/batch`

Request: `{"snapshot"?, "cases": [...], "trace"? (default false), "on_behalf_of"?}`.
One snapshot is loaded for the whole batch. Response: `results` (same shape as
`result`, in request order, `label` echoed) and

```json
"summary": {"cases": 4, "allowed": 4, "denied": 0, "unavailable": 0,
            "changed": 2, "allow_to_deny": 0, "deny_to_allow": 2}
```

(`changed`/`allow_to_deny`/`deny_to_allow` only with a candidate). This is the
impact (what-if) primitive of ADR 0019: Hangang streams retained historical
contexts in batches and aggregates changed outcomes. Any invalid case rejects the
whole batch (400) so a batch is never partially audited.

## `POST /v1/explain/diff`

Request: `{"base_revision", "policy", "cursor"? (0), "limit"? (100), "on_behalf_of"?}`.
Compares role-expanded compiled rights by name (vocabulary reordering is not a
change) between the current snapshot and the candidate:

```json
{"version": 1, "kind": "simulation", "audit_id": 43,
 "snapshot": {"source": "candidate", "revision": 8, "base_revision": 7, "candidate_sha256": "…", "serving": true},
 "total": 5, "next_cursor": 2,
 "changes": [
   {"entity": "assignment", "service": "orders", "map": "users", "subject": "u_reader",
    "change": "modified", "before": {...}, "after": {...},
    "delta": {"added_permissions": ["write"], "removed_permissions": [],
              "added_information_classes": ["internal"], "removed_information_classes": [],
              "minimum_aal": [0, 2]}},
   {"entity": "network", "service": "orders", "cidr": "198.51.100.0/24", "change": "modified", "...": "..."}
 ]}
```

Entities, in deterministic order: `information_classes`, then per service (sorted)
`service` (context, `require_guard`, permission vocabulary), `assignment` per map
and subject, `network` per CIDR; then `resource`. The cursor is an offset into that
order and is stable for an identical candidate and base revision.

## `GET /v1/audit/simulations?after_id=N`

Admin only. Up to 100 rows in ID order:

```json
[{"id": 42, "at_unix": 1792130000, "kind": "simulation", "actor": "mtls:…",
  "on_behalf_of": "console:alice", "operation": "explain", "source": "published",
  "revision": 7, "request_sha256": "…", "cases": 1, "allowed": 0, "denied": 1,
  "unavailable": 0, "changed": 0}]
```

`actor` is the transport identity (client certificate SHA-256 or loopback), never a
request field. `on_behalf_of` is caller-declared and untrusted; it is recorded for
correlation with the Hangang console audit only. `revision` is the published
revision for published simulations and the base revision for candidates.

## Hangang console broker contract (not yet implemented in Hangang)

Hangang should expose these operations to console plugins through its host API
broker, never directly from the browser:

| Console operation | Broker path | Pumgye call |
| --- | --- | --- |
| Simulate one request | `POST /v1/pumgye/explain` | `POST /v1/explain` |
| Simulate many / impact | `POST /v1/pumgye/explain/batch` | `POST /v1/explain/batch` |
| Draft impact diff | `POST /v1/pumgye/explain/diff` | `POST /v1/explain/diff` |
| Simulation audit | `GET /v1/pumgye/audit/simulations` | `GET /v1/audit/simulations` |

- The broker holds the Pumgye administrator credential and client certificate
  server-side, revalidates the console actor and permission (for example
  `policy:simulate`), sets `on_behalf_of` from its authenticated session (never from
  the browser) and forwards bodies unchanged within the bounds above.
- The broker rate-limits per console actor *before* Pumgye's process-wide bucket
  and maps 429/503 to the console retry state; 409 means the draft base is stale.
- The console renders `message_key`/`hint_key`/`code`/`label_key` with its EN/KO
  catalogs (seeded from the Pumgye catalogs) and labels every result *simulation*
  with `snapshot.source` and `snapshot.revision`.
- The broker records a Hangang `simulation` decision event (ADR 0019) referencing
  `audit_id`; Pumgye does not emit decision events itself.

## Hot-path performance

The trace-generic refactor was measured against `0409a7a` (the ADR 0021 regression
floor) and `849ca90` (the parent of this change) with one standalone release build per
revision of the same timed loop: `CompiledPolicy::evaluate` on one pinned core,
65,536 users and 65,536 `/32` network rules, 20 M decisions per run; *allow* is
all-allow, *mixed* rotates allow / permission / class / guard denials. Values are
medians in ns per decision; the host was shared (load average ≈ 7 on 16 cores), so
spread between runs was ±20 %.

| Pattern | `0409a7a` | `849ca90` | this branch |
| --- | --- | --- | --- |
| sequential, allow (5 runs) | 367.6 | 283.2 | 282.1 |
| sequential, mixed (5 runs) | 330.9 | 264.4 | 222.4 |
| shuffled, allow (5 + 9 runs) | 1242.9 | 506.9 / 599.4 | 619.6 / 581.6 |
| shuffled, mixed (5 + 9 runs) | 881.1 | 405.5 / 545.6 | 417.6 / 471.2 |

No configuration is slower than `0409a7a`; against `849ca90` the differences are
within run-to-run noise (the second shuffled series, 9 interleaved runs, has this
branch faster on both medians and minimums: allow min 520 vs 529 ns, mixed 417 vs
495 ns). The production instantiation is the same machine code path with the trace
calls removed; `no_alloc.rs` remains the deterministic guard. These numbers are
core-only and are not comparable with the mTLS request-chain figures in
[PERFORMANCE.md](PERFORMANCE.md).

## Limitations

- Model is policy version 1. ADR 0021 v2 stages (groups, explicit deny, zones,
  clearance, validity windows) will be added to the same trace when v2 exists.
- No who-can/what-can (ADR 0021 P1) and no stored candidate IDs: candidates are
  supplied inline per request.
- Explain results are not signed (ADR 0019 open question 6).
- Guard evidence is simulated input; explain does not query Sumunjang. Hangang's
  orchestrated simulation queries Sumunjang separately.

## Policy model version 2

`/v2/explain`, `/v2/explain/batch` and `/v2/candidates/diff` explain and diff the
version 2 model with stages `catalog`, `principal`, `explicit_deny`, `allow_set`,
`network_ceiling` and `clearance`, binding provenance, simulated time and
hypothetical groups. Codes and keys share the catalogs above (`pumgye.explicit_denied`
and the v2 `pumgye.detail.*` codes are registered). See [MODEL_V2.md](MODEL_V2.md).
