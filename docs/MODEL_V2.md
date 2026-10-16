# Policy model version 2 (ADR 0021 P0, unreleased)

[한국어](MODEL_V2.ko.md)

Version 2 replaces per-service subject maps and roles with Hopae-owned principals
and groups, global role templates, explicit allow and deny **bindings** with
lifecycle metadata, Catalog clearance labels and Sumunjang network zones
(Hangang ADR 0021). Version 1 stays authoritative until an operator approves a
cutover after a shadow window with zero unexplained mismatches; rollback
republishes version 1. The compiled snapshot stays bitset based and the hot path
stays allocation-free.

## Document

```json
{
  "version": 2,
  "catalog": {"revision": 12, "levels": ["public", "internal", "confidential", "restricted"],
              "compartments": ["finance", "hr"],
              "resources": {"db:payroll": {"service": "orders", "level": "confidential",
                            "compartments": ["finance"], "actions": {"select": "read"}, "minimum_aal": 2}}},
  "zones": {"source": "sumunjang", "revision": 418,
            "zones": {"corp": {"prefixes": ["10.0.0.0/8"]}, "office": {"prefixes": ["192.0.2.0/24"]}}},
  "templates": {
    "reader": {"permissions": ["read", "list"], "clearance_ceiling": {"level": "internal"}},
    "writer": {"permissions": ["write"], "inherits": ["reader"],
               "clearance_ceiling": {"level": "confidential", "compartments": ["finance"]}, "minimum_aal": 2}},
  "services": {
    "orders": {"permissions": ["read", "list", "write", "admin"],
               "network_ceiling": [{"zone": "office", "max": ["writer"]}, {"zone": "corp", "max": "reader"}]},
    "reports": {"permissions": ["view", "export"], "permission_map": {"read": "view", "list": "view"},
                "require_guard": false, "network_ceiling": [{"zone": "corp", "max": "reader"}]}},
  "bindings": [
    {"id": "bnd_alice_writer", "effect": "allow",
     "subjects": [{"kind": "human", "ref": "human1:<64 hex>"}], "role": "writer",
     "scope": {"services": ["orders"]},
     "conditions": {"zones": ["office"], "minimum_aal": 2, "expires_at": "2027-01-01T00:00:00Z"},
     "metadata": {"reason": "order desk", "approval_ref": "CHG-1001"}},
    {"id": "bnd_incident", "effect": "deny", "subjects": [{"group": "grp1:<26 crockford>"}],
     "permissions": "all", "scope": {"services": "all"}, "metadata": {"reason": "INC-77"}}]
}
```

A complete fixture is [examples/v2/policy.json](../examples/v2/policy.json); 21
adversarial fixtures with their expected located refusal are in
[examples/v2/adversarial](../examples/v2/adversarial). The serde model in
`pumgye_core::v2` is normative (`deny_unknown_fields` everywhere); a descriptive
JSON Schema is [docs/schema/policy-v2.schema.json](schema/policy-v2.schema.json).

| Element | Rules |
| --- | --- |
| Principal | `{kind, ref}`: `human` = `human1:` + 64 hex; `service` = `s_` + 48 hex; `workload` = `wk2:` + 64 hex (legacy Pod-bound `s_` accepted with a deprecation warning). Kind is part of the key: the same string under another kind is a different subject. |
| GroupRef | `grp1:` + 26 characters of `0123456789abcdefghjkmnpqrstvwxyz`, compared byte for byte (no case folding). Membership comes only from the signed Hopae projection; there is no request field for groups. |
| Template | Global; `permissions` (abstract names, mapped per service through `permission_map`, identity by default), `inherits` (≤ 8, acyclic), `clearance_ceiling` (`{level, compartments}` or `null` = no clearance), `minimum_aal` (max along the chain). |
| Service | `permissions` (≤ 256), `permission_map`, `network_ceiling` (`{zone, max}`, `max` = template, list of templates, or `"guest"`), `require_guard` (default true), context `network_and_guard` only (Kubernetes API services stay on v1, ADR 0022). |
| Binding | `id` `bnd_…` unique; `effect` `allow` (needs `role`) or `deny` (needs `permissions`: list or `"all"`); 1–64 `subjects`; `scope.services` list or `"all"`; `conditions` `zones` (list or `"any"`), `minimum_aal`, `not_before`/`expires_at` (RFC 3339, authority clock). |
| Metadata | `reason`, `approval_ref`, `source` (`native`, `kubernetes:<uid>`, `jit:<id>`, `migrated:v1`), and server-stamped `granted_by`, `created_at`, `revision` (body values are ignored). |
| Catalog | Read-only import of the Catalog owner: ordered `levels`, `compartments`, resource labels and action → permission. |
| Zones | Read-only import (`source: sumunjang` with the Sumunjang revision, or `local` CIDR fallback). |

Bounds (validated at compile; located `pumgye.validation.*` refusals): 4,096
services, 1,024 templates, 1,048,576 bindings and principals, 256 referenced
groups per snapshot (one projection shard), 64 zones and 65,536 prefixes, 256
permissions per service, 16 levels, 64 compartments, 64 grants per subject per
service, 8 templates per ceiling.

## Evaluation (ADR 0021 order)

1. **Fences** (authority): healthy and fresh snapshot, `minimum_revision`, and, when
   the snapshot references groups, a verified membership projection inside its
   staleness bound. Otherwise unavailable (never guest-to-allow).
2. Unknown service → `UnknownService`; context mismatch → `PermissionDenied`.
3. Sumunjang `deny` → `GuardDenied`; `require_guard` without enforced allow → `GuardUnavailable`.
4. Catalog: resource/action → permission and label; unknown resource/action/permission/class refuse.
   On the permission-shaped entrypoint the class names a level or a compartment
   (advisory label); on resource entrypoints the label is the Catalog's.
5. Principal: kind-keyed lookup plus projection groups (Humans). Nothing bound → `Guest`.
6. **Explicit deny**: a live deny matching subject or group, service, permission and
   zone → `ExplicitDenied`. Deny overrides every allow.
7. Allow set: live (validity window) allows whose zone condition intersects the
   request's zones. None live → `Guest`; none in zone → `NetworkGuest`.
8. **Network ceiling**: the most specific ceiling prefix (exact hosts first, like
   v1's longest prefix). None → `NetworkGuest`; `guest` bounds to nothing.
9. Permission: some live allow template and the ceiling grant it → else `PermissionDenied`.
10. **Clearance per granting template**: label level ≤ the template's level and
    compartments ⊆ its compartments, for both the binding template and the
    ceiling template → else `ClassDenied`. `reader@public` + `admin@internal`
    never yields `read@internal` unless an internal template grants `read`.
11. Assurance: presented AAL ≥ max(template chain, binding condition, ceiling,
    resource) for the best granting pair → else `AssuranceDenied` with
    `obligations.required_aal`.
12. `Allow`.

`ExplicitDenied` reaches unchanged v1 wire peers (PPG1, `/v1/decision`, gRPC) as
`PermissionDenied`; `/v2/explain` and the shadow report show the exact variant.

**AAL alignment.** AAL0 is machine evidence, 1–3 follow NIST SP 800-63B as issued by
Hopae; service and workload cases must present 0. A template, binding or resource
requiring an AAL above the projection's `max_aal` compiles with
`pumgye.warning.unsatisfiable_assurance` (status and explain) and is never
downgraded (Hopae now issues AAL3 only to opted-in applications).

**Validity.** `not_before`/`expires_at` are enforced on every decision by integer
comparison with authority time; `/v2/status` lists expired bindings and the next
validity boundary.

## Hopae owners

`--hopae-owner owner.json` configures one authenticated HTTPS client to Hopae's
admin listener (pinned CA, client certificate, optional bearer from an
environment variable, `x-hopae-admin-request: 1`):

```json
{"address": "https://hopae-admin.example.test:9443", "ca": "/etc/pumgye/hopae-ca.pem",
 "certificate": "/etc/pumgye/pumgye.pem", "key": "/etc/pumgye/pumgye.key", "token_env": "PUMGYE_HOPAE_TOKEN",
 "projection": {"audience": "pumgye", "keys": [{"issuer_ref": "hopae-groups", "key_epoch": 1, "public_key": "<base64>"}],
                "max_age_secs": 300, "max_staleness_secs": 900, "poll_interval_secs": 15},
 "lifecycle": {"poll_interval_secs": 30, "reconcile_interval_secs": 3600}}
```

**Caller credential.** Pumgye authenticates to Hopae's admin listener with mTLS
plus a scoped bearer (`token_env`). Use a **dedicated read-only Hopae credential
limited to `/v1/groups/projection/snapshot`, `/v1/groups/projection/changes`,
`/v1/subjects/lifecycle` and `/v1/subjects/lifecycle/snapshot`**; never an
administrator session or a write-capable role. If Hopae cannot yet scope a
credential to those routes, that route scoping is a Hopae-side prerequisite for
production (until then use the narrowest read-only role Hopae offers and keep the
credential in the private service environment).

**Membership projection** (Hopae `docs/GROUPS.md`). Pumgye sends the relevant group
vocabulary of the published snapshot and verifies every page exactly as the
contract requires: envelope format, pinned `(issuer_ref, key_epoch)` key (never one
from the envelope), strict Ed25519 over
`"hangang-zerotrust:hopae-membership-projection:v1\0" || payload bytes` before
parsing, then `kind`, issuer/epoch, `audience`, `vocabulary_sha256` and freshness
(`issued_at` within `max_age_secs`, ≤ 60 s ahead). Snapshot pages must echo the
requested cursor and the first page's watermark; the feed is applied from the
watermark with `from` equal to the requested revision and a non-decreasing
`next_cursor`; a different `store`, a continuity break or `410 cursor_expired`
triggers a new snapshot. Null principals and non-active entries are ignored;
`member_removed` (including suspended memberships), `member_added`/`restored` and
`group_deleted` are set operations. GroupRefs outside the vocabulary or not in
canonical lowercase refuse the page. The projection's `max_aal` feeds the AAL3
warning. After each successful refresh the membership is fresh for
`max_staleness_secs`; group grants fail closed beyond it. Key rotation: add the
next `(issuer_ref, key_epoch)` first, switch Hopae, then remove the old key.

**Subject lifecycle** (Hopae `docs/SUBJECT_DIRECTORY.md`). The reconcile snapshot
and feed (`created`, `disabled`, `enabled`, status-applied) run periodically.
Deleted principals are removed from binding subjects at compile time; a binding
whose subjects are all deleted is **orphaned** — excluded from compilation, kept
read-only in the document and listed in `/v2/status` until an administrator
republishes without it. Disabled principals are listed (`subject_disabled`) with no
rights change. With a complete lifecycle snapshot, publishing a new or changed
binding that names a deleted or unknown Human is refused
(`pumgye.validation.subject_deleted` / `subject_unresolved`).

## Sumunjang zone contract (CIDR fallback until Sumunjang exports zones)

Zones are owned by Sumunjang. Until Sumunjang ships `NetworkZone` and its zone
snapshot export, documents use `"source": "local"` zones (the converter's
`legacy.<service>.<n>` zones are proposals for Sumunjang). The contract Pumgye
consumes when Sumunjang exports zones:

- A revisioned snapshot `{"revision": N, "zones": {"<name>": {"prefixes": ["CIDR", …]}}}`
  with names matching `[A-Za-z0-9_.:-]{1,128}`, canonical prefixes (no host bits),
  ≤ 64 zones and ≤ 65,536 prefixes per Pumgye snapshot.
- Imported into the document as `"zones": {"source": "sumunjang", "revision": N, …}`
  and published through the normal CAS path, so the decision revision fences the
  zone revision. Signed fetch of the snapshot by Pumgye is ADR 0021 P1 (PPG2/HGD).
- Zone conditions and ceilings refer to names only; Pumgye never answers "is this
  IP allowed" — Sumunjang denial still dominates (stage 3).

## Admin API (`/v2`, administrator credential, management admission)

| Endpoint | Purpose |
| --- | --- |
| `GET /v2/policy` / `PUT /v2/policy` | Read / publish `{revision, policy}`; `If-Match: "<v2 revision>"` (`"0"` for the first). The new revision is one above every revision ever issued (v1 and v2 share one sequence and one publication audit with `document: v1|v2`). 409 with `current_revision`, located 422, 413. Refused in Kubernetes-owned mode. |
| `GET /v2/status` | Authoritative model, revisions, warnings, orphaned/disabled/expired bindings, next boundary, projection and lifecycle state, membership freshness, shadow gate. |
| `POST /v2/explain`, `/v2/explain/batch` | v2 explain (below). |
| `POST /v2/candidates/diff` | `{base_revision, policy, cursor?, limit?}` → (subject, service) rights changes: added/removed permissions and denies, condition changes, before/after grants. |
| `POST /v2/migration/preview` | Converts the current v1 document (`{workload_mapping?}`); never stored. |
| `GET /v2/shadow` | Decision-pair matrix, recent mismatches (≤ 64), explanations, gate. |
| `POST /v2/shadow/explanations` | `{service?, v1_decision?, v2_decision?, reason}`: classify future mismatches as explained (≤ 64 rules, audited with the actor). |
| `POST /v2/shadow/reset` | `{reason}`: start a new window. |
| `POST /v2/cutover` | `{approval_ref, reason}`: requires the gate; republishes the v2 document at a new revision and switches the model in one transaction. |
| `POST /v2/rollback` | `{reason}`: republishes the retained v1 document at a new revision and switches back. |
| `GET /v2/model/history` | Model switches with actor, approval reference, reason and the gate evidence. |

Errors use the structured explain-API body (`pumgye.error.*`, located details).

## Shadow evaluation and cutover

While a v2 document is published, every PPG1, HTTP, gRPC and resource decision is
also evaluated by v2 (same request, kind from typed evidence or the canonical
prefix on generic entrypoints) and compared, allocation-free: counts per
(v1, v2) decision pair, outcome mismatches (allow ≠ deny), reason-only drift,
explained/unexplained, and a bounded sample ring. Counters persist every 30 s and
resume after a restart when the revision pair is unchanged; any publication starts
a new window. The **gate** is satisfied when the window (`--shadow-window-days`,
default 7) has elapsed, decisions were observed and **unexplained** outcome
mismatches are zero. Explanations apply from the moment they are recorded;
resetting the window is explicit. After cutover v2 decides and v1 is shadowed;
replies carry the v2 revision. Rollback republishes v1 above every issued revision,
so client revision floors never move backwards.

## Migration (`pumgye --migrate-v1-to-v2 policy.json`)

Deterministic and fail closed; prints `{document, report}` without touching a
database. Roles become templates `<service>.<role>`; identical roles across services
are reported as merge candidates. `users` are classified by the owner lookup
(prefix form offline; the preview endpoint also requires Humans to be known to the
lifecycle feed); unresolved subjects are reported and **not migrated**.
`human_users` → `human`; `workload_users` → `workload` (`wk2:` only through an
administrator-confirmed mapping, otherwise deprecated legacy subjects). Networks
become local zones `legacy.<service>.<n>` (one per role set) and ceilings; the
ceiling AAL and binding conditions reproduce v1's union AAL. Classes become ordered
levels when every role's class set is downward closed in the v1 vocabulary order,
otherwise compartments under one base level (exact v1 membership per template),
with a review item for the Catalog owner. Cross-role class unions that v1 allowed
are reported (`pumgye.migration.class_union`). Kubernetes API services and the RBAC
mapping stay on v1.

The parity test converts the v1 qualification corpus and compares every decision:
zero unexplained allow/deny mismatches; the remaining differences are exactly the
subjects and unions the report lists.

## Explain v2

`POST /v2/explain {snapshot?, case, trace?}` and `/v2/explain/batch {snapshot?, cases, trace?}`
use the same evaluation function with a recording tracer. Cases:
`{subject: {kind, id}, service, resource+action | permission+information_class, ip,
aal, guard, minimum_revision?, at?, hypothetical_groups?}` — `at` simulates authority
time, `hypothetical_groups` replaces the projection for one Human case. Stages:
`fence, service, context, guard, catalog, principal, explicit_deny, allow_set,
network_ceiling, permission, clearance, assurance`, each with registered
`pumgye.detail.*` codes; deny and contributing allow bindings are reported with
provenance (`id`, role, conditions, `reason`, `granted_by`, `approval_ref`,
`source`, `revision`). Candidate snapshots add a comparison with the published
outcome. Every call is audited as `explain_v2`/`explain_v2_batch`/`diff_v2`.

## Performance

Release build, single pinned core, 65,536 service principals each with one direct
binding and 65,536 `/32` ceiling prefixes, versus v1 at the same cardinality in the
same process (interleaved rounds, ns per decision, minimums of 6 rounds on a shared
host with load ≈ 5):

| Case (sequential subjects) | v1 | v2 |
| --- | --- | --- |
| allow | 256 | 271 |
| permission denied | 237 | 258 |
| class denied | 246 | 258 |
| Sumunjang observe | 21 | 16 |
| shuffled allow | 462–475 | 443–461 |
| shuffled mixed | 351–355 | 357–371 |

Single-path cases are within +4–11 % of v1 and faster than the ADR's `0409a7a`
regression floor (≈ 368 ns sequential, ≈ 1,243 ns shuffled allow measured with the
same loop on this host). Evaluation is allocation-free (`tests/no_alloc.rs` covers
every v2 outcome).

**Residual (open).** A strictly alternating mix of four outcomes over *sequential*
subjects (the whole working set cache-resident, ≈ 200 ns of pure CPU per decision)
remains +20–28 % slower than v1 after a focused attempt (straight-line fast path for
unconditional single grants with the general path out of line, combined
ceiling/clearance loop, compact ceiling indexes, FNV vocabularies). Analysis: v2
resolves the permission bit *and* the Catalog label for every request at stage 4
(ADR order), and evaluates the ceiling and clearance per template, while v1 resolves
the class lazily and stops at the first failing union check; with outcomes
alternating every request, the extra hash lookup and the per-template clearance
branches are not hidden by memory stalls. The absolute delta is ≈ 40 ns; on the
cache-missing *shuffled* mix (65,536 principals) v2 is at parity (391–397 vs
400–415 ns) and on the measured mTLS request chain (≈ 7 µs per decision) it is below
1 %. Removing it would require dropping the ADR stage order (resolving labels lazily)
or caching per-(principal, service, permission) results, both rejected for P0.

## ADR 0021 P0 acceptance status

| Gate | Status |
| --- | --- |
| v2 schema, valid and adversarial examples | Done (serde model, JSON Schema, 1 + 21 fixtures) |
| Compiler and evaluator (deny, groups, templates, zones, clearance, validity) | Done |
| Explain `NoTrace`/`VecTrace` parity | Done (corpus parity tests) |
| Candidate diff | Done |
| v1 → v2 converter and shadow mode | Done |
| Property tests (deny monotonicity, ceiling-only-reduces, no rights without binding, kind isolation, expiry) | Done (deterministic generators) |
| Adversarial fixtures (group spoofing via header, orphan, AAL3 unsatisfiable, class header mismatch) | Done: no group input exists on any request shape (unknown fields refused), projection forgeries refused; orphans; AAL3 warning without downgrade; client class is advisory on the permission path and never accepted on resource paths |
| v1/v2 shadow parity on the qualification corpus | Done in tests; the 7-day production window is an operational gate |
| Performance within 10 % of `0409a7a` | Met against the ADR floor; versus current v1, single paths +4–11 % and a cache-resident alternating mix +20–28 % (residual analysed above) |
| Hopae membership projection + lifecycle consumption | Done: unit-tested with signed pages and qualified live against Hopae `integrate/identity-platform` (`60b3a60`) with the local interop tool (20/20) |
| Sumunjang `NetworkZone` export | Contract defined; local CIDR fallback until Sumunjang ships it |
| Real four-component chain on the remote k3s (ADR 0022) | Not run in this change |

## Local interoperability qualification (opt-in)

`tools/hopae_v2_interop.py` runs a real Hopae (`integrate/identity-platform`,
groups + subject directory) and a real Pumgye as loopback processes, without a
cluster or OIDC provider:

```sh
python3 tools/hopae_v2_interop.py --hopae <hopae binary> --pumgye target/debug/pumgye [--workdir DIR] [--keep]
```

It configures Hopae with the projection key, the native Human receipt issuer
(needed for `human1:` subjects, which requires Hopae's mTLS gRPC listener) and the
unified delegation key; lays people down in Hopae's store with SQL as Hopae's own
scenario tests do; creates groups, memberships and disables through Hopae's real
admin API; and points Pumgye's `--hopae-owner` at a loopback mTLS relay that signs
delegated requests and admits only the four projection/lifecycle read routes (the
shape of the dedicated read-only credential above). Checks (20): signed snapshot
and feed consumed; group-based allow; explicit deny precedence; feed removal
revokes; Hopae unreachable → fail closed after `max_staleness_secs`, then recovery;
disable → `subject_disabled` without rights change; store deletion → orphaned
binding and refusal of new bindings to the deleted principal; journal pruned behind
Pumgye's cursor → `410 cursor_expired` → resnapshot and convergence. Needs Python
3.11+ and the `cryptography` package. Last run: 20/20 against Hopae `60b3a60`.

## Limitations

- JIT access requests, access reviews, who-can/what-can and PPG2 are P1/P2.
- Group grants apply to Human principals (the projection carries `human1:` subjects).
- Permit owners in v2 mode receive v1-shaped Catalog metadata (level as the
  information class; compartments are not yet carried in permits).
- Projection sharding beyond 256 relevant groups is P1.
- Group grants for workloads (namespace/ServiceAccount principals, Hopae
  `feat/k8s-workload-identity`) are P1.
