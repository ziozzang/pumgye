# Changelog

## Unreleased

### Added

- The `observed-*` owners reload their Hopae client certificate and CA without a
  restart. They use the Hopae SDK reloadable endpoint (ziozzang/hopae#15).
  `hopae-grpc` is pinned to `1c23931` (ziozzang/hopae#17); move the pin to
  the merged rev.
- Prometheus `GET /metrics` on the HTTPS management listener, readable with the
  administrator credential or an optional read-only scrape credential
  (`--metrics-token-env`). It covers:
  - decisions by context, outcome and reason
  - per-transport latency histograms
  - policy revision and publication CAS conflicts
  - shadow v1/v2 mismatches
  - Hopae owner freshness and `cursor_expired`
  - simulation audit rows
  - TLS reload counters and leaf expiry
  - observed permit issuance and refusals

  Recording is allocation-free, and no label carries a subject or IP.
- The Kubernetes API source counts CA/token rotations, which it already re-reads on
  every relist. A test now covers rotation without a restart.
- TLS hot reload (`--tls-reload-interval-secs`, default 10 s, content polling,
  no inotify) for the HTTP, PPG1, gRPC and SAR listeners, the Sumunjang/Hopae
  live clients and the Hopae owner client. Invalid material keeps the previous
  configuration and raises `tls_reload_failing` in `/v1/status`. See
  `docs/SERVER.md`.
- Policy model version 2 (Hangang ADR 0021 P0): Hopae-owned principals and
  GroupRefs, global role templates with per-service permission maps, allow and
  explicit-deny bindings with validity windows and server-stamped metadata,
  Catalog clearance labels (levels + compartments), Sumunjang zone imports with a
  local CIDR fallback, allocation-free evaluator in the ADR order, explain v2 with
  binding provenance, candidate diff, deterministic v1→v2 converter
  (`--migrate-v1-to-v2`, `/v2/migration/preview`), JSON Schema and valid /
  adversarial fixtures. See `docs/MODEL_V2.md` / `docs/MODEL_V2.ko.md`.
- Hopae owners (`--hopae-owner`): signed membership projection verification and
  application (pinned keys, strict Ed25519 with domain separation, vocabulary and
  freshness binding, cursor/watermark continuity, 410 resnapshot) and the subject
  lifecycle feed with orphan reconciliation.
- Opt-in local Hopae interop qualification (`tools/hopae_v2_interop.py`): direct
  Hopae service credential (`hsc1`, preset `pumgye-v2`), workload principals.
- Kubernetes workload principals: v2 bindings by `wk2:` principal or SPIFFE ID,
  wire-subject aliases from Hopae `include_workloads` lifecycle events, retirement
  orphans, `GET /v2/workloads` and reasoned `POST /v2/workloads/regrants/apply`.
- AAL3 from Hopae-sealed evidence (receipts, permission contexts, observed Human
  permits); `SealedAssurance`; explain `assurance_evidence`.
- Hopae owner client: `token_file`, `audience` (`x-hopae-audience`) and
  `connect_address` for Hopae route-scoped service credentials.
- Shadow evaluation of v2 beside v1 with persisted counters and explanations; the
  zero-unexplained-mismatch cutover gate (`--shadow-window-days`), approved cutover,
  rollback and model history; `--v2-production` reason requirement.

- Administrative explain API (ADR 0019 D2, ADR 0020 simulator, ADR 0021 P0 explain
  and candidate diff): `POST /v1/explain`, `POST /v1/explain/batch`,
  `POST /v1/explain/diff` and `GET /v1/audit/simulations`, administrator
  credential only. Ordered stage traces (fence, service/resource/scope, context,
  principal, action, Sumunjang evidence, subject map, network rule with shadowed
  rules, role expansion, permission, information class, assurance), registered
  `pumgye.*` reason/detail codes with en/ko message catalogs
  (`crates/pumgye-core/messages/`), step-up obligations, what-if against an
  unpublished candidate with published comparison and impact summary, revision
  pinning with compare-and-swap conflicts, bounded batches and diff pages, a
  simulation token bucket, and a separate `kind=simulation` audit table.
  See `docs/EXPLAIN.md` / `docs/EXPLAIN.ko.md`.
- `pumgye_core::Tracer`, `NoTrace`, `VecTrace` and `*_traced` evaluation
  entrypoints; `pumgye_core::explain` and `pumgye_core::diff`.
- `simulation_queries` in `GET /v1/status`.
- Structured, located errors (`{"error":{code,message_key,details[{path,code,message_key}],current_revision?}}`)
  for 400/409/413/422/429 on the explain/batch/diff/audit-simulations endpoints only;
  candidate validation reports the document path and a registered
  `pumgye.validation.*` code (`Policy::compile_located`, `PolicyViolation`).
- `--simulation-audit-retention-days` (default 30): simulation audit rows are trimmed
  by age and by the 100,000-row cap on every insert.

### Changed

- v1 and v2 publications share one revision sequence: `PUT /v1/policy` issues the
  next global revision, and the publication audit carries `document: v1|v2`.
- `pumgye_core::Policy::compile` errors carry document-path context.

- All evaluation entrypoints delegate to one evaluator generic over a trace sink;
  production uses the zero-sized `NoTrace`. Decisions are unchanged, the hot path
  remains allocation-free (new allocation-counting test) and compiled network
  entries keep their size.
- Policy compile errors now carry document-path context (`at services.<id>…`);
  refusal behaviour is unchanged.
- The SQLite schema gains an additive `simulation_audit` table (created on start).
