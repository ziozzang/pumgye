# Changelog

## Unreleased

### Added

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
- Opt-in local Hopae interop qualification (`tools/hopae_v2_interop.py`).
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
