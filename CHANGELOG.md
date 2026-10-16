# Changelog

## Unreleased

### Added

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

### Changed

- All evaluation entrypoints delegate to one evaluator generic over a trace sink;
  production uses the zero-sized `NoTrace`. Decisions are unchanged, the hot path
  remains allocation-free (new allocation-counting test) and compiled network
  entries keep their size.
- The SQLite schema gains an additive `simulation_audit` table (created on start).
