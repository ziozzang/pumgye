# Pumgye (품계)

Deterministic service authorization for Hangang. Hopae owns identity and sessions;
Sumunjang supplies network evidence; Pumgye owns service roles, permissions and
information classes. Hangang enforces the combined result.

The initial Rust library compiles bounded policies into immutable permission
bitsets and Sumunjang's compressed IP prefix trie. User and network rights must
both permit the request. Unassigned users are guests. Network deny dominates,
and mandatory network enforcement rejects unavailable or observe evidence.

Native gateway enforcement, configuration CAS publication and the administrator
matrix are integrated in [Hangang](https://github.com/ziozzang/hangang/pull/5).
Qualification covers owned HOP1/HGD1 fixtures and the deployed Linux binaries;
this does not establish 100k end-to-end HTTP QPS. Callers must
provide authenticated identity, trusted transport IP and verified Guard evidence;
these enums do not themselves authenticate a remote peer.

Run `cargo test` and `cargo clippy --all-targets -- -D warnings`.

[한국어](README.ko.md)

Qualify an owned gateway process with `python3 tools/hangang_smoke.py --gateway-binary /path/to/hangang`. The fixture tests guest/observe/deny rejection, CAS publication and streaming revocation without operational credentials.
