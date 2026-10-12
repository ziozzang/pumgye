# Pumgye (품계)

Deterministic service authorization for Hangang. Hopae owns identity and sessions;
Sumunjang supplies network evidence; Pumgye owns service roles, permissions and
information classes. Hangang enforces the combined result.

The initial Rust library compiles bounded policies into immutable permission
bitsets and Sumunjang's compressed IP prefix trie. User and network rights must
both permit the request. Unassigned users are guests. Network deny dominates,
and mandatory network enforcement rejects unavailable or observe evidence.

This is an implementation in progress: native gateway enforcement, policy
publication and the administrator matrix are not yet integrated. Callers must
provide authenticated identity, trusted transport IP and verified Guard evidence;
these enums do not themselves authenticate a remote peer.

Run `cargo test` and `cargo clippy --all-targets -- -D warnings`.

[한국어](README.ko.md)
