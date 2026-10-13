# Kubernetes authority adapter

[한국어](KUBERNETES.ko.md)

The server provides a bounded **read-only RBAC inventory** command:

```sh
pumgye --inspect-kubernetes-rbac rbac-list.json --kubernetes-cluster example-cluster
```

Input is a `v1/List` of `rbac.authorization.k8s.io/v1` Role, ClusterRole,
RoleBinding and ClusterRoleBinding objects. Include referenced roles in the same
collection. The maximum input is 4 MiB / 4096 objects. Include persisted metadata
UID/resourceVersion and explicit namespace for each ServiceAccount subject.
Export only these RBAC resources, not Secrets or an unrestricted all-resource dump.
Output contains role names and subjects; handle it as authorization metadata.

The command returns before opening the policy database or network listeners and
requires no administrator/decision token. Output is deterministically ordered and
preserves cluster identity, object UID, opaque resourceVersion, native rules,
aggregation selectors, role references and subjects. Unknown rule fields, source
kind/API, duplicate identity, wrong reference scope and unresolved roles fail the
whole inspection. Resource versions are never interpreted as integers.

The inventory does not prove a globally atomic Kubernetes collection, evaluate
Kubernetes API access or publish application permissions. Aggregation metadata is
preserved, not evaluated; live role aggregation must be observed through the API.
Offline output does not verify ServiceAccount identity or token validity. It does
not change the existing SQLite authority or active memory snapshot.

Next gates are authenticated bounded list/watch and full relist recovery, explicit
application permission mapping and source-aware publication. Workload identity
verification through TokenReview remains pending. Revocation, follower fences and
actual cluster qualification are also required. Do not use this
inventory as an allow decision. Four-component source ownership and Kubernetes
semantics are defined in [ADR 0015](https://github.com/ziozzang/hangang-zerotrust/blob/main/docs/adr/0015-kubernetes-iam-authority.md).

## Live read-only HTTPS collection

```sh
pumgye --observe-kubernetes-rbac --kubernetes-cluster example-cluster \
  --kubernetes-api https://kubernetes.example.test \
  --kubernetes-namespace example \
  --kubernetes-ca /run/secrets/kubernetes-ca.pem \
  --kubernetes-token /run/secrets/kubernetes-token
```

This separate observation command opens no authority DB or decision listener. It
collects all four RBAC kinds and emits newline-delimited observations. Namespace
scope applies to Role/RoleBinding; ClusterRole/ClusterRoleBinding discovery still
requires explicit cluster-wide read permissions. Omitting namespace collects
namespaced resources across the cluster. It reads no Secrets. Use a dedicated
read-only identity, not the Ingress controller's unrelated credentials.

Only an HTTPS origin with the configured CA is accepted: public root trust,
redirects and environment proxies are disabled. Bounded token/CA files are read
again every collection cycle. Each HTTP request has a three-second deadline;
the whole collection has fifteen seconds. There are at most 32 pages per kind,
4096 total objects and 4 MiB total response bytes. Continuation tokens are encoded
as query parameters and cycles are rejected; each kind's opaque collection version
must remain identical across pages. Any HTTP error, including expired continuation,
restarts from a complete fresh collection on the next cycle, never from partial
state. Different kinds have independent collection versions: this is not a globally
atomic cross-resource snapshot.

An immutable ArcSwap observation has a local process revision, the four collection
versions, inventory and process-relative `valid_until_ms`. Changes, deletion and
source version changes advance this local revision; identical observations retain
it. The old view is removed before collection and failures emit `available:false`.
Freshness lasts at most one second after collection. Output is diagnostic metadata,
not a reusable authorization receipt; it contains no verified workload identities,
application mapping or policy grants. Revisions are not durable authorization
floors and reset when the observer restarts.

The collector waits one second between complete collection cycles. This is an
initial read-only polling path, not the planned scalable watch adapter. Do not
turn it on for every production replica as a substitute for bounded shared
list/watch reconciliation. Watch bookmarks, resource-specific resume, source-aware
publication, replica recovery and actual Kubernetes API-server qualification
remain required. Current native policy authority and production settings are
unchanged.

Run the owned HTTPS fixture:

```sh
python3 tools/kubernetes_source_smoke.py --binary target/debug/pumgye
```

It verifies pagination, opaque versions, deterministic observations, deletion,
version/scope/redirect rejection, recovery after HTTP 410, token/CA file changes,
proxy isolation and no authority DB or credential output. The source protocol
follows [Kubernetes API pagination](https://kubernetes.io/docs/reference/using-api/api-concepts/#retrieving-large-results-sets-in-chunks).
