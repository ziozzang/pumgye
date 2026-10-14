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

## Explicit application mapping candidates

A bounded administrator-owned mapping file can be supplied to either inspection
or live observation with `--kubernetes-mapping`. Try the fictional examples:

```sh
pumgye --inspect-kubernetes-rbac examples/kubernetes-rbac-list.json \
  --kubernetes-cluster example-cluster \
  --kubernetes-mapping examples/kubernetes-mapping.json
```

A mapping defines a full native policy template with no independent user grants,
then explicit grants selecting a service/application role, verified native subject
reference, exact Kubernetes subject and pinned Role/Binding kind, namespace, name
and UID. A same-name recreated Role/Binding does not satisfy its old pin. All source
rule requirements must match literal API group/resource (including subresource),
verb, resource namespace and optional resource name. RoleBindings cannot satisfy
cluster-wide or foreign-namespace requirements. Wildcards do not implicitly match
literal requirements, and requirement wildcards, privileged bind/escalate/impersonate
or serviceaccount token issuance are refused. Group and aggregated-role translation
require additional verified membership/reconciliation and remain unsupported.
The configured resource namespace is an explicit administrator constraint; API
discovery and native authorizer qualification still have to verify resource scope.

The source cluster must match exactly. Missing/recreated objects, changed roleRef,
removed subjects/rules and restricted resource-name mismatches produce an inactive
mapping and remove its candidate user assignment. Every refresh rebuilds from the
empty-user template; it never retains yesterday's source-derived grants. The native
candidate is recompiled and still enforces network rights and required Sumunjang
evidence. Multiple explicit matches union only their declared application roles.
The complete mapping is at most 64 KiB, 256 grants and 16 required rules per grant.

Output adds `candidate.mode=candidate_only`, the exact mapping-file SHA-256, candidate
policy and per-mapping active/reason fields. Live output wraps the observation under
`source`; candidate computation/serialization is followed by a final source freshness
check. The mapping file is loaded once; changing it requires a new observation
process and new reviewed mapping digest. No policy DB, API grant or authority
revision is updated. Do not POST this diagnostic candidate as an automatic production
grant: it lacks durable source-authority publication and globally reconciled source
fences. `native_subject` is an operator-provisioned association, not proof that a
Kubernetes subject authenticated; Hopae still must verify the actual request and
its cluster/issuer/audience/bound-object identity. These examples contain fictional
identities and UIDs and must not be used as operational assignments.

The owned HTTPS fixture also supports `--mapping`; it checks mapped candidates and
withdrawal after source deletion alongside failure recovery and credential rotation.

## Actual API qualification

The collector accepts missing item kind/apiVersion only inside a validated typed
RBAC collection, supplying its known API/type. Explicit conflicting item types or
versions fail the collection; this does not relax offline mixed-List inspection.
Real Kubernetes typed lists may omit item TypeMeta, while kubectl supplies it in
combined output. The owned v1.37.0 API fixture found and verifies this distinction.

```sh
python3 tools/kubernetes_real_cluster.py --binary target/debug/pumgye \
  --state-dir /private/owned-kind-qualification
```

The fixture is restricted to the named owned kind cluster and private kubeconfig,
using unique namespaces and read-only source identities. Namespace Role/Binding
reads and cluster Role/Binding reads have separate RBAC grants. It verifies actual
collection/candidate mapping, Binding deletion withdrawal, recreated Binding UID
refusal, credential failure/recovery and no policy DB creation. Fixture RBAC and
namespaces are removed. Python PyYAML and the cluster's bundled kubectl are required.
Native subject is an explicit fictional reference: this fixture does not claim
Hopae workload association, automatic authoritative publication or production
activation. v1.37.0 is qualified here; other versions and scalable watches remain
separate gates.
