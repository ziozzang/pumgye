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
application permission mapping and source-aware publication. Hopae separately verifies workload identity through TokenReview and live object UID checks. Distributed follower fences and full-chain qualification are still required. Do not use this
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
the whole collection has one second. There are at most 32 pages per kind,
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
Freshness ends one second after collection starts; network, parsing and hashing consume that budget. Output is diagnostic metadata,
not a reusable authorization receipt; it contains no verified workload identities,
application mapping or policy grants. Revisions are not durable authorization
floors and reset when the observer restarts.

The collector waits one second between complete collection cycles. This is an
initial read-only polling path, not the planned scalable watch adapter. Do not
turn it on for every production replica as a substitute for bounded shared
list/watch reconciliation. Watch bookmarks, resource-specific resume, source-aware
replica recovery and scalable watch reconciliation remain required. Current native policy authority and production settings are
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
then explicit grants selecting a service/application role, administrator-supplied native subject
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


## Kubernetes source-authoritative decisions

`--authorize-kubernetes-rbac` runs the same collector and explicit mapping as the
sole writer of the server's durable policy and immutable decision view. Supply
all observation connection arguments plus `--kubernetes-mapping`, the usual
`--database`, initial `--policy`, administrator/decision credentials and listener
TLS options. Use a separate database for this source mode. Inspection, observation
and authoritative modes are mutually exclusive.

The server compiles the mapped policy and commits policy/revision/audit together
before installing it. Policy changes advance the durable revision; identical
policy renewal does not create audit churn. Binding deletion or UID replacement
removes mapped users on reconciliation. Administrator `PUT /v1/policy` returns
409 in this mode. A persisted source-owner marker also rejects restarting that
DB as a native-policy writer. Switching authority requires an explicit migration,
not omission of a command-line flag.

Every process starts with decisions unavailable, even with a previously granted
policy in SQLite. It withdraws availability before each complete collection;
HTTP/mapping/compilation failures never reuse the previous permit. A live view
expires one second after collection starts, including compilation
and durable-write time. Persistence uncertainty fences the authority until restart.
The loop pauses 500 ms between collections. Source health and decision eligibility
are reported by `/healthz` and authenticated `/v1/status`; administrative policy
reads remain available for inspection of the last durable policy. HTTP and PPG1
use the same source gate, without a DB access on each decision.

This conservative polling implementation deliberately has unavailable intervals
while collecting. It is not a high-availability watch/follower implementation or a
claim of globally atomic cross-kind RBAC observation. Each `native_subject` remains
an explicit administrator association; this phase does not automatically establish
its relationship with Hopae's verified workload identity. Keep the file private,
review exact UID pins and application translation, and never use unverified client
headers as subjects. Production source mode has not been enabled by this fixture.

```sh
python3 tools/kubernetes_real_cluster.py --binary target/debug/pumgye \
  --state-dir /private/owned-kind-qualification --authority
```

The owned actual API fixture additionally verifies native HTTP allow/deny,
durable deletion revision, writer exclusion, authentication failure recovery and
restart refusal of cached grants in an isolated DB. Automatic verified Hopae
association, watch reconciliation and full Hangang integration qualification are
subsequent gates.


## Hopae workload subject association

A grant can use `workload` instead of an opaque `native_subject` reference. The
fictional [workload mapping](../examples/kubernetes-workload-mapping.json) pins
issuer, namespace, ServiceAccount name/UID and Pod name/UID. The mapping's cluster
is Hopae's configured `cluster_id`. These exact strings derive the canonical
Hopae Workload subject, so operators do not copy opaque subject hashes manually.
The workload namespace/account must match the grant's RBAC ServiceAccount subject.
Supplying both forms is rejected. User, network and non-workload authentication
continue to use their explicit native references.

This derives an identity address; it does not authenticate a credential. Hopae
still owns issuer/audience checks, trusted TokenReview, current object UID/deletion
verification and bounded evidence. Hangang must obtain that subject through the
trusted native authentication path. The issuer/cluster and both UIDs are part of
the identity domain: another Pod of the same ServiceAccount receives another
subject, and recreated objects do not inherit this pinned grant. The mapping is
administrator-owned and static for this server process; automatic live discovery,
source editing, UID repinning and distributed watches remain separate work.

The canonical algorithm matches Hopae's existing implementation: SHA-256 of
`hopae:kubernetes:pod-subject:v1` followed by a NUL and each namespace/account
name/account UID/Pod name/Pod UID as a big-endian u32 byte length then UTF-8 bytes,
rendered as `w_` plus full lowercase hex. Hash principal-kind byte `2` followed by
issuer/cluster/that workload string, each with a big-endian u64 byte length and
UTF-8 bytes. The first 24 digest bytes render as `s_` plus lowercase hex. Hashing
runs during policy compilation, not per decision. This address is not a signed
receipt or a substitute for authenticated evidence.

```sh
python3 tools/kubernetes_real_cluster.py --binary target/debug/pumgye \
  --state-dir /private/owned-kind-qualification --authority \
  --hopae-driver /path/to/hopae/target/debug/examples/qualify_kubernetes_tokenreview
```

The actual owned v1.37.0 fixture additionally uses signed Pod-bound TokenRequest
credentials, native Hopae TokenReview/live-object verification and the pinned
workload mapping. The subject computed by Pumgye must match the native Hopae
subject and allow the mapped role over mTLS HTTP/pooled PPG1. A second genuinely
verified Pod of the same ServiceAccount remains guest; deleting the first Pod
invalidates its credential. Existing Binding deletion/recreation, source failure,
writer exclusion and restart fences remain checked. This qualifies the two native
components' association, not the complete Hangang request/stream pipeline.


## Four native component request qualification

Supply three additional executable paths to the owned workload qualification:

```sh
python3 tools/kubernetes_real_cluster.py --binary /path/to/pumgye \
  --state-dir /private/owned-kind-qualification --authority \
  --hopae-driver /path/to/qualify_kubernetes_tokenreview \
  --gateway-binary /path/to/hangang --hopae-binary /path/to/hopae \
  --sumunjang-binary /path/to/sumunjang
```

`kubernetes_gateway.py` starts actual Hangang, Hopae and Sumunjang processes beside
the existing Pumgye source authority, using only fresh fixture state and keys.
The public request uses HTTPS; the application's configured port matches the
owned listener's actual TLS port. HOP1, PPG1 and HGD1 use pinned mTLS with separate
application credentials. Native Hopae verifies actual Kubernetes Pod-bound tokens.
This fixture refuses a gateway binary lacking the required native TLS flags rather
than downgrading to an unauthenticated protocol peer.

Only the mapped Pod reaches the backend. Another valid Pod and spoofed unauthenticated
identity headers do not. The backend receives the canonical Workload subject,
AAL zero and the matching service, and never the incoming Authorization credential.
Actual Sumunjang observe evidence fails the required Guard gate; an explicit IP
block denies access and removal recovers it. Binding deletion prevents subsequent
upstream requests, a source credential failure returns unavailable, and Pod deletion
returns authentication denial. All rejected cases check that no backend request
was issued. The delegated Hangang policy/status API exposes Kubernetes ownership
and rejects a source-policy overwrite even with the correct native administrator
and both revision fences.

The fixture closes its processes, removes its unique Kubernetes resources and
leaves production configuration/images unchanged. This qualifies actual request
enforcement; it does not prove streaming credential withdrawal, Kubernetes Pod
packaging/Ingress ownership, distributed watch/follower availability, CNI-wide
network protection or full-chain throughput. Conservative source polling still
has unavailable collection intervals. These remain explicit completion gates.


## Actual Hopae workload renewal

Add `--qualify-renewal` to the four-component command. After the normal
Kubernetes-authoritative Binding/source/restart checks, a separate fixture uses
an isolated native Pumgye DB bootstrapped from the previously verified candidate.
This fixed policy deliberately isolates authentication renewal from the polling
source's unavailable intervals; it is not a fallback or a production source-mode
change, and does not qualify Kubernetes RBAC watch continuity.

Actual Hopae, Hangang, Sumunjang and the isolated Pumgye process use native mTLS.
The stream enables `auth.renew_native_evidence`, uses the real Pod-bound signed
token and remains open with heartbeat bytes for more than 2.2 seconds. Deleting
the actual Pod then closes that stream within the owned fixture's 1.5-second
post-delete deadline and makes subsequent authentication return 401. Backend
identity/AAL/service and credential stripping assertions remain active. Fixture
DBs/processes/resources are separate and cleaned up; production is unchanged.

The private report names the fixed-policy isolation explicitly and records that
RBAC watch continuity is not qualified. This advances actual provider renewal
qualification without treating authentication and authorization source freshness
as interchangeable. Distributed watches, failure topology and fleet throughput
remain additional gates.


Slow complete collections are refused instead of being given a fresh lease at
completion. The one-second whole-collection timeout and post-normalization age
check fence network and CPU delay; overflow is refused. A 1.2-second owned HTTPS
response must produce unavailable and then recover on the next successful cycle.
This fixes stale collection age, but does not establish a globally atomic
cross-kind RBAC snapshot or continuous watch availability. Large/slow sources
that cannot fit the budget remain unavailable until scalable reconciliation is
implemented; the budget must not silently expand to publish old grants.


## Source transport pool reuse

The collector retains a pinned HTTPS client when the actual CA/token material
fingerprint is unchanged. Files are still read and validated every cycle and the
Authorization header is freshly constructed as sensitive data. Changed material
retires the previous trust pool before constructing its replacement; invalid CA
cannot fall back to the old pool. No raw credential is included in diagnostic
fingerprints or output. The pool retains at most two idle connections per origin
with ten-second idle expiry; this is transport reuse, not an authorization cache.
Source freshness still expires one second from collection start.

The owned HTTP/1.1 HTTPS fixture counts accepted TLS connections: two unchanged
complete paginated cycles use one connection, while credential change and recovery
open replacement connections. Existing CA failure/recovery, redirect, HTTP 410,
slow collection and deletion checks remain. The actual Kubernetes/four-process
and isolated renewal fixture also passes. This reduces repeated handshake work;
full-chain throughput and scalable watch reconciliation remain unqualified.

## Integrated administration status

The authenticated `/v1/status` response reports `source_state`: `native`,
`starting`, `collecting`, `fresh`, `expired`, `collection_failed`,
`candidate_rejected`, or `persistence_failed`. `source_lease_remaining_ms` is
process-local time remaining at response generation, not a reusable permission
receipt. `source_writable` describes whether the native policy publication API
accepts writes; it does not promise healthy storage or Kubernetes edit privileges.
`policy_revision` is the last applied local revision; persisted policy remains
inspectable during a source outage and must not be mistaken for a live grant.
Errors are bounded categories; provider bodies, URLs and credential paths are not
returned. Hangang displays these facts with source-managed editing disabled.
This does not implement Kubernetes source editing or full package deployment.

## Hangang World deployment building block

`deploy/kubernetes` is the Pumgye building block for the integrated Hangang World
package, not a standalone claim of four-component deployment. Kustomize rendering
and the real API server's dry-run accept these resources. Actual Pod rollout and
package integration remain unqualified. Replace the deliberately unusable image
reference with the exact qualified image digest before applying an overlay.

The native-authoritative baseline uses one SQLite writer, `Recreate`, persistent
state and a deny-all initial policy. Do not scale this SQLite deployment; distributed
followers/backbone require separate qualification. Bootstrap changes do not override
an established database. Select the storage class and retention/recovery policy in
the package overlay; PVC deletion can delete storage with a Delete reclaim policy.
Provision `pumgye-tls` with `tls.crt`, `tls.key`, `ca.crt` and distinct credentials
in `pumgye-credentials` keys `admin-token`, `decision-token`. No example credentials
are generated. Client certificates must verify the Pumgye Service DNS name.

Management (9084) and PPG1 (9085) remain mTLS plus role-separated credentials.
The optional `--readiness-listen` endpoint serves only `GET /-/ready`, an empty
200/503 response with `Cache-Control: no-store`; no policy, status, audit or decision
route exists there. Port 9086 is not exported by the Service. Readiness consults
the same in-memory freshness fence as decisions, including Kubernetes startup,
expiry and persistence failure. Liveness is a socket check and does not assert
policy availability. Protect the probe port with the package network policy.
The native baseline does not mount an API token or grant RBAC. Kubernetes-authoritative
mode needs an explicit mapping, bounded projected token, CA and namespaced/cluster
RBAC source permissions; it must never silently fall back to this native baseline.

Build the static binary and run native fixtures before packaging:

```sh
CARGO_INCREMENTAL=0 cargo build --locked --release --target x86_64-unknown-linux-musl -p pumgye-server
docker build -f deploy/Dockerfile -t pumgye:QUALIFIED_VERSION .
kubectl kustomize deploy/kubernetes
```

Use the configured cluster wrapper for validation and deployment. This packaging
recipe does not publish a release or authorize overwriting an existing installation.
