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
