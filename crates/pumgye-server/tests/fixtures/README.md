`kubernetes-workload-v1-candidate.json` freezes the version1 candidate from the
pre-Workload-policy Pumgye static binary SHA256
`054249265e0eec9bbfae3e3fe93c3074648e511f2082ebc88a016e0365e9b598`.
Its inputs are the unchanged `examples/kubernetes-rbac-list.json` and
`examples/kubernetes-workload-mapping.json`, cluster `example-cluster`.
It is the `candidate` member of the ordinary `--inspect-kubernetes-rbac` JSON
output. All identifiers are fictional. This verifies old output rather than
regenerating an expectation from the current mapping implementation.
