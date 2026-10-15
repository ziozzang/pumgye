# Human policy metadata (core prerequisite)

The optional Service `human_users` map assigns canonical `human1:` plus64lowercase
hex subjects to existing roles in the SAME compiled Policy. Empty maps serialize
exactly as before; users/workload_users remain independent with no fallback.
HumanSubject::parse validates metadata only, never identity, assurance or permission.

`evaluate_scoped_human_resource` is deterministic policy evaluation. The caller
must authenticate actual Human evidence and supply verified AAL1/2; numeric input
to this pure method is not a trusted capability. Malformed/unknown Human subjects
are Guest, other AALs AssuranceDenied, wrong service/API context UnknownService.
Same resource/action/class and network/Guard intersection remain mandatory. Each
user's assigned roles supplies their assurance floor, combined with network and
resource floors; no new global floor is introduced. Existing requiredAAL3 remains
unsatisfiable by this initial Human path. All three maps share65536assignment cap.

KubernetesApi services cannot contain Human or Workload assignments. Kubernetes
source mapping templates reject preexisting Human grants for both mapping versions;
this adapter does not import Humans. Existing Service/Workload RPCs and v1/v2 mapping
output contracts are unchanged. No Human RPC, private SDK source owner, signer,
permit, ledger or route activation is added. New fields must not be published to
old strict policy consumers until their dependencies are updated.

Grant removal takes effect in a newly compiled snapshot. An old pure compiled
snapshot does not retire itself: the server's exact Authority/View/current-source
fences remain responsible for publication and withdrawal. Human native permission
and actual end-to-end qualification are later work, requiring H2's private actual
session source, original deadline, current owner and final dispatch checks.
