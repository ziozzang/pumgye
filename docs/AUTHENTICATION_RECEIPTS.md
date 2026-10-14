# Authentication receipt verification (unreleased)

[한국어](AUTHENTICATION_RECEIPTS.ko.md)

The owning server library `pumgye_server::authentication` consumes the pinned,
provider-independent Hopae receipt contract. It introduces no provider, session,
HTTP or database dependency in `pumgye-core`.

`ServiceTrust` is constructed from server-owned issuer/key epoch/public key,
identity authority epoch base, service/audience and minimum profile revision.
Request metadata cannot select another trusted key or classification. Verification
requires the canonical Service/AAL0 subject, matching profile/credential generation,
canonical service epoch, final request digest and a valid Authentication-purpose
signature/time window. Only after those checks does `CheckedService` retain the
verified context, exact receipt hash and expiry. It has no public constructor,
Clone, Debug or serialization; later changes to the supplied numeric context do
not rewrite its verified facts.

Tests cover valid extraction, independently signed but wrong scope/kind/generation,
identity/profile epoch mismatch, revision floors, wrong key/purpose, every-byte
tampering and time boundaries. Verification uses immutable resources and performs
no request-time SQL or provider calls.

This is a cryptographic server-library boundary, not an active permit endpoint.
Static revision floors do not establish live Hopae/key freshness. The signer must
combine current identity/key/epoch fences, verified network evidence, the native
resource Allow and final request/plan binding, then recheck those owners before
releasing its private candidate. Replay consumption remains required at projection.
Server trust configuration loading/publication, durable retirement floors and RPC
integration remain open. Existing service/resource transports are unchanged.

## Checked identity resource boundary (unreleased)

`authorization::authorize_resource_then` evaluates only the service, canonical
subject and AAL held by `CheckedService`. Its native resource request has no
identity, service, assurance or class override. The compiled catalog selects
classification/action rights. Mandatory owner-fence and clock callbacks guard
admission, candidate production and final return. Authentication verification time
is a rollback floor; authentication/network expiry and backward time refuse the
candidate. The operation receives owner metadata and must keep output private.

Tests combine a real signed authentication receipt with native resource Allow and
refuse network/unknown-action denial, initial retirement/expiry, retirement during
candidate production, authentication/network expiry and clock rollback after work.
This public server-library adapter remains unwired to an RPC. The current-owner
callback must be supplied by real identity/key/network/policy/route/plan owners;
this helper supplies no remote freshness discovery or signed permit by itself.

## Native permit candidate signer (unreleased)

`permit::Signer` uses a separate Pumgye signing identity and Permit purpose. It runs
inside checked-authentication resource authorization, then rechecks native owners
and every sampled clock before returning `SignedPermit`. The candidate binds the
exact authentication receipt hash, verified identity/service/audience/request,
decision/resource/action, authority epoch and policy/catalog/network/route/plan
revisions. Catalog and policy share one atomic document revision. No caller class
or assurance is accepted. Nonces come from the OS CSPRNG.

Expiry is the earliest authentication, network, policy, route, plan or one-second
limit. Independent receiver verification qualifies purpose/key separation, exact
chain/revision binding, expiry and distinct nonces. Denial, initial/final owner
retirement, invalid revisions, expired plans and clock rollback discard candidates.
All 44 workspace tests and strict Clippy pass.

The signer is a server-library capability, not a configured permission endpoint.
Native owner state and the mandatory freshness callback must originate in actual
owners. Signing key loading/rotation, owner discovery/coherence, RPC wiring,
receiver replay consumption and credential projection remain required. No operating
permit issuer is activated by this source change.

## Native permit signing resources (unreleased)

`--permit-key <file>` optionally loads reference-only JSON with `issuer_ref`,
`key_epoch`, `public_key` (base64 Ed25519 public bytes) and `seed_env` (environment
reference). Unknown fields, including inline `seed`, are refused. Files are bounded
to 16 KiB. Public identity/epoch/reference syntax is checked before resolving
secret material. The 32-byte seed must match the declared non-weak public key;
encoded seed and decode/file buffers are zeroized. Missing or invalid resources
fail before database creation or listener binding. Administrator status exposes
only `permit_key_configured`.

Use a separate deployment permit identity from release artifact and Hopae
authentication identities. Restart is the current loading boundary; dynamic
publication remains open. The durable startup fence is described below. Loading a key does not
activate a permit RPC or satisfy live owner/network/plan checks. The option conflicts
with inspection/observation-only modes. Existing deployments without the option
retain their ordinary decision behavior.

## Server-owned authentication trust loading (unreleased)

`--authentication-trust <file>` loads a bounded 64 KiB document with 1..128
`entries`. Each entry declares `issuer_ref`, `key_epoch`, `identity_epoch`,
`service`, `audience`, `minimum_revision` and a base64 `public_key`. Unknown fields
and secret fields are refused. Native validation checks references, epochs,
revision floors and strong public material. Duplicate issuer/service/audience
bindings, inconsistent key/epoch/identity bases for one issuer and public-material
reuse across issuers are rejected. Different audiences for the same declared
issuer/service can share its single active identity.

Compiled trust uses borrowed issuer/service/audience hash lookups without allocating
request-time composite keys. The request cannot choose a public key or introduce
an undeclared scope. Invalid trust fails before DB creation or listener binding;
administrator status reports only `authentication_trust_entries`. The option
conflicts with inspection/observation-only modes. Loading is restart-bound and
does not implement live Hopae revalidation, dynamic trust publication or permit
RPC activation. Key retirement is fenced by the durable startup transition below.

## Durable startup key history (unreleased)

Before opening listeners, the server compiles the combined authentication and
permit public descriptors and commits their immutable registry plus SHA-256 audit
in its private SQLite database. The combined set permits up to 64 active keys,
128 authority/purpose floors and 256 historical public keys; the 128 trust-scope
limit remains separate. Queries perform no database access for this fence.

Each successful startup transition advances the registry revision. Removing either
configuration retires its keys while retaining history. Restarting with an unchanged
active key is allowed; rotation requires a higher epoch and fresh public material.
Removed or replaced material cannot return at any epoch or move between issuers
or authentication/permit purposes. Failed transitions leave snapshot and audit
unchanged and refuse startup. Tests exercise actual process startup, SQLite restart,
retirement, fresh replacement and write failure.

This history does not persist service profile minimum revisions or identity epochs,
prove live provider/app freshness, fence rollback of the whole DB backup, or activate
permit RPC. Distributed floors and restore protection remain required.
