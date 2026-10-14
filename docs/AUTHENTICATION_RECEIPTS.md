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
