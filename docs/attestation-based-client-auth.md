# Attestation-Based Client Authentication

`draft-ietf-oauth-attestation-based-client-auth-10`, 6 July 2026 — the current
draft at the time of writing.

## The problem

A public client has no secret. Anything holding its `client_id` — a repackaged
app, a script, a modified build — is indistinguishable from the real one, because
there is nothing to prove otherwise.

PKCE binds a code to a one-time secret. DPoP binds a token to a key. Neither says
anything about **what** holds that key. A repackaged app generates a perfectly
good DPoP key and produces perfectly good proofs.

ABCA adds a third party. A **Client Attester** vouches that a particular key
belongs to a genuine instance of a known application; the instance then proves it
holds that key. So the token endpoint learns two things it could not learn
before: this is the app we think it is, and this is the instance the attester saw.

## Two artefacts

```
OAuth-Client-Attestation:      signed by the ATTESTER, carries cnf.jwk
OAuth-Client-Attestation-PoP:  signed by the INSTANCE key named in that cnf
```

The first is long-lived and reusable; the second is per-request. That split is
what lets an attester issue an attestation once, offline, while the instance
proves liveness on every call — and it is also the reason `typ` matters so much
(below).


## Decisions we made that the draft leaves open

**Symmetric attester keys are refused.** §4 permits an attestation to be "signed
or integrity protected with a Message Authentication Code". We accept asymmetric
signatures only. A symmetric attester key is a key *this server holds*, so this
server could mint attestations indistinguishable from the attester's own — and an
attestation we could have forged ourselves vouches for nothing. It would be worth
exactly as much as trusting the `client_id` we already had. The CLI refuses to
register a JWKS containing private keys for the same reason, at the moment
somebody makes the mistake.

**A challenge is mandatory, because we offer the endpoint.** §5.1 makes the
`challenge` claim OPTIONAL, but §6.1 is unambiguous once an endpoint exists: "If
the Authorization Server offers a challenge endpoint, the Client MUST retrieve a
challenge and MUST use this challenge."

**Challenges are single-use.** The draft does not require it. Single use is what
makes a captured PoP *worthless* rather than merely short-lived, and it costs one
`UPDATE … WHERE used_at IS NULL` — the same technique authorization codes and
credential nonces use here.

**`jti` replay detection as well.** Belt and braces while challenges are
mandatory, and the thing that still works if a deployment later turns challenges
off.

## Testing

Every rule of §7.1 and §7.2 has a test that makes exactly one thing wrong, so a
failure names the rule. Then each was mutated to confirm it can fail. Two
mutations survived the first pass and both were real gaps:

**The PoP `typ` check was untested.** The attestation had a `typ` test; the PoP
did not. The case that matters is substituting an **attestation** as a PoP — both
are signed JWTs, and the attestation is the long-lived artefact that travels in a
header on every single request. Without the `typ` check, anyone who captured one
could present it as the per-request proof, and nothing else in the verifier would
have objected. That is exactly the cross-protocol substitution `typ` exists to
prevent, and the test suite could not see it.

**Three branches turned out to be diagnostic, not load-bearing.** An absent `exp`
decodes to zero and is refused as "expired in 1970"; an absent `challenge` fails
the store lookup and is refused as "unknown or expired"; a missing DPoP proof
fails a constant-time compare on length. All safe, all with the wrong message —
each sends an integrator to investigate a clock, an expiry, or a key mismatch
that never happened. Those branches are now tested on the message, which is what
they actually buy. This is the fourth and fifth time this pattern has appeared in
this codebase; the rule it keeps producing is *a check that cannot be made to
fail is not yet known to be doing anything*, and sometimes the honest answer is
that what it does is explain.

## What the wiring cost, and one thing worth remembering

`oauth.RequireClientAuth` decides whether *any* authentication method applies
before one is attempted. It could only see secrets in the request body, so it
refused the request before the attestation was ever looked at — and the error
said "client authentication is required" to a client that had supplied it.

Its own comment already recorded this happening to `private_key_jwt`, and then
again to mutual TLS. ABCA is the third. The gate now carries the general rule
instead of a third special case, and `clients.Client` carries the registered
method so the gate can see it at all.

## Not implemented

- **DPoP combined mode** (§5.2, §7.3), `attest_jwt_client_auth_dpop`. Not
  advertised in metadata either — advertising a method we would refuse is the
  same dishonesty as advertising an endpoint that 404s.
- **§6.2 challenges on previous responses.** We return a fresh challenge on
  `use_attestation_challenge`, which is the case §7.4 makes mandatory; attaching
  one to every successful response is optional and not done.
- **Resource-server-side attestation** (§7.6, "as an additional security signal").
