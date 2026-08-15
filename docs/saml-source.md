
The **inbound** half. `/saml/sso` serves applications consuming assertions this
engine issues; this consumes assertions issued by somebody else's.

```sh
signari idp add -org <uuid> -kind saml -slug corp \
  -entity-id https://adfs.corp.example/adfs/services/trust \
  -sso-url https://adfs.corp.example/adfs/ls/ \
  -sp-cert /etc/signari/adfs-signing.pem \
  -nameid-format emailAddress
```

```
sign-in URL : /saml/source/corp/start
ACS URL     : <issuer>/saml/source/corp/acs
metadata    : <issuer>/saml/source/corp/metadata
```

Give the upstream the **metadata URL** rather than typing the entity ID and ACS
URL into its console by hand. A mistyped audience produces an assertion this
engine refuses correctly and unhelpfully.


## Consuming an assertion is a security boundary

Issuing one is arithmetic. Consuming one is not: the document arrives from a
browser under an attacker's control, and every field is a claim by whoever sent
it until proven otherwise. Each check below has been the CVE in some other
implementation.

| Check | Why skipping it is a full bypass |
|---|---|
| signature | an unsigned assertion is a claim by anybody |
| `InResponseTo` | otherwise an assertion captured anywhere replays into any browser |
| `Destination` | an assertion minted for another service is not ours |
| `Audience` | same, stated by the issuer rather than the transport |
| `NotBefore` / `NotOnOrAfter` | otherwise it is a permanent credential |
| assertion ID | a valid assertion must work **once** |

## No email matching, at any setting

An external identity is matched on `(provider, subject)`. Never on email.


## Signature wrapping, tested five ways

The XSW family works by making the verifier and the application look at
different elements. The defence is structural: `ConsumeResponse` returns the
assertion **inside the element goxmldsig verified**, so reading a different
subtree is not a discipline somebody has to remember.

```
forged assertion placed before the signed one      refused
forged assertion placed after the signed one       refused
signed assertion hidden inside Extensions          refused
forged assertion nested inside the signed one      refused
duplicate IDs                                      refused
```

The test runs each **twice** — once normally, once with the outermost guard
switched off — because a layered defence claimed in a comment is not a layered
defence. That experiment corrected the claim originally written here: without
the assertion-count guard, no payload yields the forged subject, but one is
*accepted* while returning the honest one. Harmless in itself, and a malformed
document accepted is where the next bug starts. The guard stays.

## Unsolicited sign-in is off

An IdP-initiated response has no `InResponseTo`, so it cannot be tied to a
request this browser made — meaning a valid assertion captured from a log, a
proxy or a shared machine can be posted into a victim's session. Some portals
only do IdP-initiated flows, so `-allow-unsolicited` exists and prints a warning
that says exactly that.

## Transient NameIDs are refused

A transient NameID is a different value on every sign-in. Linking an account to
one creates a new orphaned account each time somebody signs in. Refused at
configuration **and** at sign-in, with the fix in the message.

## Verified against a live engine

Not only unit tests. A signed assertion was posted to the running ACS endpoint,
signed by an independent implementation (`lxml` + `cryptography` — a different
canonicaliser and different crypto from the engine's `goxmldsig`), so the
interoperability claim is agreement between two implementations rather than one
library agreeing with itself.

| | |
|---|---|
| valid assertion | user created, linked, session issued, `amr: ["fed"]` |
| the same assertion again | refused — no sign-in in progress |
| replayed against a fresh request | refused — answers a different request |
| same assertion ID, fresh request, re-signed | refused — **already used** |
| no RelayState (unsolicited) | refused |
| subject tampered, signature untouched | refused — signature |

Each was refused for a *different* reason, which is the point of running them:
the last one is the only proof that the replay table fires at all, since the
first three were caught earlier in the chain by `InResponseTo`.

### The disagreement worth having

The first signature the Python signer produced was **rejected**. The cause was
whitespace: `lxml`'s `remove()` takes the element *and its tail text*, while the
enveloped-signature transform removes only the element. So the signer digested a
document the verifier would never see.

Two independent implementations disagreeing is exactly what this exercise is
for. The bug was in the test harness — but it took a real signature to find out
which side was wrong.

## Email addresses are recorded as verified

A SAML assertion has no `email_verified` field; there is nowhere to put one. So
the question is answered by the deployment, and for an enterprise upstream the
honest answer is yes: the organisation's own directory authenticated the person
and stated their address, which is the premise of federating to it at all.

Left off, a freshly registered source refuses every sign-in with a message about
a claim the protocol cannot make — a dead feature, and the first deployment to
hit it would reasonably conclude the software is broken.

This is safe to default on **only because** the address is never used to find or
match an account. It is recorded, displayed, used for notifications. The vector
that makes email trust dangerous elsewhere is closed one level up.

## Not yet

- **Encrypted assertions.** Refused with a message saying so, rather than
  silently ignored. The decryption side of `internal/saml/encrypt.go` exists for
  the outbound direction; wiring it here is the next piece.
- **Signed AuthnRequests.** Most upstreams do not require them, and the security
  of this flow rests on verifying the response.
- **SAML single logout as a source.** Sessions here end normally; the upstream
  is not notified.

Each is absent from the metadata document as well as from the code — a
capability advertised and not implemented is the failure this project sweeps for.
