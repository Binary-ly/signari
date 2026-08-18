# Security review: FAPI 2.0 Security Profile

FAPI 2.0 Security Profile, **Final, 22 February 2025** — a general-purpose
high-security profile of OAuth 2.0 that has "been proved by formal analysis to
meet the stated attacker model".


## §5.3.2.1, requirement by requirement

| Requirement | Signari |
|---|---|
| Distribute discovery metadata per OIDD/RFC 8414 | yes |
| Reject the resource owner password credentials grant | yes |
| Only support confidential clients | **profile mode** — we support public clients generally, which a FAPI deployment would disable |
| Only issue sender-constrained access tokens | **profile mode** — supported, not mandatory |
| Sender-constraining via mTLS or DPoP | both implemented |
| Client authentication via mTLS or `private_key_jwt` | both implemented |
| Not expose open redirectors | yes |
| Accept **only** the issuer identifier in a client assertion `aud` | **no** — see below |
| Not use refresh token rotation | **no** — we rotate; see below |
| Authorization codes with a maximum lifetime of 60 seconds | **yes, exactly 60** |
| If using DPoP, support Authorization Code Binding to DPoP Key | **was missing — now implemented** |
| Accept JWT `iat`/`nbf` 0–10s in the future, reject >60s | partial |

Two rows are deliberate differences rather than gaps, and one was a real defect.

## The defect: no authorization code binding to a DPoP key

FAPI 2.0 requires it "if using DPoP", and RFC 9449 §10.1 is blunter about who it
binds:

> **Both mechanisms MUST be supported by an authorization server that supports
> PAR and DPoP.**

Signari supports PAR and supports DPoP, so that MUST applied — and neither
mechanism existed. `dpop_jkt` appeared nowhere in the codebase.

### What it buys that PKCE does not

PKCE binds an authorization code to a secret the client generated. `dpop_jkt`
binds it to the **key the resulting token will be bound to**, which closes the
flow end to end: an authorization code intercepted in the front channel cannot be
redeemed by an attacker's own DPoP key, because the code names the key permitted
to redeem it.

§10 notes they are complementary, and that `dpop_jkt` "only provides similar
protections when a unique DPoP key is used for each authorization request".

### Both mechanisms, because §10.1 requires both

- `dpop_jkt` as an authorization request parameter, and in the PAR POST body.
- A **DPoP header on the PAR request**, in which case the server "MUST further
  behave as if the contained public key's thumbprint was provided using
  dpop_jkt".

Supporting only the first would silently drop the binding for a client that
attaches its DPoP header to every authorization-server request — which is
precisely the client §10.1 exists to accommodate.

And when both are present: "the authorization server MUST reject the request if
the JWK Thumbprint in dpop_jkt does not match the public key in the DPoP header".

### The mistake I made implementing it

The redemption check went in after the PKCE block. That block returns early when
a code carries a challenge — which is every code, since PKCE is required by
default — so the check never ran.

The test caught it on the first execution. Reading the function did not, because
the early return is four lines below where the eye stops. The mutation that moves
the check back to the wrong place is now part of the suite:

| Mutation | Test that caught it |
|---|---|
| Drop the thumbprint comparison | `TestACodeBoundToADPoPKeyIsOnlyRedeemableWithThatKey` |
| Move the check after the PKCE early return | same test |

## The two deliberate differences

**Client assertion audience.** FAPI: "shall only accept its issuer identifier
value... as a string in the `aud` claim received in client authentication
assertions". Ours accepts three values — the issuer, the token endpoint, and the
endpoint being called. That third one was added because a client authenticating
at `/oauth2/par` naturally addresses its assertion to `/oauth2/par`, and refusing
it broke PAR outright.

Every accepted value names this server and nobody else, so the audience check
still does its job. But a FAPI deployment would need the stricter form, and this
is recorded as a mode rather than defended as equivalent.

**Refresh token rotation.** FAPI *prohibits* it; RFC 9700 §2.2.2 *requires*
rotation or sender-constraining for public clients. There is no contradiction —
FAPI mandates sender-constraining, which removes the need — but the two standards
point opposite ways for a server supporting both worlds, and ours follows RFC
9700 by default.

## Verdict

One MUST-level defect, which was also an RFC 9449 §10.1 MUST that had gone
unnoticed through an earlier DPoP review — because that review checked the proof
and the binding at the resource, and never asked what binds the *code*.

The remaining FAPI gaps are profile modes: restrictions a FAPI deployment must
turn on (confidential clients only, sender-constrained tokens only, single
assertion audience), not behaviours that are wrong by default. Making them a
selectable profile is the honest next step, and is not built.
