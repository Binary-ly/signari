# DPoP — sender-constrained tokens

RFC 9449. A client that sends a `DPoP` proof at the token endpoint gets a token
bound to its key. Every later request must carry a fresh signature from that
key.

Nothing changes for clients that do not use it: send no proof, get an ordinary
bearer token.

## What it changes

A bearer token is a bearer credential — whoever holds it, uses it. Every defence
around one is about stopping it being *obtained*, because once obtained there is
nothing left to check. Tokens leak through referrer headers, proxy logs, browser
history, crash reports and copy-paste into support tickets.

DPoP makes a stolen token inert. Demonstrated against the running server:

```
1. token_type -> DPoP
   cnf in token -> {'jkt': 'GsuFxxuSySHM37h6wjI9_mdOYeRx3k6T7am3_mMVgNM'}
2. rightful holder, valid proof -> 200
3. STOLEN token, no proof       -> 401
4. STOLEN token + thief's key   -> 401
5. REPLAY of the valid proof    -> 401
```

Line 4 is the one that matters. The thief's proof is **completely valid** — fresh
`iat`, correct `htm` and `htu`, correct `ath` for the token they hold, signed
properly with a key they generated. Every check passes except the binding. That
comparison is the entire feature; without it the proof demonstrates possession
of *a* key rather than *the* key the token was issued to.

## What is refused, and why each matters

The proof is a JWT supplied by the caller, so every field is attacker-chosen
until checked:

| refused | otherwise |
|---|---|
| `alg: none` | the proof would be unsigned |
| HMAC | the proof carries its own verification key; with a symmetric algorithm that key is also the signing key, so anyone could mint a proof for any key |
| signature not matching the advertised `jwk` | the key named and the key used could differ |
| private key in `jwk` | the client has published its own secret; continuing authorises a request with a key everyone now holds |
| wrong `typ` | an ID token or access token would be usable as a proof |
| wrong `htm` / `htu` | a proof for `/userinfo` would authorise `/admin` |
| stale or future `iat` | a captured proof would keep working |
| missing `jti` | a replay could not be detected at all |
| missing or mismatched `ath` | a proof made while using one token would authorise another |
| two proofs in one header | which one was checked would be up to the parser |

21 tests, each an entry in that table.

## Decisions worth naming

**The request URI is rebuilt from the configured issuer**, not from the `Host`
header. Taking the host from a header would let a caller choose what their proof
authorises by lying about where they sent it.

**Replay detection fails closed.** If the database cannot record a `jti`, the
proof cannot be shown to be fresh, and the request is refused. Failing open would
silently drop the protection exactly when the database is unhappy.

**The replay key is `(jkt, jti)`, not `jti` alone.** Two clients may legitimately
choose the same identifier, and a shared namespace lets either deny service to
the other by burning identifiers.

**Proof records live in their own table**, separate from `revoked_jtis`. Those
are identifiers *we* issued; these are chosen by clients. A shared namespace
would let a client revoke somebody else's token by picking its `jti`.

**`token_type` is `DPoP`, not `Bearer`**, when the token is constrained (§5).
Not cosmetic: a client told "Bearer" sends no proof and every request it makes is
refused.

**`Authorization: DPoP <token>` is accepted** as well as `Bearer` (§7.1).
Accepting only Bearer would make every bound token unusable at the very endpoint
that enforces the binding — working at issuance and failing at use, which is the
most confusing possible split.

**Query and fragment are ignored in `htu`** (§4.3), which is what the RFC
specifies. Comparing them would fail against clients that include them, and that
interoperability failure looks like an attack in the logs.

## Coverage

Enforced at `/oauth2/userinfo`. The binding is carried in the token's `cnf`
claim, so any resource server that reads it can enforce the same thing.

`dpop_signing_alg_values_supported` is advertised in discovery because it works
end to end — bound at issuance, enforced at the resource. Binding without
enforcement would be worse than plain bearer tokens: a relying party reading
`cnf` would believe a claim nothing checks.

## Pinning a client to DPoP

By default, whether a token comes out sender-constrained is decided per request,
by whether a proof was attached. That is what RFC 9449 §5 intends — an
authorization server "MAY elect to issue access tokens that are not DPoP bound",
signalled by `token_type: Bearer` — but it leaves a client no way to say *I
always use DPoP*, and one request that omits the header quietly yields an
ordinary bearer token. The downgrade needs no attack on DPoP itself, only the
absence of a proof.

§5.2 defines the client registration metadata that closes it:

> `dpop_bound_access_tokens`: A boolean value specifying whether the client
> always uses DPoP for token requests. If omitted, the default value is false.
> If the value is true, the authorization server **MUST reject token requests
> from the client that do not contain the DPoP header**.

```sh
signari client set-dpop -client payments -dpop-bound
```

Every token request from `payments` that carries no DPoP proof is then refused
with `invalid_dpop_proof` and HTTP 400 — including through the OID4VCI
pre-authorized code grant, which resolves its client from the offer rather than
from the request and so needs the check applied separately.

To unpin:

```sh
signari client set-dpop -client payments
```

The default is `false` because §5.2 says it is, and because any other default
would refuse every existing client's next token request.
