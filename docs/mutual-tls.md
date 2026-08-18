# Mutual-TLS client authentication

RFC 8705. A client proves who it is with a certificate instead of a secret, and
its access tokens are bound to that certificate.


```sh
# PKI: certificates issued by an authority you trust
signari client set-tls -client-id payments -tls-san-dns payments.example.test \
  -tls-bound-tokens
SIGNARI_TLS_CLIENT_CA=/etc/signari/client-ca.pem signari serve ...

# No PKI: the client registers its own certificate
signari client set-tls -client-id jobs -sp-cert ./jobs.crt -tls-bound-tokens
```

Match on exactly one of `-tls-subject-dn`, `-tls-san-dns`, `-tls-san-uri` or a
registered certificate. Two would be an AND nobody expects; any-of is weaker than
it looks. The database enforces it as a CHECK constraint.

## Two halves, and the one usually missing

**Authentication** — no shared secret to leak from a config file, a CI log or an
environment listing.

**Binding** — `cnf.x5t#S256` ties the token to the certificate, so a stolen token
is useless without the private key. Same idea as DPoP, which this engine already
does; mTLS suits service-to-service callers with a PKI, DPoP suits browsers and
mobile apps.

Authenticating with a certificate and then issuing an unbound bearer token is the
common half-implementation, and it leaves the token exactly as stealable as
before — which is most of what mTLS was for.

**That bug happened here.** Binding was added to the authorization-code path and
not to `client_credentials`, which is the path a service client actually uses. It
was caught by looking at an issued token rather than trusting the code:

```
cnf: None            <- what the first version produced
cnf: {'x5t#S256': '32cI5Ks8_P1bQ9QY85hlsH7rrOtAyjPybWImtkYg_tA'}
```

The expected value was computed independently with openssl, not read back from
our own encoder.

Binding is a **separate flag** from authentication. A client may authenticate by
certificate and still want plain tokens during a migration — and turning binding
on is what breaks callers who do not present the certificate at the resource
server, so it should be a deliberate flip rather than a side effect.

## The design problem testing found

The obvious listener configuration is `tls.VerifyClientCertIfGiven` with a CA
pool. It cannot support both methods at once:

- **with** a pool, a self-signed client is killed during the handshake, before
  any application code runs
- **with no** pool, *every* offered certificate fails the handshake — which
  breaks `self_signed_tls_client_auth`, the method that exists precisely because
  there is no CA

So the two methods were mutually exclusive, and the self-signed one could never
work at all. The listener now uses `tls.RequestClientCert` — ask, verify nothing
— and the chain check moved into `VerifyClientCertificate`, where it can depend
on which method the client registered.

Both methods now work on one listener:

| | |
|---|---|
| PKI client, correct SAN | 200, bound to its certificate |
| self-signed client, matching thumbprint | 200, bound to its certificate |
| self-signed certificate presented for the PKI client | refused — chains to nothing |
| PKI certificate presented for the self-signed client | refused — wrong thumbprint |

## What the chain check is load-bearing for

Without it, a peer certificate is merely something the client sent. Matching a
subject string against it would authenticate **anybody who can write that string
into a certificate they signed themselves**. A test proves it: a self-signed
certificate carrying the exact expected `CN` and SAN is refused.

`ExtKeyUsageClientAuth` is required too — otherwise a certificate issued for
serving TLS would satisfy a client check.

With no authority configured, `tls_client_auth` is **refused outright** rather
than downgraded to trusting whatever was presented. `signari doctor` reports that
combination as critical, because otherwise every request from those clients fails
in a way that looks like the client's fault.

## Matching rules

- **Subject DN** — RFC 4514 string form, compared exactly. Deliberately not
  normalised: DN equivalence has real subtleties (attribute order, case,
  encoding) and every one is a way for two different names to compare equal.
- **dNSName** — case-insensitive, because DNS is. **No wildcards**: a wildcard in
  a client identity means a whole namespace can authenticate as that client.
- **URI SAN** — exact. Works with SPIFFE identifiers.
- **Thumbprint** — SHA-256 over the DER, compared in constant time. A test
  registers one certificate and presents a *different* certificate with the same
  common name; it is refused, which is the whole difference between matching a
  name and matching a credential.

## One binding per token

A token carries `cnf.jkt` or `cnf.x5t#S256`, never both. A client doing DPoP and
mTLS together would be asserting two possession proofs for one token, and a
resource server has to know which to check. DPoP wins, because it is the proof
the client constructed deliberately for that request; the certificate is a
property of a connection it may not know is mutually authenticated.

Both members are `omitempty`, so an unbound token carries no `cnf` at all rather
than an empty object — a resource server checking for the claim must not be told
"yes, and it is blank".

---

# Lifecycle pass: the refresh token was not certificate-bound either

Found by running the same review over mutual TLS that had just found the DPoP
defect — follow one grant through every refresh instead of checking each handler.
The gap was the same one, in the other half of the product.

## RFC 8705 §4

> "When the authorization server issues a refresh token to such a client, it
> SHOULD also bind the refresh token to the respective certificate and **check the
> binding when the refresh token is presented** to get new access tokens."

"Such a client" is §4's public client: one presenting a certificate to obtain
certificate-*bound* tokens without using that certificate to authenticate. §7.1
exempts confidential clients, whose refresh tokens are already "indirectly
certificate-bound by way of the client ID and the associated requirement for
(certificate-based) authentication" — so the enforcement here is for public
clients only, exactly as with DPoP.

This is a SHOULD, not a MUST. Implemented anyway: the alternative is minting a
certificate-bound access token — one whose `cnf.x5t#S256` tells every resource
server it may only be used by the holder of a particular certificate — from a
refresh token that anybody could present. The access token advertises a
constraint the grant behind it does not keep.

Migration 0084, on the family rather than the token, for the same reason as 0083:
§4's check happens "when the refresh token is presented", every time, not once.

## Two things the tests got wrong first, both worth recording

**The client must be registered for bound tokens.** `tls_bound_tokens` is off by
default and rightly so — turning binding on breaks every caller not yet
presenting its certificate at the resource server, which is a cutover rather than
a side effect of enabling mTLS. The first version of the test never set it,
received plain tokens, and would have passed vacuously against a completely
unimplemented binding.

**A certificate-bound token is still `token_type: Bearer`.** Unlike DPoP, RFC 8705
signals the binding with the `cnf.x5t#S256` claim and not the token type. The
first guard asserted `token_type != "Bearer"` and failed against correct code.
Asserting on `cnf` is both correct and the thing that actually matters.

Both mistakes share a shape: a test that checks a *proxy* for the property rather
than the property. The proxy was wrong in one direction (never set) and wrong in
the other (never true), and only one of those announces itself.

## Mutation results

```
CAUGHT   cert binding never validated at rotation
CAUGHT   cert binding: no-certificate bypass
CAUGHT   cert binding lost after one rotation
CAUGHT   cert binding never recorded at issuance
```

## Three protocols, one seam

| | RFC 9396 | RFC 9449 | RFC 8705 |
|---|---|---|---|
| Endpoint in isolation | correct | correct | correct |
| Missing at refresh | granted details | DPoP key binding | certificate binding |
| Symptom | constraint widened to `scope` | sender-constraint became bearer | bound token from an unbound credential |

Every one of these was invisible to a review organised by endpoint, because at
every endpoint the code was right. What they have in common is a property
established at authorization and consulted — or not — an hour later.
