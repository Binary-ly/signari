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
