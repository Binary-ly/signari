# Signing in with a wallet

A person can sign in with a credential from their digital identity wallet. This
deployment acts as an OpenID for Verifiable Presentations 1.0 verifier: it asks the
wallet for one SD-JWT VC, checks what comes back, and signs in the person a claim of
that credential identifies. After the check it is an ordinary external sign-in. The
linking rules, account creation, [attribute and group mapping](social-login.md) and
the audit events are the same as for any provider.

It works on one device. The sign-in page sends the browser to the wallet, the wallet
posts its answer back here, and then sends the browser back. Signing in on a computer
with a phone's wallet needs a page showing a code to scan, with words to go with it in
every language the sign-in pages speak, and this deployment does not have one.

## Setting one up

```sh
signari idp add -kind oid4vp -org <org> -slug wallet -name "Your wallet" \
  -client-id-prefix x509_san_dns -vct urn:eudi:pid:1 \
  -subject-claim personal_administrative_number -email-claim email \
  -client-key-file verifier.key -client-cert-file verifier-chain.pem

signari idp vp-issuer -slug wallet -issuer https://pid.example -jwks-file pid-issuer.jwks
```

The Admin API does the same with `POST /admin/organizations/{orgID}/identity-providers`
and `PUT .../identity-providers/{slug}/vp-issuers` ([admin-api.md](admin-api.md)).

| | |
|---|---|
| `-client-id-prefix` | How wallets know who is asking. `x509_san_dns` and `x509_hash` sign every request with the key of the certificate chain given, and a wallet validates that chain against the roots it trusts. Under `x509_san_dns` the certificate must name this deployment's host, because the wallet holds the address it posts to that name, and a sign-in is refused, with the reason logged, while it does not. `redirect_uri` cannot sign at all, and is for a wallet that already trusts the address it posts to |
| `-vct` | The credential types accepted, separated by commas |
| `-subject-claim` | The claim that identifies a person. A name, or a JSON path such as `["address","country"]` |
| `-email-claim`, `-name-claim` | Where the address and the name are, if the credential has them |
| `-wallet-url` | Where the browser is sent: `openid4vp://`, or a wallet's own https link |
| `-response-mode` | `direct_post`, or `direct_post.jwt` to have the answer encrypted. Each request then carries a P-256 key of its own, made when the sign-in starts and kept sealed with it, and the answer comes as a JWE to that key (ECDH-ES, with A128GCM or A256GCM, both named in the request), named by its `kid`. A credential sent in clear to such a request is refused, since only an error may come unencrypted |

Every claim named is asked for, and a credential without one of them is refused.

## Whom it believes

Nobody, until `idp vp-issuer` names an issuer, exactly as the `iss` its credentials
carry. SD-JWT VC lets the verifier's policy decide how an issuer's key is found, and
the operator chooses, issuer by issuer, between two ways.

### Where an issuer's keys come from

**Pinned**, with `-jwks-file`: the public keys in the file are the only ones a
credential from that issuer is checked against. A private key or a MAC key in the file
is refused. Rotating them is the operator's job.

**From its metadata**, with `-keys-from-metadata`, for an issuer whose `iss` is an
`https` URL with no query or fragment:

```sh
signari idp vp-issuer -slug wallet -issuer https://pid.example -keys-from-metadata
```

For each presentation from that issuer, before its signature is checked, its JWT VC
Issuer Metadata is read from `https://pid.example/.well-known/jwt-vc-issuer` (for an
issuer with a path, the path follows the well-known name), through the same outbound
rules as every other request this server makes. It has to be served as
`application/json`, name exactly the same `issuer`, and carry either `jwks` or a
`jwks_uri` at an `https` address, not both. Those keys check the credential, and its
status list, if it names one. Nothing is kept, so an issuer's rotation is seen at once,
and an issuer whose metadata cannot be read signs nobody in until it can.

Only an issuer named here is ever looked up: a credential naming any other is refused
before anything is fetched, so a credential cannot choose where this server goes.

**From its certificate**, with `-root-cert`, for an issuer whose credentials carry
the X.509 chain of their signing key in `x5c`:

```sh
signari idp vp-issuer -slug wallet -issuer https://pid.example -root-cert pid-roots.pem
```

The file holds one or more CA certificates, PEM, and nothing else: a certificate that
is not a CA's, or a key, is refused. For each presentation from that issuer, the
chain in the credential's protected header has to lead to one of them, be valid now,
and its first certificate has to be the key the credential is signed with and name
the issuer:

- a URI subject alternative name that is the `iss` exactly, or
- for an `iss` that is `https://<host>` and nothing more, a DNS subject alternative
  name that is that host. A host does not name an issuer at a path under it, since one
  host may keep several, and a wildcard names nobody.

Any extended key usage is accepted, since an issuer's certificate is not a server's.
A key usage that leaves out digital signatures is refused. The issuer's status list,
if the credential names one, has to be signed by the same key.

Each certificate below the root that names a CRL at an `http` or `https` address is
checked against it, fetched for each presentation and kept for none, through the same
outbound rules. The CRL has to be from that certificate's issuer and signed by it,
current, and carry no critical extension. A delta CRL, an indirect one and one scoped
by an issuing distribution point each carry one, so each is refused rather than read
partly. A certificate that is listed, or whose CRL cannot be read or believed, signs
nobody in. A certificate that names no CRL is left to you: remove the issuer or
replace the roots to stop believing it. OCSP is not asked.

An issuer is believed one way. A credential naming a pinned issuer is checked with the
pinned keys, whatever certificate it carries, so a credential cannot choose how its
issuer is checked.

## Who is signed in

A claim is unique only within the issuer that made it, so the person is the issuer
and the claim together. They are linked as the subject `<issuer>|<claim value>`. A
URL cannot hold a bare `|`, so that subject divides one way only. To let somebody who
already has an account sign in with their wallet:

```sh
signari idp link -slug wallet -subject 'https://pid.example|12345' -email person@example.com
```

Otherwise somebody new is given an account if `allow_signup` is on, as for any
provider. An address from the credential is recorded as verified only when the
provider is set to believe it (`-trust-email-verification`).

## What a presentation has to pass

The wallet posts its answer to `/oid4vp/<slug>/response`, and it is checked there, so a
wallet is told at once that it was refused:

- the request it answers is live and unanswered, before anything is verified;
- exactly one credential, for the one query asked;
- the credential is typed `dc+sd-jwt` (or `vc+sd-jwt`, the name it replaced), signed with
  an asymmetric algorithm by one of its issuer's keys, pinned, from its metadata or from
  its certificate, of a type asked for, and not expired or not yet valid;
- its disclosures are all referenced by it, none twice;
- it carries a key binding (`cnf`), and a Key Binding JWT signed by that key, typed
  `kb+jwt`, made in the last five minutes, for this deployment's whole client
  identifier, with this request's nonce, over exactly the credential and disclosures
  presented;
- every claim asked for is there, with one string or number where a person is named;
- none of the claims SD-JWT VC says must be signed (`iss`, `nbf`, `exp`, `cnf`, `vct`,
  `vct#integrity`, `aka_vcts`, `status`) came in a disclosure. An issuer that made one
  disclosable let every holder leave it out;
- for an issuer believed by its certificate, no certificate of its chain is on a CRL that
  chain names (above);
- if it names a `status`, its issuer has not revoked or suspended it (below).

### Revocation

A credential whose issuer keeps a Token Status List carries a `status_list` claim: an
`https` address and its place in the list. Once everything above has passed, and not
before, so nobody without an otherwise good credential can make this server fetch
anything, the list is fetched from that address through the same outbound rules as
every other request this server makes (`SIGNARI_OUTBOUND_ALLOW_PRIVATE` for a list in
the private network). It has to be:

- served as `application/statuslist+jwt`, typed `statuslist+jwt`;
- signed by one of the credential's own issuer's keys, pinned, from its metadata, or the
  key of the credential's own certificate. A list kept by a separate status issuer is not
  believed, since nothing here says who may speak for whom;
- about this credential's list (`sub` the address the credential names), with an `iat`,
  not expired, not yet to come, and a positive `ttl` if it has one.

The credential's place has to read `0x00`, valid. Revoked (`0x01`), suspended (`0x02`)
and every other value refuse, and so does a place past the list's end, a list that cannot
be read, or a `status` kept by some other mechanism, because none of them shows the
credential was not revoked. The list is fetched for every presentation and never kept: a
cached answer would let a credential revoked since sign somebody in again.

An answer that passes is kept, sealed under a key from a fresh code that is not stored,
and the wallet is told to send the browser to `/oid4vp/<slug>/done` with that code. The
browser has to bring the code and the cookie set when it left. A presentation posted
from another device therefore cannot finish a sign-in that this browser started, and a
code used once is gone.

## Tested against

The OpenID Foundation's OpenID4VP 1.0 verifier plan, the suite playing the wallet:
signed requests under `x509_san_dns` and unsigned ones under `redirect_uri`, with
`direct_post`, and signed requests with `direct_post.jwt`, zero failures in each. Each refusal the plan tests, a credential or key binding
signed with another key, the wrong `sd_hash`, nonce or audience, and a key binding a year
old or a year ahead, is answered at the response URI with a 400. How to run it is in
[the harness](../deploy/conformance/README.md).

## Not done

- **Another device.** A page with a code to scan, which needs words a person has written
  in both languages.
- **The Digital Credentials API**, where the browser carries the request to a wallet itself.
- **mdoc** credentials.
- **A separate status issuer**, whose key is linked to the credential's issuer by a
  certificate authority. Only the issuer's own keys sign a list believed here.
- **OCSP** for an issuer's certificates. CRLs are read; a certificate that names
  neither is left to the operator.

## Routes

| | |
|---|---|
| `GET /oid4vp/<slug>/start` | The sign-in button. Sends the browser to the wallet |
| `GET`, `POST /oid4vp/<slug>/request/<state>` | The signed request object, `application/oauth-authz-req+jwt`; by POST with the wallet's `wallet_nonce` echoed in it |
| `POST /oid4vp/<slug>/response` | Where the wallet posts its answer: `vp_token` and `state` (`direct_post`), or `response`, the JWE (`direct_post.jwt`) |
| `GET /oid4vp/<slug>/done` | Where the wallet sends the browser back |
