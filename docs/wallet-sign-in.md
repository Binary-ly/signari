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
carry, with the public keys they are signed with. A private key or a MAC key in the file
is refused. Those keys are the only ones a credential from that issuer is checked
against. They are not fetched from the issuer and not taken from a certificate in the
credential: SD-JWT VC lets the verifier's policy decide how an issuer's key is found,
and this policy is "the keys the operator gave".

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
  an asymmetric algorithm by a key held for its issuer, of a type asked for, and not
  expired or not yet valid;
- its disclosures are all referenced by it, none twice;
- it carries a key binding (`cnf`), and a Key Binding JWT signed by that key, typed
  `kb+jwt`, made in the last five minutes, for this deployment's whole client
  identifier, with this request's nonce, over exactly the credential and disclosures
  presented;
- every claim asked for is there, with one string or number where a person is named.

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
- **Revocation.** A credential's `status` is not checked, which SD-JWT VC says should be
  done.
- **Finding an issuer's key** from its metadata or a certificate chain. Keys are pinned.

## Routes

| | |
|---|---|
| `GET /oid4vp/<slug>/start` | The sign-in button. Sends the browser to the wallet |
| `GET`, `POST /oid4vp/<slug>/request/<state>` | The signed request object, `application/oauth-authz-req+jwt`; by POST with the wallet's `wallet_nonce` echoed in it |
| `POST /oid4vp/<slug>/response` | Where the wallet posts its answer: `vp_token` and `state` (`direct_post`), or `response`, the JWE (`direct_post.jwt`) |
| `GET /oid4vp/<slug>/done` | Where the wallet sends the browser back |
