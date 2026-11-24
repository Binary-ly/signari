# Signing in with a wallet

## Introduction

Some people carry digital credentials in a wallet on their phone, such as an
identity card or a mobile driving licence. A person can sign in with a
credential from their digital identity wallet.

Signari acts as a "verifier" under OpenID for Verifiable Presentations
([OpenID4VP](glossary.md#openid4vp)) 1.0. It asks the wallet for one credential,
checks what comes back, and signs in the person a claim of that credential
identifies.

The credential is one of two kinds. The first is built on a JSON Web Token (JWT)
whose holder can reveal some claims and keep others hidden. That is a Selective
Disclosure JWT ([SD-JWT](glossary.md#sd-jwt)), and the credential is an SD-JWT
VC. The second is an ISO mdoc, such as a mobile driving licence
([below](#an-iso-mdoc)).

You set it up with `signari idp add -kind oid4vp`, or through the
[Admin API](admin-api.md).

## How it works

After the check, it is an ordinary external sign-in. The linking rules, account
creation, [attribute and group mapping](social-login.md) and the audit events are
the same as for any provider.

By default it works on one device. The sign-in page sends the browser to the
wallet, the wallet posts its answer back to Signari, and then sends the browser
back.

Signing in on a computer with a phone's wallet can be turned on too. It finishes
only with a code emailed to the account, because of an attack that flow cannot
otherwise tell apart ([below](#the-wallet-on-another-device)).

Asking through the browser's Digital Credentials API can be turned on as well.
There, the browser carries the request to the wallet and the answer back
([below](#through-the-browser)).

## Setting one up

These two commands add a wallet sign-in, and then name an issuer whose
credentials it believes:

```sh
signari idp add -kind oid4vp -org <org> -slug wallet -name "Your wallet" \
  -client-id-prefix x509_san_dns -vct urn:eudi:pid:1 \
  -subject-claim personal_administrative_number -email-claim email \
  -client-key-file verifier.key -client-cert-file verifier-chain.pem

signari idp vp-issuer -slug wallet -issuer https://pid.example -jwks-file pid-issuer.jwks
```

The Admin API does the same with `POST /admin/organizations/{orgID}/identity-providers`
and `PUT .../identity-providers/{slug}/vp-issuers` ([the Admin API](admin-api.md)).

The flags of `idp add -kind oid4vp` are these. An encrypted answer comes as a
JWE (JSON Web Encryption), with its key agreed by ECDH-ES (Elliptic Curve
Diffie-Hellman Ephemeral Static).

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

Nobody, until `idp vp-issuer` names an issuer, exactly as the `iss` its
credentials carry. SD-JWT VC lets the verifier's policy decide how an issuer's
key is found, and you choose, issuer by issuer, between two ways.

### Where an issuer's keys come from

**Pinned**, with `-jwks-file`: the public keys in the file are the only ones a
credential from that issuer is checked against. A private key or a MAC
(message authentication code) key in the file is refused. Rotating them is your
job.

**From its metadata**, with `-keys-from-metadata`, for an issuer whose `iss` is an
`https` URL with no query or fragment:

```sh
signari idp vp-issuer -slug wallet -issuer https://pid.example -keys-from-metadata
```

For each presentation from that issuer, its JWT VC Issuer Metadata is read
before its signature is checked. It is read from
`https://pid.example/.well-known/jwt-vc-issuer` (for an issuer with a path, the
path follows the well-known name). The read goes through the same outbound rules
as every other request Signari makes.

The metadata has to be served as `application/json`, and name exactly the same
`issuer`. It has to carry either `jwks` or a `jwks_uri` at an `https` address,
not both. Those keys check the credential, and its status list, if it names one.
Nothing is kept, so an issuer's rotation is seen at once. An issuer whose
metadata cannot be read signs nobody in until it can.

Only an issuer named here is ever looked up. A credential naming any other is
refused before anything is fetched, so a credential cannot choose where Signari
goes.

**From its certificate**, with `-root-cert`, for an issuer whose credentials carry
the X.509 chain of their signing key in `x5c`:

```sh
signari idp vp-issuer -slug wallet -issuer https://pid.example -root-cert pid-roots.pem
```

The file holds one or more certificate authority (CA) certificates, PEM, and
nothing else. A certificate that is not a CA's, or a key, is refused.

For each presentation from that issuer, the chain in the credential's protected
header has to lead to one of them, and be valid now. Its first certificate has
to be the key the credential is signed with, and name the issuer:

- a URI subject alternative name that is the `iss` exactly, or
- for an `iss` that is `https://<host>` and nothing more, a DNS subject alternative
  name that is that host. A host does not name an issuer at a path under it, since one
  host may keep several, and a wildcard names nobody.

Any extended key usage is accepted, since an issuer's certificate is not a
server's. A key usage that leaves out digital signatures is refused. The
issuer's status list, if the credential names one, has to be signed by the same
key.

Each certificate below the root that names a certificate revocation list (CRL)
at an `http` or `https` address is checked against it. The CRL is fetched for
each presentation and kept for none, through the same outbound rules.

The CRL has to be from that certificate's issuer and signed by it, current, and
carry no critical extension. A delta CRL, an indirect one and one scoped by an
issuing distribution point each carry one, so each is refused rather than read
partly. A certificate that is listed, or whose CRL cannot be read or believed,
signs nobody in.

A certificate that names no CRL is left to you: remove the issuer or replace the
roots to stop believing it. OCSP (Online Certificate Status Protocol) is not
asked.

An issuer is believed one way. A credential naming a pinned issuer is checked
with the pinned keys, whatever certificate it carries. So a credential cannot
choose how its issuer is checked.

## Who is signed in

A claim is unique only within the issuer that made it, so the person is the
issuer and the claim together. They are linked as the subject
`<issuer>|<claim value>`. A URL cannot hold a bare `|`, so that subject divides
one way only.

To let somebody who already has an account sign in with their wallet, link the
credential to it:

```sh
signari idp link -slug wallet -subject 'https://pid.example|12345' -email person@example.com
```

Otherwise somebody new is given an account if `allow_signup` is on, as for any
provider. An address from the credential is recorded as verified only when the
provider is set to believe it (`-trust-email-verification`).

## What a presentation has to pass

The wallet posts its answer to `/oid4vp/<slug>/response`, and it is checked
there, so a wallet is told at once that it was refused. The answer has to pass
every one of these:

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

A credential whose issuer keeps a Token Status List carries a `status_list`
claim: an `https` address and its place in the list.

The list is fetched once everything above has passed, and not before, so nobody
without an otherwise good credential can make Signari fetch anything. It is
fetched from that address through the same outbound rules as every other request
Signari makes (`SIGNARI_OUTBOUND_ALLOW_PRIVATE` for a list in the private
network). It has to be:

- served as `application/statuslist+jwt`, typed `statuslist+jwt`;
- signed by one of the credential's own issuer's keys, pinned, from its metadata, or the
  key of the credential's own certificate. A list kept by a separate status issuer is not
  believed, since nothing in Signari says who may speak for whom;
- about this credential's list (`sub` the address the credential names), with an `iat`,
  not expired, not yet to come, and a positive `ttl` if it has one.

The credential's place has to read `0x00`, valid. Revoked (`0x01`), suspended
(`0x02`) and every other value refuse. So does a place past the list's end, a
list that cannot be read, or a `status` kept by some other mechanism. None of
them shows the credential was not revoked.

The list is fetched for every presentation and never kept: a cached answer would
let a credential revoked since sign somebody in again.

An answer that passes is kept, sealed under a key from a fresh code that is not
stored. The wallet is told to send the browser to `/oid4vp/<slug>/done` with that
code. The browser has to bring the code and the cookie set when it left.

A presentation posted from another device therefore cannot finish a sign-in that
this browser started, and a code used once is gone.

## The wallet on another device

A person can sign in on a computer with the wallet on their phone. This is off
unless you turn it on, and only for a signed request (`x509_san_dns` or
`x509_hash`). To turn it on:

```sh
signari idp vp-cross-device -slug wallet          # -remove turns it off
```

The sign-in button then leads to a page with two ways. The person can open the
wallet on this device, which is the flow above. Or they can scan a QR code with
the wallet on a phone.
The page waits, asking every two seconds whether the wallet has answered. It
works without its script too, by a link.

**Why it needs a second code.** A sign-in started on one screen and answered on
another cannot be told apart from an attack. In the attack, somebody starts a
sign-in on their own screen and relays it to you with a story. Your wallet shows
the real verifier's name, you share, and their browser is signed in as you.

OpenID4VP says plainly that the verifier has no session context to detect this
(`direct_post` without a redirect, its section 14.2). The cross-device Best
Current Practice (BCP) asks for a risk assessment first, and for mitigations that
fit (draft-ietf-oauth-cross-device-security, sections 2 and 6.1). Here they are:

- **A code to the account's own address.** Once the wallet has answered, the account
  linked to the credential is emailed a six-digit code (ten minutes, five tries, bound
  to this sign-in). Only that code, typed on the page that began it, finishes the
  sign-in. The mail says somebody is signing in with your wallet on another screen,
  and not to give the code to anybody. Somebody who relayed the QR code has to phish
  the code too, and the person they are after receives a mail they did not expect.
- **Existing accounts only.** The credential has to be linked already to an active
  account with an address. Nobody is created, and nothing is linked, from another
  device. The account is read again in the transaction that signs in, so an unlink in
  between ends it.
- **No response code.** The wallet answering a cross-device request is given no
  `redirect_uri`, so no browser can finish the sign-in with a response code. A
  same-device request never sends a mail, and a cross-device one never takes a
  response code: they are separate sign-ins, marked as such.
- **Short-lived, used once.** The request lives five minutes, the sign-in ten, and the
  answer is taken once.
- **Words on the page**, in each language: scan only a code on a page you opened
  yourself.

What the page says while it waits tells nobody whose account it is. The code page
does not name the address either.

[Mail](mail.md) has to be set up, or the code never arrives. The sign-in is
recorded as `federation.wallet_code_sent`. A wrong code is recorded as
`login.failed` with reason `bad_wallet_code`, counted against the account's
second-factor budget.

## Through the browser

Asking through the browser is off unless you turn it on:

```sh
signari idp vp-dc-api -slug wallet          # -remove turns it off
```

The sign-in page then asks the browser's Digital Credentials API too, where the
browser offers it. The page carries the request, and its script shows a button
only where the browser says it allows the protocol.

The click hands the request to `navigator.credentials.get` while it is still the
person's own click, as the API requires. The browser takes it to the wallet the
person picks, with this page's origin.

What comes back is posted by the page itself. So the answer, the redirect and the
session all happen in the browser that holds the sign-in's cookie. That is the
OpenID4VP appendix for this API.

- **The request.** Under `x509_san_dns` or `x509_hash` it is signed
  (`openid4vp-v1-signed`). It names this deployment's client identifier, and
  `expected_origins` names Signari's origin alone, which the wallet holds the
  browser's origin to. Under `redirect_uri` it is unsigned (`openid4vp-v1-unsigned`),
  with no client identifier, as the appendix requires. `direct_post.jwt` becomes
  `dc_api.jwt`, with the request's own key to encrypt to. No `state` and no
  `response_uri`: the API has no use for either.
- **The answer.** It has to be made for `origin:` followed by Signari's origin,
  never for the client identifier, signed request or not. The appendix's examples
  write the origin with a trailing slash. An origin has none, and the normative text
  names the origin, so none is accepted. Everything else is checked as in
  [what a presentation has to pass](#what-a-presentation-has-to-pass). An error from
  the wallet ends the sign-in as cancelled. Closing the browser's dialog leaves the
  person on the page with the other ways.
- **Each way its own.** A request handed to the browser is a sign-in of its own. It
  is never fetched at the request URI, never answered at the response URI, and never
  given a response code. A sign-in begun any other way is not finished by an answer
  posted as the browser's. The sign-in is consumed with the browser's cookie before
  the answer is read, so an answer is tried once.

The page's script is `/static/wallet-dcapi.js`. The page's policy lets it run its
own scripts and nothing else.

## An ISO mdoc

A wallet sign-in can ask for an mdoc in place of an SD-JWT VC. An mdoc is the
format of a mobile driving licence (ISO/IEC 18013-5), and of documents built the
same way.

It names one document type rather than credential types. It believes an issuing
authority's IACA certificate rather than an issuer's keys. This command adds a
sign-in that asks for a driving licence:

```sh
signari idp add -org <org> -kind oid4vp -slug mdl -name "Driving licence" \
  -client-id-prefix x509_san_dns -client-key-file verifier.key -client-cert-file verifier-chain.pem \
  -credential-format mso_mdoc -doctype org.iso.18013.5.1.mDL -root-cert iaca.pem \
  -subject-claim '["org.iso.18013.5.1","document_number"]' \
  -name-claim '["org.iso.18013.5.1","given_name"]'
```

A claim of an mdoc is named by two parts, its namespace and its element. Where
the IACA certificates come from is your choice. An issuing authority publishes
its own, and `signari idp vp-iaca -slug mdl -root-cert iaca.pem` replaces them
when it re-keys.

The person is identified within the document type and the issuing country, and
state where the authority is a state's. The subject is
`mdoc:org.iso.18013.5.1.mDL:<country>[-<state>]|<the subject claim>`, so the same
document number from two countries is two people.

An mdoc's answer is checked as ISO/IEC 18013-5 has a reader check it:

- **The document signer** is the first certificate the issuer's signature carries.
  It leads to one of the IACA certificates, and carries the document signer's
  extended key usage and a key usage that allows a signature. It has the IACA's
  country, and its state where the IACA has one. A CRL it names is read, as for an SD-JWT VC's issuer.
- **The issuer's signature** over the mobile security object, with that certificate's
  key, by ES256, ES384, ES512 or EdDSA with Ed25519.
- **Every element returned** has the digest the issuer signed for it, carries at least
  16 bytes of random, and is returned once. The document type the issuer signed is
  the one presented.
- **The validity:** signed while the signer's certificate was valid, valid from now
  or before, and until now or after.
- **The device's signature** over this request. The session transcript names this
  verifier's client identifier, the nonce, the response URI, and for an encrypted
  answer the key it was encrypted to. Through the browser, it names the origin. An answer made
  for another request, verifier or key is refused. An element the device signs
  itself has to be one the issuer authorized its key for, and is never read.

Some things are not accepted. Brainpool curves and Ed448 are allowed by the
standard, but Go's standard library does not implement them. A device that
authenticates with a MAC needs a reader key, which a request over OpenID4VP does
not carry here. Each is refused by name.

## Tested against

The OpenID Foundation's OpenID4VP 1.0 verifier plan, with the suite playing the
wallet. It ran signed requests under `x509_san_dns` and unsigned ones under
`redirect_uri`, with `direct_post`, and signed requests with `direct_post.jwt`,
with zero failures in each.

The plan tests these refusals: a credential or key binding signed with another
key; the wrong `sd_hash`, nonce or audience; and a key binding a year old or a
year ahead. Each is answered at the response URI with a 400. How to run it is in
[the harness](../deploy/conformance/README.md).

An mdoc was checked against the example data in ISO/IEC 18013-5 Annex D. Its
issuer signature verifies with its document signer certificate, which leads to
its IACA and carries the document signer's key usage. Its mobile security object
reads, and the digest of an element it returns matches the one signed. The
DeviceAuthenticationBytes made here equal the standard's, byte for byte.

The session transcripts equal OpenID4VP's own examples for a request by redirect
and through the browser.

## Not done

- **An mdoc authenticated by a MAC**, and mdocs on brainpool curves or Ed448
  ([above](#an-iso-mdoc)).
- **A separate status issuer**, whose key is linked to the credential's issuer by a
  certificate authority. Only the issuer's own keys sign a list believed here.
- **OCSP** for an issuer's certificates. CRLs are read; a certificate that names
  neither is left to you.

## Routes

A wallet sign-in serves these addresses:

| | |
|---|---|
| `GET /oid4vp/<slug>/start` | The sign-in button. Sends the browser to the wallet, or with another device or the browser's API turned on, shows the page offering each; `?device=this` goes straight to the wallet |
| `GET`, `POST /oid4vp/<slug>/request/<state>` | The signed request object, `application/oauth-authz-req+jwt`; by POST with the wallet's `wallet_nonce` echoed in it |
| `POST /oid4vp/<slug>/response` | Where the wallet posts its answer: `vp_token` and `state` (`direct_post`), or `response`, the JWE (`direct_post.jwt`) |
| `GET /oid4vp/<slug>/done` | Where the wallet sends the browser back |
| `GET /oid4vp/<slug>/wait` | For the page a cross-device sign-in began on, with its cookie: whether the wallet has answered, as JSON |
| `GET`, `POST /oid4vp/<slug>/confirm` | The code page: sends the linked account its code once, then takes it and signs in |
| `GET /static/wallet-wait.js` | The waiting page's one script |
| `POST /oid4vp/<slug>/dcapi` | Where the page posts what the browser's Digital Credentials API brought back |
| `GET /static/wallet-dcapi.js` | The script that asks the browser |
