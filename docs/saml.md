# SAML 2.0

## Introduction

Many business applications sign people in with Security Assertion Markup
Language ([SAML](glossary.md#saml)) 2.0, and some offer nothing newer. Grafana,
Jira, Zendesk, Salesforce and most other enterprise software speak it. So does
Acme's chat application.

Signari is a SAML identity provider. When Ada opens the chat application, it
sends her browser to Signari. Signari checks who she is, then sends her back with
a signed XML document, called an "assertion", that says who she is. In SAML's
words, the chat application is a "service provider". [Which protocol do I
need?](protocols-explained.md#saml-20) explains SAML in plain words.

You register each SAML application with the command line, the Admin API or a
configuration file. Then you give the application Signari's metadata.

## Register an application

A SAML application has an "entity ID", the name it calls itself, which is usually
a URL. It also has an "Assertion Consumer Service (ACS) URL", the address on the
application that receives the assertion. This command registers Grafana with
both:

```sh
signari saml add-sp \
  -org        <org-uuid> \
  -entity-id  https://grafana.example.com/metadata \
  -name       Grafana \
  -acs        https://grafana.example.com/login/saml/acs
```

Then point the application at `https://auth.example.com/saml/metadata`. That is
Signari's "metadata": an XML document that lists its addresses and its signing
certificates. If the application publishes metadata of its own, [register it from
that](saml-metadata.md) instead of typing it in.

The Admin API registers SAML applications the same way, under
`/admin/organizations/{orgID}/saml-providers`. It also sets their signing, and
which attributes and groups are released to them. See [the Admin
API](admin-api.md).

A SAML "binding" is the way a message travels. It can travel in the query string
of a redirect, in a form the browser posts, or from server to server over SOAP.
Signari answers SAML at these addresses:

| Endpoint | Purpose |
|---|---|
| `GET /saml/metadata` | what the service provider imports |
| `GET /saml/sso` | HTTP-Redirect binding |
| `POST /saml/sso` | HTTP-POST binding |
| `POST /saml/artifact` | the artifact resolution service, SOAP; see [the Artifact binding](#the-artifact-binding) |
| `POST /saml/ecp` | sign-on over SOAP for a client that is not a browser; see [ECP](#ecp-signing-in-without-a-browser) |

## One entity ID, several organisations

A software-as-a-service (SaaS) application usually sends the same entity ID for
every customer. Two organisations in one deployment may then both need to
register it. An "AuthnRequest", the application's request to sign someone
in, names only its issuer. A WS-Federation `wtrealm` does the same. So the path
the request arrives at has to say whose provider it is:

| | |
|---|---|
| The deployment's endpoints | `/saml/sso`, `/saml/slo`, `/saml/metadata`, `/wsfed`. An entity ID is held here once. This server's entity ID is `<issuer>/saml` |
| An organisation's endpoints | `/saml/org/<slug>/sso`, `/slo`, `/metadata`, `/wsfed/org/<slug>`, and `/wsfed/org/<slug>/FederationMetadata.xml`. An entity ID is held once in the organisation. This server's entity ID is `<issuer>/saml/org/<slug>` |

A provider answers at one set of endpoints or the other. Suppose another
organisation already holds an entity ID at the deployment's endpoints.
Registering the same entity ID then puts the new registration at its own
organisation's endpoints. `saml add-sp`, the Admin API and `signari apply` all do
this without being asked:

```sh
signari saml add-sp -org <uuid> -metadata https://app.example.com/saml/metadata -metadata-unsigned
Another organisation holds this entity id at the deployment's endpoints, so this
one answers at its own: give the provider the metadata from /saml/org/<slug>/metadata.
```

Nothing moves for the organisation that held the entity ID first. A request at a
path finds only that path's provider. So one organisation's certificate cannot
check another's request, and its reply URLs cannot receive the other's
assertion. A person of one organisation is refused at the other's path.

Registration decides this, not sign-in, on purpose. Suppose sign-in refused an
entity ID that two organisations hold at the deployment's endpoints. Any
organisation could then switch off another's sign-in by registering the same
entity ID.

`signari saml org-endpoint -entity-id <id> [-org <uuid>]` moves a provider to its
organisation's endpoints. `-remove` moves it back, which is refused while somebody
else holds the entity ID there. Either way, the provider has to be given the new
metadata, because the entity ID it knows Signari by has changed.

An organisation's "slug" is the short name in its endpoints' paths. It cannot be
changed through Signari, by command, Admin API or configuration file, so this
entity ID stays as it was issued. Changing the slug in the database by hand would
change the entity ID in the same way. Every provider at the organisation's
endpoints would then need the new metadata.

Where two organisations hold an entity ID, a command that takes `-entity-id`
needs `-org` as well, and says so.

## What was built against, and why it looks like this

Before any of this was written, the published security advisories for the three
most-used Go SAML libraries were read, not recalled:

| library | advisories |
|---|---|
| `github.com/crewjam/saml` | 4 |
| `github.com/russellhaering/gosaml2` | 5 |
| `github.com/russellhaering/goxmldsig` | 3 |

Almost every one is a **signature-validation or authentication bypass**. Not one
is a cryptographic break. They are parsing and policy decisions, such as:

- An assertion accepted because *something* in the document was signed.
- A LogoutRequest acted on with no signature at all.
- A compressed request expanded without a bound.

So Signari's defences are explicit, and the dangerous configuration is the one you
would have to ask for.

**The assertion is signed, not only the response.** Suppose only the response
carries a signature. An attacker holding one valid response can often move the
signed element aside and insert their own assertion. The document still contains
a valid signature over *something*. Signing the assertion means the element that
carries the identity is the element the signature covers.

Some providers want the Response signed as well. For them,
`signari saml signing -entity-id <id> -sign-responses` adds an "enveloped"
signature, one placed inside the element it signs, over the whole Response. It is
made last. The assertion is signed first, then encrypted when the provider
registered an encryption certificate. The order is sign, encrypt, sign, so the
last signature covers the ciphertext as it is sent.

`-sign-assertions=false` leaves the assertion unsigned, for a provider that
checks only the Response. The two cannot both be off. A flag left out of the
command leaves its setting alone. Until October 2026, both settings were stored
and ignored, and every response signed the assertion only.

**XML comments inside the document are refused outright.** Go parses
`<Issuer>admin<!---->@evil.test</Issuer>` as `admin@evil.test`. Canonicalisation
drops comments before the digest is computed, and other parsers keep only the
first text node. So the signed bytes, Signari's value and the other party's value
can all differ. That is CVE-2017-11427 and its relatives.

Signari does not try to agree with every other implementation. Instead, a
document with a comment anywhere inside its document element is rejected. No
legitimate application puts a comment in an AuthnRequest. A comment before
or after the document element is allowed, because it is in no element's text and
under no signature. Shibboleth's metadata generator begins every document with
one, and until November 2026 that refused its metadata.

**Decompression is bounded during the read**, not measured afterwards. A few
kilobytes of DEFLATE expands to gigabytes. That is how both `crewjam/saml` and
`gosaml2` were taken down.

**ACS URLs are an exact-match allow-list.** This is the SAML equivalent of
OpenID Connect's `redirect_uri`, and it is where assertions get stolen. Whoever
can steer the `AssertionConsumerServiceURL` receives a genuine, correctly signed
assertion for a real person, at a server they control. Seventeen evasion
techniques are tested:

- An attacker's host.
- The registered host as a prefix.
- Userinfo, with `@`.
- A subdomain.
- Path traversal.
- A trailing slash.
- A scheme downgrade.
- An explicit `:443`.
- A change of case.
- Percent-encoding.
- An appended query and fragment.
- A double slash.
- A backslash.
- An embedded null.
- A newline.

**A request that fails validation is refused to the browser.** It is never turned
into a SAML error POSTed to the URL the request named. Doing that would make the
endpoint a redirector for any entity ID an attacker invents, because the ACS URL
is exactly what is in dispute.

**NameIDs are pairwise by default.** The "NameID" is the identifier for the
person inside the assertion. Each application sees a different opaque
identifier for the same person, so two of them cannot correlate the people they
share. A pairwise NameID also survives an email change, which an `emailAddress`
NameID does not. The application treats the NameID as the account key, so a
new value means a new, empty account.

**The authentication context is what really happened.** The "authentication
context" says how the person signed in. A password-only session asserts
`PasswordProtectedTransport`, never `MultiFactorAuthentication`. Overstating it
would tell an application that its step-up requirement, a demand for a
stronger sign-in, was met when it was not.

## Proof, from tools that are not ours

Checking Signari's own signature with Signari's own library proves only that
Signari agrees with itself. So these tools check it instead:

- **xmlsec1** (the reference C implementation most SAML software is built on)
  verifies the assertion, and rejects it once the NameID is edited.
- **xmllint against the official OASIS schemas**, copied into `testdata`,
  confirms the document is schema-valid.
- The parser has taken 3.5M fuzz executions with no crash.

Schema validation earned its place at once. It caught a document carrying **two
identical `<ds:Signature>` elements**. `goxmldsig` appends the signature onto
etree's child slice without setting its parent. So the reordering code's
`RemoveChild` silently did nothing, and the insert left the same element in the
list twice.

xmlsec1 reported OK, because it found a valid signature, so every signature-based
test passed. A duplicated signature is also exactly the shape a "wrapping attack"
takes, where a forged element sits beside a signed one. Strict providers reject
it.

## Keys and certificates

SAML needs an X.509 certificate where OpenID Connect ([OIDC](glossary.md#oidc))
needs only a public key. That is because SAML applications **pin** the
certificate out of the metadata: they keep it, and trust only signatures it
verifies.

That makes rotation a coordinated change, not a background one. The certificate
is generated once and stored, and never regenerated. A fresh certificate has a new
fingerprint. Every application pinning the old one would start rejecting
assertions now and then, depending on which node answered.

Metadata publishes **every** current certificate, so providers can pick up an
incoming one before it is used. Rotation is then: publish, wait for providers to
refresh, switch.

Each certificate names its key in the subject, `OU=key <kid>`, beside the host in
the common name (CN). Some providers trust every published certificate and find
the signer's by name, so they need the names to differ. With three certificates
all called `O=Signari, CN=<host>`, xmlsec1 verified a response with them loaded in
one order, and found no key in another. A certificate made before October 2026
keeps its old name, since its fingerprint is pinned. It leaves when its key
rotates out.

### Which key signs a provider

Each provider is signed with **RSA-SHA256** by the active
[RS256](glossary.md#rs256) key. A provider can instead be set to
**ECDSA-SHA256**, which the active [ES256](glossary.md#es256) key signs. This
command sets a provider to ECDSA, the Elliptic Curve Digital Signature Algorithm:

```sh
signari saml signing -entity-id https://sp.example.com -signature-alg ecdsa-sha256
```

RSA is the default because ECDSA is in the specification, and a great deal of real
SAML application software refuses it. An ECDSA-signed assertion to a provider that
cannot verify it is correct, and rejected anyway. Only someone who knows the far
end can say it accepts ECDSA. That is why the setting is per provider, and never
follows whichever key happens to be active. The command refuses an algorithm that
the provider's instance has no active key for, since every sign-in to it would
then fail.

A provider's metadata, `/saml/metadata?sp=<entity-id>`, carries the certificates
of the algorithm it is set to. Give the provider the new document before its next
sign-in, because it checks signatures against the certificates it already holds.
The default document, with no `sp`, carries the RS256 certificates. Set a provider
to ECDSA only once every node runs a release that reads the setting. An older node
ignores it and signs with RSA.

An ECDSA signature value is r and s as two 32-byte integers, concatenated, which
is what xmlsec1 writes and accepts. A key's `crypto.Signer` returns the DER
(Distinguished Encoding Rules) encoding instead, and xmlsec1 refuses that with
`SIGNATURE`. The engine converts it. The redirect binding's `Signature` parameter
carries the same encoding under the same `SigAlg`. No independent receiver has
checked that encoding for the redirect binding here.

Signing goes through the key's `crypto.Signer` alone. So a key whose private half
never leaves a key store signs SAML exactly as a software key does. Until October
2026, SAML required an in-process RSA private key and refused every other.

## Single Logout

With SAML's Single Logout, an application can start a sign-out on the
HTTP-Redirect binding. To allow that, register the application's sign-out URL and
its certificate:

```sh
signari saml add-sp ... -slo https://sp.example.com/slo -sp-cert ./sp.crt
```

**A LogoutRequest is acted on only when signed.** gosaml2 accepted unsigned ones
(GHSA-pcgw-qcv5-h8ch). That meant anybody who could reach the endpoint could sign
any person out of everything, needing no credential at all. It is the cheapest
denial of service there is against an identity provider.

So a provider with no certificate on file cannot use SAML sign-out. Registering a
sign-out URL without one is refused at the command line. Otherwise you would have a
configuration that looks complete and rejects every request.

The signature is checked over the **raw query-string octets**, in the order the
specification fixes. It is not checked over any `<ds:Signature>` the document
happens to carry. On the redirect binding, the signature *is* the query
parameters, and an embedded element proves nothing about what was really sent.

Rebuilding the string from a parsed map is the classic mistake. Go's encoder
escapes a different set of characters, sorts keys and drops an empty RelayState.
The bytes checked are then not the bytes signed.

Verified live against the running engine:

| | |
|---|---|
| unsigned LogoutRequest | refused, session stays live |
| valid request substituted for the signed one | refused at signature verification |
| correctly signed | `200`, session revoked |
| replay of the same request id | `Requester`, session not touched again |

RSA-SHA1 is refused outright. Chosen-prefix collisions against SHA-1 are
practical, and a warning nobody reads is not a control.

## Logout propagation

Signing out of Signari also signs the person out of the SAML applications.

The SOAP binding is a "back channel", from server to server, and few providers
offer it. So for most providers, propagation means walking the **browser** through
each provider's sign-out endpoint in turn. Signari redirects to the first provider,
which ends its session and redirects back. Then Signari redirects to the second,
and so on until the list is empty.

**Signari's own session is ended before the chain starts, never at the end**. A
chain that ended the local session last would leave the person signed in here
whenever a provider fails to redirect back. Providers fail all the time: a closed
tab, a 500, a dropped network. By the time the first redirect is issued, signing
out of Signari has already happened.

Everything after that is best-effort notification. What could not be reached is
recorded, not assumed, in the `saml.logout_propagated` audit event.

Sometimes nothing asked for the browser to be sent on afterwards. The person is
then shown a page that says they are signed out. It says which applications were
told, and which could not be reached and may still have a session open. It is the
`signedout` page, and it can be overridden like any other
([theming](theming.md)). A caller that does not ask for HTML is given the same
report as JSON:

```json
{"status":"signed out",
 "notified":["https://spb.test/md","https://spa.test/md"],
 "failed":[]}
```

Verified end to end against two SAML applications:

| | |
|---|---|
| requests sent | exactly one per provider |
| NameID | each provider received its **own** pairwise value |
| SessionIndex | the one from that provider's assertion |
| signature | verified by **openssl** against the key in our published metadata |
| local session | revoked before the chain began |

The chain's state lives in the database, not in a cookie and not in the URL. A
cookie would be editable by the person, and it names the endpoints to visit. An
attacker could rewrite it, and have a browser carrying Signari's signature visit
their own server. The URL would leak the state into every referrer header and
access log along the way. The chain token travels as `RelayState`, which providers
return unchanged, and only its hash is stored.

A chain is bounded at ten providers and expires after five minutes. The janitor,
Signari's background clean-up, sweeps away abandoned ones.

**One deliberate asymmetry:** an inbound LogoutRequest must be signed, but a
LogoutResponse coming back is not required to be. A response ends nothing,
because the session is already gone. The worst a forged one achieves is moving
Signari's bookkeeping past a provider it was about to notify. Even that costs a
valid chain token, which the attacker does not have. Requiring a signature would
instead strand the chain at every provider that answers unsigned, which most do.

### With no browser

A chain needs a browser, and most sessions do not end in one. An administrator
ends them, a person is deactivated, or a session expires. A provider with a SOAP
address hears of all of these. The address comes from the provider's metadata, as
a `SingleLogoutService` on the SOAP binding. You can also set it by hand:

```sh
signari saml soap-logout -entity-id https://sp.example.com/shibboleth \
  -url https://sp.example.com/Shibboleth.sso/SLO/SOAP
```

Every session that ends and reached that provider queues a notice, in the same
transaction. The notice holds IDs and no NameID, since a queue is the last place to
keep somebody's address. The outbox, Signari's queue of messages to deliver, then
posts a signed `LogoutRequest` in a SOAP 1.1 envelope. It carries the NameID and
SessionIndex the assertion did, with the signature the provider's copy of the
metadata verifies.

It is delivered like a [Back-Channel Logout](logout.md) notice. It is retried with
backoff when the provider:

- is down;
- answers with anything but a `LogoutResponse` to that request saying `Success`;
- or sends a SOAP fault.

After that it is parked, with the failure on record. A provider since disabled is
not chased.

The signature on the answer is not checked. The provider was reached at its
registered address over Transport Layer Security ([TLS](glossary.md#tls)), and all
the answer decides is whether to try again. A SOAP address is never given to a
browser. A provider with both kinds of address is told both ways, which it can
bear: the second finds nothing left to end.

## Signed AuthnRequests

Signari can require a provider to sign its AuthnRequests. It is off by default,
and set per provider. To require it, register the provider's certificate with
`-want-signed-requests`:

```sh
signari saml add-sp -org <uuid> -entity-id https://sp.test/md \
  -acs https://sp.test/acs -sp-cert sp.crt -want-signed-requests
```

The certificate is not optional. Requiring signatures with nothing to verify them
against refuses every sign-in through that provider. So `-want-signed-requests`
without `-sp-cert` is rejected at registration. It is the same "fail-closed" rule,
refusing when in doubt, that the sign-out URL already had. `signari doctor` reports
the same combination as critical if it is ever created another way.

The signature is checked **before** validation. Everything validation goes on to
decide is read out of the document: which ACS URL, which NameID format, and
whether to force re-authentication.

**A signed AuthnRequest is answered once.** Its ID is recorded when the assertion
is issued. The same request presented again is answered with a `Requester` status
and no assertion. So a captured request cannot keep drawing fresh assertions for
whoever holds a signed-in browser.

The ID is recorded at issuance, not on arrival, because a request held across
sign-in comes back carrying the same document. An unsigned request is not
recorded, because anyone can mint a new ID for one. Until October 2026, the table
documented this and nothing wrote to it.

### The two bindings sign different things

Each binding signs a different part of the message:

| Binding | What is signed | Verified by |
| --- | --- | --- |
| HTTP-Redirect | the raw query octets, `SigAlg`/`Signature` as separate parameters | `VerifyRedirectSignature` |
| HTTP-POST | an enveloped `<ds:Signature>` inside the document | `VerifyEmbeddedSignature` |

A redirect-binding request can *also* contain a `<ds:Signature>`. Verifying that
one proves nothing, because the attacker supplied the whole document. So the
binding the request arrived on decides which check runs, and there is no fallback
between them.

### What the POST binding needed on top of goxmldsig

goxmldsig gets the cryptography right, and deliberately leaves the policy to its
caller. Three of its behaviours are each reasonable alone, and together a bypass:

- `findSignature` **traverses the tree**, so a signature anywhere inside the
  document can satisfy it.
- a `Reference URI` of `""` is accepted, meaning "the whole document".
- **RSA-SHA1 is accepted.** The redirect binding here already refuses SHA-1, and a
  signature scheme is only as strong as the weakest binding that accepts it.

So the structure is checked first, and only then is anything verified
cryptographically:

1. Exactly one `Signature` element in the whole document.
2. It is a **direct child of the root**.
3. Exactly one `Reference`, whose URI is `#<root ID>`.
4. No duplicate `ID` attributes anywhere.
5. SHA-1 refused on both the signature method and the digest.
6. Afterwards, the element goxmldsig says it verified must still be the element
   Signari parsed, compared by ID and tag.

Rule 2 is the one that stops classic wrapping. Its test uses distinct IDs on
purpose, so that the duplicate-ID rule cannot be what passes it. Without rule 2,
that document has one valid signature and no duplicate IDs, and it is accepted.

### Service providers with an EC key

A provider whose certificate holds a P-256 elliptic-curve (EC) key can sign with
`ecdsa-sha256`, on either binding. The signature value is r and s as two 32-byte
integers, which is what xmlsec1 writes. The goxmldsig library checks ECDSA as DER,
so the value is converted before it is checked. The value is not covered by the signature, so
converting it changes nothing that was signed.

A DER-encoded value is refused by name, as xmlsec1 refuses it. The other ECDSA
algorithms are refused, as is any algorithm that does not match the key in the
registered certificate. Until October 2026, an EC provider was refused on the
redirect binding as an unsupported signature algorithm. On the POST binding it was
refused as a signature that did not verify.

### Surviving the sign-in redirect

A request that arrives before the person is signed in gets parked while they sign
in. On the redirect binding, the signed bytes are *the query as the
application encoded it*. Rebuilding that query with `url.Values` changes the escaping
and the ordering, and the signature no longer verifies. That would surface
**after** the person had already typed their password, the worst place to
discover it.

So the original query is carried across verbatim, as one opaque `SigQuery` value.
It is attacker-supplied like anything else on a URL, so it earns nothing on its
own. It still has to verify against the registered certificate, and it must name
the same `SAMLRequest` being processed. Both were tested by tampering:

```
drop SigQuery from the resumed URL     -> "no signature on the redirect binding"
swap in a different signed AuthnRequest -> "the preserved signature covers a
                                            different AuthnRequest than the one
                                            being processed"
```

### Metadata

`WantAuthnRequestsSigned` is set per provider here, so one document for everyone
cannot state it truthfully. `/saml/metadata` reports the default, `false`, which is
what a new registration gets. `/saml/metadata?sp=<entityID>` reports what is
really configured for that provider.

An unknown entity ID gets the default document, not an error. Failing would make
the endpoint a way to enumerate which applications are registered.

## Single Logout on both bindings

`GET /saml/slo` takes the HTTP-Redirect binding, and `POST /saml/slo` the
HTTP-POST binding. The binding a request arrived on decides how it is decoded
**and** how its signature is checked. The redirect binding signs the raw query
octets, and the POST binding signs the document. There is no fallback between
them.

Unlike for AuthnRequests, the signature here is never optional. A LogoutRequest
acted on unsigned lets anybody sign anybody out with no credential at all (gosaml2
GHSA-pcgw-qcv5-h8ch). So a provider with no certificate on file cannot use SAML
sign-out.

Tested against the running engine, with a SAML application built separately from
the engine:

| request | result |
| --- | --- |
| correctly signed | accepted, session ended |
| unsigned | refused — "the LogoutRequest carries no signature" |
| subject changed after signing | refused — signature does not verify |
| signature-wrapped | refused — "the Signature is not a direct child of the LogoutRequest" |

The wrapping case used a **different** outer ID, so the duplicate-ID rule was not
what caught it. The placement rule was.

### The response goes back on the binding that was registered

This was found by watching the wire, not by reading the code. Every
`LogoutResponse` used to leave as an auto-submitting POST form. That included
endpoints registered as `HTTP-Redirect`, which was all of them, since that was the
only binding `saml add-sp` could store. A provider expecting
`SAMLResponse`/`SigAlg`/`Signature` as query parameters got a form POST, and had
nothing to parse.

The binding is now stored and honoured. To register a sign-out endpoint on the POST
binding:

```sh
signari saml add-sp ... -slo https://sp.test/slo -slo-binding HTTP-POST
```

`HTTP-Artifact` is the third binding; see [sign-out by
artifact](#logout-by-artifact). A provider that registered both is answered on
whichever binding it used.

The redirect-bound response was checked with **openssl**, against the certificate
Signari publishes in its own metadata. That is an entirely separate path from the
code that produced it:

```
openssl dgst -sha256 -verify idp.pub -signature sig.bin signed.bin
Verified OK
```

## Encrypted assertions

Signari can also encrypt the assertion. This is opt-in per provider, and needs a
**separate certificate** from the signing one. To register both certificates:

```sh
signari saml add-sp ... -sp-cert sp-signing.crt -sp-encryption-cert sp-encryption.crt
```

Applications sign with one key and decrypt with another. In SAML metadata,
they appear as separate `KeyDescriptor` elements with `use="signing"` and
`use="encryption"`.

Passing the same file for both is refused at registration, because the failure is
otherwise silent. Assertions encrypt perfectly, and the provider cannot read a
single one. RSA below 2048 bits is refused at registration *and* again at the
point of use, since a certificate can be replaced later.

### Sign, then encrypt

The assertion is signed first and encrypted afterwards. The other order leaves the
signature over the ciphertext. That says who produced the envelope, and nothing
about the identity inside it. A provider that decrypts is then left holding an
unsigned assertion, and has to trust the wrapper.

### AES-256-GCM only, never CBC

XML Encryption's CBC (cipher block chaining) modes are broken in practice, not in
theory. Jager and Somorovsky (CCS 2011) recovered plaintext at a few thousand
queries per block. They used the application itself as a decryption oracle.
It tells "this decrypted to malformed XML" apart from "this decrypted cleanly",
and that one bit is enough.

GCM (Galois/Counter Mode) rejects the whole ciphertext on the authentication tag
before anything is parsed, so there is no oracle to query. CBC is not offered at
all. A provider that cannot do GCM is better served by TLS alone than by
encryption that does not hold. There is a test that tampers with a ciphertext and
requires the decryption to fail.

"Key transport" is how the key that encrypts the assertion is itself sent to the
provider. It is `rsa-oaep-mgf1p` by default. The SHA-1 in its name is OAEP's mask
generation function, which needs a pseudorandom function, not collision
resistance. That is a different question from SHA-1 in a signature, which this
package refuses on both bindings. See `docs/security-scanning.md`.

A provider that supports it can be given `xmlenc11#rsa-oaep` with SHA-256 and
MGF1-SHA-256 instead (`saml add-sp -sp-key-transport rsa-oaep-sha256`). It is the
one to choose under [FIPS](fips.md), the Federal Information Processing Standards.

### Proved end to end, by tools that are not ours

A real sign-in through a provider with encryption turned on, then decrypted the
way the application would:

```
openssl pkeyutl -decrypt -inkey enc.key -pkeyopt rsa_padding_mode:oaep \
        -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1
  -> session key unwrapped, 32 bytes

AES-256-GCM(iv || ciphertext || tag)
  -> 3294 bytes of assertion

xmlsec1 --verify --trusted-pem idp.crt --id-attr:ID ... assertion.xml
  Verification status: OK
```

The envelope was checked for leakage too. No `Assertion`, `Issuer`, `NameID` or
`SignatureValue` appears in the clear, and each encryption uses a fresh session key
and initialisation vector (IV).

## A NameID from an attribute

Some providers key their accounts on a value you already hold, such as an employee
number. You can make that value the NameID, and later set the NameID back to the
format alone:

```sh
signari saml nameid -entity-id https://app.example/saml -attribute employee_number
signari saml nameid -entity-id https://app.example/saml        # back to the format alone
```

`-attribute` is a declared attribute or `username`. `PATCH .../saml-providers/{id}`
takes the same thing as `name_id_attribute`. The format the provider is registered
with still goes out. It is carried in the sign-out request exactly as the assertion
had it, since a provider matches on it.

An attribute a person can edit is refused. It is refused when it is set, and again
at every sign-in in case the declaration has changed since. Whoever writes that
value chooses who they are at the provider.

Somebody with no value is refused, not given a different identifier, which would
be a new, empty account there. A transient format cannot take an attribute.

Nothing here can make the values unique. Two people who share a value share an
account at that provider. Set it before people sign in, or expect them to arrive
there as new accounts.

## What a service provider asks of the sign-in

An application can ask how strongly the person signed in, with
`RequestedAuthnContext`. It is held to the session on every request, as
`acr_values` is for an application. A password session must not answer a demand
for a second factor only because it was already live.

Signari reads the classes it recognises like this:

| Asked for | Means here |
|---|---|
| `PasswordProtectedTransport`, `Password`, `unspecified` | A password |
| Signari's multi-factor class, `MobileTwoFactorContract`, `TimeSyncToken`, or the `multipleauthn` claim | A second factor |

Any class in the list will do, so the weakest one recognised decides. `exact` and
`minimum` are both a floor. The assertion states what was really done, and
refusing a stronger sign-in for being stronger helps nobody. `better` is the rung
above, and `maximum` forces nothing.

A session that falls short is sent to sign in, and asked for the second factor.
Sometimes that cannot succeed, because the account has none or the flow never
asks. Sometimes no class in the list is one Signari knows. In either case, the
application gets `NoAuthnContext`, not a person sent round a sign-in page for
ever. With `IsPassive`, it gets `NoPassive`.

## A sign-in that starts here

Usually the application starts a sign-in. But some applications have no
sign-in page of their own to send anybody from, and some people start from the
[portal](app-portal.md). For them, you can opt an application in to a sign-in
that starts at Signari:

```
signari saml idp-initiated -entity-id https://app.example.com -relay-state /dashboard
```

The provider then has a tile on the portal, and `/saml/init/{id}` sends the person
there. The command prints that URL. `-remove` stops it, and it is off until set.

The response answers no request, so it has no `InResponseTo`. The provider has to
be set up to take one. Most refuse it until they are, which is why this is per
provider and not a setting of the deployment.

A provider that requires signed requests has no request here to check. Opting it
in is the administrator's statement that it may be sent a response without one.

Nothing about the sign-in comes from the URL except which provider. The assertion
goes to the provider's default URL. The `RelayState` is the one set here, never
one from the link. So a link can start a sign-in, and cannot choose where the
person lands inside the application. The person signs in first if they have not.
A provider that does not exist, belongs to another organisation or has not opted
in all look the same.

The [access policy](policy.md) is held to it as to any assertion, by the entity
ID, and the portal asks the same question. A provider the policy refuses shows as
refused, with the policy's message. Opening its link directly says the same thing
here, not at the provider, which was not expecting anything.

## The Artifact binding

An application can take its response by "artifact" (SAML Bindings 2.0 §3.6).
The browser carries only a short reference, the artifact. The provider fetches the
response itself, over SOAP, from `POST /saml/artifact`, or from
`/saml/org/<slug>/artifact` for an organisation's entity. The response never
crosses the browser. Register the URL that takes artifacts, and the provider's
signing certificate:

```sh
signari saml add-sp -org <org-uuid> -entity-id https://sp.example.com/shibboleth \
  -acs https://sp.example.com/Shibboleth.sso/SAML2/POST \
  -artifact-acs https://sp.example.com/Shibboleth.sso/SAML2/Artifact \
  -sp-cert sp-signing.pem
```

A provider's metadata does the same with an `AssertionConsumerService` on the
HTTP-Artifact binding. So do `artifact_acs_urls` in the Admin API and in [a
configuration file](config-as-code.md).

An artifact URL is never the default. A request reaches it by naming it, or by
asking for HTTP-Artifact in its `ProtocolBinding`. A request that names one
binding and a URL registered for the other is refused. It used to be answered by
POST, whatever it asked for.

The metadata publishes the "resolution service", where providers fetch their
responses, at index 0. A resolution has to pass these checks:

- The artifact is one this deployment issued in the last minute, and nobody has
  asked for it yet. It is gone after the first request for it, whoever makes it.
- The `ArtifactResolve` is signed with the certificate registered for the
  provider the artifact was issued to, and names that provider as its `Issuer`.
  A provider with no certificate registered cannot show it is the recipient, so
  it is never given anything. Configure it to sign its back-channel requests
  (for Shibboleth, `signing="back"` or `"true"`).

Anything else is answered as the specification asks: a `Success` with no message
in it. The reason is logged, and audited as `saml.artifact_refused`. The
`ArtifactResponse` is signed.

While it waits, the response is sealed under a key derived from the artifact
itself. That key is not stored, so the database alone cannot read the response.

### Requests by artifact

A provider can send its `AuthnRequest` by artifact too. The browser brings
`SAMLart` to the sign-on service. The request is then fetched from the provider's
own artifact resolution service over SOAP (SAML Bindings 2.0 §3.6.5). The metadata
lists the sign-on service on the HTTP-Artifact binding for it. Register where the
provider resolves its artifacts, by the index an artifact names:

```sh
signari saml add-sp ... -artifact-resolution 1=https://sp.example.com/Shibboleth.sso/Artifact/SOAP
```

A provider can also give it as an `ArtifactResolutionService` in its metadata, as
`artifact_resolution` in the Admin API, or in [a configuration
file](config-as-code.md). A provider with none sends no request by artifact. Here
is what happens to one:

- The artifact names its provider by the SHA-1 of the entity ID, and the service by
  index. Only a provider answered at the endpoint the artifact was brought to, with
  a service at that index, is asked.
- The `ArtifactResolve` is signed with this deployment's key for that provider.
- The answer is believed because it comes from the address registered for the
  provider, over https with its certificate verified. The specification calls
  this a binding mechanism. A signature on the answer is not checked. A provider
  that signs its answer around a request it also signed puts two signatures in
  one document. Every check here refuses that as the shape of a wrapping attack.
- The answer has to reply to this request, come from the provider, say `Success`,
  and carry an `AuthnRequest` in that provider's name. Anything else is refused on
  the page, with the reason.
- An artifact is resolved once. Brought again, it is refused without asking the
  provider, and one whose resolution failed is spent as well.
- The request is then handled as one arriving by POST: held across sign-in,
  validated, and refused if seen before. A provider registered to sign its
  requests has to sign the `AuthnRequest` itself, as on the POST binding. A
  signature on the answer around it does not count.

### Logout by artifact

A sign-out can go both ways by artifact. A provider's `LogoutRequest` or
`LogoutResponse` comes as `SAMLart` to the sign-out service. It is fetched from the
provider as a request by artifact is, so the provider needs a resolution service
registered.

A `LogoutRequest` fetched that way has to name that provider as its `Issuer`. It
is then acted on as one arriving by POST: only when it is signed with the
certificate registered for it. A request to end somebody's session is never
believed unsigned. A `LogoutResponse` moves this deployment's sign-out along, as one
arriving by redirect does.

The other way, a provider whose sign-out endpoint is registered with the
HTTP-Artifact binding is sent its `LogoutRequest` by artifact. So is the answer to
its own. The message waits here, and the provider fetches it from
`POST /saml/artifact` with an `ArtifactResolve` signed as itself, as it fetches a
response. To register such a sign-out endpoint:

```sh
signari saml add-sp ... -slo https://sp.example.com/Shibboleth.sso/SLO/Artifact -slo-binding HTTP-Artifact
```

The metadata lists the sign-out service on the HTTP-Artifact binding as well.
Reading a provider's metadata takes its redirect sign-out endpoint, or else its
POST one, and never an artifact one. So a sign-out goes by artifact only to a provider
registered for it with `-slo-binding` or the Admin API's `slo_binding`.

Both were run against Shibboleth SP 3.4.1, sending its `AuthnRequest` and its
`LogoutRequest` by artifact (`outgoingBindings` on its `SSO` and `Logout`):

- The request was fetched from its `/Shibboleth.sso/Artifact/SOAP`, held across
  the sign-in, and answered by artifact.
- Its `LogoutRequest` was fetched, ended the session and was answered by artifact
  at its `/SLO/Artifact`. Shibboleth resolved that here, and reported a completed
  global sign-out.

The run found one fault. A request handed on that way lost its binding when it was
held across the sign-in, and was refused after the password.

## ECP: signing in without a browser

The Enhanced Client or Proxy (ECP) profile is defined in SAML Profiles 2.0 §4.2.
It is how a command-line tool, a desktop client or a script signs a person in to
a SAML application. The client takes the provider's `AuthnRequest`, and brings it to
Signari in a SOAP body at `POST /saml/ecp` (or `/saml/org/<slug>/ecp`). It sends
the person's name and password by HTTP Basic. Then it carries the `Response` back
to the provider's PAOS endpoint, which the answer's `ecp:Response` header names.

A provider takes part by registering a PAOS endpoint, and one without one is
refused. To register it:

```sh
signari saml add-sp ... -ecp-acs https://sp.example.com/Shibboleth.sso/SAML2/ECP
```

A provider can also give it as a PAOS `AssertionConsumerService` in its metadata,
as `ecp_acs_urls` in the Admin API, or in [a configuration
file](config-as-code.md). Decide it per provider, because no page here can ask the
person for anything:

- The password goes through the same check that Lightweight Directory Access
  Protocol ([LDAP](ldap.md)) and Remote Authentication Dial-In User Service
  ([RADIUS](radius.md)) use. It has the same failure budget per account, and the
  same audit, `via: saml_ecp`.
- A second factor, when one is wanted, comes after the password, as
  `password;123456`. The organisation's rule on password-only binds applies.
  Under `refuse_when_mfa`, a person the sign-in page would ask for a code is
  refused without one. That is the default for an organisation made since that
  rule existed. Under `allow`, they are not.
- A request asking for a second factor (`RequestedAuthnContext`) is answered
  `NoAuthnContext` unless a code came.
- The access policy, the NameID and the attribute releases are those of a
  browser sign-in.
- Every refusal of the person is the same `401`.

The assertion names no `SessionIndex`, and is recorded against no session, since
there is no browser session behind it. So a sign-out started here does not reach it.

## Not yet built

- **Decrypting inbound encrypted `NameID`s.** Signari encrypts outbound
  assertions. It does not accept encrypted identifiers in inbound requests.

It is absent from the metadata document as well as listed here. The rule that an
endpoint enters discovery only once it works applies here too.
