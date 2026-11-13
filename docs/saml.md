# SAML 2.0

Signari is a SAML identity provider. Applications that speak SAML — Grafana,
Jira, Zendesk, Salesforce, most enterprise software — sign in against it.

```sh
signari saml add-sp \
  -org        <org-uuid> \
  -entity-id  https://grafana.example.com/metadata \
  -name       Grafana \
  -acs        https://grafana.example.com/login/saml/acs
```

Then point the application at `https://auth.example.com/saml/metadata`. If the
application publishes metadata of its own, [register it from
that](saml-metadata.md) instead of typing it in.

The Admin API registers service providers and sets their signing and their
attribute and group releases the same way, under
`/admin/organizations/{orgID}/saml-providers`; see [admin-api.md](admin-api.md).

| Endpoint | Purpose |
|---|---|
| `GET /saml/metadata` | what the service provider imports |
| `GET /saml/sso` | HTTP-Redirect binding |
| `POST /saml/sso` | HTTP-POST binding |
| `POST /saml/artifact` | the artifact resolution service, SOAP; see [the Artifact binding](#the-artifact-binding) |
| `POST /saml/ecp` | sign-on over SOAP for a client that is not a browser; see [ECP](#ecp-signing-in-without-a-browser) |

## One entity ID, several organisations

A SaaS application usually sends the same entity ID for every customer, so two
organisations in a deployment may both need to register it. An AuthnRequest names
only its issuer, and a WS-Federation `wtrealm` does the same, so the path has to say
whose provider it is:

| | |
|---|---|
| The deployment's endpoints | `/saml/sso`, `/saml/slo`, `/saml/metadata`, `/wsfed`. An entity ID is held here once. This server's entity ID is `<issuer>/saml` |
| An organisation's endpoints | `/saml/org/<slug>/sso`, `/slo`, `/metadata`, `/wsfed/org/<slug>`, and `/wsfed/org/<slug>/FederationMetadata.xml`. An entity ID is held once in the organisation. This server's entity ID is `<issuer>/saml/org/<slug>` |

A provider answers at one or the other. Registering an entity ID somebody else holds
at the deployment's endpoints puts the new registration at its organisation's, and
`saml add-sp`, the Admin API and `signari apply` all do this without being asked:

```sh
signari saml add-sp -org <uuid> -metadata https://app.example.com/saml/metadata -metadata-unsigned
Another organisation holds this entity id at the deployment's endpoints, so this
one answers at its own: give the provider the metadata from /saml/org/<slug>/metadata.
```

Nothing moves for whoever held it first. A request at a path finds only that path's
provider, so one organisation's certificate cannot check another's request, its reply
URLs cannot receive the other's assertion, and a person of one is refused at the
other's path.

Registration decides this rather than sign-in, on purpose. Refusing an entity ID two
organisations hold at the deployment's endpoints would let any tenant switch off
another's sign-in by registering the same entity ID.

`signari saml org-endpoint -entity-id <id> [-org <uuid>]` moves a provider to its
organisation's endpoints, `-remove` back, which is refused while somebody else holds
the entity ID there. Either way the provider has to be given the new metadata,
because the entity ID it knows this server by has changed. So does renaming an
organisation's slug.

Where two organisations hold an entity ID, a command that takes `-entity-id` needs
`-org` as well, and says so.

## What was built against, and why it looks like this

Before writing any of it, the published advisories for the three most-used Go
SAML libraries were read rather than recalled:

| library | advisories |
|---|---|
| `github.com/crewjam/saml` | 4 |
| `github.com/russellhaering/gosaml2` | 5 |
| `github.com/russellhaering/goxmldsig` | 3 |

Almost every one is a **signature-validation or authentication bypass**. Not one
is a cryptographic break. They are parsing and policy decisions — an assertion
accepted because *something* in the document was signed, a LogoutRequest acted
on with no signature at all, a compressed request expanded without a bound.

So the defences are explicit, and the dangerous configuration is the one you
would have to ask for:

**The assertion is signed, not just the response.** If only the response carries
a signature, an attacker holding one valid response can often move the signed
element aside and insert their own assertion; the document still contains a
valid signature over *something*. Signing the assertion means the element
carrying the identity is the element covered.

For a provider that wants the Response signed as well,
`signari saml signing -entity-id <id> -sign-responses` adds an enveloped
signature over the whole Response. It is made last, after the assertion is
signed and, when the provider registered an encryption certificate, encrypted:
sign, encrypt, sign, so it covers the ciphertext as it is sent.
`-sign-assertions=false` leaves the assertion unsigned for a provider that checks
only the Response. The two cannot both be off, and a flag left out of the
command leaves its setting alone. Until October 2026 both settings were stored
and ignored, and every response signed the assertion only.

**XML comments inside the document are refused outright.** Go parses
`<Issuer>admin<!---->@evil.test</Issuer>` as `admin@evil.test`. Canonicalisation
drops comments before the digest is computed, and other parsers keep only the
first text node — so the signed bytes, our value, and the peer's value can all
differ. That is CVE-2017-11427 and its relatives. Rather than trying to agree
with every other implementation, a document with a comment anywhere inside its
document element is rejected. No legitimate service provider puts a comment in an
AuthnRequest. A comment before or after the document element is allowed, being in
no element's text and under no signature: Shibboleth's metadata generator begins
every document with one, and until November 2026 that refused its metadata.

**Decompression is bounded during the read**, not measured afterwards. A few
kilobytes of DEFLATE expands to gigabytes; that is how both `crewjam/saml` and
`gosaml2` were taken down.

**ACS URLs are an exact-match allow-list.** This is the SAML equivalent of
`redirect_uri`, and it is where assertions get stolen: whoever can steer the
`AssertionConsumerServiceURL` receives a genuine, correctly signed assertion for
a real user at a server they control. Seventeen evasion techniques are tested —
attacker host, registered host as a prefix, userinfo `@`, subdomain, traversal,
trailing slash, scheme downgrade, explicit `:443`, case, percent-encoding,
appended query and fragment, double slash, backslash, embedded null, newline.

**A request that fails validation is refused to the browser**, never turned into
a SAML error POSTed to the URL the request named. Doing that would make the
endpoint a redirector for any entity id an attacker invents — the ACS URL is
precisely what is in dispute.

**NameIDs are pairwise by default.** Each service provider sees a different
opaque identifier for the same person, so two of them cannot correlate their
users. It also survives an email change, which `emailAddress` NameIDs do not —
the SP treats the NameID as the account key, so a new value means a new, empty
account.

**The authentication context is what actually happened.** A password-only
session asserts `PasswordProtectedTransport`, never
`MultiFactorAuthentication`. Overstating it tells a service provider its
step-up requirement was satisfied when it was not.

## Proof, from tools that are not ours

Verifying our own signature with our own library proves only self-consistency.

- **xmlsec1** (the reference C implementation most SAML software is built on)
  verifies the assertion, and rejects it once the NameID is edited.
- **xmllint against the official OASIS schemas**, vendored into `testdata`,
  confirms the document is schema-valid.
- The parser has taken 3.5M fuzz executions with no crash.

Schema validation earned its place immediately: it caught a document carrying
**two identical `<ds:Signature>` elements**. `goxmldsig` appends the signature
onto etree's child slice without setting its parent, so the reordering code's
`RemoveChild` silently did nothing and the insert left the same element in the
list twice. xmlsec1 reported OK — it found a valid signature — so every
signature-based test passed. A duplicated signature is also exactly the shape a
wrapping attack takes, and strict providers reject it.

## Keys and certificates

SAML needs an X.509 certificate where OIDC needs only a public key, because
service providers **pin** it out of the metadata.

That makes rotation a coordinated change rather than a background one. The
certificate is generated once and stored, never regenerated — a fresh
certificate has a new fingerprint, and every SP pinning it would start rejecting
assertions intermittently depending which node answered.

Metadata publishes **every** current certificate so providers can pick up an
incoming one before it is used. Rotation is then: publish, wait for providers to
refresh, switch.

Each certificate names its key in the subject, `OU=key <kid>`, beside the host
in the CN. A provider that trusts every published certificate and finds the
signer's by name needs the names to differ: with three certificates all called
`O=Signari, CN=<host>`, xmlsec1 verified a response with them loaded in one order
and found no key in another. A certificate made before October 2026 keeps its
old name, since its fingerprint is pinned, and leaves when its key rotates out.

### Which key signs a provider

Each provider is signed with **RSA-SHA256** by the active RS256 key, unless it
has been set to **ECDSA-SHA256**, which the active ES256 key signs:

```sh
signari saml signing -entity-id https://sp.example.com -signature-alg ecdsa-sha256
```

RSA is the default because ECDSA is specified and refused by a great deal of
real service-provider software, so an EC-signed assertion to a provider that
cannot verify it is correct and rejected anyway. Only whoever knows the far end
can say it can, which is why the setting is per provider and never follows
whichever key happens to be active. The command refuses an algorithm the
provider's instance has no active key for, since every sign-in to it would then
fail.

A provider's metadata, `/saml/metadata?sp=<entity-id>`, carries the
certificates of the algorithm it is set to. Give it the new document before its
next sign-in: it checks signatures against the certificates it already holds.
The default document, with no `sp`, carries the RS256 certificates. Set a
provider to ECDSA only once every node runs a release that reads the setting;
an older node ignores it and signs with RSA.

An ECDSA signature value is r and s as two 32-byte integers, concatenated,
which is what xmlsec1 writes and accepts. A key's `crypto.Signer` returns the
DER encoding instead, and xmlsec1 refuses that with `SIGNATURE`; the engine
converts it. The redirect binding's `Signature` parameter carries the same
encoding under the same `SigAlg`. No independent receiver has checked that
encoding for the redirect binding here.

Signing goes through the key's `crypto.Signer` alone, so a key whose private
half never leaves a key store signs SAML exactly as a software key does. Until
October 2026 SAML required an in-process RSA private key and refused every
other.

## Single logout

Service-provider-initiated logout works on the HTTP-Redirect binding:

```sh
signari saml add-sp ... -slo https://sp.example.com/slo -sp-cert ./sp.crt
```

**A LogoutRequest is acted on only when signed.** gosaml2 GHSA-pcgw-qcv5-h8ch
accepted unsigned ones, which meant anybody who could reach the endpoint could
sign any user out of everything, needing no credential at all — the cheapest
denial of service there is against an identity provider.

So a provider with no certificate on file cannot use single logout, and
registering a logout URL without one is refused at the CLI rather than
producing a configuration that looks complete and rejects every request.

The signature is checked over the **raw query-string octets** in the order the
specification fixes, not over any `<ds:Signature>` the document happens to
carry. On the redirect binding the signature *is* the query parameters; an
embedded element proves nothing about what was actually sent. Rebuilding the
string from a parsed map is the classic mistake — Go's encoder escapes a
different character set, sorts keys, and drops an empty RelayState, so the bytes
verified are not the bytes signed.

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

Signing out of Signari now signs the user out of the SAML service providers too.

The SOAP binding is a back channel few providers offer, so for most of them
propagation means walking the **browser** through each provider's logout endpoint
in turn. Signari redirects to provider one, it ends its session and redirects
back, then provider two, until the list is empty.

**Our session is terminated before the chain starts, never at the end.** A chain
that ended the local session last would leave the user signed in here whenever a
provider fails to redirect back — and they fail all the time: closed tab, 500,
dropped network. By the time the first redirect is issued, signing out of Signari
has already happened. Everything after is best-effort notification, and what
could not be reached is recorded rather than assumed. It goes in the
`saml.logout_propagated` audit event. When nothing asked for the browser to be sent
on afterwards, the person is shown a page that says they are signed out, which
applications were told and which could not be reached and may still have a session
open. It is the `signedout` page, and it can be overridden like any other
([theming](theming.md)). A caller that does not ask for HTML is given the same
report as JSON:

```json
{"status":"signed out",
 "notified":["https://spb.test/md","https://spa.test/md"],
 "failed":[]}
```

Verified end to end against two service providers:

| | |
|---|---|
| requests sent | exactly one per provider |
| NameID | each provider received its **own** pairwise value |
| SessionIndex | the one from that provider's assertion |
| signature | verified by **openssl** against the key in our published metadata |
| local session | revoked before the chain began |

The chain state lives in the database, not a cookie and not the URL. A cookie
would be editable by the user, and it names the endpoints to visit — an attacker
could rewrite it and have a browser carrying our signature visit their own
server. The URL would leak it into every referrer header and access log along
the way. The chain token travels as `RelayState`, which providers return
unmodified, and only its hash is stored.

Chains are bounded at ten providers and expire after five minutes; the janitor
sweeps abandoned ones.

**One deliberate asymmetry:** an inbound LogoutRequest must be signed, but a
LogoutResponse coming back is not required to be. A response ends nothing — the
session is already gone — so the worst a forged one achieves is advancing our own
bookkeeping past a provider we were about to notify, and it costs a valid chain
token the attacker does not have. Requiring a signature would instead strand the
chain at every provider that answers unsigned, which most do.

### With no browser

A chain needs a browser, and most sessions do not end in one: an administrator ends
them, a person is deactivated, a session expires. A provider with a SOAP address hears
of all of these. It comes from the provider's metadata, as a `SingleLogoutService` on
the SOAP binding, or is set by hand:

```sh
signari saml soap-logout -entity-id https://sp.example.com/shibboleth \
  -url https://sp.example.com/Shibboleth.sso/SLO/SOAP
```

Every session that ends and reached that provider queues a notice in the same
transaction, which holds ids and no NameID, since a queue is the last place to keep
somebody's address. The outbox then posts a signed `LogoutRequest` in a SOAP 1.1
envelope, carrying the NameID and SessionIndex the assertion did, with the signature
the provider's copy of the metadata verifies. It is delivered like a back-channel
logout: retried with backoff when the provider is down, answers with anything but a
`LogoutResponse` to that request saying `Success`, or sends a SOAP fault, and parked
after that with the failure on record. A provider since disabled is not chased.

The signature on the answer is not checked. The provider was reached at its
registered address over TLS, and all the answer decides is whether to try again. A
SOAP address is never given to a browser, and a provider with both is told both ways,
which it can bear: the second finds nothing left to end.

## Signed AuthnRequests

Off by default, per provider:

```sh
signari saml add-sp -org <uuid> -entity-id https://sp.test/md \
  -acs https://sp.test/acs -sp-cert sp.crt -want-signed-requests
```

The certificate is not optional. Requiring signatures with nothing to verify them
against refuses every login through that provider, so `-want-signed-requests`
without `-sp-cert` is rejected at registration — the same fail-closed rule the
logout URL already had. `signari doctor` reports the same combination as critical
if it is ever created another way.

The signature is checked **before** validation, because everything validation goes
on to decide — which ACS URL, which NameID format, whether to force
re-authentication — is read out of the document.

**A signed AuthnRequest is answered once.** Its ID is recorded when the assertion
is issued, and the same request presented again is answered with a `Requester`
status and no assertion, so a captured request cannot keep drawing fresh
assertions for whoever holds a signed-in browser. It is recorded at issuance
rather than on arrival because a request parked across sign-in comes back
carrying the same document. An unsigned request is not recorded: anyone can mint
a new ID for one. Until October 2026 the table documented this and nothing wrote
to it.

### The two bindings sign different things

| Binding | What is signed | Verified by |
| --- | --- | --- |
| HTTP-Redirect | the raw query octets, `SigAlg`/`Signature` as separate parameters | `VerifyRedirectSignature` |
| HTTP-POST | an enveloped `<ds:Signature>` inside the document | `VerifyEmbeddedSignature` |

A redirect-binding request may *also* contain a `<ds:Signature>`. Verifying that
one proves nothing — the attacker supplied the whole document — so the binding the
request arrived on decides which check runs, and there is no fallback between them.

### What the POST binding needed on top of goxmldsig

goxmldsig gets the cryptography right and deliberately leaves the policy to its
caller. Three of its behaviours are individually reasonable and collectively a
bypass:

- `findSignature` **traverses the tree**, so a signature anywhere inside the
  document can satisfy it.
- a `Reference URI` of `""` is accepted, meaning "the whole document".
- **RSA-SHA1 is accepted.** The redirect binding here already refuses SHA-1, and a
  signature scheme is only as strong as the weakest binding that accepts it.

So the structure is checked first, and only then is anything verified
cryptographically:

1. exactly one `Signature` element in the whole document,
2. and it is a **direct child of the root**,
3. exactly one `Reference`, whose URI is `#<root ID>`,
4. no duplicate `ID` attributes anywhere,
5. SHA-1 refused on both the signature method and the digest,
6. and afterwards, the element goxmldsig says it verified must still be the
   element we parsed — compared by ID and tag.

Rule 2 is the one that stops classic wrapping, and the test for it uses distinct
IDs deliberately so the duplicate-ID rule cannot be what passes it. Without rule 2
that document has one valid signature, no duplicate IDs, and sails through.

### Service providers with an EC key

A provider whose certificate holds a P-256 key may sign with `ecdsa-sha256`, on
either binding. The signature value is r and s as two 32-byte integers, which
is what xmlsec1 writes. goxmldsig checks ECDSA as DER, so the value is
converted before it is checked; the value is not covered by the signature, so
converting it changes nothing that was signed. A DER-encoded value is refused
by name, as xmlsec1 refuses it. The other ECDSA algorithms are refused, as is
any algorithm that does not match the key in the registered certificate. Until
October 2026 an EC provider was refused on the redirect binding as an
unsupported signature algorithm, and on the POST binding as a signature that
did not verify.

### Surviving the sign-in redirect

A request that arrives before the user is signed in gets parked. On the redirect
binding the signed bytes are *the query as the service provider encoded it*, so
rebuilding that query with `url.Values` changes the escaping and the ordering and
the signature no longer verifies — which would surface **after** the user had
already typed their password, the worst place to discover it.

The original query is therefore carried across verbatim as one opaque `SigQuery`
value. It is attacker-supplied like anything else on a URL, so it earns nothing on
its own: it still has to verify against the registered certificate, and it must
name the same `SAMLRequest` being processed. Both were tested by tampering:

```
drop SigQuery from the resumed URL     -> "no signature on the redirect binding"
swap in a different signed AuthnRequest -> "the preserved signature covers a
                                            different AuthnRequest than the one
                                            being processed"
```

### Metadata

`WantAuthnRequestsSigned` is per provider here, so one global document cannot state
it truthfully for everyone. `/saml/metadata` reports the default (`false`, what a
new registration gets) and `/saml/metadata?sp=<entityID>` reports what is actually
configured for that provider. An unknown entity id gets the default document rather
than an error — failing would make the endpoint a way to enumerate which service
providers are registered.

## Single logout on both bindings

`GET /saml/slo` takes the HTTP-Redirect binding, `POST /saml/slo` the HTTP-POST
binding. Which one a request arrived on decides how it is decoded **and** how its
signature is checked — redirect signs the raw query octets, POST signs the
document — and there is no fallback between them.

Unlike AuthnRequests this is never optional. A LogoutRequest acted on unsigned
lets anybody sign anybody out with no credential at all (gosaml2
GHSA-pcgw-qcv5-h8ch), so a provider with no certificate on file cannot use single
logout.

Tested against the running server with a service provider built separately from
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

Found by watching the wire rather than reading the code: every `LogoutResponse`
used to leave as an auto-submitting POST form, including to endpoints registered
as `HTTP-Redirect` — which was all of them, since that was the only binding
`saml add-sp` could store. A provider expecting `SAMLResponse`/`SigAlg`/`Signature`
as query parameters got a form POST and had nothing to parse.

The binding is now stored and honoured:

```sh
signari saml add-sp ... -slo https://sp.test/slo -slo-binding HTTP-POST
```

`HTTP-Artifact` is the third; see [Logout by artifact](#logout-by-artifact). A
provider that registered both is answered on whichever binding it used. The
redirect-bound response was checked with **openssl**, against the certificate the
IdP publishes in its own metadata — an entirely separate path from the code that
produced it:

```
openssl dgst -sha256 -verify idp.pub -signature sig.bin signed.bin
Verified OK
```

## Encrypted assertions

Opt-in per provider, with a **separate certificate** from the signing one:

```sh
signari saml add-sp ... -sp-cert sp-signing.crt -sp-encryption-cert sp-encryption.crt
```

Service providers sign with one key and decrypt with another — in SAML metadata
they appear as separate `KeyDescriptor` elements with `use="signing"` and
`use="encryption"`. Passing the same file for both is refused at registration,
because the failure is otherwise silent: assertions encrypt perfectly and the
provider cannot read a single one. RSA below 2048 bits is refused at registration
*and* again at the point of use, since a certificate can be replaced later.

### Sign, then encrypt

The assertion is signed first and encrypted afterwards. The other order leaves the
signature over ciphertext — which says who produced the envelope and nothing about
the identity inside it, so a provider that decrypts is left holding an unsigned
assertion and has to trust the wrapper.

### AES-256-GCM only, never CBC

XML Encryption's CBC modes are broken in practice, not in theory. Jager and
Somorovsky (CCS 2011) recovered plaintext at a few thousand queries per block,
using the service provider itself as a decryption oracle: it distinguishes "this
decrypted to malformed XML" from "this decrypted cleanly", and that one bit is
enough.

GCM rejects the whole ciphertext on the authentication tag before anything is
parsed, so there is no oracle to query. CBC is not offered at all — a provider
that cannot do GCM is better served by TLS alone than by encryption that does not
hold. There is a test that tampers with a ciphertext and requires the decryption
to fail.

Key transport is `rsa-oaep-mgf1p` by default. The SHA-1 in its name is OAEP's
mask generation function, which needs a pseudorandom function rather than
collision resistance — a different question from SHA-1 in a signature, which
this package refuses on both bindings. See `docs/security-scanning.md`. A
provider that supports it can be given `xmlenc11#rsa-oaep` with SHA-256 and
MGF1-SHA-256 instead (`saml add-sp -sp-key-transport rsa-oaep-sha256`), which is
the one to choose under FIPS.

### Proved end to end, by tools that are not ours

A real login through an encryption-enabled provider, then decrypted the way the
service provider would:

```
openssl pkeyutl -decrypt -inkey enc.key -pkeyopt rsa_padding_mode:oaep \
        -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1
  -> session key unwrapped, 32 bytes

AES-256-GCM(iv || ciphertext || tag)
  -> 3294 bytes of assertion

xmlsec1 --verify --trusted-pem idp.crt --id-attr:ID ... assertion.xml
  Verification status: OK
```

The envelope was checked for leakage too: no `Assertion`, `Issuer`, `NameID` or
`SignatureValue` appears in the clear, and each encryption uses a fresh session
key and IV.

## A NameID from an attribute

A provider that keys its accounts on something you already hold can be given it:

```sh
signari saml nameid -entity-id https://app.example/saml -attribute employee_number
signari saml nameid -entity-id https://app.example/saml        # back to the format alone
```

`-attribute` is a declared attribute or `username`, and `PATCH .../saml-providers/{id}`
takes the same thing as `name_id_attribute`. The format the provider is registered with
still goes out, and is carried in the logout request exactly as the assertion had it,
since a provider matches on it.

An attribute a person can edit is refused, when it is set and again at every sign-in in
case the declaration has changed since: whoever writes that value chooses who they are
at the provider. Somebody with no value is refused rather than given a different
identifier, which would be a new, empty account there. A transient format cannot take
an attribute. Nothing here can make the values unique: two people sharing one share an
account at that provider. Set it before people sign in, or expect them to arrive there
as new accounts.

## What a service provider asks of the sign-in

`RequestedAuthnContext` is held to the session on every request, as `acr_values` is
for an application, because a password session must not answer a demand for a second
factor just because it was already live.

| Asked for | Means here |
|---|---|
| `PasswordProtectedTransport`, `Password`, `unspecified` | A password |
| Signari's multi-factor class, `MobileTwoFactorContract`, `TimeSyncToken`, or the `multipleauthn` claim | A second factor |

Any class in the list will do, so the weakest one recognised decides. `exact` and
`minimum` are both a floor: the assertion states what was really done, and refusing a
stronger sign-in for being stronger helps nobody. `better` is the rung above, and
`maximum` forces nothing.

A session short of it is sent to sign in, asked for the second factor. If that cannot
succeed, because the account has none or the flow never asks, or if no class in the
list is one this directory knows, the service provider gets `NoAuthnContext` rather
than a person sent round a sign-in page for ever. With `IsPassive` it gets `NoPassive`.

## A sign-in that starts here

Some applications have no sign-in page of their own to send anybody from, and some
people start from the [portal](app-portal.md). For those a service provider can be
opted in:

```
signari saml idp-initiated -entity-id https://app.example.com -relay-state /dashboard
```

It then has a tile on the portal, and `/saml/init/{id}` sends the person there. The
command prints the URL. `-remove` stops it, and it is off until set.

The response answers no request, so it has no `InResponseTo`, and the provider has to be
set up to take one. Most refuse it until they are, which is why this is per provider
and not a setting of the deployment. A provider that requires signed requests has no
request here to check: opting it in is the operator's statement that it may be sent a
response without one.

Nothing about the sign-in comes from the URL except which provider. The assertion goes
to the provider's default URL, and the `RelayState` is the one set here, never one from
the link, so a link can start a sign-in and cannot choose where the person lands inside
the application. The person signs in first if they have not, and a provider that does not
exist, belongs to another organisation or has not opted in all read the same.

The [access policy](policy.md) is held to it as to any assertion, by the entity
ID, and the portal asks the same question: a provider refused shows as refused, with
the policy's message, and opening its link directly says the same thing here, not at the
provider, which was not expecting anything.

## The Artifact binding

A service provider can take its response by artifact (SAML Bindings 2.0 §3.6):
the browser carries a short reference, and the provider fetches the response
itself, over SOAP, from `POST /saml/artifact` (or
`/saml/org/<slug>/artifact` for an organisation's entity). The response never
crosses the browser. Register the URL that takes artifacts, and the provider's
signing certificate:

```sh
signari saml add-sp -org <org-uuid> -entity-id https://sp.example.com/shibboleth \
  -acs https://sp.example.com/Shibboleth.sso/SAML2/POST \
  -artifact-acs https://sp.example.com/Shibboleth.sso/SAML2/Artifact \
  -sp-cert sp-signing.pem
```

A provider's metadata does the same with an `AssertionConsumerService` on the
HTTP-Artifact binding, and so do `artifact_acs_urls` in the Admin API and in
[a configuration file](config-as-code.md). An artifact URL is never the default:
a request reaches it by naming it, or by asking for HTTP-Artifact in its
`ProtocolBinding`. A request that names one binding and a URL registered for the
other is refused, where it used to be answered by POST whatever it asked for.

The metadata publishes the resolution service at index 0. What a resolution
has to pass:

- the artifact is one this deployment issued in the last minute and nobody has
  asked for yet. It is gone after the first request for it, whoever makes it;
- the `ArtifactResolve` is signed with the certificate registered for the
  provider the artifact was issued to, and names that provider as its `Issuer`.
  A provider with no certificate registered cannot show it is the recipient, so
  it is never given anything; configure it to sign its back-channel requests
  (for Shibboleth, `signing="back"` or `"true"`).

Anything else is answered as the specification asks: a `Success` with no
message in it, the reason logged and audited as `saml.artifact_refused`. The
`ArtifactResponse` is signed. The response waits sealed under a key derived from
the artifact itself, which is not stored, so the database alone cannot read it.

### Requests by artifact

A provider can send its `AuthnRequest` by artifact too. The browser brings `SAMLart`
to the sign-on service, and the request is fetched from the provider's own artifact
resolution service over SOAP (SAML Bindings 2.0 §3.6.5). The metadata lists the
sign-on service on the HTTP-Artifact binding for it. Register where the provider
resolves its artifacts, by the index an artifact names:

```sh
signari saml add-sp ... -artifact-resolution 1=https://sp.example.com/Shibboleth.sso/Artifact/SOAP
```

or an `ArtifactResolutionService` in its metadata, `artifact_resolution` in the Admin
API, or in [a configuration file](config-as-code.md). A provider with none sends no
request by artifact. What happens to one:

- The artifact names its provider by the SHA-1 of the entity ID, and the service by
  index. Only a provider answered at the endpoint the artifact was brought to, with a
  service at that index, is asked.
- The `ArtifactResolve` is signed with this deployment's key for that provider.
- The answer is believed because it comes from the address registered for the
  provider, over https with its certificate verified: what the specification calls a
  binding mechanism. A signature on the answer is not checked. A provider that signs
  its answer around a request it also signed puts two signatures in one document,
  which every check here refuses as the shape of a wrapping attack.
- The answer has to reply to this request, come from the provider, say `Success` and
  carry an `AuthnRequest` in that provider's name. Anything else is refused on the
  page, with the reason.
- An artifact is resolved once. Brought again, it is refused without asking the
  provider, and one whose resolution failed is spent as well.
- The request is then handled as one arriving by POST: held across sign-in,
  validated, and refused if seen before. A provider registered to sign its requests
  has to sign the `AuthnRequest` itself, as on the POST binding; a signature on the
  answer around it does not count.

### Logout by artifact

A logout can go both ways by artifact. A provider's `LogoutRequest` or
`LogoutResponse` comes as `SAMLart` to the logout service and is fetched from the
provider as a request by artifact is, so the provider needs a resolution service
registered. A `LogoutRequest` fetched that way has to name that provider as its
`Issuer`, and is then acted on as one arriving by POST: only when it is signed with
the certificate registered for it, since a request to end somebody's session is
never believed unsigned. A `LogoutResponse` moves this deployment's logout along, as
one arriving by redirect does.

The other way, a provider whose logout endpoint is registered with the HTTP-Artifact
binding is sent its `LogoutRequest`, and the answer to its own, by artifact. The
message waits here, and the provider fetches it from `POST /saml/artifact` with an
`ArtifactResolve` signed as itself, as it fetches a response:

```sh
signari saml add-sp ... -slo https://sp.example.com/Shibboleth.sso/SLO/Artifact -slo-binding HTTP-Artifact
```

The metadata lists the logout service on the HTTP-Artifact binding as well. Reading a
provider's metadata takes its redirect logout endpoint, or else its POST one, and
never an artifact one, so a logout goes by artifact only to a provider registered
for it with `-slo-binding` or the Admin API's `slo_binding`.

Both were run against Shibboleth SP 3.4.1 sending its `AuthnRequest` and its
`LogoutRequest` by artifact (`outgoingBindings` on its `SSO` and `Logout`): the
request was fetched from its `/Shibboleth.sso/Artifact/SOAP`, held across the
sign-in and answered by artifact, and its logout was fetched, ended the session and
was answered by artifact at its `/SLO/Artifact`, which it resolved here and reported
as a completed global logout. The run found that a request handed on that way lost
its binding when it was held across the sign-in, and was refused after the password.

## ECP: signing in without a browser

The Enhanced Client or Proxy profile (SAML Profiles 2.0 §4.2) is how a command-line
tool, a desktop client or a script signs a person in to a SAML service provider.
The client takes the provider's `AuthnRequest`, brings it here in a SOAP body to
`POST /saml/ecp` (or `/saml/org/<slug>/ecp`) with the person's name and password
by HTTP Basic, and carries the `Response` back to the provider's PAOS endpoint,
which the answer's `ecp:Response` header names.

A provider takes part by registering a PAOS endpoint, and one without one is
refused:

```sh
signari saml add-sp ... -ecp-acs https://sp.example.com/Shibboleth.sso/SAML2/ECP
```

or a PAOS `AssertionConsumerService` in its metadata, `ecp_acs_urls` in the Admin
API, or in [a configuration file](config-as-code.md). It is a decision to make per
provider, because no page here can ask the person for anything:

- The password goes through the same check LDAP and RADIUS use, with the same
  failure budget per account and the same audit, `via: saml_ecp`.
- A second factor, when one is wanted, comes after the password,
  `password;123456`. The organisation's rule on password-only binds applies:
  under `refuse_when_mfa`, the default for an organisation made since that rule
  existed, a person the sign-in page would ask for a code is refused without
  one; under `allow` they are not. A request asking for a second factor
  (`RequestedAuthnContext`) is answered `NoAuthnContext` unless a code came.
- The access policy, the NameID and the attribute releases are those of a
  browser sign-in.
- Every refusal of the person is the same `401`.

The assertion names no `SessionIndex` and is recorded against no session, since
there is no browser session behind it, so a logout started here does not reach
it.

## Not yet built

- **Decrypting inbound encrypted `NameID`s.** We encrypt outbound assertions; we
  do not accept encrypted identifiers in inbound requests.

It is absent from the metadata document as well as from this list — the rule
that an endpoint enters discovery only once it works applies here too.
