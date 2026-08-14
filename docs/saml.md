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

Then point the application at `https://auth.example.com/saml/metadata`.

| Endpoint | Purpose |
|---|---|
| `GET /saml/metadata` | what the service provider imports |
| `GET /saml/sso` | HTTP-Redirect binding |
| `POST /saml/sso` | HTTP-POST binding |

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

**XML comments are refused outright.** Go parses
`<Issuer>admin<!---->@evil.test</Issuer>` as `admin@evil.test`. Canonicalisation
drops comments before the digest is computed, and other parsers keep only the
first text node — so the signed bytes, our value, and the peer's value can all
differ. That is CVE-2017-11427 and its relatives. Rather than trying to agree
with every other implementation, documents containing comments are rejected. No
legitimate service provider puts a comment in an AuthnRequest.

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

SAML requires an **RS256** key. ECDSA is specified and refused by a great deal
of real service-provider software, so an EC-signed assertion would be correct
and rejected anyway. Signari says so up front rather than letting you find out:

```
this instance's active key is ECDSA, which most SAML service providers cannot
verify. Rotate in an RS256 key before enabling SAML: `signari keys rotate -alg RS256`
```

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

SAML has no usable back-channel — the SOAP binding exists and almost nothing
implements it — so propagation means walking the **browser** through each
provider's logout endpoint in turn. Signari redirects to provider one, it ends
its session and redirects back, then provider two, until the list is empty.

**Our session is terminated before the chain starts, never at the end.** A chain
that ended the local session last would leave the user signed in here whenever a
provider fails to redirect back — and they fail all the time: closed tab, 500,
dropped network. By the time the first redirect is issued, signing out of Signari
has already happened. Everything after is best-effort notification, and what
could not be reached is recorded rather than assumed:

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

## Not yet built

- **Single logout on the HTTP-POST binding.** That binding carries an enveloped
  XML signature rather than signed query octets — a different job, with the
  wrapping attacks living in it. Refused plainly rather than half-implemented.
- **Signed AuthnRequests.** `want_authn_requests_signed` is stored and not yet
  enforced. Leave it off until it is.
- **Encrypted assertions.** Transport is TLS; the assertion itself is not
  encrypted.

Each is absent from the metadata document as well as from this list — the rule
that an endpoint enters discovery only once it works applies here too.
