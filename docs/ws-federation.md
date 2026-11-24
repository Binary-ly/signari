# WS-Federation

## Introduction

WS-Federation is an older Microsoft protocol for signing in, much like SAML.
Signari speaks its "passive requestor profile", the part used by web browsers.
SharePoint and Windows Identity Foundation applications use it. So does anything
federated to Active Directory Federation Services (ADFS) before SAML 2.0 was the
default. [Which protocol do I
need?](protocols-explained.md#ws-federation) explains it in plain words.

**This is a compatibility shim for an estate being migrated, not a protocol to
choose**. It is here so that moving off ADFS does not have to mean rewriting
every application first.

You register a WS-Federation application exactly as you register a SAML service
provider. There is nothing else to configure.

## Configuration

There is none beyond registering the application as a SAML service provider.
This command registers a SharePoint intranet:

```sh
signari saml add-sp -org <uuid> \
  -entity-id "urn:sharepoint:intranet" \
  -name "Intranet" \
  -acs "https://intranet.example.com/_trust/"
```

The `wtrealm` is the entity ID, the application's name for itself. WS-Federation
calls an application a "realm". `wreply` must be one of the registered reply URLs,
the addresses the token can be sent to.

One registration serves both protocols. So an application configured for
WS-Federation is released, policy-gated and audited exactly like a SAML one. It
gets the same attributes, the same access policy and the same audit trail.

To set up the application, give it Signari's metadata at this address:

```
https://id.example.com/FederationMetadata/2007-06/FederationMetadata.xml
```

The document names a "security token service", the part of Signari that issues
tokens. It also names that service's token issuer, the endpoint, and every
certificate in use. During a rotation it includes the incoming certificate too, so
a key can change without the application being reconfigured.

`?wtrealm=<realm>` gives the certificates of an application set to
`ecdsa-sha256`. An unknown `wtrealm` gets the default document, so this does not
say which applications exist.

An application another organisation also holds answers at `/wsfed/org/<slug>`,
with its metadata at `/wsfed/org/<slug>/FederationMetadata.xml`. See [one entity
ID, several organisations](saml.md#one-entity-id-several-organisations).

## Endpoints

Signari serves WS-Federation at these addresses:

| | |
|---|---|
| `GET` or `POST /wsfed?wa=wsignin1.0&wtrealm=…` | Sign-in. Answers with a self-posting form carrying the token |
| `GET` or `POST /wsfed?wa=wsignout1.0` | Sign-out. Handled by the ordinary end-session path |
| `GET /FederationMetadata/2007-06/FederationMetadata.xml` | What an application imports |

A request can arrive in the URL or as a form. A form is sent straight back as a
`GET`, because of the session cookie. It is `SameSite=Lax`, so the browser leaves
it behind on a POST from another site. Answered where it landed, the request would
read as nobody signed in, and a sign-out would end nothing while saying it had.

Each parameter can be given once, wherever it comes from, and twice is refused. A
`wreply` in both places is two answers to where the token goes.

These are the parameters Signari reads:

| Parameter | |
|---|---|
| `wtrealm` | The application, by its entity id. Required to sign in |
| `wreply` | Where the token is posted. See below |
| `wctx` | Passed back untouched, which is what the application uses to resume whatever the person was doing |
| `wfresh` | The age a sign-in may be, in whole minutes, and the longest the token may live. `0` asks for a sign-in now |
| `wauth` | How the person must have signed in, as a SAML authentication context class, or `urn:oasis:names:tc:SAML:1.0:am:password` |
| `whr` | Where the person signs in. A provider's slug, its issuer or SAML entity id, or a domain it signs in |

`wfresh` and `wauth` are held to the session on every request, as `max_age` and
`acr_values` are at the authorization endpoint. A session that is too old, or
short of a second factor the person has, is sent to sign in, and comes back.

A `wauth` that this directory offers no way of meeting is refused with `400`. One
that this account cannot reach is refused with `403`, since signing in again would
bring the same session back. Neither is ignored when it cannot be read. An
application that asked for a fresh sign-in must not be handed an old one because
of how it spelled it.

A `wfresh` shorter than the provider's token lifetime shortens the token too. The
assertion's conditions and the response's `Lifetime` are shortened alike. That is
because WS-Federation 1.2 §13.2.2 says the identity provider should not issue a
token that lives longer.

`wreq` and `wreqptr` are refused with `400`. Either carries a WS-Trust token
request, which the specification makes the authoritative source of the request's
parameters. Nothing here reads one. A token issued past it would answer a request
the application did not make. Until November 2026, both were passed over.

The request is not signed, so anyone holding the browser can edit these off the
URL. An application that depends on them reads the authentication instant in the
token, which only signing in can move.

`whr` chooses a route and nothing else. The provider still authenticates the
person, and every link rule still applies. It looks only among the providers of
the application's own organisation, and is not read at all for somebody already signed
in. One that names nothing here is ignored, and the sign-in page is shown.

## Whose application, and whether it is switched on

An application belongs to one organisation. A session from any other organisation
is refused with `403 access_denied`, and so is an application whose registration
is disabled. A disabled application is refused before the sign-in page, so nobody
is asked to authenticate for an application that will be turned away anyway.

The SAML endpoint makes the same two checks, and so does the function that signs
the assertion for both protocols. This endpoint was originally written with
neither check. A session in one organisation could get a signed token for another
organisation's application, or for one its administrator had switched off. The check
inside the signing function exists so that a third caller cannot repeat that
mistake.

## wreply is matched exactly

A `wreply` that is not registered for the application is answered with this
message:

```
wreply is not one of the reply URLs registered for this application. It is
matched exactly, because anything looser would let a link decide where a signed
assertion is delivered
```

Leaving out `wreply` is normal, and safest: the registered default reply URL is
used. A prefix match would turn this endpoint into a redirector, one that delivers
a signed assertion wherever a crafted link points. That is how this class of
endpoint is usually broken.

## Signing out

`wa=wsignout1.0` asks the person, on the same page every sign-out link gets.
Otherwise one HTML tag on any page could sign out everyone who visits it. Only
that page's own form confirms. An application's POST is a request, not the
confirmation.

A `wreply` says where they land afterwards, and is held to the same list:

- With a `wtrealm`, it must be one of that application's reply URLs.
- Without one, which is what Windows Identity Foundation sends, it must be a reply
  URL of an application this session was given a token for.

A `wreply` that fails is dropped, not refused. The person asked to sign out, and
they are signed out. They stay here instead of following the link. So a page an
application wants people to land on after signing out has to be registered with
`-acs`, like any reply URL.

Every application the session gave a token to is told, wherever the sign-out
started. It could start here, at another application, or at the OpenID Connect
end-session endpoint.

The page that confirms the sign-out loads each application's reply URL, the one it
took its token at, with `wa=wsignoutcleanup1.0`. It loads them all at once, beside
the frames of the OpenID Connect applications. WS-Federation 1.2 §13.2.4 has the
identity provider send this clean-up message to every application it issued a
token to for the session. The application's own
cookies, which the browser brings, say whose session to end. A reply URL that has
since been taken off the provider is not loaded.

It is a page in the person's browser, so it reaches an application only as far as
the browser lets it. The browser does not send a session cookie that is
`SameSite=Lax` or `Strict` in a frame from another site. An application with such a
cookie keeps its session until the session runs out.

And the page is not shown at all when the session also holds a SAML service
provider with single logout. That provider's chain takes the browser from one
provider to the next instead. In that case the OpenID Connect applications' frames
are not shown either. Until November 2026, nothing was sent at all.

## The token

The token is a `RequestSecurityTokenResponse` containing a **signed SAML 2.0
assertion**. It is built by the same code path that builds one for a SAML 2.0
response.

That reuse is deliberate. A second assertion builder would be a second place for
an audience restriction, a subject confirmation or an authentication context to be
forgotten. Everything that makes the SAML side safe is in the code this reuses.
Assertion encryption works here too, without this endpoint containing a line about
encryption.

The token is always signed. `saml signing -sign-assertions=false` is a choice
between the assertion and the Response around it. A WS-Federation answer has no
Response, so that setting is not read here. A provider set that way was once sent
a token with a signature on nothing.

## SAML 1.1

ADFS issues SAML 1.1 tokens for WS-Federation by default, and some very old
applications accept nothing else. To move one application to SAML 1.1 tokens:

```sh
signari saml wsfed-token -entity-id "urn:sharepoint:intranet" -saml-version 1.1
```

SAML 2.0 stays the default because it says more. A 1.1 assertion has no place for
the `Recipient` and `InResponseTo` that tie a 2.0 assertion to one delivery and one
request. So its audience and its lifetime are all that bound it. Keep the lifetime
short, and choose this only for an application that takes nothing else.

Nor is a 1.1 token encrypted. Setting 1.1 on a provider with an encryption
certificate is refused. A certificate that arrives afterwards makes sign-in fail,
rather than send in the clear what the provider asked to have sealed.

A released attribute named by URL, such as
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`, is split at
its last slash. The two halves are the `AttributeNamespace` and `AttributeName`
SAML 1.1 requires, so the application joins it back into the same claim. Any other
name goes in the namespace `http://schemas.xmlsoap.org/claims`.

The setting is per application, and touches WS-Federation alone. The same
provider's SAML 2.0 sign-ins do not change.

## One bug worth recording

The first version declared `xmlns:wsu` on the `<wsu:Created>` element, so its
sibling `<wsu:Expires>` had an unbound prefix. The document was well-formed to
look at, and failed to parse at the far end with an error naming a column number.

Namespaces are now declared on the root. It was found by parsing Signari's own
output, not by reading it, which is the only way this class of thing is found.
