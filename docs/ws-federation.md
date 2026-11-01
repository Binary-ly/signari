# WS-Federation

The passive requestor profile, for SharePoint, Windows Identity Foundation
applications, and anything federated to ADFS before SAML 2.0 was the default.

**This is a compatibility shim for an estate being migrated, not a protocol to
choose.** It is here so that moving off ADFS does not have to mean rewriting
every application first.

## Configuration

There is none beyond registering the application as a SAML service provider:

```sh
signari saml add-sp -org <uuid> \
  -entity-id "urn:sharepoint:intranet" \
  -name "Intranet" \
  -acs "https://intranet.example.com/_trust/"
```

The `wtrealm` is the entity id and `wreply` must be one of the registered reply
URLs. One registration serves both protocols, so an application configured for
WS-Federation is released, policy-gated and audited exactly like a SAML one.

To set up the application, give it this server's metadata:

```
https://id.example.com/FederationMetadata/2007-06/FederationMetadata.xml
```

The document names a security token service, its token issuer, the endpoint, and
every certificate in use, the incoming one too during a rotation, so a key can
change without the application being reconfigured. `?wtrealm=<realm>` gives the
certificates of a realm set to `ecdsa-sha256`; an unknown realm gets the default
document, so this does not say which realms exist.

An application another organisation also holds answers at
`/wsfed/org/<slug>`, with its metadata at
`/wsfed/org/<slug>/FederationMetadata.xml`. See
[saml.md](saml.md#one-entity-id-several-organisations).

## Endpoints

| | |
|---|---|
| `GET` or `POST /wsfed?wa=wsignin1.0&wtrealm=…` | Sign-in. Answers with a self-posting form carrying the token |
| `GET` or `POST /wsfed?wa=wsignout1.0` | Sign-out. Handled by the ordinary end-session path |
| `GET /FederationMetadata/2007-06/FederationMetadata.xml` | What an application imports |

A request may arrive in the URL or as a form. A form is sent straight back as a
`GET`, for the reason that decides it: the session cookie is `SameSite=Lax`, so it
stays behind on a POST from another site. Answered where it landed, the request
would read as nobody signed in, and a sign-out would end nothing while saying it
had. Each parameter may be given once, wherever it comes from, and twice is refused:
a `wreply` in both places is two answers to where the token goes.

| Parameter | |
|---|---|
| `wtrealm` | The application, by its entity id. Required to sign in |
| `wreply` | Where the token is posted. See below |
| `wctx` | Passed back untouched, which is what the application uses to resume whatever the person was doing |
| `wfresh` | The age a sign-in may be, in whole minutes. `0` asks for a sign-in now |
| `wauth` | How the person must have signed in, as a SAML authentication context class, or `urn:oasis:names:tc:SAML:1.0:am:password` |
| `whr` | Where the person signs in. A provider's slug, its issuer or SAML entity id, or a domain it signs in |

`wfresh` and `wauth` are held to the session on every request, as `max_age` and
`acr_values` are at the authorization endpoint. A session too old, or short of a
second factor the person has, is sent to sign in and comes back. A `wauth` this
directory offers no way of meeting is refused with `400`, and one this account
cannot reach with `403`, since signing in again would bring the same session back.
Neither is ignored when it cannot be read: an application that asked for a fresh
sign-in must not be handed an old one because of how it spelled it.

The request is not signed, so anyone holding the browser can edit these off the URL.
An application that depends on them reads the authentication instant in the token,
which only signing in can move.

`whr` chooses a route and nothing else. The provider still authenticates the person
and every link rule still applies. It looks only among the providers of the realm's
own organisation, and is not read at all for somebody already signed in. One that
names nothing here is ignored, and the sign-in page is shown.

## Whose application, and whether it is switched on

A realm belongs to one organisation. A session from any other organisation is
refused with `403 access_denied`, and so is a realm whose registration is
disabled. A disabled realm is refused before the sign-in page, so nobody is asked
to authenticate for an application that will be turned away anyway.

The SAML endpoint makes the same two checks, and so does the function that signs
the assertion for both protocols. This endpoint was originally written with
neither check. A session in one organisation could get a signed token for another
organisation's realm, or for one its operator had switched off. The check inside
the signing function exists so that a third caller cannot repeat that mistake.

## wreply is matched exactly

```
wreply is not one of the reply URLs registered for this application. It is
matched exactly, because anything looser would let a link decide where a signed
assertion is delivered
```

Omitting `wreply` is normal and safest: the registered default reply URL is
used. A prefix match would turn this endpoint into a redirector that delivers a
signed assertion wherever a crafted link points, which is how this class of
endpoint is usually broken.

## Signing out

`wa=wsignout1.0` asks the person, on the same page every sign-out link gets, because
one HTML tag on any page could otherwise sign out everyone who visits it. Only that
page's own form confirms: an application's POST is a request, not the confirmation.

A `wreply` says where they land afterwards, and is held to the same list:

- With a `wtrealm`, it must be one of that realm's reply URLs.
- Without one, which is what Windows Identity Foundation sends, it must be a reply
  URL of an application this session was given a token for.

One that fails is dropped rather than refused. The person asked to sign out, and they
are, and they stay here instead of following the link. So a page an application wants
people to land on after signing out has to be registered with `-acs` like any reply
URL.

An application is not told of a sign-out that started somewhere else. There is no
`wsignoutcleanup1.0` sent to it, so it keeps its own session until that runs out.

## The token

A `RequestSecurityTokenResponse` containing a **signed SAML 2.0 assertion**,
built by the same code path that builds one for a SAML 2.0 response.

That reuse is deliberate. A second assertion builder would be a second place for
an audience restriction, a subject confirmation or an authentication context to
be forgotten — and everything that makes the SAML side safe is in the code this
reuses. Assertion encryption works here too, without this endpoint containing a
line about encryption.

The token is always signed. `saml signing -sign-assertions=false` is a choice between
the assertion and the Response around it, and a WS-Federation answer has no Response,
so that setting is not read here. A provider set that way was once sent a token with
a signature on nothing.

## SAML 1.1

ADFS issues SAML 1.1 tokens for WS-Federation by default, and some very old
relying parties accept nothing else. Move one application with:

```sh
signari saml wsfed-token -entity-id "urn:sharepoint:intranet" -saml-version 1.1
```

SAML 2.0 stays the default because it says more. A 1.1 assertion has no place for
the `Recipient` and `InResponseTo` that tie a 2.0 assertion to one delivery and one
request, so its audience and its lifetime are all that bound it: keep the lifetime
short, and choose this only for an application that takes nothing else.

Nor is a 1.1 token encrypted. Setting 1.1 on a provider with an encryption
certificate is refused, and a certificate that arrives afterwards makes sign-in
fail rather than send in the clear what the provider asked to have sealed.

A released attribute named by URL, such as
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`, is split at its
last slash into the `AttributeNamespace` and `AttributeName` SAML 1.1 requires, so
the application joins it back into the same claim. Any other name goes in the
namespace `http://schemas.xmlsoap.org/claims`.

The setting is per application and touches WS-Federation alone: the same provider's
SAML 2.0 sign-ins do not change.

## One bug worth recording

The first version declared `xmlns:wsu` on the `<wsu:Created>` element, so its
sibling `<wsu:Expires>` had an unbound prefix. The document was well-formed to
look at and failed to parse at the far end with an error naming a column number.

Namespaces are now declared on the root. It was found by parsing our own output
rather than by reading it, which is the only way this class of thing is found.
