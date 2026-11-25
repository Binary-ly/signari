# Applications known by their URL

## Introduction

Some applications are installed by a person, not set up by an administrator. A
Model Context Protocol ([MCP](mcp-authorization.md)) client is one: a person
installs it and points it at a server nobody has set up for it. Registering each
such application in Signari first would get in the way.

So an application can be its own registration. Its `client_id` is an https URL,
and the JSON at that URL says what a registration would say. This JSON is its
"client metadata document". There is no step between it and a person signing in.

This follows the Client ID Metadata Document draft
([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)).
It is off until you add a rule with `signari client-metadata allow`.

## Nothing happens until you say so

With no rule, no document is ever fetched. A URL for a `client_id` is then an
unknown application like any other.

A rule says whose URLs to believe, which organisation they land in, and the most
they may be given. You add a rule, list the rules, and remove one like this:

```sh
signari client-metadata allow -url-prefix https://mcp.example.com/ -org <uuid> -scopes openid,profile,tools
signari client-metadata rules
signari client-metadata forget -url-prefix https://mcp.example.com/
```

A prefix has to name a host and end in `/`. So `https://good.example` cannot also
cover `https://good.example.evil.test/`.

There is no way to write "anybody". Letting any site on the internet ask your
people to sign in is a decision about phishing. It would need more than a line
here.

Where several rules match, the longest wins. With no `-scopes`, an application
gets `openid` and nothing else. Whatever a document asks for beyond the list is
dropped.

Forgetting a rule **deletes the applications it admitted**, with their sessions
and tokens. They had no other standing here.

Discovery says `client_id_metadata_document_supported` while there is a rule.

## What arrives

An authorization request may have a `client_id` that falls under a rule. Signari
then fetches that URL before it reads anything else. That holds for a [pushed
request](par.md) too.

The application serves something like this:

```json
{
  "client_id": "https://mcp.example.com/client.json",
  "client_name": "Example Tools",
  "redirect_uris": ["http://127.0.0.1:8123/callback"],
  "scope": "openid tools",
  "grant_types": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_method": "none"
}
```

From then on, it is an application like any other, in the rule's organisation.

It shows on the consent page as `Example Tools (mcp.example.com)`. The name is
anybody's to choose, and the host is the part that cannot be faked. It is never
"first-party", the kind of application that skips consent, so a person always
sees that page. `logo_uri` is not read at all.

**The fetch.** It goes through the same dialer as every other outbound request.
So a URL that resolves into a private network is refused when it connects. It
follows no redirects, takes only a `200` in JSON, reads no more than 5 KiB, and
gives up after five seconds. One address can cause thirty fetches a minute.

**The document.** `client_id` has to equal the URL exactly, or one site could
speak for another. The URL itself is https with a path. It has no userinfo (a name
before the host, as in `name@host`), no fragment and no dot segments.

A shared secret of any kind is refused, whether by `client_secret` or by an
authentication method that needs one. There is no way to have agreed one.
So is any `grant_type` beyond `authorization_code` and `refresh_token`, and any
`response_type` but `code`.

**Redirects.** A `redirect_uris` entry has to be at the document's own origin, or
on `http://127.0.0.1` or `http://[::1]`, where a native application listens.
Without that, a document at evil.example could name a redirect at somebody else's
application and ride on its name. The draft leaves that to Signari to refuse
(§8.1).

A native application with a custom scheme is refused for the same reason, because
anybody can claim a scheme. Register one like that yourself, as [an application somebody
registered](#an-application-somebody-registered) describes.

**Keys.** `token_endpoint_auth_method` is `none` for a public client, the default.
Or it is `private_key_jwt`, with `jwks` or `jwks_uri` in the document. An
application that says it holds a key has to use it.

A `jwks_uri` is fetched once along with the document. So an application's new keys
arrive when its document is next read, and private key material is refused.

## How long it lasts

A document is kept as its `Cache-Control` says, or an hour if it says nothing. It
is never kept less than a minute or more than a day.

It is kept on the application's own row. There is no cache to go stale, and
nothing that failed is remembered, so the next request asks again.

Past that, the next authorization request reads it again, and a new redirect or
name comes in with that. If the site does not answer, the request is refused as
expired. The application stays that way until the site answers.

Tokens already issued, and refreshing them, carry on. The document decides who
may start a sign-in, and what a person agreed to is ended the usual ways. There is
no attempt to notice a changed key and revoke anything, which the draft leaves
open (§8.4.1).

## An application somebody registered

An application created in Signari stays as it was made. Create one with an https
`client_id`, and no document is ever read for it, whatever the rules say. That is
the draft's "pre-registration" (§7.2). It is also how to let in an application
the rules above would refuse.
