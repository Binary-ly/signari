# Clients known by their URL

An application can be its own registration: its `client_id` is an https URL, and the JSON
at that URL says what a registration would say. There is no step between it and a person
signing in, which is what you want from something like an MCP client, one a person installs
and points at a server nobody has set up for it.

This follows the Client ID Metadata Document draft
([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)).

## Nothing happens until you say so

With no rule, no document is ever fetched, and a URL for a `client_id` is an unknown client
like any other. A rule says whose URLs to believe, which organisation they land in, and the
most they may be given:

```sh
signari client-metadata allow -url-prefix https://mcp.example.com/ -org <uuid> -scopes openid,profile,tools
signari client-metadata rules
signari client-metadata forget -url-prefix https://mcp.example.com/
```

A prefix has to name a host and end in `/`, so `https://good.example` cannot also cover
`https://good.example.evil.test/`. There is no way to write "anybody": letting any site on
the internet ask your people to sign in is a decision about phishing, and it would need more
than a line here. Where several rules match, the longest wins. With no `-scopes` a client
gets `openid` and nothing else, and whatever a document asks for beyond the list is dropped.

Forgetting a rule **deletes the clients it admitted**, with their sessions and tokens. They
had no other standing here.

Discovery says `client_id_metadata_document_supported` while there is a rule.

## What arrives

An authorization request, pushed or not, whose `client_id` falls under a rule, has that URL
fetched before anything else is read. A client application serves something like:

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

and from then on it is a client like any other, in the rule's organisation. It shows on the
consent page as `Example Tools (mcp.example.com)`: the name is anybody's to choose, and the
host is the part that cannot be faked. It is never first-party, so a person always sees that
page. `logo_uri` is not read at all.

**The fetch.** It goes through the same dialer as every other outbound request, so a URL
that resolves into a private network is refused when it connects. It follows no redirects,
takes only a `200` in JSON, reads no more than 5 KiB, and gives up after five seconds. One
address can cause thirty fetches a minute.

**The document.** `client_id` has to equal the URL exactly, or one site could speak for
another. The URL itself is https with a path, and no userinfo, fragment or dot segments. A
shared secret of any kind is refused, by `client_secret` or by an authentication method
that needs one, since there is no way to have agreed one. So is any `grant_type` beyond
`authorization_code` and `refresh_token`, and any `response_type` but `code`.

**Redirects.** A `redirect_uris` entry has to be at the document's own origin, or on
`http://127.0.0.1` or `http://[::1]`, where a native application listens. Without that a
document at evil.example could name a redirect at somebody else's application and ride on
its name, which the draft leaves to the server to refuse (§8.1). A native application with a
custom scheme is refused for the same reason, because anybody can claim a scheme. Register
one like that yourself, as below.

**Keys.** `token_endpoint_auth_method` is `none` for a public client, the default, or
`private_key_jwt` with `jwks` or `jwks_uri` in the document. A client that says it holds a
key has to use it. A `jwks_uri` is fetched once along with the document, so a client's new
keys arrive when its document is next read, and private key material is refused.

## How long it lasts

A document is kept as its `Cache-Control` says, an hour if it says nothing, and never less
than a minute or more than a day. It is kept on the client's own row: there is no cache to
go stale, and nothing that failed is remembered, so the next request asks again.

Past that, the next authorization request reads it again, and a new redirect or name comes
in with that. If the site does not answer the request is refused as expired, and the client
stays that way until it does. Tokens already issued, and refreshing them, carry on: the
document decides who may start a sign-in, and what a person agreed to is ended the usual
ways. There is no attempt to notice a changed key and revoke anything, which the draft leaves
open (§8.4.1).

## A client somebody registered

A client created here stays as it was made. Create one with an https `client_id` and no
document is ever read for it, whatever the rules say, which is the draft's pre-registration
(§7.2). It is also how to let in an application the rules above would refuse.
