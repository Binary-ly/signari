# Opaque access tokens

An access token is a signed JWT by default: a resource server checks it with the published
keys and reads it without asking anybody, and so can whoever holds it. Set a client to
opaque and it gets a handle instead, which says nothing to anybody:

```sh
signari client set-token-format -client-id web-app -token-format opaque
```

A resource server takes the handle to the introspection endpoint and is told what the JWT
would have said: who, for which client, with which scopes, until when, and that it is
still active. Use this when a token should tell the application holding it nothing, or
when a resource server should hear about a revocation on its next call rather than at the
token's expiry.

It costs a call to this server for each check, where a JWT costs none.

## What it is

The handle is a reference. The signed token it stands for is kept in
`core.opaque_access_tokens`, sealed under a key derived from the handle, and the row is
found by the handle's hash, so **a read of the table gives nobody a working token**: the
handle is not there, and nothing else opens the row.

Everything that takes an access token takes a handle: userinfo, introspection, revocation,
token exchange, forward auth, the credential endpoint and the Admin API. Binding is by the
same rules, and a DPoP proof's `ath` is the hash of the handle, since that is what the
client holds. An ID token's `at_hash` is too.

A switch applies from the next token issued. Tokens already out stay what they are, and
go on working. Handles past their expiry are refused at once and swept by the janitor.
