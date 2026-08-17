# Federated sign-in providers

```sh
signari idp add -org <uuid> -slug google -name "Google" -kind google \
  -client-id-ext <id> -client-secret <secret>
```

| Kind | |
|---|---|
| `google` | `email_verified` in the ID token is authoritative |
| `microsoft` | The plain `email` claim is never believed; needs the optional `xms_edov` claim |
| `github` | Not OIDC. `/user/emails` is queried so only a confirmed address counts |
| `apple` | No userinfo endpoint. The client secret is a JWT that expires — see below |
| `gitlab` | gitlab.com. For self-managed, use `oidc` with your own issuer |
| `discord` | Consumer accounts with no domain ownership behind them |
| `twitch` | Needs `user:read:email` *and* a claims parameter before it returns an address |
| `linkedin` | Issuer and userinfo are on different hosts, which is unusual and correct |
| `oidc` | Anything else with a discovery document |
| `saml` | An upstream SAML identity provider |

**Every endpoint above was read from that provider's own
`/.well-known/openid-configuration`**, not from documentation or memory. A
preset with wrong endpoints is worse than no preset: it looks configured and
fails at the moment a user is trying to sign in.

## Apple, and the secret that expires

Every other provider issues a client secret: a string you paste in and forget.
Apple does not. Apple's client secret is a **JWT that you sign**, with an ECDSA
key downloaded once as a `.p8` file, valid for **at most six months**.

So every Sign in with Apple integration in the world breaks twice a year. It
fails as `invalid_client`, which reads like the credentials are wrong rather
than expired, at a moment nobody changed anything. The usual mitigation is a
calendar reminder, and the usual outcome is that the reminder outlives whoever
set it.

```sh
signari idp apple-secret -slug apple \
  -apple-team ABCDE12345 -apple-key-id KEY1234567 -apple-key ./AuthKey.p8

minted Apple client secret for apple
  services id : com.example.service
  expires     : 2027-02-13 (in 180 days)
```

Run it again before it expires. That is the whole maintenance story.

Two things the errors call out by name, because they are the mistakes people
actually make:

- **The Services ID, not the App ID.** They sit in the same list, look alike, and
  the wrong one produces `invalid_client` without saying which identifier was
  wrong.
- **The `.p8` file as downloaded**, including the BEGIN and END lines. An RSA key
  is refused by naming the key type rather than reporting a parse failure.

Apple also returns the user's **name only on the first authorization**, in the
form post, never again. An account created without capturing it then has no
name, and re-authorizing does not produce one.

## One bug worth recording

Adding these providers worked everywhere except the database: the `kind` column
carries a CHECK constraint enumerating the known providers, and it was a second
list nothing kept in step. The preset was right, the CLI help was right, and
registering one failed with a constraint violation naming nothing useful.

There is now a test that reads the constraint out of the database and compares
it against the presets **in both directions** — a kind the code can produce that
the database refuses, and a kind the database permits that no preset backs.
`Kinds()` is derived from the presets map for the same reason.
