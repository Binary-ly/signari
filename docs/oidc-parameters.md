# Authorization request parameters

What this server does with the OpenID Connect parameters a relying party can send
beside the ones every request needs. Each is worth knowing about because a parameter
quietly ignored is a client that believes it asked for something.

| Parameter | What happens |
|---|---|
| `login_hint` | Fills in the sign-in box, and sends the person to the provider that signs in its domain when there is one ([social-login.md](social-login.md#sending-people-to-their-own-provider)). A suggestion: it can be typed over, and it proves nothing |
| `id_token_hint` | An ID token this server issued to this client, naming who is expected. See below |
| `claims` | A request for claims, read as a request for the scopes that release them. See below |
| `display` | Not read. There is one page, and it suits `page`, `popup` and `touch`, which is what discovery lists as `display_values_supported` |
| `prompt`, `max_age`, `acr_values` | Held to the session on every request; see [flows.md](flows.md) and [accounts.md](accounts.md) |

## `id_token_hint`

The token is checked as this server's own: signature, issuer and that it was issued to
this client. Past its expiry is fine, since an expired ID token is the usual one a client
has to hand. A token that fails any of that is `invalid_request`, sent back to the client.

Then the session is held to it:

| The session is | The answer |
|---|---|
| The person it names | As any other request |
| Somebody else, with `prompt=none` | `login_required` |
| Somebody else, otherwise | The sign-in page, saying so. A code for the wrong person never comes back |
| Nobody | As any other request with no session |

## `claims`

There is one way a claim is released here, which is by scope, so that there is one
consent screen and one release rule. A request for a claim becomes a request for the scope
that carries it:

| Claim | Scope |
|---|---|
| `email`, `email_verified` | `email` |
| `name`, `given_name`, `family_name`, `preferred_username` | `profile` |
| `groups` | `groups` |

So the parameter cannot release anything the client is not registered for or that the
person did not consent to. A claim whose scope the client is not registered for simply
does not come back, essential or not, and that is not an error. An `acr` marked essential
in `id_token` is added to `acr_values` and held as they are. A `sub` with a value holds the
session to that person, as `id_token_hint` does.

The cost is precision. Asking for `email` under `userinfo` alone puts it in the ID token
too, because the scope does: a client gets what its scopes would give it, not exactly what
it listed.

OpenID Connect Core is not among the specifications held in this repository, so this page
describes what the server does and not what the specification says. The OpenID
Foundation's suite is what would hold it to the text; see
[the conformance notes](../deploy/conformance/README.md) for what has been run.
