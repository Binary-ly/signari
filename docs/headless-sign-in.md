# A sign-in page of your own

An application can draw its own sign-in page and walk the sign-in over JSON. It ends the
way any sign-in does: a code at the application's redirect URI, redeemed with PKCE. No
token is ever answered by these routes.

```sh
signari client set-login-ui -client-id wiki -url https://wiki.example.com/login
```

Or `login_ui_url` on `PATCH /admin/clients/{clientID}` or in a
[configuration file](config-as-code.md). Empty goes back to this server's page. It has to be
https, or http on `localhost` for development. A client that has not named one cannot be
signed in this way: its answer is `403 unauthorized_client`, because a page of an
application's own is one more place a password is typed, and that is a decision about the
application.

A browser reaches these routes from the origin of one of the client's redirect URIs, as it
does the token endpoint.

## The walk

An authorization request that needs a sign-in is sent to that page with the request in
`authz`:

```
https://wiki.example.com/login?authz=client_id%3Dwiki%26response_type%3Dcode...
```

The page gives that to the first route, and answers what it is asked:

```http
POST /login/api/start
Content-Type: application/json

{"authz": "client_id=wiki&response_type=code&code_challenge=...&code_challenge_method=S256..."}
```

```json
{
  "done": false,
  "page": "login",
  "status": 200,
  "state": "EYcaLr4l...",
  "forms": [
    {
      "action": "/login",
      "fields": [
        {"name": "username", "type": "input", "label": "Email", "required": true},
        {"name": "password", "type": "password", "label": "Password", "required": true}
      ]
    }
  ],
  "providers": [{"name": "Google", "url": "https://id.example.com/login/oidc/google/start?..."}]
}
```

```http
POST /login/api/submit
Content-Type: application/json

{"state": "EYcaLr4l...", "action": "/login", "fields": {"username": "ada@example.com", "password": "..."}}
```

Each answer is the next thing to ask: `page` names it (`mfa`, `prompt`, `consent` and so on),
`message` carries what went wrong when something did, and `state` goes to the next call. A
form's `buttons` are named submit buttons, and which one is pressed is an answer: `{"decision":
"allow"}` on the consent page. When the walk is over:

```json
{"done": true, "redirect_to": "https://wiki.example.com/cb?code=...&state=..."}
```

Go there, and redeem the code with the verifier at the token endpoint, as ever. `redirect_to`
is also where a refusal goes, with `error=` in it, as a browser's would.

The walk must be `response_type=code` with an S256 `code_challenge`, answered in the query.

`providers` are links for the browser to follow, so signing in somewhere else is the same
journey it always is, and comes back to the application with a code.

## It is the same journey

This has no walker of its own. Each step is a request to the handlers the HTML pages post
to, and the page they answer with is read back as JSON. So the [sign-in flow](flows.md), the
rate limits, the access policy, hooks, prompts, every second factor and every refusal apply
as they do in a browser, and a stage added to a flow reaches this with nothing added here. A
test walks one person through both, wrong answers included, and requires them to be asked the
same things in the same order.

## What the application holds

`state` is sealed under the root key, and carries what a browser would hold in cookies, so
the application's script cannot read it, including the session the walk makes. It lasts ten
minutes from the last step. It is not tied to a browser, so treat it as you would the password
it stands in for: in memory, and for as long as the page is open. A step can post only the forms
the last step offered, and the page's hidden fields stay the page's: naming one in `fields` does
nothing. Without a root key these routes answer `503 not_available`.

There is no cookie, so nothing is ambient and there is nothing for a forged request to spend.

## What differs from a browser

The person has no session cookie in their browser. The sign-in made a session, which is listed
and can be ended like any other, but the next application they go to asks again. That is what
the page being yours costs. Two things do not work over this:

- Passkeys: a ceremony is bound to the origin it runs on, and this page's is yours, so the
  forms it would need are not on the page this reads. Send the person to this server's page.
- A CAPTCHA widget on the sign-in page, which belongs to this server's origin. An application
  can answer it only by carrying the provider's token in `fields`.
