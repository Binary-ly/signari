# Forward authentication

## Introduction

Some applications have a weak sign-in of their own, or none at all, such as n8n,
a dashboard or an internal tool. They know nothing about [OpenID Connect
(OIDC)](glossary.md#oidc), so they cannot send people to Signari themselves.

"Forward authentication" puts Signari in front of such an application. The
reverse proxy that serves the application asks Signari about every request before
serving it. An answer of 200 means let it through, and 401 means send the browser
to sign in.

You register each protected host with `signari proxy`, and you set up the proxy
itself with one of the recipes on this page.

## How a request is checked

Before the proxy serves anything, it makes a "subrequest": a request of its own to
Signari's `/proxy/verify`, carrying the browser's cookie. Signari answers 200 with
the person's identity, and only then does the proxy pass the request to the
application:

```
browser ──▶ nginx ──▶ (subrequest) ──▶ signari /proxy/verify
                │                              │
                │◀───── 200 + identity ────────┘
                ▼
            the app
```

## The three things that must line up

Forward authentication is configuration, and it fails silently. These are the parts
people get wrong, in the order they cause trouble.

**1. Both hosts must share a parent domain.** Signari's session cookie has the
`__Host-` prefix. That prefix forbids a `Domain` attribute, so the cookie is never
sent to another host. Forward authentication therefore issues a second, narrower
cookie, scoped to the parent domain. That only works if there is one, and
`SIGNARI_PROXY_COOKIE_DOMAIN` names it for the whole deployment:

| Issuer | Protected app | `SIGNARI_PROXY_COOKIE_DOMAIN` | |
|---|---|---|---|
| `auth.example.com` | `n8n.example.com` | `example.com` | works |
| `auth.example.com` | `n8n.other.com` | — | no shared parent: see [a cookie of its own](#an-application-on-another-domain) |
| `auth.localhost` | `n8n.localhost` | `localhost` | works (local development) |
| `localhost:9443` | `127.0.0.1:8080` | — | different hosts, not parent/child |

`signari proxy cookie -org <uuid> -host <h> -cookie <domain>` gives one host a
parent domain of its own, instead of the deployment's. That domain must cover the
issuer too. A browser refuses a cookie for a domain that the address setting it is
not under. So such a domain is refused at sign-in, by the same check.

If you get this wrong, the browser loops forever. The proxy says 401, and Signari
sets a cookie that the application's host will never receive. Signari redirects
back, and the proxy says 401 again. Nothing logs an error, because nothing is wrong
from any single component's point of view.

Signari refuses this at `/proxy/start`, instead of leaving you to find it:

```
the proxy cookie is scoped to "localhost", which "127.0.0.1" is not under, so
the browser would never send it back and would loop between the proxy and here
forever.
```

**2. Every protected host must be registered.** After sign-in, Signari sends the
browser back to the address in `rd`. That address comes from a header the proxy
set from the original request, so it is attacker-influenced. Signari uses an
allow-list of hosts, not a "same domain" pattern, because a hostname an attacker
controls under your domain would satisfy a pattern.

Register a host, list the hosts, and disable one, with `signari proxy`:

```sh
signari proxy add-host -org <org-uuid> -host n8n.example.com
signari proxy list
signari proxy disable-host -org <org-uuid> -host n8n.example.com   # or enable-host, remove-host
```

You can do the same with `PUT /admin/organizations/{orgID}/proxy-hosts` in the
[Admin API](admin-api.md), or with `proxy_hosts:` in a [configuration
file](config-as-code.md). Each change is audited, and bumps the configuration
version.

The host is written as the browser sends it, **including a non-default port**
(`n8n.example.com:8443`). It is lower-cased, and a scheme, path or query is refused,
not guessed at.

Until these commands existed, raw SQL was the only way to register a host, and
nothing in the product could. Every deployment that followed the documentation as
far as the command line therefore stopped at the sign-in page. The person signed in,
and was then told the application they came from was not a registered protected
host.

A host belongs to **one organisation in the whole deployment**. Registering a host
that another organisation already protects is refused. The Admin API answers
`409 host_taken`, and the command line and `signari apply` return an error.

The verify endpoint lets in people from the organisation that registered the host.
If two organisations could both register it, the second one's administrator could
let their own people into the first one's application. Their identity headers would
carry whatever the second organisation said about them.

**3. Identity headers must come from the auth response, never from the client.**
The "auth response" is Signari's answer to the proxy's subrequest. Reading identity
from the client instead is the classic forward-authentication vulnerability. If the
proxy passes the client's `X-Forwarded-User` through, anyone can claim to be anyone
by setting a header.

Signari sends **all three** identity headers on every `200`, taken from the
verified token. It sends `X-Forwarded-Email` **empty** when the account has no
address.

The empty header matters. Suppose a proxy copies a header from the auth response
only when the response carries it. If the header were left out, the client's own
`X-Forwarded-Email` would reach the application unchanged. A person with no address
on record could then claim any address. Check how your proxy behaves, instead of
relying on either assumption.

This page used to say that Signari "deletes those headers before doing anything
else". The code did delete them, but from its own empty response, so nothing was
protected. The proxy must still read the headers from the auth response, which is
what `auth_request_set` does in the nginx recipe below.

## nginx

This recipe was verified end to end against nginx 1.31. An anonymous request was
sent to sign in, and a signed-in request was served. A forged `X-Forwarded-User` was
replaced with the real subject, and access was refused again after sign-out.

Here is the nginx `server` block for one protected application, n8n at
`n8n.example.com`:

```nginx
server {
    listen 443 ssl;
    server_name n8n.example.com;

    ssl_certificate     /etc/nginx/tls.crt;
    ssl_certificate_key /etc/nginx/tls.key;

    # The subrequest nginx makes before serving anything. `internal` keeps it
    # unreachable from outside -- without it, a client could call this path
    # directly and read the identity headers Signari sets.
    location = /signari-auth {
        internal;
        proxy_pass              https://auth.example.com/proxy/verify;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";

        # What was originally asked for. Signari validates these against the
        # allow-list and uses them to build the URL to return to.
        proxy_set_header X-Forwarded-Proto  $scheme;
        proxy_set_header X-Forwarded-Host   $http_host;
        proxy_set_header X-Forwarded-Uri    $request_uri;
        proxy_set_header X-Forwarded-Method $request_method;
    }

    location / {
        auth_request /signari-auth;

        # THE LINES THAT MATTER. Identity is read from the auth RESPONSE and
        # then set on the upstream request. Without them nginx forwards whatever
        # the client sent, and authentication is a formality anyone can skip.
        auth_request_set $signari_user  $upstream_http_x_forwarded_user;
        auth_request_set $signari_email $upstream_http_x_forwarded_email;
        auth_request_set $signari_sub   $upstream_http_x_forwarded_sub;
        auth_request_set $signari_groups $upstream_http_x_forwarded_groups;
        auth_request_set $signari_jwt    $upstream_http_x_forwarded_jwt;
        proxy_set_header X-Forwarded-User   $signari_user;
        proxy_set_header X-Forwarded-Email  $signari_email;
        proxy_set_header X-Forwarded-Sub    $signari_sub;
        proxy_set_header X-Forwarded-Groups $signari_groups;
        proxy_set_header X-Forwarded-Jwt    $signari_jwt;

        # On 401, send the browser to sign in. The target comes from the auth
        # response's Location header, which already carries the return URL.
        auth_request_set $signari_login $upstream_http_location;
        error_page 401 = @signari_login;

        proxy_pass http://n8n:5678;
    }

    location @signari_login {
        return 302 $signari_login;
    }
}
```

## Traefik and Caddy: point them at `/proxy/verify/redirect`

Traefik and Caddy hand a refusal from Signari to the browser as it is: the status,
the `Location` and the body. A browser follows `Location` only on a redirect.
nginx's recipe above turns the `401` into one, but Traefik and Caddy do not. A
person behind them is left on a blank error page, signed in to nothing.

`/proxy/verify/redirect` answers a browser loading a page (`GET` or `HEAD`,
accepting `text/html`) with `302` to sign in. It keeps the `401` for everything
else, so an API client is not handed a redirect to a page it cannot use. Until
October 2026 these recipes pointed at `/proxy/verify`, and `proxy check` passed
them.

Both recipes below were run end to end in November 2026, in Traefik 3.1 and Caddy
2.8. They stood in front of an application that prints what it receives. An anonymous page load
was sent to sign in, and an API call was refused with `401`. After sign-in, the
application received the person's identity headers. A forged `X-Forwarded-User` from
the client was replaced with the real one, and `signari proxy check` found nothing
open.

Check yours with `signari proxy check`. Its browser probe fails a set-up that
strands a browser on the `401`.

### Traefik

In Traefik, Signari is a `forwardAuth` middleware, which you attach to every
router:

```yaml
http:
  middlewares:
    signari:
      forwardAuth:
        address: https://auth.example.com/proxy/verify/redirect
        # Traefik's own X-Forwarded-* headers, never the client's. Set to true,
        # Traefik keeps a client-supplied X-Forwarded-Host, and Signari
        # authorises whichever host that names.
        trustForwardHeader: false
        # Only these are copied from the auth response onto the upstream
        # request. Anything not listed here is NOT forwarded, which is the
        # behaviour you want -- it is an allow-list.
        authResponseHeaders:
          - X-Forwarded-User
          - X-Forwarded-Email
          - X-Forwarded-Sub
  routers:
    n8n:
      rule: Host(`n8n.example.com`)
      middlewares: [signari]   # attach to EVERY router, not just this one
      service: n8n
```

### Caddy

In Caddy, the `forward_auth` directive asks Signari before `reverse_proxy` serves
the application:

```caddyfile
n8n.example.com {
    # https:// explicitly: without a scheme Caddy dials the auth server over
    # plain HTTP on port 80, carrying the proxy cookie in the clear.
    forward_auth https://auth.example.com {
        uri /proxy/verify/redirect
        copy_headers X-Forwarded-User X-Forwarded-Email X-Forwarded-Sub
    }
    reverse_proxy n8n:5678
}
```

### Envoy

Envoy uses its `ext_authz` filter, over HTTP. It relays a refusal to the browser as
Traefik and Caddy do, so it too points at `/proxy/verify/redirect`.

Measured against Envoy 1.31, there are two differences. Envoy adds the request's
own path and query to that path, asking at `/proxy/verify/redirect/dashboard?tab=1`.
It also asks with the request's own method.

Signari answers anything below the path, by any method. It reads what is asked
about from the `X-Forwarded-*` headers. Envoy sets none of its own, so the
configuration tells it to set them. This recipe was run end to end like the two
above, with the same results:

```yaml
- name: envoy.filters.network.http_connection_manager
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
    stat_prefix: app
    # Without these Envoy passes /a/../b on as it came, to Signari and to the app,
    # so a rule for one path can be asked about another.
    normalize_path: true
    merge_slashes: true
    route_config: { ... }   # the application's routes
    http_filters:
    - name: envoy.filters.http.ext_authz
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
        failure_mode_allow: false   # Signari unreachable is a refusal, never a pass
        allowed_headers:
          patterns: [{exact: cookie}, {exact: accept}, {exact: authorization}]
        http_service:
          server_uri: {uri: "https://auth.example.com", cluster: signari, timeout: 3s}
          path_prefix: /proxy/verify/redirect
          authorization_request:
            headers_to_add:
            - {key: X-Forwarded-Host, value: "%REQ(:authority)%"}
            - {key: X-Forwarded-Uri, value: "%REQ(:path)%"}
            - {key: X-Forwarded-Method, value: "%REQ(:method)%"}
            - {key: X-Forwarded-Proto, value: "https"}
          authorization_response:
            # Copied onto the request to the app, replacing any the client sent.
            allowed_upstream_headers:
              patterns: [{exact: x-forwarded-user}, {exact: x-forwarded-email}, {exact: x-forwarded-sub}]
            # What a refusal gives the browser: where to sign in.
            allowed_client_headers:
              patterns: [{exact: location}, {exact: www-authenticate}]
    - name: envoy.filters.http.router
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

In this example, `signari` is a cluster for Signari's address, with an
`UpstreamTlsContext` whose `sni` is its host name. `allowed_headers` belongs on
`ExtAuthz` itself. Envoy 1.31 still takes it inside `authorization_request`, and
warns that this is going.

## Prove it works

Configuration that looks right is not the same as configuration that works. The
browser gives you no way to tell the difference: you see a sign-in page, so you
assume you are covered.

`signari proxy check` tests the set-up from outside, as an attacker would see it:

```sh
signari proxy check \
  -app     https://n8n.example.com \
  -issuer  https://auth.example.com \
  -origin  http://127.0.0.1:5678      # the app's own address
```

It probes as an anonymous attacker would, and exits non-zero on any finding. It
needs no database, so you can run it from continuous integration (CI). You can also
run it from outside the network, which is where the answer matters. It looks for:

- **paths that slipped through**: a rule on `/` does not cover `/rest` or
  `/webhook`, and those are how the application is really driven;
- **method bypasses**: authentication written as a GET-only condition leaves writes
  open;
- **identity-header injection**: a request that merely *claims* to be a person;
- **direct-to-origin bypass**: the application still listening on its own port,
  which makes everything else in the report irrelevant;
- **a sign-in that never arrives**: the proxy hands a browser its 401 instead of a
  redirect. Or, for a host that [keeps a cookie of its
  own](#an-application-on-another-domain), `/.signari/` is not routed to Signari,
  or its redirect comes back rewritten. Nothing is open, and nobody can sign in, so
  it is reported as `STUCK`.

A clean run is evidence, not a guarantee. It covers the paths and methods listed in
the output, from wherever it ran, and nothing more. The command says so.

## Who may reach which application

A valid proxy cookie is not enough. On every request, the verify endpoint checks
three things:

1. **The host is one of the signed-in person's organisation's protected hosts,
   and it is enabled**. The host comes from `X-Forwarded-Host`, which the proxy
   must send (the configurations on this page do). Suppose a person from another
   organisation, an unregistered host or a disabled host is involved, or no host
   is named. Then the answer is `403`, and no identity headers are sent.
2. **The access policy allows it.** A protected host is keyed `proxy:<host>`, the
   way an application is keyed by its client ID. So this rule decides who reaches
   the payroll application:

   ```yaml
   policies:
     - name: payroll-is-for-finance
       when: {client: "proxy:payroll.example.com"}
       require: {groups: [finance], mfa: true}
   ```

   A refusal is `403`, with the rule's message in `X-Signari-Reason`.
3. **Network, device and travel conditions are treated as unknown, so they
   refuse**. The request that reaches the verify endpoint comes from the proxy, so
   its address is the proxy's own. A `from_networks` rule checked against it would
   let everybody in from inside the office the proxy sits in. Until October 2026
   this held for the network and device conditions only. The travel condition read
   the missing address as "not checked", counted that as met, and let everybody
   through.

The answer is `403` and not `401`, because the person is signed in and may not
reach this application. A `401` would send them back to sign in. Signari would let
them through, and they would arrive here again, in a loop.

Until October 2026 none of this was checked. Anyone who could sign in anywhere in
the deployment passed every protected host of every organisation.

## An application on another domain

A cookie can only be set for a domain that the address setting it is under. So the
issuer cannot set one for an application on a domain they do not share. That
application can keep a cookie of its own, set on its own address:

```sh
signari proxy cookie -org <uuid> -host n8n.other.com -cookie own
```

Its proxy has to route one more path to Signari, `/.signari/`, sending the
application's name in `X-Forwarded-Host`. It must also hand Signari's redirects back
unchanged. On nginx, add this alongside the `location` blocks above:

```nginx
location /.signari/ {
    proxy_pass              https://auth.example.com;
    proxy_ssl_server_name   on;
    # Without it, nginx rewrites the issuer's address in Signari's redirect to this
    # application's, and the browser goes round between here and /proxy/start.
    proxy_redirect          off;
    proxy_set_header Host             auth.example.com;
    proxy_set_header X-Forwarded-Host $http_host;
}
```

This was measured with nginx 1.31.8 in November 2026, with two applications on a
domain the issuer shares nothing with. The sign-in worked, and the page asked for
was served with the person's headers. A forged `X-Forwarded-User` was replaced. The
neighbouring application signed in on the same session, with no second password. A
link that ends a sign-in was refused in another browser. Sign-out at the issuer
ended it at the application.

The first version of this block had no `proxy_redirect off`, and no browser could
sign in through it. The default in nginx rewrote
`Location: https://auth.example.com/proxy/start?…` to `/proxy/start?…`, which the
browser then asked the application for. Its forward authentication sent the browser back to the
beginning, and so on for ever. Nothing was exposed, so a check that only looks for
open paths passed it. `signari proxy check` now follows the sign-in begun at the
application's address one step, and names this.

With a cookie of its own, the sign-in then goes like this:

1. The proxy asks about a request with no cookie. The answer sends the browser to
   `https://n8n.other.com/.signari/proxy/begin`, not to the issuer.
2. That sets a state cookie on the application's address and sends the browser to
   the issuer, carrying the state.
3. The issuer signs the person in as usual. It sends them back to
   `/.signari/proxy/callback` with a code that lasts a minute, for this host and
   this state.
4. There, the code is held to the state in the browser, the host, and a session
   that is still live. The proxy cookie is set on the application's address alone,
   and the browser goes back to the page it asked for.

The state is why step 2 exists. A code in a URL works for whoever opens it. Without
the state, somebody could sign in, stop at the callback, and send the link to
somebody else. That person would then be using the application as them, and telling
it things. The code is good only in the browser that started the sign-in.

A cookie set this way names its application, and is refused at any other, the same
organisation's included. Everything else is as it was. The session is checked on
every request, so signing out at the issuer ends it. It needs signing in once per
application, instead of once per parent domain.

Registering a host this way changes what its proxy has to do, so do the two
together. Until `/.signari/` is routed, the person is sent to a page the application
does not have.

## Rules for one path

A host protects every path alike until it has rules. Rules are for the paths that
this does not fit. Examples are a health check that must answer anybody, a metrics path
nothing outside should reach, or a console held to more than the rest.

Rules are written in a file, one `effect methods path` line each, and the first rule
that matches decides:

```
# rules.txt: the first that matches decides
public GET,HEAD /static/**
public *        /health
deny   *        /metrics/**
auth:console *  /console/**
```

Set a host's rules from the file with `signari proxy rules`, or leave out `-file` to
show them:

```sh
signari proxy rules -org <uuid> -host grafana.example.com -file rules.txt
signari proxy rules -org <uuid> -host grafana.example.com          # show them
```

You can do the same with `"rules"` on `PUT /admin/organizations/{orgID}/proxy-hosts`,
or with `rules:` under `proxy_hosts:` in a [configuration file](config-as-code.md).
Each replaces the whole list, because the order is what it means. An empty list
clears it.

Each rule has one of three effects:

| Effect | |
|---|---|
| `public` | Nobody has to be signed in. The application is told of nobody, even when somebody is: every identity header is sent empty |
| `deny` | `403` for everybody, signed in or not |
| `auth` | What every path no rule names gets, written out to take a path back from a wider rule after it, or with `:name` to hold it to more |

A path is matched whole. `*` stands for anything within one segment. `**`, alone in
a segment, stands for any number of segments, none included. So `/static/**` matches
`/static`, `/static/` and `/static/js/app.js`, and not `/staticfiles`.

`auth:console` gives a path an access policy of its own, keyed
`proxy:<host>#console`, on top of the host's:

```yaml
policies:
  - name: the-console-needs-a-second-factor
    when: {client: "proxy:grafana.example.com#console"}
    require: {groups: [ops], mfa: true}
```

### A path that could mean two things is refused

Signari checks the rule, but the application serves the path, and the application
decides for itself what a path means. Where the two differ, a rule is a way past the
check. `/static/../metrics` matches `/static/**` at Signari, and is `/metrics` at the
application.

So on a host with rules, these are refused with `403`, signed in or not, and never
compared:

- A dot segment, spelled out or encoded (`/a/../b`, `/a/%2e%2e/b`).
- An empty segment (`//admin`).
- An encoded slash or backslash, and a plain backslash.
- A path parameter (`/a;x/b`).
- Anything still encoded once decoded (`/a/%252e`).

Each of those was sent, spelled as it is here, through the nginx, Traefik, Caddy and
Envoy configurations on this page. Each was refused before the application saw it,
signed in or not. Envoy's `normalize_path` resolves some first. It then sends the
resolved path to the engine and the application alike, so the two still judge one
path.

An application whose paths really look like that cannot have rules on the host.

Upper and lower case are decided for you. A `deny` or `auth` rule meets every
spelling of its path. So `deny /admin/**` refuses `/ADMIN/users` to an application
that serves it as `/admin/users`. A `public` rule meets only the spelling written,
so `public /static/**` does not open `/STATIC/` to anybody. No spelling gets more
than the one the rule names.

Until November 2026 every rule minded case. An application that did not had to be
given each spelling a `deny` should cover.

Two things are still yours to get right.

First, a path is compared with its trailing slash. `deny * /metrics` leaves
`/metrics/` open, which many applications serve as `/metrics`. So a `deny` is written
`/metrics/**`, which covers both and everything below. This page's example said
`/metrics` until November 2026. Then running it behind real proxies showed
`/metrics/` reaching the application.

Second, a rule is only as good as what the proxy says. With rules on a host, a proxy
that sends no `X-Forwarded-Uri` is refused, not guessed at. If a proxy sends no
`X-Forwarded-Method`, every rule naming methods is read the strict way. A `public`
one does not apply, and a `deny` one does. The configurations on this page send
both.

Rules are read on every request, and take effect on commit. A disabled host opens
nothing, whatever its rules say. A host is held by one organisation, so no
organisation can write rules for another's application.

## What the application receives

On every `200`, the application receives these headers:

| Header | Contents |
|---|---|
| `X-Forwarded-User` | the user's uuid |
| `X-Forwarded-Sub` | the same uuid, for apps expecting `sub` |
| `X-Forwarded-Email` | the email, or **empty** when the account has none — present either way, so a client-sent copy is overwritten |
| `X-Forwarded-Groups` | the groups released to this application that the person is in, comma-separated, or **empty** |
| `X-Forwarded-Jwt` | a signed statement of the above, or **empty** |

The person's ID is sent instead of their email address, because an email address can
change and can be reassigned. The universally unique identifier (UUID) is the stable
identity.

### Groups and a signed identity

Nothing about groups is sent until you say which groups an application may hear of,
because a group's name says something about a person.

Release groups, or a signed identity, with `signari proxy release`:

```sh
signari proxy release -org <uuid> -host grafana.example.com -groups admins,viewers
signari proxy release -org <uuid> -host grafana.example.com -signed-identity on
```

Each flag keeps what the other set. `-groups ""` releases none. A name holding a
comma is refused, since the header is a comma-separated list.

The headers are only as good as the network between the proxy and the application.
Anything that reaches the application directly can send them itself.

With `-signed-identity on`, `X-Forwarded-Jwt` carries a [JSON Web Token
(JWT)](glossary.md#jwt). The application can check it for itself against this
issuer's keys:

```json
{"iss": "https://id.example.com", "aud": "https://grafana.example.com",
 "sub": "7c1e…", "email": "ada@example.com", "groups": ["admins"],
 "iat": 1793440000, "exp": 1793440060}
```

Check the signature against `jwks_uri`, that `typ` is `proxy-identity+jwt`, that
`iss` and `aud` are what you expect, and `exp`. The token lasts a minute and is made
afresh for every request. So it is proof of this request, and not something to keep.

## Programs: an access token instead of a cookie

A script or a service has no browser to sign in with. When a request carries no
proxy cookie and does carry `Authorization: Bearer`, that token is checked instead.

Register the protected address as a resource that tokens can be issued for. The
program then sends its token with each request:

```sh
signari resource add -org <uuid> -resource https://app.example.com

curl -H "Authorization: Bearer $TOKEN" https://app.example.com/report
```

The token's `aud` has to be `https://<the host>`, so ask for it with
`resource=https://app.example.com`. A token for anything else is refused, and that
includes one for the client itself or for another protected host.

What ends a token ends it here on the next request:

- revoking it;
- revoking its grant;
- ending its session;
- deactivating the person;
- disabling the client.

After that, the token goes through the same decision as a cookie. The host has to
be one of the organisation's, and enabled, and the access policy has to allow it.

A `client_credentials` token passes as its client. So `X-Forwarded-User` is the
client ID, and `X-Forwarded-Email` is empty. To a policy it is a client in no
groups, so a rule requiring a group or a second factor refuses it.

When a request carries both, the cookie decides, because the application behind the
proxy may use `Authorization` for something of its own.

A "sender-constrained" token is bound to a key or a certificate: [Demonstrating
Proof of Possession (DPoP)](glossary.md#dpop) or certificate-bound. Such a token is
refused. What proves it is bound to the application's address, and only the
application could check that, so a proxy would be taking it on trust.

Your proxy has to pass `Authorization` to `/proxy/verify`. nginx's `auth_request`
does, unless it has been told not to.

### When the sign-in behind a token was not strong enough

A policy rule can ask for factors, such as `mfa: true` or
`phishing_resistant: true`. Suppose that is all a rule asks for, and the token's
sign-in did not give it.
Then the answer is a 401 with the challenge that RFC 9470, OAuth 2.0 Step Up
Authentication Challenge Protocol, defines:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="Sign in with a second factor to reach the reports.", acr_values="2"
```

The program sends the person to sign in again with `acr_values=2`, which asks for
two factors, and the token from that sign-in passes. `phishing_resistant` asks for
`4`, a device-bound key. A rule with `factors_any_of` gets the challenge without
`acr_values`, because no single value means "one of these factors".

Stepping up is a new sign-in, and it replaces the session. The token from before it
then gets a 401 saying the session has ended. The program carries on with the token
from the new sign-in.

A refusal that no sign-in would change stays a 403. Examples are a group the person
is not in, a network rule, or a `deny`. A token with no session behind it stands for
nobody who could sign in, so it also gets a 403. So does a browser, which the proxy
sends to sign in in its own way.

The 401 carries the same `Location` as any other refusal, so a proxy that turns
refusals into a sign-in goes on doing so. That also means a program sees the
challenge only if your proxy hands it the 401.

nginx's `auth_request` passes a 401's `WWW-Authenticate` on by itself, as checked
with nginx 1.31.8. So do not add it again with `add_header`, which sends it twice.
The nginx recipe above, though, sends every 401 to sign in with `error_page`. Serve
programs from a location without that line.

## Session lifetime

The proxy cookie lasts 30 minutes and is refreshed by the flow. But **the live
session is rechecked on every single request**. Signing out of Signari revokes proxy
access immediately. Forward authentication cannot be used to outlive a sign-out,
which is the failure this project spent a day making visible elsewhere.

The recheck also reads the person. A session whose person is no longer active is
refused, whichever path deactivated them.

The check used to read only the session row. So a deactivation that ended no
session left the proxy cookie working for the rest of its 30 minutes. One example is
a [System for Cross-domain Identity Management (SCIM)](glossary.md#scim) PUT with
`"active": false`.
