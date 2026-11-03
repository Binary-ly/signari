# Forward authentication

Put Signari in front of an application that knows nothing about OIDC — n8n, a
dashboard, an internal tool, anything with weak or no authentication of its own.

The reverse proxy asks Signari about every request before serving it. 200 means
let it through; 401 means send the browser to sign in.

```
browser ──▶ nginx ──▶ (subrequest) ──▶ signari /proxy/verify
                │                              │
                │◀───── 200 + identity ────────┘
                ▼
            the app
```

## The three things that must line up

Forward auth is configuration, and it fails silently. These are the parts people
get wrong, in the order they bite:

**1. Both hosts must share a parent domain.** The IdP session cookie is
`__Host-` prefixed, which forbids a `Domain` attribute, so it is never sent to
another host. Forward auth therefore issues a second, narrower cookie scoped to
the parent domain — and that only works if there is one:

| Issuer | Protected app | `SIGNARI_PROXY_COOKIE_DOMAIN` | |
|---|---|---|---|
| `auth.example.com` | `n8n.example.com` | `example.com` | works |
| `auth.example.com` | `n8n.other.com` | — | no shared parent: see [a cookie of its own](#an-application-on-another-domain) |
| `auth.localhost` | `n8n.localhost` | `localhost` | works (local development) |
| `localhost:9443` | `127.0.0.1:8080` | — | different hosts, not parent/child |

`signari proxy cookie -org <uuid> -host <h> -cookie <domain>` gives one host a parent
of its own instead of the deployment's, and it must cover the issuer too. A browser
refuses a cookie for a domain the address setting it is not under, so that is refused
at sign-in by the same check.

Get this wrong and the browser loops forever: the proxy says 401, Signari sets a
cookie the app's host will never receive, redirects back, the proxy says 401
again. Nothing logs an error, because nothing is wrong from any single
component's point of view.

Signari refuses this at `/proxy/start` rather than letting you find it:

```
the proxy cookie is scoped to "localhost", which "127.0.0.1" is not under, so
the browser would never send it back and would loop between the proxy and here
forever.
```

**2. Every protected host must be registered.** `rd` comes from a header the
proxy set from the original request, so it is attacker-influenced. An allow-list
is used rather than a "same domain" pattern, because a hostname an attacker
controls under your domain would satisfy a pattern.

```sh
signari proxy add-host -org <org-uuid> -host n8n.example.com
signari proxy list
signari proxy disable-host -org <org-uuid> -host n8n.example.com   # or enable-host, remove-host
```

The same is `PUT /admin/organizations/{orgID}/proxy-hosts` in the
[admin API](admin-api.md), and `proxy_hosts:` in a
[configuration file](config-as-code.md). Each change is audited and bumps the
configuration version.

The host is written as the browser sends it, **including a non-default port**
(`n8n.example.com:8443`). It is lower-cased, and a scheme, path or query is
refused rather than guessed at. Until these commands existed, raw SQL was the
only way to register a host, and nothing in the product could. Every
deployment that followed the documentation as far as the CLI therefore stopped
at the sign-in page: the person authenticated, and was then told the
application they came from was not a registered protected host.

A host belongs to **one organisation in the whole deployment**. Registering a
host that another organisation already protects is refused: `409 host_taken`
from the admin API, and an error from the CLI and from `signari apply`. The
verify endpoint lets in people from the organisation that registered the host.
When two organisations could both register it, the second one's administrator
could let their own people into the first one's application, with identity
headers carrying whatever the second organisation said about them.

**3. Identity headers must come from the auth response, never from the client.**
This is the classic forward-auth vulnerability. If the proxy passes the client's
`X-Forwarded-User` through, anyone can claim to be anyone by setting a header.

Signari sends **all three** identity headers on every `200`, taken from the
verified token, and sends `X-Forwarded-Email` **empty** when the account has no
address. The empty header matters. Suppose a proxy copies a header from the
auth response only when the response carries it. If the header were left out,
the client's own `X-Forwarded-Email` would reach the application unchanged, and
a person with no address on record could claim any address. Check your proxy's
behaviour rather than relying on either assumption. This page used to say Signari "deletes those headers before doing
anything else". The code did delete them, but from its own empty response, so
nothing was protected. The proxy must still read the headers from the auth
response, which is what `auth_request_set` does below.

## nginx

Verified end to end against nginx 1.31: anonymous request redirected to sign-in,
signed-in request served, forged `X-Forwarded-User` overridden with the real
subject, and access refused again after logout.

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

Both hand a refusal from the auth server to the browser as it is: the status,
the `Location` and the body. A browser follows `Location` only on a redirect,
so the `401` that nginx's recipe above turns into one leaves a Traefik or Caddy
user on a blank error page, signed in to nothing. `/proxy/verify/redirect`
answers a browser loading a page (`GET` or `HEAD`, accepting `text/html`) with
`302` to sign in, and keeps the `401` for everything else, so an API client is
not handed a redirect to a page it cannot use. Until October 2026 these recipes
pointed at `/proxy/verify`, and `proxy check` passed them.

Both recipes below were run end to end in November 2026, in Traefik 3.1 and
Caddy 2.8 in front of an application that prints what it receives. An anonymous
page load was sent to sign in and an API call refused with `401`. After sign-in
the application received the person's identity headers. A forged
`X-Forwarded-User` from the client was replaced with the real one, and
`signari proxy check` found nothing open. Check yours with `signari proxy check`,
whose browser probe fails a set-up that strands a browser on the `401`.

### Traefik

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

Envoy's `ext_authz` filter, over HTTP. It relays a refusal to the browser as
Traefik and Caddy do, so it too points at `/proxy/verify/redirect`, with two
differences, measured against Envoy 1.31. Envoy adds the request's own path and
query to that path, asking at `/proxy/verify/redirect/dashboard?tab=1`. It also
asks with the request's own method. Signari answers anything below the path,
by any method, and reads what is asked about from the `X-Forwarded-*` headers,
which Envoy is told to set because it sets none of its own. Run end to end like
the two above, with the same results.

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

`signari` is a cluster for Signari's address, with an `UpstreamTlsContext` whose
`sni` is its host name. `allowed_headers` belongs on `ExtAuthz` itself: Envoy
1.31 still takes it inside `authorization_request` and warns that it is going.

## Prove it works

Configuration that looks right is not the same as configuration that works, and
the browser gives you no way to tell the difference: you see a login page, so
you assume you are covered.

```sh
signari proxy check \
  -app     https://n8n.example.com \
  -issuer  https://auth.example.com \
  -origin  http://127.0.0.1:5678      # the app's own address
```

It probes as an anonymous attacker would, exits non-zero on any finding, and
needs no database — run it from CI, or from outside the network, which is where
the answer actually matters. It looks for:

- **paths that slipped through** — a rule on `/` does not cover `/rest` or
  `/webhook`, and those are how the application is really driven
- **method bypasses** — auth written as a GET-only condition leaves writes open
- **identity-header injection** — a request that merely *claims* to be a user
- **direct-to-origin bypass** — the app still listening on its own port, which
  makes everything else in the report irrelevant

A clean run is evidence, not a guarantee. It covers the paths and methods listed
in the output, from wherever it ran — nothing more, and the command says so.

## Who may reach which application

A valid proxy cookie is not enough. On every request the verify endpoint
checks three things:

1. **The host is one of the signed-in person's organisation's protected hosts,
   and it is enabled.** The host comes from `X-Forwarded-Host`, which the proxy
   must send (the configurations below do). If a person from another
   organisation, an unregistered host or a disabled host is involved, or no
   host is named, the answer is `403` and no identity headers are sent.
2. **The access policy allows it**, keyed `proxy:<host>` the way a relying party
   is keyed by its client ID. So a rule like

   ```yaml
   policies:
     - name: payroll-is-for-finance
       when: {client: "proxy:payroll.example.com"}
       require: {groups: [finance], mfa: true}
   ```

   decides who reaches that application. A refusal is `403`, with the rule's
   message in `X-Signari-Reason`.
3. **Network, device and travel conditions are treated as unknown, so they
   refuse.** The request that reaches the verify endpoint comes from the proxy,
   so its address is the proxy's own. A `from_networks` rule checked against it
   would let everybody in from inside the office the proxy sits in. Until
   October 2026 this held for the network and device conditions only. The
   travel condition read the missing address as "not checked", counted that as
   met, and let everybody through.

`403` and not `401`: the person is signed in and may not reach this
application. A `401` would send them back to sign in, the IdP would let them
through, and they would arrive here again in a loop.

Until October 2026 none of this was checked. Anyone who could sign in anywhere
in the deployment passed every protected host of every organisation.

## An application on another domain

A cookie can only be set for a domain the address setting it is under, so the issuer
cannot set one for an application on a domain they do not share. That application can
keep a cookie of its own, set on its own address:

```sh
signari proxy cookie -org <uuid> -host n8n.other.com -cookie own
```

Its proxy has to route one more path to Signari, sending the application's name in
`X-Forwarded-Host`. On nginx, alongside the `location` blocks below:

```nginx
location /.signari/ {
    proxy_pass              https://auth.example.com;
    proxy_ssl_server_name   on;
    proxy_set_header Host             auth.example.com;
    proxy_set_header X-Forwarded-Host $http_host;
}
```

The sign-in then goes:

1. The proxy asks about a request with no cookie. The answer sends the browser to
   `https://n8n.other.com/.signari/proxy/begin`, not to the issuer.
2. That sets a state cookie on the application's address and sends the browser to
   the issuer, carrying the state.
3. The issuer signs the person in as ever, and sends them back to
   `/.signari/proxy/callback` with a code that lasts a minute, for this host and this
   state.
4. There the code is held to the state in the browser, the host, and a session that is
   still live. The proxy cookie is set on the application's address alone and the
   browser goes back to the page it asked for.

The state is why step 2 exists. A code in a URL works for whoever opens it, so without
it somebody could sign in, stop at the callback, and send the link to somebody else,
who would then be using the application as them, and telling it things. The code is
good only in the browser that started the sign-in.

A cookie set this way names its application, and is refused at any other, the same
organisation's included. Everything else is as it was: the session is checked on every
request, so signing out at the issuer ends it, and it needs signing in once per
application instead of once per parent domain. Registering a host this way changes
what its proxy has to do, so do the two together: until `/.signari/` is routed, the
person is sent to a page the application does not have.

## Rules for one path

A host protects every path alike until it has rules. They are for what that does not
fit: a health check that must answer anybody, a metrics path nothing outside should
reach, a console held to more than the rest.

```
# rules.txt: the first that matches decides
public GET,HEAD /static/**
public *        /health
deny   *        /metrics/**
auth:console *  /console/**
```

```sh
signari proxy rules -org <uuid> -host grafana.example.com -file rules.txt
signari proxy rules -org <uuid> -host grafana.example.com          # show them
```

The same is `"rules"` on `PUT /admin/organizations/{orgID}/proxy-hosts` and `rules:`
under `proxy_hosts:` in a [configuration file](config-as-code.md). Each replaces the
whole list, because the order is what it means, and an empty list clears it.

| Effect | |
|---|---|
| `public` | Nobody has to be signed in. The application is told of nobody, even when somebody is: every identity header is sent empty |
| `deny` | `403` for everybody, signed in or not |
| `auth` | What every path no rule names gets, written out to take a path back from a wider rule after it, or with `:name` to hold it to more |

A path is matched whole. `*` stands for anything within one segment, and `**`, alone in
a segment, for any number of them, none included: `/static/**` matches `/static`,
`/static/` and `/static/js/app.js`, and not `/staticfiles`.

`auth:console` gives a path an access policy of its own, keyed `proxy:<host>#console`,
on top of the host's:

```yaml
policies:
  - name: the-console-needs-a-second-factor
    when: {client: "proxy:grafana.example.com#console"}
    require: {groups: [ops], mfa: true}
```

### A path that could mean two things is refused

The rule is checked here and the path is served by the application, which decides for
itself what a path means. Where the two differ, a rule is a way past the check:
`/static/../metrics` matches `/static/**` here and is `/metrics` there. So on a host
with rules, these are refused with `403`, signed in or not, and never compared:

- a dot segment, spelled out or encoded (`/a/../b`, `/a/%2e%2e/b`)
- an empty segment (`//admin`)
- an encoded slash or backslash, and a plain backslash
- a path parameter (`/a;x/b`)
- anything still encoded once decoded (`/a/%252e`)

Behind the nginx, Traefik, Caddy and Envoy configurations on this page, each of those, sent
as it is spelled here, was refused before the application saw it, signed in or not.
Envoy's `normalize_path` resolves some first, and then sends the resolved path to the
engine and the application alike, so the two still judge one path.

An application whose paths really look like that cannot have rules on the host. Three
things are still yours to get right. A path is compared with its case, so an
application that does not care about case has to be given every spelling a `deny`
should cover. A path is compared with its trailing slash too: `deny * /metrics` leaves
`/metrics/` open, which many applications serve as `/metrics`, so a `deny` is written
`/metrics/**`, which is both and everything below. This page's example said
`/metrics` until November 2026, when running it behind real proxies showed `/metrics/`
reaching the application. And a rule is only as good as what the proxy says: with rules on a host,
a proxy that sends no `X-Forwarded-Uri` is refused rather than guessed at. One that
sends no `X-Forwarded-Method` has every rule naming methods read the strict way: a
`public` one does not apply, and a `deny` one does. The configurations below send both.

Rules are read on every request and take effect on commit. A disabled host opens
nothing, whatever its rules say, and a host is held by one organisation, so no tenant
can write rules for another's application.

## What the app receives

| Header | Contents |
|---|---|
| `X-Forwarded-User` | the user's uuid |
| `X-Forwarded-Sub` | the same uuid, for apps expecting `sub` |
| `X-Forwarded-Email` | the email, or **empty** when the account has none — present either way, so a client-sent copy is overwritten |
| `X-Forwarded-Groups` | the groups released to this application that the person is in, comma-separated, or **empty** |
| `X-Forwarded-Jwt` | a signed statement of the above, or **empty** |

The user id is sent rather than the email because an email can change and can be
reassigned; the uuid is the stable identity.

### Groups and a signed identity

Nothing about groups is sent until you say which an application may hear of,
because a group's name says something about a person:

```sh
signari proxy release -org <uuid> -host grafana.example.com -groups admins,viewers
signari proxy release -org <uuid> -host grafana.example.com -signed-identity on
```

Each flag keeps what the other set. `-groups ""` releases none. A name holding a
comma is refused, since the header is a comma-separated list.

The headers are only as good as the network between the proxy and the application:
anything that reaches the application directly can send them itself. With
`-signed-identity on`, `X-Forwarded-Jwt` carries a JWT the application can check for
itself against this issuer's keys:

```json
{"iss": "https://id.example.com", "aud": "https://grafana.example.com",
 "sub": "7c1e…", "email": "ada@example.com", "groups": ["admins"],
 "iat": 1793440000, "exp": 1793440060}
```

Check the signature against `jwks_uri`, that `typ` is `proxy-identity+jwt`, that
`iss` and `aud` are what you expect, and `exp`. It lasts a minute and is made afresh
for every request, so it is proof of this request and not something to keep.

## Programs: an access token instead of a cookie

A script or a service has no browser to sign in with. When a request carries no
proxy cookie and does carry `Authorization: Bearer`, that token is checked instead:

```sh
signari resource add -org <uuid> -resource https://app.example.com

curl -H "Authorization: Bearer $TOKEN" https://app.example.com/report
```

The token's `aud` has to be `https://<the host>`, so ask for it with
`resource=https://app.example.com`. A token for anything else is refused, and that
includes one for the client itself or for another protected host. What ends a token
ends it here on the next request: revoking it, revoking its grant, ending its
session, deactivating the person or disabling the client.

After that it goes through the same decision as a cookie: the host has to be one of
the organisation's, enabled, and the access policy has to allow it. A
`client_credentials` token passes as its client, so `X-Forwarded-User` is the client
id and `X-Forwarded-Email` is empty; to a policy it is a client in no groups, so a
rule requiring a group or a second factor refuses it.

A cookie decides when both arrive, because the application behind the proxy may use
`Authorization` for something of its own. A sender-constrained token, DPoP or
certificate-bound, is refused: what proves it is bound to the application's address
and only the application could check that, so a proxy would be taking it on trust.
Your proxy has to pass `Authorization` to `/proxy/verify`, which nginx's
`auth_request` does unless it has been told not to.

## Session lifetime

The proxy cookie lasts 30 minutes and is refreshed by the flow, but **the live
session is rechecked on every single request**. Signing out of Signari revokes
proxy access immediately — forward auth cannot be used to outlive a logout,
which is the failure this project spent a day making visible elsewhere.

The recheck also reads the person: a session whose person is no longer active
is refused, whichever path deactivated them. The check used to read only the
session row, so a deactivation that ended no session, such as a SCIM PUT with
`"active": false`, left the proxy cookie working for the rest of its 30 minutes.
