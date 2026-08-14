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
| `auth.example.com` | `n8n.other.com` | — | impossible, no shared parent |
| `auth.localhost` | `n8n.localhost` | `localhost` | works (local development) |
| `localhost:9443` | `127.0.0.1:8080` | — | different hosts, not parent/child |

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

```sql
INSERT INTO core.proxy_hosts (org_id, host, enabled)
VALUES ('<org-uuid>', 'n8n.example.com', true);
```

The host is stored exactly as the browser sends it, **including a non-default
port** (`n8n.example.com:8443`).

**3. Identity headers must come from the auth response, never from the client.**
This is the classic forward-auth vulnerability. If the proxy passes the client's
`X-Forwarded-User` through, anyone can claim to be anyone by setting a header.

Signari deletes those headers before doing anything else, then sets them itself
from the verified token — but that only protects its half. The proxy must be
configured to read them from the auth response, which is what
`auth_request_set` does below.

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
        proxy_set_header X-Forwarded-User  $signari_user;
        proxy_set_header X-Forwarded-Email $signari_email;
        proxy_set_header X-Forwarded-Sub   $signari_sub;

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

## Traefik

Not verified end to end here — the shape is standard, but check it with
`signari proxy check` before trusting it.

```yaml
http:
  middlewares:
    signari:
      forwardAuth:
        address: https://auth.example.com/proxy/verify
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

## Caddy

```caddyfile
n8n.example.com {
    forward_auth auth.example.com {
        uri /proxy/verify
        copy_headers X-Forwarded-User X-Forwarded-Email X-Forwarded-Sub
    }
    reverse_proxy n8n:5678
}
```

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

## What the app receives

| Header | Contents |
|---|---|
| `X-Forwarded-User` | the user's uuid |
| `X-Forwarded-Sub` | the same uuid, for apps expecting `sub` |
| `X-Forwarded-Email` | the email, when the account has one |

The user id is sent rather than the email because an email can change and can be
reassigned; the uuid is the stable identity.

## Session lifetime

The proxy cookie lasts 30 minutes and is refreshed by the flow, but **the live
session is rechecked on every single request**. Signing out of Signari revokes
proxy access immediately — forward auth cannot be used to outlive a logout,
which is the failure this project spent a day making visible elsewhere.
