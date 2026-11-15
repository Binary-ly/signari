# Quickstart: a Django application

[examples/django-quickstart](../examples/django-quickstart/quickstart/views.py) signs
people in with Signari from a [Django](https://www.djangoproject.com) application, using
[Authlib](https://authlib.org)'s Django client.

## 1. Register the application

```sh
signari client create -org <org-id> -client-id quickstart -name Quickstart \
  -redirect http://127.0.0.1:8000/callback/
```

It prints the client secret once. Keep it. A redirect URI is matched exactly, the
trailing slash Django's URLs end in included.

## 2. Run it

```sh
cd examples/django-quickstart
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
DJANGO_SECRET_KEY=<a long random value> SIGNARI_ISSUER=https://id.example.com \
  CLIENT_ID=quickstart CLIENT_SECRET=<the secret> REDIRECT_URI=http://127.0.0.1:8000/callback/ \
  ./venv/bin/python manage.py runserver 127.0.0.1:8000
```

Open `http://127.0.0.1:8000/login/`, sign in, and the page says who signed in. The
versions are pinned in `requirements.txt`. `runserver` is Django's development server;
serve it as you serve any Django application. For a certificate your machine does not
trust, give requests the certificate with `REQUESTS_CA_BUNDLE=<file.pem>`.

## In compose

The `demo` profile of `deploy/docker-compose.yml` runs this example from its
[Dockerfile](../examples/django-quickstart/Dockerfile) as `demo-django`, the public client
`demo-django` of [deploy/demo/client.yaml](../deploy/demo/client.yaml), at
`http://localhost:8093/login/`. With the exports the [README](../README.md#quick-start)
gives:

```sh
cd deploy && docker compose --profile first-run --profile demo up -d
```

The image makes a `DJANGO_SECRET_KEY` each time it starts unless it is given one, so
none is built into it. `REQUESTS_CA_BUNDLE` names the engine's own certificate under
`deploy/tls`, not the development CA beside it. Python 3.13 and later hold a CA to RFC
5280, and that CA has no `keyUsage` extension, so requests refuses it with "CA cert does
not include key usage extension". The engine must still present exactly that
certificate, within its dates, for the name `localhost`. A CA made with
`keyUsage = critical, keyCertSign` is trusted as it is.

## What it does, and why each step is there

1. **Discovery.** Authlib reads the document from the configured issuer, and holds the
   ID token to the issuer that document names. It does not compare that issuer with
   the one configured, so `/login/` does, and refuses a document naming another.
2. **The redirect out.** `authorize_redirect` makes the `state`, `nonce` and PKCE
   verifier (`code_challenge_method` `S256`, which Signari requires of every client)
   and keeps them in the session. The session is a signed cookie, so the quickstart
   needs no database.
3. **The callback.** `authorize_access_token` takes the state back once and refuses
   one this browser never began. It exchanges the code with the verifier over
   `client_secret_basic`. It checks the ID token's signature against `jwks_uri`, then
   its issuer, audience, expiry and nonce.

A public client has no secret: leave `CLIENT_SECRET` unset, register it with `-public`,
and it authenticates with `none`, PKCE its only proof. The messages a refusal shows are
the server's own; see [troubleshooting.md](troubleshooting.md).

## Verified

On 14 November 2026, with Python 3.14, Django 6.1.3, Authlib 1.9.5 and requests 2.34.2,
against a running engine over TLS. Ada signed in through the engine's pages and the
application said "Signed in as ada@staff.test". The engine's access log showed
`/oauth2/jwks` fetched for the signature. A callback this browser never began was
refused with Authlib's state check.
