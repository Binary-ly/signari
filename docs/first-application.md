# Your first application

## Introduction

The quickest way to understand an identity provider is to watch one work. In this
tutorial you start Signari on your own computer, with an example application
beside it, and sign in to that application through Signari.

You will not install anything except what Docker downloads, and you will not
make any choices. At the end, the application says who you are. Then you
register an application of your own, ready for one of the framework guides.

> [!NOTE]
> You need Docker, with `docker compose`, and git. Ports 8091 to 8095, 8097 and
> 8099 on your computer must be free.

## 1. Start Signari and the example applications

Download the Signari repository and go to its `deploy` folder:

```sh
git clone https://github.com/Binary-ly/signari.git
cd signari/deploy
```

> [!NOTE]
> The example applications use Docker's host networking, so they reach Signari at
> the same address your browser does. Docker Desktop supports it from version
> 4.34, once you turn it on. Sign in to your Docker account in Docker Desktop
> first. Then turn on **Enable host networking** under **Settings**,
> **Resources**, **Network**, and press **Apply and restart**. Docker Engine on
> Linux needs no setting.

Write Signari's settings to a file called `.env` in this folder, where
`docker compose` reads them. Use your own email address in place of
`you@example.com`:

```sh
cat > .env <<EOF
SIGNARI_ROOT_KEY=$(head -c 32 /dev/urandom | base64)
SIGNARI_FIRST_EMAIL=you@example.com
SIGNARI_TLS_CERT=/tls/engine.crt
SIGNARI_TLS_KEY=/tls/engine.key
EOF
```

In this example, the file sets four settings:

- `SIGNARI_ROOT_KEY` is a new random "root key", the secret Signari encrypts its
  own keys with;
- `SIGNARI_FIRST_EMAIL` is the address of the first person who may sign in;
- `SIGNARI_TLS_CERT` and `SIGNARI_TLS_KEY` let Signari serve HTTPS, with a
  certificate made for development.

Keep the file. Signari cannot read its own keys under a different root key, so
every later start needs this one.

Start Signari, its database and the example applications:

```sh
docker compose --profile first-run --profile demo up -d
```

The first time, Docker builds Signari and six example applications from source.
That can take several minutes.

Signari runs at `https://localhost:8099`. The example applications run at
`http://localhost:8097` and on ports 8091 to 8095.

## 2. Accept the development certificate

Signari serves HTTPS with a certificate made for development, signed by a
certificate authority in `deploy/tls/ca.crt`. Your browser does not know that
authority, so the first time you open `https://localhost:8099` it warns you that
the connection is not private.

For this tutorial it is safe to go on, because `localhost` is your own computer.
Each browser words it differently:

- in Chrome, press **Advanced**, then **Proceed to localhost (unsafe)**;
- in Edge, press **Advanced**, then **Continue to localhost (unsafe)**;
- in Firefox, press **Advanced**, then **Accept the Risk and Continue**;
- in Safari, press **Show Details**, then **visit this website**.

Your browser makes an exception for this one certificate at this one address.
The example applications need no exception, because each is given
`tls/ca.crt` to trust.

If your browser offers no way to go on, another project has left it a rule to
accept only trusted certificates for `localhost`. In Chrome, delete that rule:
open `chrome://net-internals/#hsts` and enter `localhost` under **Delete domain
security policies**.

> [!WARNING]
> Do not add `tls/ca.crt` to your computer's trusted authorities. Its private key
> was made on another computer, so whoever holds that key could then pose as any
> website to yours. The development certificate's own key is in the repository,
> so use it only for this tutorial. A real server needs a certificate of its own,
> as [Installation](installation.md) describes.

## 3. Create your account

Signari has made an organisation with nobody in it, and a one-time link for the
first person. Show the link:

```sh
docker compose logs bootstrap
```

Among the lines it prints, after the name of the service, is a message like this
one:

```text
The first person, you@example.com, finishes setting up here, once, within 72h0m0s:

  https://localhost:8099/signup?invite=...
```

Open the link in your browser. The page is called **Create your account**. Choose
a password of at least 15 characters, such as four unrelated words, and press
**Create account**. The next page says that your address can now sign in.

## 4. Sign in to the example application

Open the example application:

```text
http://localhost:8097/login
```

Your browser goes to Signari's **Sign in** page, at `https://localhost:8099`.
Under **Username or email**, enter your email address. Enter the password you
chose, and press **Sign in**.

Signari then asks whether the **Demo application** may have access to your
account. Press **Allow**.

Your browser goes back to the application, which says:

```text
Signed in as you@example.com.
```

That is a real sign-in. The application never saw your password. It learned
your email address from an "ID token", a signed statement from Signari about who
you are. Before it believed the token, it checked Signari's signature, that the
token was meant for it, and that it had not expired.

## What happens when you click Sign in

Every application that signs people in with OpenID Connect does it the same way.
In short, the application sends you to Signari, and you prove who you are. Signari
sends you back with a code, and the application swaps the code for tokens.

Here is each step, as it happened in the example application:

1. You opened `http://localhost:8097/login`. The application made up three
   random values for this one sign-in: a "state", a "nonce" and a "verifier". It
   kept all three.
2. The application sent your browser to Signari's address for sign-in,
   `https://localhost:8099/oauth2/authorize`. With it went the application's
   client ID, `demo`, and its redirect URI, `http://localhost:8097/callback`. The
   state, the nonce and a hash of the verifier went too.
3. Signari checked that it knew the client ID `demo`, and that the redirect URI
   was exactly one registered for it. Had either been wrong, Signari would have
   stopped here and shown an error, without sending your browser anywhere.
4. Signari asked who you are, and you gave your password. Signari started a
   "session", so that it need not ask you again for a while.
5. Signari asked whether to allow the Demo application, and you allowed it.
6. Signari sent your browser back to the redirect URI, with the state and a
   one-time "authorization code". The code works once, for 60 seconds.
7. The application checked that the state was the one it made in step 1. Then,
   from its own server and not through your browser, it sent the code and the
   verifier to Signari's token address, `https://localhost:8099/oauth2/token`.
8. Signari checked that the code was issued to `demo` and not used before, and
   that the verifier matched the hash from step 2. It answered with tokens,
   among them the ID token.
9. The application checked the ID token's signature against the keys Signari
   publishes. It checked the token's issuer, that it was issued to `demo`, its
   expiry, and the nonce from step 1. Then it showed your email address, which
   the token carries as a "claim".

The verifier is what makes this safe for an application that has no secret. An
attacker who sees the code in step 6 cannot use it, because only the application
holds the verifier. This check is called Proof Key for Code Exchange (PKCE).
Signari requires it of every application by default.

[How Signari works](how-signari-works.md) explains sessions, tokens and claims in
more detail.

## 5. Register an application of your own

The example applications were registered for you, from the file
`deploy/demo/client.yaml`. The first entry looks like this:

```yaml
version: 1
clients:
  - client_id: demo
    name: Demo application
    public: true
    redirect_uris: [http://localhost:8097/callback]
```

You can also register an application with one command. Signari's commands call
an application a "client", which is the protocols' word for it. Register one
called `my-first-app`:

```sh
docker compose exec engine /signari client create -client-id my-first-app \
  -name "My first application" -redirect http://localhost:8090/callback
```

In this example:

- `-client-id` is the name the application gives when it talks to Signari;
- `-name` is the name people see when Signari asks them to allow it;
- `-redirect` is the address Signari sends people back to. It must match exactly,
  so `http://localhost:8090/callback/` with a final slash is a different address.

Signari answers with the registration, and a secret:

```text
client my-first-app (confidential)
  redirect_uri http://localhost:8090/callback
  client_secret ...
  (shown once)
```

The application must send that secret to prove it is itself. It is shown only
once, so copy it now. An application that runs in a browser or on a phone cannot
keep a secret. Register that kind with `-public`, and it relies on PKCE alone.

The client ID, the secret and the redirect URI are the three values every
framework guide asks you for. Signari's address, `https://localhost:8099`, is the
fourth.

## 6. Sign in to the others

The same command started five more example applications, one for each framework
guide. Each one signs you in the way you have seen:

| Framework | Open | Guide |
|---|---|---|
| Express | `http://localhost:8091/login` | [Express](quickstart-express.md) |
| Next.js | `http://localhost:8092/login` | [Next.js](quickstart-nextjs.md) |
| Django | `http://localhost:8093/login/` | [Django](quickstart-django.md) |
| Spring Boot | `http://localhost:8094/`, then **Sign in with Signari** | [Spring Boot](quickstart-spring.md) |
| Laravel | `http://localhost:8095/login` | [Laravel](quickstart-laravel.md) |

This time Signari does not ask for your password. You still have a session with
Signari from step 4, so it only asks you to allow each new application. That is
single sign-on.

## 7. Stop when you are done

Stop everything you started:

```sh
docker compose --profile first-run --profile demo down
```

The database is kept for next time, and the root key is kept in `.env`. Start
everything again, in the `deploy` folder, with the command from step 1:

```sh
docker compose --profile first-run --profile demo up -d
```

Signari reads the same root key from `.env`, so it can read its own keys. Your
account is still there, so the bootstrap service prints no new link.

To delete the database as well, add `-v` to the `down` command. Then delete
`.env` too, since its root key has nothing left to open.

## If something goes wrong

The message on the screen comes from Signari or from the application, word for
word. [When an application cannot sign
in](troubleshooting.md#when-an-application-cannot-sign-in) explains the messages
you are most likely to meet, and what to do about each.

## Next steps

- Connect a real application with the guide for its framework: [Go](quickstart-go.md),
  [Express](quickstart-express.md), [Next.js](quickstart-nextjs.md),
  [Django](quickstart-django.md), [Spring Boot](quickstart-spring.md) or
  [Laravel](quickstart-laravel.md).
- Read [How Signari works](how-signari-works.md), now that you have seen it
  work.
- [Install Signari](installation.md) on a server, for people other than you.
