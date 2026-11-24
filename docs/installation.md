# Installation

## Introduction

Signari is one program, `signari`, and one PostgreSQL database. Installing it
means putting the program on a server, preparing the database, and creating the
first organisation and the first person who can sign in.

One command does all of that. It works out what it can by itself. It asks you only
what it cannot know, such as the address people will sign in at. If you run it
again, it skips whatever is already done.

> [!NOTE]
> To try Signari on your own computer before you install it on a server, follow
> [Your first application](first-application.md) instead. It needs only Docker.

## Installing on a server

On a Linux server, run the installer:

```sh
curl -fsSL https://signari.dev/install | sh
```

The installer downloads the `signari` program, checks it, and then runs
`signari setup`, which asks its questions and does the work.

### What it asks

It asks only what it cannot detect, in this order:

1. The address people will use to sign in, such as `https://login.example.com`.
   This becomes the "issuer", the address every token Signari makes carries.
   Choose it carefully, because applications refuse tokens from any other
   address.
2. The first administrator's email address.
3. For an `https://` address, who ends Transport Layer Security (TLS). See
   [Who ends TLS](#who-ends-tls).
4. Which PostgreSQL to use. If one is running on the same machine, it is found
   for you. Otherwise, give a connection URL for a PostgreSQL role that can
   create roles.
5. Whether to go ahead with the plan it shows you.

### Who ends TLS

People reach an `https://` address over TLS, the encryption HTTPS is made of. Either
a reverse proxy in front of Signari ends TLS, or Signari serves HTTPS itself.
Setup looks at the machine first, and offers what it finds:

- When a program already listens on port 443 or 80, setup takes it to be a
  proxy and offers `proxy`.
- When Let's Encrypt has a certificate for the address's host, in
  `/etc/letsencrypt/live`, setup offers `files`.
- Otherwise, it offers `proxy`.

With `proxy`, Signari listens on `127.0.0.1:8080` in plain HTTP. It believes the
`X-Forwarded-For` header from the proxies `-trusted-proxies` names, which is
`127.0.0.1` and `::1` unless you say otherwise. Point the proxy at that address.

With `files`, Signari serves HTTPS itself on port 443 with the certificate and
key you give, `-tls-cert` and `-tls-key`. Setup refuses a certificate whose key
is not its own, which does not name the host, or which has expired. It warns
when one expires within 14 days.

Signari reads its certificate only when it starts. For a Let's Encrypt
certificate, setup copies the certificate and key into `/etc/signari/tls/` for
the service, and installs a certbot hook. After each renewal, the hook copies
the new certificate and restarts the service. When you give files of your own,
restart the service after you renew them.

With `none`, setup writes no TLS setting. Signari serves plain HTTP until you add
a certificate or a proxy.

You can answer in advance, for example for a proxy on another machine:

```sh
signari setup -tls proxy -trusted-proxies 10.0.0.5
```

### What it does

Once you agree to the plan, it does these steps in order:

1. Runs its pre-flight checks: the checks it makes before it changes anything.
2. Creates the database.
3. Applies migration 0001 as the PostgreSQL superuser. This creates Signari's
   database roles, including `signari_engine`.
4. Gives `signari_engine` a newly generated password. From then on, the server
   runs as `signari_engine`, never as a superuser.
5. Applies the remaining migrations as `signari_engine`.
6. Generates the "root key", the secret that encrypts everything sensitive
   Signari stores. It writes the key to a file that only its owner can read:
   `/etc/signari/root.key` when run as root, and a file under
   `~/.config/signari/` otherwise.
7. Creates the instance, the organisation, and a one-time link for the first
   administrator. The link works for 72 hours.
8. Writes the settings `signari serve` needs to an environment file,
   `/etc/signari/signari.env`.
9. Prints a summary of what it did.

It is safe to run again. A step that is already done is skipped, so a second run
after an interruption finishes the job without repeating it.

The superuser's credentials are never stored. The environment file holds the
`signari_engine` role's connection, not the superuser's.

### What it records

Each run of setup adds a record of what it did to a log file. When a run fails,
setup prints the last 15 lines of the log and where it is. Read the whole log to
see every earlier run as well:

```sh
less /var/log/signari/setup.log
```

In this example, the log is the one root's runs write. When you run setup as
yourself, the log is `~/.local/state/signari/setup.log`, or under
`$XDG_STATE_HOME/signari` when that is set. `-log-file` names another.

Each run starts with a header line. It gives the time, the release, who ran
setup and on which machine, and the flags it was given. Then there is one line
for each step: `done`, `skip`, `wait` or `fail`, how long the step took, and what
it did or found.

The log holds no secret, and only its owner can read it. The database
passwords, the root key and the token in the first administrator's link are
each written as `…`. A dry run and `-check` change nothing, so they add nothing
to the log.

The installer keeps its own log beside setup's, `install.log`. It records the
release it chose, the checks it made and what it installed.

### How downloads are checked

The installer downloads the release program and its `SHA256SUMS` file, and
refuses a program whose SHA-256 checksum does not match. When `cosign` is
installed, it also checks the release's Sigstore signature, which proves the
program was built and signed by Signari's own release workflow.

Run as root on a machine with systemd, it also installs a `signari` service, so
the server starts on boot. You can check it is running:

```sh
systemctl status signari
```

### Platforms

Release programs exist today for Linux on x86-64 only. On any other platform,
the installer offers to use Docker or to build Signari from source instead.
Both are described below.

## Answering without questions

For automation, such as a provisioning script, give the installer every answer
at once. With `--yes`, it never stops to ask:

```sh
curl -fsSL https://signari.dev/install | sh -s -- --yes --issuer https://login.example.com --email you@example.com
```

If you already have the `signari` program, you can run its setup yourself. It
asks only what it cannot detect, as above:

```sh
signari setup
```

With `-yes` and the two answers it cannot detect, it never asks anything:

```sh
signari setup -yes -issuer https://login.example.com -email you@example.com
```

To see the plan without changing anything, add `-dry-run`. It prints every step
it would take, and stops:

```sh
signari setup -dry-run
```

To see what is already set up on this machine, use `-check`:

```sh
signari setup -check
```

## With Docker

The Signari repository includes a Docker Compose file, `deploy/docker-compose.yml`,
for running Signari on one computer. It builds Signari from source, and starts
PostgreSQL beside it. You need Docker with Compose version 2.

Start the server and its database, and create the first organisation and person:

```sh
git clone https://github.com/Binary-ly/signari.git
cd signari/deploy
export SIGNARI_ROOT_KEY=$(head -c 32 /dev/urandom | base64) SIGNARI_FIRST_EMAIL=you@example.com \
  SIGNARI_TLS_CERT=/tls/engine.crt SIGNARI_TLS_KEY=/tls/engine.key
docker compose --profile first-run up -d
```

The one-time link for the first person is in the log of the `bootstrap` service:

```sh
docker compose logs bootstrap
```

The compose file groups its services into "profiles", which you turn on with
`--profile`. Without one, it starts only the database and the server:

| Profile | Starts | Address |
|---|---|---|
| none | PostgreSQL, the migrations, and the Signari server | `https://localhost:8099` |
| `first-run` | A first run: the instance, the organisation and the one-time link | |
| `console` | The web console for administrators | `http://localhost:8098/admin` |
| `demo` | Six example applications to sign in to | `http://localhost:8097`, and ports 8091 to 8095 |

The `console` profile needs an Admin API token and an administrator account
first. [Deployment artefacts](deployment-artefacts.md) gives the commands.

> [!WARNING]
> This compose file is for trying Signari, not for production. Its TLS
> certificate's private key is published in the repository, so anyone can
> impersonate it. Use the installer or the [Helm chart](deployment-artefacts.md)
> for a real deployment.

Keep the value of `SIGNARI_ROOT_KEY` you exported. The server needs the same key
every time it starts.

## From source

You can build `signari` yourself on Linux or macOS. You need Go 1.26.11 or later,
and git.

Build the program from the repository:

```sh
git clone https://github.com/Binary-ly/signari.git
cd signari/engine
go build -o signari ./cmd/signari
```

Check what you built. `signari version` prints the release, the Go version, and
the database schema version the program expects:

```sh
./signari version
```

Then run its setup, which asks its questions and does the rest, as on a server:

```sh
./signari setup
```

## What you have now

After a successful setup, you have:

- a PostgreSQL database holding Signari's tables, with the `signari_engine` role
  that the server runs as;
- the root key, in a file only its owner can read;
- the server's settings, in `/etc/signari/signari.env`;
- an instance whose issuer is the address you chose, with its first signing keys;
- one organisation, with no people in it yet;
- a one-time link for the first administrator, good for 72 hours.

Open the link in a browser and choose a password. That makes the first account.
The link works once. Running setup again before anyone has used it prints a new
one.

People must reach Signari over HTTPS, because the issuer is an `https://`
address. The summary's `TLS` line says what setup chose, and what is left for
you to do. For a proxy, see
[behind a reverse proxy](configuration.md#behind-a-reverse-proxy) for the
settings it needs.

To check that the deployment is sound, run `signari doctor` with the same
settings the server uses. It lists anything wrong, with how to fix it. See
[doctor](doctor.md).

## Back up the root key

The root key encrypts every secret Signari stores: its signing keys, the secrets
behind people's authenticator apps, RADIUS secrets and directory passwords.
Signari never stores the root key in the database it protects. A database backup
that contained its own key would protect nothing.

That design has a cost. The database and the root key are one backup, and
neither is any use without the other.

> [!WARNING]
> Lose the root key, and every secret Signari sealed with it is gone for good.
> No token it signed can be checked, and every authenticator app stops working.
> Keep a copy of the key outside the server today, beside your database backups.

Keep a second copy somewhere a database failure cannot reach, such as a password
manager. [Backup and restore](runbook-backup-restore.md) explains how to back up
the key and the database together, and how to test a restore.

## Next steps

- [Your first application](first-application.md): register an application and
  sign in to it.
- [How Signari works](how-signari-works.md): what an instance, an organisation
  and an application are.
- [Configuration](configuration.md): every setting the server reads.
- [Upgrading](upgrading.md): moving to a new release.
- [Running more than one instance](high-availability.md), when one server is not
  enough.
