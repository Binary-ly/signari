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
curl -fsSL https://raw.githubusercontent.com/Binary-ly/signari/main/scripts/install.sh | sh
```

The installer downloads the `signari` program, checks it, and then runs
`signari setup`, which asks its questions and does the work. Neither of them
starts Signari. You do that once setup has finished, as
[Start Signari](#start-signari) shows.

### What it asks

It asks these questions, in this order. Where it detected an answer, it offers
that one:

1. The address people will use to sign in, such as `https://login.example.com`.
   This becomes the "issuer", the address every token Signari makes carries.
   Choose it carefully, because applications refuse tokens from any other
   address.
2. The first administrator's email address.
3. For an `https://` address, who ends Transport Layer Security (TLS). See
   [Who ends TLS](#who-ends-tls).
4. Which PostgreSQL to use. If one is running on the same machine, it is found
   for you. Otherwise, give a connection URL for a PostgreSQL superuser, such as
   `postgres`.
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

Before it shows you the plan, setup runs its pre-flight checks: the checks it
makes before it changes anything. Once you agree to the plan, it does these
steps in order:

1. Creates the database.
2. Applies migration 0001 as the PostgreSQL superuser. This creates Signari's
   database roles, including `signari_engine`.
3. Generates the "root key", the secret that encrypts everything sensitive
   Signari stores. It writes the key to a file that only its owner can read:
   `/etc/signari/root.key` when run as root, and `~/.config/signari/root.key`
   otherwise.
4. When Signari serves HTTPS itself, settles its certificate. A Let's Encrypt
   certificate is copied into `/etc/signari/tls/`, with a certbot hook for its
   renewals. A port below 1024 gets a setting that lets the service listen
   there. See [Who ends TLS](#who-ends-tls).
5. Writes the settings `signari serve` needs to an environment file:
   `/etc/signari/signari.env` when run as root, and
   `~/.config/signari/signari.env` otherwise.
6. Gives `signari_engine` a newly generated password, and signs in with it. From
   then on, the engine runs as `signari_engine`, never as a superuser.
7. Applies the remaining migrations as `signari_engine`.
8. Creates the instance, the organisation, and a one-time link for the first
   administrator. The link works for 72 hours.
9. Makes the first administrator the organisation's owner, `org-owner`. Until
   they have used the link, they have no account, so this step waits for a
   later run. See [Become the owner](#become-the-owner).
10. Prints a summary of what it did.

When `XDG_CONFIG_HOME` is set, the two files that are otherwise under
`~/.config/signari/` go under `$XDG_CONFIG_HOME/signari/` instead.

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

Run as root on a machine with systemd, the installer also writes a `signari`
service, but does not start it. [Start Signari](#start-signari) shows how.

### Platforms

Release programs exist today for Linux on x86-64 only. On any other platform,
run the installer with `--docker`, or build Signari from source. Both are
described below.

## Answering without questions

For automation, such as a provisioning script, give the installer every answer
at once. With `--yes`, it never stops to ask:

```sh
curl -fsSL https://raw.githubusercontent.com/Binary-ly/signari/main/scripts/install.sh | sh -s -- --yes --issuer https://login.example.com --email you@example.com
```

If you already have the `signari` program, you can run its setup yourself. It
asks the same questions, as above:

```sh
signari setup
```

With `-yes`, it never asks anything, and takes the answer it detected for each
question. Only the first administrator's email has no such answer, so give
`-email`. Give `-issuer` as well, unless the address setup works out is the one
you want. With no PostgreSQL on this machine, give `-superuser-dsn` too:

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

On macOS, on ARM, or on any machine where you would rather use containers, the
installer can run Signari with Docker Compose. You need Docker with Compose
version 2, and git:

```sh
curl -fsSL https://raw.githubusercontent.com/Binary-ly/signari/main/scripts/install.sh | sh -s -- --docker
```

In this example, the installer fetches the release's source and builds the
Signari image from it. That image's `signari setup -compose` then writes a
compose project to `~/signari`, asking what it needs as setup does. The
installer starts the project, waits until it is healthy, and prints the first
administrator's one-time link. `--dir` puts the project somewhere else.

No image is published yet, so the installer always builds one. The build takes a
few minutes the first time.

### The compose project

The project is a directory of four files, each written only when it is missing,
so that running setup again keeps every password:

| File | Holds |
|---|---|
| `compose.yaml` | PostgreSQL 17, a one-shot `setup` service and the Signari server, each with a healthcheck |
| `.env` | The project's settings, and the PostgreSQL superuser's generated password |
| `signari.env` | The engine's settings, with `signari_engine`'s own generated password |
| `root.key` | The root key, mounted read-only into the engine |

The `setup` service is `signari setup` itself, run on every start. It uses the
superuser once, and the engine runs as `signari_engine`. The database is in a
Docker volume, `signari_pgdata`. The engine's port is published on
`127.0.0.1:8080` unless you give another with `--addr`.

You can write a project yourself, where the `signari` program is installed:

```sh
signari setup -compose ~/signari -email you@example.com
```

Then start it from its directory:

```sh
cd ~/signari && docker compose up --detach --wait
```

To see what is set up, run the check, which looks inside the project's own
network:

```sh
signari setup -check -compose ~/signari
```

`signari uninstall -compose ~/signari` stops the project and removes what setup
wrote. It keeps the database's volume, the root key and the files that hold the
passwords, unless you give `-drop-database` and `-delete-root-key`, as in
[Removing Signari](#removing-signari).

### The development stack

The Signari repository also includes a Docker Compose file for development,
`deploy/docker-compose.yml`. It builds Signari from source, and starts
PostgreSQL beside it.

Download the repository, and write the stack's settings to `deploy/.env`, where
`docker compose` reads them:

```sh
git clone https://github.com/Binary-ly/signari.git
cd signari/deploy
cat > .env <<EOF
SIGNARI_ROOT_KEY=$(head -c 32 /dev/urandom | base64)
SIGNARI_FIRST_EMAIL=you@example.com
SIGNARI_TLS_CERT=/tls/engine.crt
SIGNARI_TLS_KEY=/tls/engine.key
EOF
```

Start the engine and its database, and create the first organisation and person:

```sh
docker compose --profile first-run up -d
```

The one-time link for the first person is in the log of the `bootstrap` service:

```sh
docker compose logs bootstrap
```

The compose file groups its services into "profiles", which you turn on with
`--profile`. Without one, it starts only the database and the engine:

| Profile | Starts | Address |
|---|---|---|
| none | PostgreSQL, the migrations, and the engine. On a database with no instance yet, the engine stops at once, so the first start needs `first-run` | `https://localhost:8099`, with `SIGNARI_TLS_CERT` and `SIGNARI_TLS_KEY` set |
| `first-run` | A first run: the instance, the organisation and the one-time link | |
| `console` | The web console for administrators | `http://localhost:8098/admin` |
| `demo` | Six example applications to sign in to, registered from `deploy/demo/client.yaml`. Give `first-run` with it, since their registration waits for the first run | `http://localhost:8097`, and ports 8091 to 8095 |

The `console` profile needs an Admin API token and an administrator account
first. [Deployment artefacts](deployment-artefacts.md) gives the commands.

> [!WARNING]
> This compose file is for trying Signari, not for production. Its TLS
> certificate's private key is published in the repository, so anyone can
> impersonate it. Use the installer or the [Helm chart](deployment-artefacts.md)
> for a real deployment.

Keep `deploy/.env`. The engine needs the same root key every time it starts, and
the file is where `docker compose` finds it.

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
  that the engine runs as;
- the root key, in a file only its owner can read;
- the engine's settings, in `/etc/signari/signari.env`, or in
  `~/.config/signari/signari.env` when you did not run setup as root;
- an instance whose issuer is the address you chose, with its first signing keys;
- one organisation, with no people in it yet;
- a one-time link for the first administrator, good for 72 hours.

Signari is not running yet. Finish in this order: start it, put TLS or a proxy
in front of it, and then open the link.

### Start Signari

The summary's `Start it` line gives the command for this machine. With the
installer's service, run this as root:

```sh
systemctl enable --now signari
```

In this example, `enable` starts Signari each time the machine boots, and
`--now` starts it now as well. Check that it is running:

```sh
systemctl status signari
```

Without the service, load the environment file and run `signari serve`, as the
summary shows. For a setup run as yourself, that is:

```sh
set -a; . ~/.config/signari/signari.env; set +a; signari serve
```

With `--docker`, the installer has started the compose project already.

### Put TLS or a proxy in front

People must reach Signari over HTTPS, because the issuer is an `https://`
address. The summary's `TLS` line says what setup chose, and what is left for
you to do. For a proxy, see
[behind a reverse proxy](configuration.md#behind-a-reverse-proxy) for the
settings it needs.

### Open the link

Open the link in a browser and choose a password of at least 15 characters, such
as four unrelated words. That makes the first account. The link works once, and is stored only as a hash, so nobody can show it again.

If you lose it before it is used, run `signari bootstrap` with the environment
file loaded. It withdraws the old link and prints a new one:

```sh
set -a; . /etc/signari/signari.env; set +a
signari bootstrap -issuer "$SIGNARI_ISSUER" -email you@example.com
```

In this example, the first line loads the settings setup wrote, as root.
`-email` is the first administrator's address, the same one you gave setup.

### Become the owner

The first account can sign in, but holds no role in the organisation yet. Once
the link has been used, run setup again, with the same flags as before:

```sh
signari setup
```

Setup then makes that person the organisation's owner, `org-owner`, which gives
every right in the console and the Admin API. It does this only when the person
is unambiguous: the only account, or the one you name with `-email`. It never
hands the role to anybody once the organisation has an owner. The summary's
`Owner` line also gives the `signari role grant` command that does the same.

### Check the deployment

To check that the deployment is sound, run `signari doctor` with the same
settings the engine uses. It lists anything wrong, with how to fix it. See
[what doctor checks](doctor.md).

## Back up the root key

The root key encrypts every secret Signari stores. These include its signing keys,
the secrets behind people's authenticator apps and directory passwords. They also
include the secrets of Remote Authentication Dial-In User Service (RADIUS)
devices.
Signari never stores the root key in the database it protects. A database backup
that contained its own key would protect nothing.

That design has a cost. The database and the root key are one backup, and
neither is any use without the other.

> [!WARNING]
> Lose the root key, and every secret Signari sealed with it is gone for good.
> No token it signed can be checked, and every authenticator app stops working.
> Keep a copy of the key off this machine today, beside your database backups.

Keep a second copy somewhere a database failure cannot reach, such as a password
manager. [Backup and restore](runbook-backup-restore.md) explains how to back up
the key and the database together, and how to test a restore.

## Removing Signari

The installer and setup each list what they make, as they make it. The list is a
"manifest": a file `signari uninstall` reads to remove exactly those things and
nothing else. It is `/var/lib/signari/install.manifest` when root ran them, and
`~/.local/state/signari/install.manifest` otherwise.

To see what would go, without removing anything:

```sh
signari uninstall -dry-run
```

To remove it, run the command without `-dry-run`. It prints the same plan, and
asks before it removes anything:

```sh
signari uninstall
```

In this example, uninstall stops and disables the service and removes its unit.
It also removes the environment file, the certificate copies, the certbot hook,
the logs, the program and the `signari` system account. A directory goes once it is empty, so a
file you put there yourself keeps it.

### The root key and the database

Uninstall keeps the root key and the database unless you ask for them by name.
Each is one half of the same backup, as [Back up the root key](#back-up-the-root-key)
explains.

To remove both, give `-delete-root-key` and `-drop-database`. At a terminal,
uninstall asks you to type the key file's path and the database's name:

```sh
signari uninstall -delete-root-key -drop-database
```

In this example, uninstall drops the database before it deletes the key. If the
database cannot be dropped, the key stays. The roles setup made in PostgreSQL go
with the database, unless another database still uses them.

With no terminal, such as in a script, give `-yes`. The first run prints a code
and stops. Run it again with the code to go ahead:

```sh
signari uninstall -yes -delete-root-key -drop-database -confirm <code>
```

> [!WARNING]
> Deleting the root key and keeping the database leaves its secrets unreadable
> for good, so uninstall asks you to type a sentence saying so.

What uninstall keeps stays listed in the manifest, so a later run can remove it.

## Next steps

- [Your first application](first-application.md): register an application and
  sign in to it.
- [How Signari works](how-signari-works.md): what an instance, an organisation
  and an application are.
- [Configuration](configuration.md): every setting the engine reads.
- [Upgrading](upgrading.md): moving to a new release.
- [Running several copies of Signari](high-availability.md), when one server is
  not enough.
