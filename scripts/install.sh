#!/bin/sh
# Signari's installer, served as https://signari.dev/install.
#
#   curl -fsSL https://signari.dev/install | sh
#   curl -fsSL https://signari.dev/install | sh -s -- --yes --issuer https://login.example.com --email you@example.com
#
# Read it before you run it. Download it, read it, see what it would do, then
# run it:
#
#   curl -fsSL https://signari.dev/install -o install.sh
#   less install.sh
#   sh install.sh --dry-run        # every command it would run, and none run
#   sh install.sh
#
# What it does, on Linux on amd64, the one platform v0.1.0 has a binary for:
#
#   1. names the release: --version, or the latest, printed so it can be pinned
#   2. downloads the binary, SHA256SUMS and the binary's Sigstore bundle from
#      the GitHub release, over HTTPS only, and installs nothing unless the
#      binary's SHA-256 is the one SHA256SUMS gives; with cosign installed,
#      nothing unless the bundle shows the release workflow signed it too.
#      There is no option to skip either check
#   3. installs it to /usr/local/bin as root, else to ~/.local/bin
#   4. as root under systemd, makes a signari system user, /etc/signari (0750)
#      and a hardened unit, signari.service, which it does not start
#   5. runs `signari setup`, which asks at the terminal what it cannot work out
#      (through /dev/tty when this script's input is the pipe), and with no
#      terminal at all asks nothing, as with --yes
#
# Anywhere else it says so, and prints how to run Signari with Docker, or to
# build it with Go, whichever is here.
#
# With --docker, on any machine with Docker and git, macOS and ARM among them,
# it instead clones the release's source at its tag, builds the engine image,
# runs that image's `signari setup -compose` to write a compose project to
# --dir (asking at the terminal as setup does), starts it with docker compose
# and waits until it is healthy, then prints the first administrator's link.
#
# Each run but a dry run appends what it did to install.log, 0600 and with no
# password in it: in /var/log/signari as root, else in $XDG_STATE_HOME/signari
# or ~/.local/state/signari. setup keeps its own setup.log beside it.
#
# Options:
#   --version vX.Y.Z           the release to install (default: the latest)
#   --dry-run                  print every command instead of running it
#   --docker                   build the release's image and run it with Docker Compose
#   --dir PATH                 with --docker: the compose project's directory (default ~/signari)
#   --yes                      passed to setup: ask nothing, take the defaults
#   --issuer URL               passed to setup: the address people will reach it at
#   --email ADDRESS            passed to setup: the first administrator's
#   --superuser-dsn URL        passed to setup, with no password in it (PGPASSWORD)
#   --superuser-dsn-file PATH  passed to setup
#   --database NAME            passed to setup
#   --addr HOST:PORT           passed to setup; with --docker, where its port is published
#   --help
#
# It talks to GitHub alone, and to Sigstore when cosign checks the signature:
# no telemetry, no address lookup, nothing about this machine sent anywhere.
#
# Everything is in functions and the last line calls main, so a download cut
# short part way defines some of them and runs nothing.

REPO="Binary-ly/signari"
RELEASES="https://github.com/$REPO/releases"
ARCHIVES="https://github.com/$REPO/archive/refs/tags"
# Who signs a release (.github/workflows/release.yml), as SECURITY.md checks it.
SIGNER='^https://github\.com/Binary-ly/signari/\.github/workflows/release\.yml@refs/(heads/main|tags/v[0-9.]+)$'
SIGNER_ISSUER="https://token.actions.githubusercontent.com"

DRY_RUN=0
DOCKER=0
YES=0
VERSION=""
ISSUER=""
EMAIL=""
SU_DSN=""
SU_DSN_FILE=""
DATABASE=""
ADDR=""
DIR=""
TMP=""
OS=""
ARCH=""
ASSET=""
SUM=""
BIN=""
LOG=""

say() {
  printf '%s\n' "$*"
}

warn() {
  printf 'signari install: %s\n' "$*" >&2
}

die() {
  warn "$*"
  log "failed: $*"
  exit 1
}

# log appends a line to install.log, once log_open has found where.
log() {
  if [ -n "$LOG" ]; then
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG" 2>/dev/null || true
  fi
}

# log_open starts this run's record in install.log, beside the setup.log that
# signari setup keeps: /var/log/signari as root, else the user's state
# directory. It is 0600 and holds no password: one in a URL among the options
# is replaced. A dry run writes none, and a log that cannot be written is said
# and gone without.
log_open() {
  if [ "$DRY_RUN" = 1 ]; then
    return 0
  fi
  mask=077
  if [ "$(id -u)" = 0 ]; then
    dir=/var/log/signari
    mask=027
  else
    case ${XDG_STATE_HOME:-} in
      /*) dir="$XDG_STATE_HOME/signari" ;;
      *) dir="$HOME/.local/state/signari" ;;
    esac
  fi
  made_dir=0
  made_log=0
  [ -d "$dir" ] || made_dir=1
  [ -e "$dir/install.log" ] || made_log=1
  if ! (umask "$mask" && mkdir -p "$dir" && umask 077 && true >>"$dir/install.log") 2>/dev/null ||
    ! chmod 600 "$dir/install.log" 2>/dev/null; then
    warn "could not write $dir/install.log, so this run keeps no log"
    return 0
  fi
  LOG="$dir/install.log"
  log "==== install.sh by $(id -un 2>/dev/null || id -u) on $(uname -n 2>/dev/null), options:$(unsecret "$@")"
  if [ "$made_dir" = 1 ]; then record dir "$dir"; fi
  if [ "$made_log" = 1 ]; then record log "$dir/install.log"; fi
}

# manifest_path is where the installer and setup list what they make, for
# signari uninstall to remove exactly that: in /var/lib/signari as root, a
# directory root alone may write, and not in /etc/signari, which belongs to the
# service's user; else in the user's state directory.
manifest_path() {
  if [ "$(id -u)" = 0 ]; then
    printf '%s' /var/lib/signari/install.manifest
  else
    case ${XDG_STATE_HOME:-} in
      /*) printf '%s' "$XDG_STATE_HOME/signari/install.manifest" ;;
      *) printf '%s' "$HOME/.local/state/signari/install.manifest" ;;
    esac
  fi
}

# record adds one thing this run made to the manifest, which is replaced whole
# or not at all, and is 0600 in a 0700 directory.
record() {
  if [ "$DRY_RUN" = 1 ]; then
    return 0
  fi
  m=$(manifest_path)
  line="$1 $2"
  if [ -f "$m" ] && grep -Fxq -- "$line" "$m"; then
    return 0
  fi
  if ! (
    umask 077
    mkdir -p "$(dirname "$m")" || exit 1
    {
      if [ -f "$m" ]; then
        cat "$m"
      else
        printf '%s\n' "# What the Signari installer and signari setup made on this machine, one thing" \
          "# a line. signari uninstall removes these and nothing else."
      fi
      printf '%s\n' "$line"
    } >"$m.tmp.$$" && mv -f "$m.tmp.$$" "$m"
  ); then
    warn "could not record $2 in $m, so signari uninstall will not remove it"
    return 0
  fi
  log "recorded $line in $m"
}

# unsecret prints its words with the password of any URL among them replaced.
unsecret() {
  if [ "$#" = 0 ]; then
    printf ' none'
  fi
  for word in "$@"; do
    printf ' %s' "$(printf '%s' "$word" | sed 's#\([a-z][a-z0-9+.-]*://[^:/@]*\):[^@/]*@#\1:…@#g')"
  done
}

have() {
  command -v "$1" >/dev/null 2>&1
}

# show prints a command as it would be typed, each word quoted when it needs it.
show() {
  line="+"
  for word in "$@"; do
    case $word in
      '' | *[!A-Za-z0-9_./:=@%+,-]*)
        word="'$(printf '%s' "$word" | sed "s/'/'\\\\''/g")'"
        ;;
    esac
    line="$line $word"
  done
  printf '%s\n' "$line"
}

# run runs a command, or with --dry-run prints it.
run() {
  if [ "$DRY_RUN" = 1 ]; then
    show "$@"
    return 0
  fi
  "$@"
}

usage() {
  cat <<'EOF'
usage: sh install.sh [options]      or      curl -fsSL https://signari.dev/install | sh -s -- [options]

  --version vX.Y.Z           the release to install (default: the latest)
  --dry-run                  print every command instead of running it
  --docker                   build the release's image and run it with Docker Compose
  --dir PATH                 with --docker: the compose project's directory (default ~/signari)
  --yes                      passed to setup: ask nothing, take the defaults
  --issuer URL               passed to setup: the address people will reach it at
  --email ADDRESS            passed to setup: the first administrator's
  --superuser-dsn URL        passed to setup, with no password in it (PGPASSWORD)
  --superuser-dsn-file PATH  passed to setup
  --database NAME            passed to setup
  --addr HOST:PORT           passed to setup; with --docker, where its port is published

The comment at the top of the script says what it does, step by step.
EOF
}

need_value() {
  if [ "$#" -lt 2 ] || [ -z "$2" ]; then
    die "$1 needs a value (--help lists the options)"
  fi
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case $1 in
      --version) need_value "$@"; VERSION=$2; shift 2 ;;
      --version=*) VERSION=${1#*=}; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --docker) DOCKER=1; shift ;;
      --yes | -y) YES=1; shift ;;
      --issuer) need_value "$@"; ISSUER=$2; shift 2 ;;
      --issuer=*) ISSUER=${1#*=}; shift ;;
      --email) need_value "$@"; EMAIL=$2; shift 2 ;;
      --email=*) EMAIL=${1#*=}; shift ;;
      --superuser-dsn) need_value "$@"; SU_DSN=$2; shift 2 ;;
      --superuser-dsn=*) SU_DSN=${1#*=}; shift ;;
      --superuser-dsn-file) need_value "$@"; SU_DSN_FILE=$2; shift 2 ;;
      --superuser-dsn-file=*) SU_DSN_FILE=${1#*=}; shift ;;
      --database) need_value "$@"; DATABASE=$2; shift 2 ;;
      --database=*) DATABASE=${1#*=}; shift ;;
      --addr) need_value "$@"; ADDR=$2; shift 2 ;;
      --addr=*) ADDR=${1#*=}; shift ;;
      --dir) need_value "$@"; DIR=$2; shift 2 ;;
      --dir=*) DIR=${1#*=}; shift ;;
      -h | --help) usage; exit 0 ;;
      *) die "$1 is not an option this installer takes (--help lists them)" ;;
    esac
  done
}

detect_platform() {
  kernel=$(uname -s 2>/dev/null || echo unknown)
  machine=$(uname -m 2>/dev/null || echo unknown)
  case $kernel in
    Linux) OS=linux ;;
    Darwin) OS=darwin ;;
    MINGW* | MSYS* | CYGWIN*) OS=windows ;;
    *) OS=$(printf '%s' "$kernel" | tr '[:upper:]' '[:lower:]') ;;
  esac
  case $machine in
    x86_64 | amd64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) ARCH=$machine ;;
  esac
}

check_version() {
  case $VERSION in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) die "$VERSION is not a release name such as v0.1.0" ;;
  esac
  case $VERSION in
    *[!A-Za-z0-9.-]*) die "$VERSION is not a release name such as v0.1.0" ;;
  esac
}

# curl_https fetches over HTTPS alone, failing on any error the server sends.
curl_https() {
  curl --proto '=https' --tlsv1.2 -fsSL "$@"
}

resolve_version() {
  if [ -n "$VERSION" ]; then
    case $VERSION in
      v*) ;;
      *) VERSION="v$VERSION" ;;
    esac
    check_version
    say "Signari $VERSION"
    log "release $VERSION, as --version named it"
    return 0
  fi
  have curl || die "curl is needed to download the release"
  # The latest release's page redirects to its tag; nothing else is asked.
  latest=$(curl_https -I -o /dev/null -w '%{url_effective}' "$RELEASES/latest") ||
    die "could not reach $RELEASES/latest to find the latest release; give --version"
  VERSION=${latest##*/}
  check_version
  say "Signari $VERSION, the latest release (--version $VERSION installs this one again)"
  log "release $VERSION, the latest"
}

sha256_of() {
  if have sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  elif have shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif have openssl; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    return 1
  fi
}

download() {
  have curl || die "curl is needed to download the release"
  base="$RELEASES/download/$VERSION"
  ASSET="signari-$VERSION-$OS-$ARCH"
  if [ "$DRY_RUN" = 1 ]; then
    TMP="${TMPDIR:-/tmp}/signari-install"
  else
    TMP=$(mktemp -d 2>/dev/null || mktemp -d -t signari) || die "could not make a temporary directory"
    trap 'rm -rf "$TMP"' EXIT
    trap 'rm -rf "$TMP"; exit 130' INT TERM
  fi
  say "downloading $ASSET and SHA256SUMS from $base"
  run curl --proto '=https' --tlsv1.2 -fsSL -o "$TMP/$ASSET" "$base/$ASSET" ||
    die "could not download $base/$ASSET"
  run curl --proto '=https' --tlsv1.2 -fsSL -o "$TMP/SHA256SUMS" "$base/SHA256SUMS" ||
    die "could not download $base/SHA256SUMS"
  if have cosign; then
    run curl --proto '=https' --tlsv1.2 -fsSL -o "$TMP/$ASSET.sigstore.json" "$base/$ASSET.sigstore.json" ||
      die "could not download $base/$ASSET.sigstore.json, which cosign needs to check the signature"
  fi
  log "downloaded $ASSET and SHA256SUMS from $base"
}

# verify refuses the download unless SHA256SUMS names it with its SHA-256, and,
# with cosign here, unless the release workflow signed it. Either way failing
# installs nothing, and nothing turns either check off.
verify() {
  if [ "$DRY_RUN" = 1 ]; then
    say "+ check $TMP/$ASSET against the line for it in SHA256SUMS"
    if have cosign; then
      show cosign verify-blob "$TMP/$ASSET" --bundle "$TMP/$ASSET.sigstore.json" \
        --certificate-oidc-issuer "$SIGNER_ISSUER" --certificate-identity-regexp "$SIGNER"
    fi
    return 0
  fi
  SUM=$(awk -v n="$ASSET" '$2 == n || $2 == "*" n {print $1}' "$TMP/SHA256SUMS")
  if [ -z "$SUM" ]; then
    die "SHA256SUMS has no line for $ASSET, so it cannot be checked. Nothing was installed."
  fi
  got=$(sha256_of "$TMP/$ASSET") ||
    die "there is no sha256sum, shasum or openssl here to check the download with. Nothing was installed."
  if [ "$got" != "$SUM" ]; then
    die "$ASSET does not match SHA256SUMS (it says $SUM, the download is $got): it is damaged, or not" \
      "the release's. Nothing was installed."
  fi
  say "checked: $ASSET has the SHA-256 the release's SHA256SUMS gives"
  log "checked the SHA-256 of $ASSET, $SUM"
  if have cosign; then
    if ! out=$(cosign verify-blob "$TMP/$ASSET" --bundle "$TMP/$ASSET.sigstore.json" \
      --certificate-oidc-issuer "$SIGNER_ISSUER" --certificate-identity-regexp "$SIGNER" 2>&1); then
      die "cosign could not verify that the release workflow signed $ASSET. Nothing was installed. $out"
    fi
    say "checked: cosign verified the release workflow's signature on $ASSET"
    log "cosign verified the release workflow's signature on $ASSET"
  else
    log "cosign is not installed, so the signature was not checked"
    say "checked by SHA-256 alone: cosign is not installed. With it, this would also prove the"
    say "release workflow signed the binary, not only that it is the file the release lists."
  fi
}

install_binary() {
  if [ "$(id -u)" = 0 ]; then
    bindir=/usr/local/bin
  else
    bindir="$HOME/.local/bin"
  fi
  BIN="$bindir/signari"
  if [ "$DRY_RUN" != 1 ] && [ -x "$BIN" ] && [ "$(sha256_of "$BIN" 2>/dev/null)" = "$SUM" ]; then
    say "$BIN is $VERSION already"
    log "skip: $BIN is $VERSION already"
  else
    run mkdir -p "$bindir" || die "could not make $bindir"
    run install -m 0755 "$TMP/$ASSET" "$BIN" || die "could not install $BIN"
    if [ "$DRY_RUN" != 1 ]; then
      say "installed $BIN"
      log "installed $BIN"
    fi
  fi
  record binary "$BIN"
  case ":$PATH:" in
    *":$bindir:"*) ;;
    *) say "$bindir is not on your PATH: add it in your shell's profile, export PATH=\"$bindir:\$PATH\"" ;;
  esac
}

# The unit the installer writes. serve writes no file, so ProtectSystem=strict
# leaves it nothing writable but its private /tmp, and it needs no
# ReadWritePaths; the root key and the env file are only read.
write_unit() {
  unit=/etc/systemd/system/signari.service
  if [ -e "$unit" ] && ! head -n 1 "$unit" | grep -q '^# Written by the Signari installer'; then
    say "$unit is there and the installer did not write it, so it is left as it is"
    return 0
  fi
  if [ "$DRY_RUN" = 1 ]; then
    say "+ write $unit: User=signari, EnvironmentFile=/etc/signari/signari.env, ExecStart=$BIN serve, hardened"
    return 0
  fi
  cat >"$TMP/signari.service" <<EOF
# Written by the Signari installer (https://signari.dev/install). A later run
# replaces this file while that first line is here; take it out to keep edits.
[Unit]
Description=Signari identity provider
Documentation=https://github.com/Binary-ly/signari/blob/main/docs/cli.md
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=signari
Group=signari
# SIGNARI_DSN, the root key's file, the issuer and the listen address, as
# signari setup wrote them.
EnvironmentFile=/etc/signari/signari.env
ExecStart=$BIN serve
Restart=on-failure
RestartSec=5s
# serve drains for 5s and lets requests finish for 20s (SIGNARI_SHUTDOWN_*).
TimeoutStopSec=30s
UMask=0077

# It writes no file: everything is read-only to it but its own /tmp.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
# No capabilities. To listen on a port below 1024, both of these need
# CAP_NET_BIND_SERVICE, which signari setup adds in a drop-in of its own when
# Signari serves HTTPS itself on such a port.
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF
  install -m 0644 "$TMP/signari.service" "$unit" || die "could not write $unit"
  say "wrote $unit"
  log "wrote $unit"
  record unit "$unit"
}

# As root under systemd: the service's own user, its directory and its unit.
# The directory is made for the user, and setup, run as root, gives a file it
# makes there to the directory's owner, so the service can read its own key.
service() {
  if [ "$(id -u)" != 0 ] || [ ! -d /run/systemd/system ]; then
    return 0
  fi
  if ! getent passwd signari >/dev/null 2>&1; then
    nologin=/usr/sbin/nologin
    if [ ! -x "$nologin" ]; then
      nologin=/sbin/nologin
    fi
    run useradd --system --user-group --no-create-home --home-dir /nonexistent --shell "$nologin" signari ||
      die "could not make the signari system user"
    log "made the signari system user"
    record user signari
  fi
  if [ ! -d /etc/signari ]; then
    run install -d -m 0750 -o signari -g signari /etc/signari || die "could not make /etc/signari"
    log "made /etc/signari, 0750, for the signari user"
    record dir /etc/signari
  fi
  write_unit
  run systemctl daemon-reload || warn "systemctl daemon-reload failed; run it before starting signari"
}


# tty_usable says whether this process has a terminal to open. In a subshell,
# and with a utility that is not special, because a redirection that fails on
# a special built-in such as : ends a POSIX shell outright.
tty_usable() {
  (true </dev/tty) 2>/dev/null
}

run_setup() {
  set -- setup
  if [ "$YES" = 1 ]; then set -- "$@" -yes; fi
  if [ -n "$ISSUER" ]; then set -- "$@" -issuer "$ISSUER"; fi
  if [ -n "$EMAIL" ]; then set -- "$@" -email "$EMAIL"; fi
  if [ -n "$SU_DSN" ]; then set -- "$@" -superuser-dsn "$SU_DSN"; fi
  if [ -n "$SU_DSN_FILE" ]; then set -- "$@" -superuser-dsn-file "$SU_DSN_FILE"; fi
  if [ -n "$DATABASE" ]; then set -- "$@" -database "$DATABASE"; fi
  if [ -n "$ADDR" ]; then set -- "$@" -addr "$ADDR"; fi
  if [ "$DRY_RUN" = 1 ]; then
    show "$BIN" "$@"
    say "(once it is installed, $BIN setup -dry-run prints setup's own plan)"
    return 0
  fi
  # A release from before setup existed (v0.1.0) installs, and is set up by hand.
  if ! "$BIN" help setup >/dev/null 2>&1; then
    say ""
    say "Signari $VERSION is installed at $BIN, and has no setup command: it came in a later"
    say "release. Set this one up as its README's quick start says:"
    say "https://github.com/$REPO/blob/$VERSION/README.md#quick-start"
    log "skip: $VERSION has no setup command, so it is set up by hand"
    return 0
  fi
  say ""
  log "running $BIN$(unsecret "$@"), which keeps its own setup.log beside this one"
  if [ -t 0 ]; then
    "$BIN" "$@"
  elif tty_usable; then
    # This script's input is the pipe it came down, so setup asks at the
    # terminal itself.
    "$BIN" "$@" </dev/tty
  else
    if [ "$YES" != 1 ]; then
      say "no terminal to ask at, so setup asks nothing, as with --yes"
      set -- "$@" -yes
    fi
    "$BIN" "$@"
  fi
  status=$?
  if [ "$status" != 0 ]; then
    warn "setup stopped (exit $status): do what it says, then run it again, $BIN setup, or this script"
    log "failed: setup exited $status"
    exit "$status"
  fi
  log "setup finished"
  if [ -f /etc/systemd/system/signari.service ] && [ "$(id -u)" = 0 ]; then
    for f in /etc/signari/root.key /etc/signari/signari.env; do
      owner=$(stat -c %U "$f" 2>/dev/null || echo signari)
      if [ "$owner" != signari ]; then
        warn "$f belongs to $owner, and the service runs as signari, which cannot read it: chown signari:signari $f"
      fi
    done
  fi
}

# docker_install builds the release's engine image from its source, has that
# image's signari setup -compose write a compose project to --dir, starts it,
# and waits until it is healthy: the way to run Signari where there is no
# release binary, macOS and ARM among them. Nothing is published but the
# engine's port, on loopback.
docker_install() {
  have docker || die "--docker needs Docker: install it (https://docs.docker.com/get-docker/), then run this again"
  docker compose version >/dev/null 2>&1 || die "--docker needs Docker Compose version 2, as docker compose"
  have git || die "--docker needs git, to fetch the source of $VERSION"
  if [ -n "$SU_DSN" ] || [ -n "$SU_DSN_FILE" ] || [ -n "$DATABASE" ]; then
    die "--docker runs its own PostgreSQL, so it takes no --superuser-dsn, --superuser-dsn-file or --database"
  fi
  DIR=${DIR:-$HOME/signari}
  case $DIR in
    /*) ;;
    *) DIR="$(pwd)/$DIR" ;;
  esac
  image="signari:$VERSION"
  if [ "$DRY_RUN" = 1 ]; then
    TMP="${TMPDIR:-/tmp}/signari-install"
  else
    TMP=$(mktemp -d 2>/dev/null || mktemp -d -t signari) || die "could not make a temporary directory"
    trap 'rm -rf "$TMP"' EXIT
    trap 'rm -rf "$TMP"; exit 130' INT TERM
  fi
  say "building $image from the source of $VERSION"
  run git clone --quiet --depth 1 --branch "$VERSION" "https://github.com/$REPO" "$TMP/src" ||
    die "could not fetch the source of $VERSION from https://github.com/$REPO"
  run docker build --quiet --tag "$image" "$TMP/src/engine" || die "could not build $image"
  log "built $image from the source of $VERSION"
  if [ "$DRY_RUN" != 1 ] && ! docker run --rm "$image" help setup 2>&1 | grep -q -- '-compose'; then
    say ""
    say "Signari $VERSION has no setup -compose: it came in a later release."
    log "skip: $VERSION has no setup -compose"
    offer_docker
    return 0
  fi
  if [ ! -d "$DIR" ]; then
    run mkdir -p "$DIR" || die "could not make $DIR"
    if [ "$DRY_RUN" != 1 ]; then
      (umask 077 && printf '%s\n' "# What the Signari installer and signari setup made on this machine, one thing" \
        "# a line. signari uninstall removes these and nothing else." "dir $DIR" >"$DIR/install.manifest") ||
        warn "could not record $DIR in $DIR/install.manifest"
    fi
  fi
  set -- setup -compose "$DIR" -image "$image"
  if [ -n "$ISSUER" ]; then set -- "$@" -issuer "$ISSUER"; fi
  if [ -n "$EMAIL" ]; then set -- "$@" -email "$EMAIL"; fi
  if [ -n "$ADDR" ]; then set -- "$@" -addr "$ADDR"; fi
  say ""
  # The project's files belong to whoever runs this, and so do its containers.
  if [ "$YES" != 1 ] && { [ -t 0 ] || tty_usable; }; then
    if [ "$DRY_RUN" = 1 ]; then
      show docker run --rm -it --user "$(id -u):$(id -g)" -v "$DIR:$DIR" "$image" "$@"
    else
      docker run --rm -it --user "$(id -u):$(id -g)" -v "$DIR:$DIR" "$image" "$@" </dev/tty
    fi
  else
    run docker run --rm --user "$(id -u):$(id -g)" -v "$DIR:$DIR" "$image" "$@" -yes
  fi
  status=$?
  if [ "$status" != 0 ]; then
    log "failed: setup -compose exited $status"
    die "setup -compose stopped (exit $status): do what it says, then run this again"
  fi
  log "wrote the compose project in $DIR"
  say "starting it, and waiting until it is healthy"
  run docker compose --project-directory "$DIR" up --detach --wait ||
    die "the project did not become healthy; docker compose --project-directory $DIR logs says why"
  log "started the compose project in $DIR"
  if [ "$DRY_RUN" = 1 ]; then
    return 0
  fi
  link=$(docker compose --project-directory "$DIR" logs --no-log-prefix setup 2>/dev/null |
    grep -o 'https\{0,1\}://[^ "]*/signup?invite=[^ "]*' | tail -n 1)
  issuer=$(sed -n "s/^SIGNARI_ISSUER='\(.*\)'$/\1/p" "$DIR/signari.env")
  say ""
  say "Signari is running in Docker, from $DIR."
  say ""
  say "  Address      $issuer"
  if [ -n "$link" ]; then
    say "  First admin  sets a password here, once, within 72 hours:"
    say "               $link"
  else
    say "  First admin  docker compose --project-directory $DIR logs setup shows the state of the link"
  fi
  say "  Root key     $DIR/root.key: copy it off this machine now. Without it the signing keys"
  say "               and every sealed secret are lost, whatever backup of the volume you hold."
  say "  Stop it      docker compose --project-directory $DIR stop"
  say "  Remove it    signari uninstall -compose $DIR where the signari binary is; without it,"
  say "               docker compose --project-directory $DIR down, then delete $DIR, and"
  say "               docker volume rm signari_pgdata to delete the database too."
}

offer_docker() {
  say ""
  say "With Docker, from the release's source:"
  say ""
  if have git; then
    say "  git clone --depth 1 --branch $VERSION https://github.com/$REPO"
    say "  cd signari/deploy"
  else
    say "  curl -fsSL $ARCHIVES/$VERSION.tar.gz | tar xz"
    say "  cd signari-${VERSION#v}/deploy"
  fi
  say "  export SIGNARI_ROOT_KEY=\"\$(head -c 32 /dev/urandom | base64)\" SIGNARI_FIRST_EMAIL=you@example.com"
  say "  export SIGNARI_TLS_CERT=/tls/engine.crt SIGNARI_TLS_KEY=/tls/engine.key"
  say "  docker compose --profile first-run --profile demo up -d"
  say "  docker compose logs bootstrap"
  say ""
  say "The last line prints the first administrator's one-time link. The engine answers at"
  say "https://localhost:8099 under a development certificate, and a demo application to sign in"
  say "to at http://localhost:8097/login. Keep the SIGNARI_ROOT_KEY you exported, off this"
  say "machine: it seals every stored secret, and compose needs it on every start."
  desktop=$(docker version --format '{{.Server.Platform.Name}}' 2>/dev/null || true)
  case $desktop in
    *"Docker Desktop"*)
      minor=$(printf '%s' "$desktop" | sed -n 's/.*Docker Desktop \([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p')
      major=${minor% *}
      minor=${minor#* }
      say ""
      if [ -n "$major" ] && { [ "$major" -lt 4 ] || { [ "$major" -eq 4 ] && [ "$minor" -lt 34 ]; }; }; then
        say "This is $desktop. The demo applications use host networking, which Docker Desktop"
        say "has from 4.34: upgrade it first, or leave out --profile demo, and the engine still runs."
      else
        say "This is $desktop. The demo applications use host networking, which it has only once"
        say "Settings, Resources, Network, \"Enable host networking\" is on (it asks you to be signed"
        say "in to a Docker account), then Apply and restart. Turn it on before you start them, or"
        say "leave out --profile demo: the engine and its database do not need it."
      fi
      ;;
  esac
}

offer_source() {
  say ""
  say "With Go (1.21 or newer, which fetches the toolchain the module names by itself):"
  say ""
  if have git; then
    say "  git clone --depth 1 --branch $VERSION https://github.com/$REPO"
    say "  cd signari/engine"
  else
    say "  curl -fsSL $ARCHIVES/$VERSION.tar.gz | tar xz"
    say "  cd signari-${VERSION#v}/engine"
  fi
  say "  go build -o signari ./cmd/signari"
  say "  ./signari setup"
  say ""
  say "A release from before setup existed, as v0.1.0 is, has no setup command: follow that"
  say "release's README instead, at https://github.com/$REPO/blob/$VERSION/README.md#quick-start"
}

# elsewhere says plainly that there is no binary here, and offers what can run
# Signari instead. It never ends quietly.
elsewhere() {
  say ""
  say "Signari $VERSION has no binary for $OS-$ARCH: the release has one for linux-amd64 alone."
  offered=0
  if have docker; then
    say ""
    say "Docker is here: run this again with --docker, and it builds the release's image and"
    say "runs it with Docker Compose, its own PostgreSQL beside it:"
    say ""
    say "  curl -fsSL https://signari.dev/install | sh -s -- --docker"
    offer_docker
    offered=1
  fi
  if have go; then
    offer_source
    offered=1
  fi
  if [ "$offered" = 0 ]; then
    say ""
    say "Neither docker nor go is installed here, and either would run it. Install Docker"
    say "(https://docs.docker.com/get-docker/) or Go (https://go.dev/dl/), then run this again."
  fi
  say ""
  die "nothing was installed on this machine."
}

main() {
  parse_args "$@"
  if [ "$DRY_RUN" = 1 ]; then
    say "dry run: every command is printed, and none is run"
  fi
  log_open "$@"
  detect_platform
  resolve_version
  if [ "$DOCKER" = 1 ]; then
    docker_install
    log "result ok"
    return 0
  fi
  if [ "$OS-$ARCH" != linux-amd64 ]; then
    log "no release binary for $OS-$ARCH"
    elsewhere
  fi
  download
  verify
  install_binary
  service
  run_setup
  log "result ok"
}

main "$@"
