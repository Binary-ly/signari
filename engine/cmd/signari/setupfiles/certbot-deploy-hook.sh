#!/bin/sh
# Written by signari setup. certbot runs every deploy hook after it renews a
# certificate; this one acts only for {{.Lineage}}.
#
# The private key there is root's alone, and the signari service is not root,
# so setup copied the certificate and key to {{.Dir}}, owned by the service.
# This copies a renewed pair there again, each whole or not at all, and then
# restarts the service: signari serve reads its certificate when it starts, and
# not again while it runs. A service that is not running is left stopped.
set -eu
[ "${RENEWED_LINEAGE:-}" = "{{.Lineage}}" ] || exit 0
umask 077
for name in fullchain.pem privkey.pem; do
  install -m 0600 -o {{.UID}} -g {{.GID}} "$RENEWED_LINEAGE/$name" "{{.Dir}}/.$name.new"
  mv -f "{{.Dir}}/.$name.new" "{{.Dir}}/$name"
done
systemctl try-restart signari.service
