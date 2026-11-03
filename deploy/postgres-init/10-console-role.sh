#!/bin/sh
# The console's role, with a password, made before migration 0001 runs: 0001 creates
# signari_admin only if it is absent, and leaves passwords out of migrations on
# purpose ("set out-of-band"). This is that, for the compose stack. It runs once, on
# an empty data directory; for one made before it, set the password by hand:
#
#   docker compose exec postgres psql -U signari_superuser -d signari \
#     -c "ALTER ROLE signari_admin PASSWORD '...'"
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v pw="${SIGNARI_ADMIN_DB_PASSWORD:-devconsole}" <<'SQL'
CREATE ROLE signari_admin LOGIN PASSWORD :'pw';
SQL
