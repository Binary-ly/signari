#!/bin/sh
# The engine's role, with a password, made before migration 0001 runs: 0001 creates
# signari_engine only if it is absent, and leaves passwords out of migrations on
# purpose ("set out-of-band"). The engine serves as this role, which reads every
# organisation by design and holds no power over the database server it does not
# need, and not as the superuser above, which can run programs and read files on
# the server, change its configuration and reach every database on it. It runs
# once, on an empty data directory; for one made before it, set the
# password by hand, or the engine cannot sign in:
#
#   docker compose exec postgres psql -U signari_superuser -d signari \
#     -c "ALTER ROLE signari_engine PASSWORD 'devengine'"
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v pw="${SIGNARI_ENGINE_DB_PASSWORD:-devengine}" <<'SQL'
CREATE ROLE signari_engine LOGIN PASSWORD :'pw';
SQL
