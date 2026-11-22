#!/bin/bash
# The nodes of a scale run, on a machine of their own: three engine processes, each pinned to
# cores of its own, behind nginx dealing round-robin on 127.0.0.1:8080 (the issuer), reaching
# database.sh's PostgreSQL over TLS. Then the database round trip, and five rounds of each
# operation from 16 workers on the remaining cores, as JSON lines into OUT/cells.jsonl.
#
#   DBHOST=<addr> DBPORT=5432 IN=./scale-out NODE_CPUS="0,1 2,3 4,5" EDGE_CPUS=6,7 ./nodes.sh
#
# IN holds what database.sh wrote. Needs `signari`, `bench`, nginx and psql on PATH.
set -euo pipefail
: "${DBHOST:?}" "${DBPORT:=5432}" "${IN:?}" "${NODE_CPUS:?three cpu lists, space-separated}" "${EDGE_CPUS:?}"
OUT=${OUT:-$PWD/scale-results}
mkdir -p "$OUT"
DSN="postgres://signari_engine:$(cat "$IN/engine-pw")@$DBHOST:$DBPORT/signari?sslmode=require&pool_max_conns=16"
# Behind the balancer every request comes from 127.0.0.1; the nodes take the client's address
# from X-Forwarded-For, which a trusted proxy alone does not turn on.
export SIGNARI_ROOT_KEY_FILE=$IN/root-key SIGNARI_INSECURE_ISSUER=1 SIGNARI_TRUSTED_PROXIES=127.0.0.1/32 \
	SIGNARI_CLIENT_IP_SOURCE=x-forwarded-for

{ echo '\timing on'; for i in $(seq 1 200); do echo 'SELECT 1;'; done; } > "$OUT/rtt.sql"
PGPASSWORD=$(cat "$IN/engine-pw") psql -q "host=$DBHOST port=$DBPORT dbname=signari user=signari_engine sslmode=require" \
	-f "$OUT/rtt.sql" 2>&1 | awk '/^Time:/ {print $2}' | tail -n +2 | sort -n |
	awk '{a[NR]=$1} END {printf "database round trip ms: min %.3f p50 %.3f p99 %.3f max %.3f (n=%d)\n", a[1], a[int(NR*0.5)], a[int(NR*0.99)], a[NR], NR}' |
	tee "$OUT/rtt.txt"

pids=()
n=0
for cpus in $NODE_CPUS; do
	n=$((n + 1))
	SIGNARI_DSN="$DSN" taskset -c "$cpus" signari serve -addr 127.0.0.1:808$n > "$OUT/node$n.log" 2>&1 &
	pids+=($!)
done
cleanup() { [ -f "$OUT/nginx.pid" ] && nginx -c "$OUT/nginx.conf" -s stop; kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT
# Every node ready before the balancer starts: one sending its first request to nodes not yet
# listening marks them all down and answers 502.
for i in $(seq 1 $n); do
	for t in $(seq 1 120); do curl -fs -o /dev/null http://127.0.0.1:808$i/readyz && break; sleep 1; done
done
upstreams=$(for i in $(seq 1 $n); do printf 'server 127.0.0.1:808%d max_fails=0; ' "$i"; done)
cat > "$OUT/nginx.conf" <<EOF
worker_processes 2;
pid $OUT/nginx.pid;
events { worker_connections 4096; }
http {
  access_log off;
  upstream nodes { $upstreams keepalive 64; }
  server {
    listen 127.0.0.1:8080;
    location / {
      proxy_pass http://nodes;
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_set_header Host \$host;
      proxy_set_header X-Forwarded-For \$remote_addr;
      proxy_set_header X-Forwarded-Proto http;
    }
  }
}
EOF
taskset -c "$EDGE_CPUS" nginx -c "$OUT/nginx.conf"
curl -fsS -o /dev/null http://127.0.0.1:8080/.well-known/openid-configuration

# Sign-in takes turns through the organisation's 1,000 seeded people: one person signed in by
# sixteen workers at once is throttled by design.
FLAGS=(-issuer http://127.0.0.1:8080 -client-id bench -client-secret "$(cat "$IN/client-secret")" -cc-scope profile
	-username signin@bench.invalid -password "$(cat "$IN/person-pw")" -signin-people 1000)
SCEN=(discovery client-credentials introspect signin refresh userinfo)
for s in "${SCEN[@]}"; do
	taskset -c "$EDGE_CPUS" bench run -c 16 -d 10s -warmup 5s "${FLAGS[@]}" "$s" > /dev/null
done
for round in 1 2 3 4 5; do
	for s in "${SCEN[@]}"; do
		taskset -c "$EDGE_CPUS" bench run -c 16 -d 15s -warmup 5s "${FLAGS[@]}" "$s" |
			jq -c --argjson r $round '. + {round: $r}' >> "$OUT/cells.jsonl"
	done
	echo "round $round done"
done
for i in $(seq 1 $n); do echo "node$i: $(grep -c 'level=ERROR' "$OUT/node$i.log") errors logged"; done
