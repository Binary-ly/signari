# A scale run

What [docs/performance.md](../../../docs/performance.md#three-nodes-a-million-people-the-database-across-the-network)
reports for three nodes and a million people, as two scripts for two machines you can throw away.

| | |
|---|---|
| `database.sh` | On the database machine, as root: PostgreSQL 17 admitting only the nodes' address over TLS, the schema, an instance and client, 1,000 people to sign in as, then `seed.sql` |
| `seed.sql` | 1,000 organisations, 1,000,000 people, a session each and 10,000,000 audit events. The audit rows are volume, not a chain `signari audit verify` passes |
| `nodes.sh` | On the nodes' machine: the round trip to the database, three engines behind nginx, and five rounds of six operations into `cells.jsonl` |

```sh
# database machine
ALLOW=203.0.113.7/32 PGDATA_DIR=/dev/shm/pg ./database.sh
# copy ./scale-out to the nodes' machine, then
DBHOST=203.0.113.9 DBPORT=5432 IN=./scale-out NODE_CPUS="0,1 2,3 4,5" EDGE_CPUS=6,7 ./nodes.sh
```

Find the nodes' address by letting one connection fail first: PostgreSQL's log names the host it
refused. Put the data on tmpfs (`PGDATA_DIR=/dev/shm/...`) only when the machine's disk is the
thing you would otherwise be measuring, and say so beside the numbers. Both machines need
`signari` and `bench` on `PATH`.

The organisation's budgets are raised to their maximum for the run, and the write-up has to say
so: at the defaults the warm-up alone spends the sign-in budget.

These scripts were run as written, on 17 November 2026, on two fresh 16-thread machines in one data
centre: `database.sh` with `PGDATA_DIR=/dev/shm/pg` (exit 0, 1,001 organisations, 1,001,002
people, 10,000,004 audit events, 4.5 GB), then `nodes.sh` with
`NODE_CPUS="0,96,13,109 51,147,53,149 34,130,63,159"` (exit 0, 30 cells, no node logging an error).
