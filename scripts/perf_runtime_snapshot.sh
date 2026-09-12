#!/usr/bin/env bash
# Collect host/container/database context that complements ZEN's in-process v0.30 metrics.
# No passwords, tokens, packet payloads or DNS query contents are printed.
set -u

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

section() {
  printf '\n============================================================\n%s\n============================================================\n' "$1"
}

run_soft() {
  "$@" || printf 'UNAVAILABLE: command exited %s\n' "$?"
}

section "ZEN PERFORMANCE RUNTIME SNAPSHOT"
date -Is 2>/dev/null || date
printf 'compose_file=%s\n' "$COMPOSE_FILE"

section "COMPOSE STATUS"
run_soft "${COMPOSE[@]}" ps

section "CONTAINER CPU / MEMORY / IO"
run_soft docker stats --no-stream \
  --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}' \
  mikrotik-control mikrotik-telemetry-db mikrotik-traffic-ingest mikrotik-pihole goflow2

section "ZEN APPLICATION PROCESS"
run_soft "${COMPOSE[@]}" exec -T mikrotik-control sh -lc \
  'ps -eo pid,comm,%cpu,%mem,rss,vsz,args 2>/dev/null | head -20 || true; echo; python3 --version'

section "POLICY SQLITE SIZE / ROW COUNTS"
run_soft "${COMPOSE[@]}" exec -T mikrotik-control python3 - <<'PY'
import os
import sqlite3
from pathlib import Path

path = Path('/data/policy.db')
print(f'policy_db_bytes={path.stat().st_size if path.exists() else 0}')
for suffix in ('-wal', '-shm'):
    extra = Path(str(path) + suffix)
    print(f'policy_db{suffix}_bytes={extra.stat().st_size if extra.exists() else 0}')
if path.exists():
    db = sqlite3.connect(path)
    try:
        tables = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        for table in tables:
            safe = table.replace('"', '""')
            count = db.execute(f'SELECT count(*) FROM "{safe}"').fetchone()[0]
            print(f'{table}\t{count}')
    finally:
        db.close()
PY

section "POSTGRESQL DATABASE SIZE / TABLE ACTIVITY"
run_soft "${COMPOSE[@]}" exec -T telemetry-db sh -lc \
  'psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB" -P pager=off -c "SELECT current_database() AS database, pg_size_pretty(pg_database_size(current_database())) AS database_size;" -c "SELECT relname, n_live_tup, seq_scan, idx_scan, n_tup_ins, n_tup_upd, n_tup_del FROM pg_stat_user_tables ORDER BY n_live_tup DESC, relname;"'

section "POSTGRESQL TOP INDEX ACTIVITY"
run_soft "${COMPOSE[@]}" exec -T telemetry-db sh -lc \
  'psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB" -P pager=off -c "SELECT relname, indexrelname, idx_scan, idx_tup_read, idx_tup_fetch FROM pg_stat_user_indexes ORDER BY idx_scan DESC NULLS LAST, indexrelname LIMIT 30;"'

section "POSTGRESQL CONNECTIONS"
run_soft "${COMPOSE[@]}" exec -T telemetry-db sh -lc \
  'psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB" -P pager=off -c "SELECT state, count(*) FROM pg_stat_activity WHERE datname=current_database() GROUP BY state ORDER BY state;"'

printf '\nRuntime snapshot complete. Pair this output with /api/performance JSON from the same deployment window.\n'
