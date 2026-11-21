#!/bin/sh
# RAVEN backend container entrypoint.
#
# Order matters: migrations must run before uvicorn boots, otherwise the
# application's ``init_db()`` (create_all) would create the tables first and
# Alembic's initial revision would fail with "relation already exists".
#
# The database wait + migration steps are best-effort: if they fail the app
# still starts and ``create_all`` guarantees the schema exists, so a broken
# migration never takes the whole stack down.

if [ "${SKIP_MIGRATIONS:-false}" != "true" ]; then
    # Wait for the database to accept connections (compose already gates on the
    # postgres healthcheck, but a restarted container can still lose the race).
    python - <<'PY' || true
import os
import time

import sqlalchemy

url = os.environ.get("DATABASE_URL", "")
if not url.startswith("postgresql"):
    raise SystemExit(0)

engine = sqlalchemy.create_engine(url, pool_pre_ping=True)
last = None
for attempt in range(30):
    try:
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text("SELECT 1"))
        print(f"[raven] database ready after {attempt + 1} attempt(s)", flush=True)
        break
    except Exception as exc:  # noqa: BLE001 - any connection error is retryable
        last = exc
        print(f"[raven] waiting for database ({attempt + 1}/30): {exc}", flush=True)
        time.sleep(2)
else:
    print(f"[raven] WARNING: database still unavailable: {last}", flush=True)
PY

    if alembic upgrade head; then
        echo "[raven] migrations applied (alembic head)"
    else
        echo "[raven] WARNING: 'alembic upgrade head' failed; continuing with create_all" >&2
    fi
fi

exec "$@"
