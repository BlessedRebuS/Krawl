#!/bin/sh
set -e

# Keep one worker per container: Krawl has process-local caches in standalone
# mode and an APScheduler instance per process. Scale with containers/pods.
# These bounds are environment-tunable without replacing the image command.
if [ "$1" = "uvicorn" ]; then
    set -- "$@" \
        --host "${KRAWL_UVICORN_HOST:-0.0.0.0}" \
        --port "${KRAWL_PORT:-5000}" \
        --workers 1 \
        --limit-concurrency "${KRAWL_UVICORN_LIMIT_CONCURRENCY:-512}" \
        --backlog "${KRAWL_UVICORN_BACKLOG:-256}" \
        --timeout-keep-alive "${KRAWL_UVICORN_KEEP_ALIVE:-5}" \
        --timeout-graceful-shutdown "${KRAWL_UVICORN_GRACEFUL_TIMEOUT:-30}"
    if [ -n "${KRAWL_UVICORN_LIMIT_MAX_REQUESTS:-}" ]; then
        set -- "$@" --limit-max-requests "$KRAWL_UVICORN_LIMIT_MAX_REQUESTS"
    fi
fi

# When the platform already pins a non-root uid (k8s securityContext), there is
# nothing to drop to and gosu would fail -- just exec.
if [ "$(id -u)" = "0" ]; then
    # ponytail: recursive chown of mounted volumes on every start; switch to
    # fsGroup in the pod spec if the data dir ever gets big enough to notice.
    chown -R krawl:krawl /app/logs /app/data /app/exports 2>/dev/null || true
    exec gosu krawl "$@"
fi

exec "$@"
