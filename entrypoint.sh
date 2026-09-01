#!/bin/sh
set -e

# When the platform already pins a non-root uid (k8s securityContext), there is
# nothing to drop to and gosu would fail -- just exec.
if [ "$(id -u)" = "0" ]; then
    # ponytail: recursive chown of mounted volumes on every start; switch to
    # fsGroup in the pod spec if the data dir ever gets big enough to notice.
    chown -R krawl:krawl /app/logs /app/data /app/exports 2>/dev/null || true
    exec gosu krawl "$@"
fi

exec "$@"
