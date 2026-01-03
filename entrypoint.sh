#!/bin/sh
set -e

# Fix ownership of mounted directories
chown -R krawl:krawl /app/logs /app/data 2>/dev/null || true

# Drop to krawl user and run the application
exec gosu krawl "$@"
