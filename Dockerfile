FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# py-tlsh needs a compiler, but the final image only needs its built wheel.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip wheel --wheel-dir /wheels -r requirements.txt

FROM python:3.13-slim

LABEL org.opencontainers.image.source="https://github.com/BlessedRebuS/Krawl" \
      org.opencontainers.image.url="https://github.com/BlessedRebuS/Krawl" \
      org.opencontainers.image.documentation="https://github.com/BlessedRebuS/Krawl#readme" \
      org.opencontainers.image.title="Krawl" \
      org.opencontainers.image.description="Krawl web crawler" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="BlessedRebuS"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MALLOC_TRIM_THRESHOLD_=65536 \
    MALLOC_ARENA_MAX=2

WORKDIR /app

# gosu lets the entrypoint drop privileges after fixing mount ownership.
# postgresql-client provides pg_dump for the optional backup task.
RUN apt-get update && apt-get install -y --no-install-recommends gosu postgresql-client && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -u 1000 krawl && \
    mkdir -p /app/logs /app/data /app/exports && \
    chown krawl:krawl /app/logs /app/data /app/exports

COPY requirements.txt /app/
COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels -r requirements.txt && rm -rf /wheels

COPY --chown=krawl:krawl src/ /app/src/
COPY --chown=krawl:krawl scripts/ /app/scripts/
COPY --chown=krawl:krawl --chmod=755 entrypoint.sh /app/
COPY --chown=krawl:krawl wordlists.json config.yaml /app/
COPY --chown=krawl:krawl helm/Chart.yaml /app/Chart.yaml

EXPOSE 5000

# The dashboard health path can be generated at runtime, so use a cheap TCP
# probe that works with every configuration. Orchestrators add readiness and
# startup semantics around the same port.
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os,socket; socket.create_connection(('127.0.0.1', int(os.getenv('KRAWL_PORT', '5000'))), 2).close()"]

ENTRYPOINT ["/app/entrypoint.sh"]
# --limit-concurrency: the DB calls on the request path run through
# asyncio.to_thread, whose executor has 32 threads and an UNBOUNDED queue. A
# slow disk (or just enough traffic) makes each call slower than arrivals, and
# every queued request pins its scope, body (64 KiB) and raw_request (16 KiB)
# until it is served -- that queue was the only thing in the process with no
# ceiling, and it is what walks RSS into the GiBs. Uvicorn sheds with a 503
# past this many in flight, which is the right answer for a honeypot: it
# already drops buffered rows under the same pressure. Raise it if the pod has
# memory to spare, lower it if it still grows -- roughly 80 KiB per slot.
CMD ["uvicorn", "app:app", "--app-dir", "src", "--no-server-header", "--no-access-log"]
