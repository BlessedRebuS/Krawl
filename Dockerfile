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
    MALLOC_TRIM_THRESHOLD_=65536

WORKDIR /app

# gosu lets the entrypoint drop privileges after fixing mount ownership
# build-essential: py-tlsh compile its C++ extension from source at install time
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends gosu postgresql-client build-essential && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -u 1000 krawl && \
    mkdir -p /app/logs /app/data /app/exports && \
    chown krawl:krawl /app/logs /app/data /app/exports

COPY requirements.txt /app/
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install -r requirements.txt

COPY --chown=krawl:krawl src/ /app/src/
COPY --chown=krawl:krawl scripts/ /app/scripts/
COPY --chown=krawl:krawl --chmod=755 entrypoint.sh /app/
COPY --chown=krawl:krawl wordlists.json config.yaml /app/
COPY --chown=krawl:krawl helm/Chart.yaml /app/Chart.yaml

EXPOSE 5000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000", "--app-dir", "src", "--no-server-header"]
