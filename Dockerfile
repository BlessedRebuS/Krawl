FROM python:3.13-slim

LABEL org.opencontainers.image.source=https://github.com/BlessedRebuS/Krawl

WORKDIR /app

# Install gosu for dropping privileges
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends gosu postgresql-client && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY src/ /app/src/
COPY scripts/ /app/scripts/
COPY wordlists.json /app/
COPY entrypoint.sh /app/
COPY config.yaml /app/

RUN useradd -m -u 1000 krawl && \
    mkdir -p /app/logs /app/data && \
    chown -R krawl:krawl /app && \
    chmod +x /app/entrypoint.sh

EXPOSE 5000

ENV PYTHONUNBUFFERED=1
ENV MALLOC_TRIM_THRESHOLD_=65536

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000", "--app-dir", "src"]
