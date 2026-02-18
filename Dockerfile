FROM python:3.11-slim

LABEL org.opencontainers.image.source=https://github.com/BlessedRebuS/Krawl

WORKDIR /app

# Install gosu for dropping privileges
RUN apt-get update && apt-get install -y --no-install-recommends gosu && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/src/
COPY wordlists.json /app/
COPY entrypoint.sh /app/
COPY config.yaml /app/

RUN useradd -m -u 1000 krawl && \
    mkdir -p /app/logs /app/data /app/exports && \
    chown -R krawl:krawl /app && \
    chmod +x /app/entrypoint.sh

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000", "--app-dir", "src"]
