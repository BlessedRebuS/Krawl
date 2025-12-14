FROM python:3.11-slim

LABEL org.opencontainers.image.source=https://github.com/BlessedRebuS/Krawl

WORKDIR /app

COPY src/ /app/src/
COPY wordlists.json /app/

RUN useradd -m -u 1000 krawl && \
    chown -R krawl:krawl /app

USER krawl

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

CMD ["python3", "src/server.py"]
