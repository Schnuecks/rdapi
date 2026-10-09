FROM python:3.12-slim

# Wird von GitHub Actions beim Release auf den Tag gesetzt (z. B. v0.3.0)
ARG VERSION=dev

LABEL org.opencontainers.image.title="RDAPI" \
      org.opencontainers.image.description="Lean self-hosted API server for the RustDesk app" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RDAPI_DB_PATH=/data/rdapi.sqlite3 \
    RDAPI_VERSION=${VERSION} \
    FORWARDED_ALLOW_IPS=127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY rdapi ./rdapi

# Läuft ohne Root; compose kann mit user: PUID:PGID einen anderen Benutzer setzen
RUN useradd --system --uid 10001 --no-create-home rdapi \
    && mkdir /data && chown rdapi /data
USER rdapi
VOLUME /data

EXPOSE 21114
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:21114/healthz', timeout=4)"
# --proxy-headers: echte Client-IP aus X-Forwarded-For übernehmen, aber nur von Absendern aus
# FORWARDED_ALLOW_IPS (oben: lokale und private Netze, also z. B. der Reverse Proxy im
# Docker-Netz). Von öffentlichen Adressen wird der Header ignoriert, sonst ließe sich die
# Begrenzung der Fehlversuche je IP mit einer erfundenen Adresse umgehen.
CMD ["uvicorn", "--factory", "rdapi.main:create_app", \
     "--host", "0.0.0.0", "--port", "21114", \
     "--proxy-headers", \
     "--no-server-header", "--no-access-log"]
