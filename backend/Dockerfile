FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# curl/unzip are used to fetch the pinned scanner binaries and the healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- Embedded scanner binaries (pinned) -------------------------------------
ARG SUBFINDER_VERSION=v2.17.0
ARG HTTPX_VERSION=v1.12.0
ARG KATANA_VERSION=v1.8.0
ARG NUCLEI_VERSION=v3.11.1

# Each download is best-effort: a blocked/slow GitHub must not break the whole
# image build. Missing binaries simply mean the pure-Python engines are used
# (their status is reported honestly by /api/scanners/status).
RUN set -eux; \
    fetch() { \
      name="$1"; url="$2"; \
      if curl -fsSL --retry 3 --connect-timeout 20 -o "/tmp/${name}.zip" "$url"; then \
        unzip -o -q "/tmp/${name}.zip" -d "/tmp/${name}"; \
        bin=""; \
        for candidate in "/tmp/${name}/${name}" "/tmp/${name}/"*/"${name}"; do \
          if [ -f "$candidate" ]; then bin="$candidate"; break; fi; \
        done; \
        if [ -n "$bin" ]; then \
          install -m 0755 "$bin" "/usr/local/bin/${name}"; \
          echo "[raven] ${name} kuruldu"; \
        else \
          echo "[raven] UYARI: ${name} arsivi beklenen binary'yi icermiyor"; \
        fi; \
        rm -rf "/tmp/${name}" "/tmp/${name}.zip"; \
      else \
        echo "[raven] UYARI: ${name} indirilemedi; yerlesik Python motoru kullanilacak"; \
      fi; \
    }; \
    fetch subfinder "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_amd64.zip"; \
    fetch httpx "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_amd64.zip"; \
    fetch katana "https://github.com/projectdiscovery/katana/releases/download/${KATANA_VERSION}/katana_${KATANA_VERSION#v}_linux_amd64.zip"; \
    fetch nuclei "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip"; \
    for tool in subfinder httpx katana nuclei; do \
      if command -v "$tool" >/dev/null 2>&1; then \
        echo "[raven] ${tool}: $(command -v "$tool")"; \
      else \
        echo "[raven] EKSIK: ${tool} (yerlesik motor devrede)"; \
      fi; \
    done

# Pre-download nuclei templates so the image works without extra setup.
RUN if command -v nuclei >/dev/null 2>&1; then \
        nuclei -update-templates || echo "nuclei templates will be fetched on first use"; \
    else \
        echo "nuclei yok; sablonlar ilk kullanımda indirilecek"; \
    fi

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY app ./app
COPY alembic.ini ./
COPY migrations ./migrations
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

# A Windows/MINGW64 checkout converts the script to CRLF and dash then dies on
# `set -u\r` ("Illegal option -"), so normalize it inside the image too.
RUN tr -d '\r' < /app/docker-entrypoint.sh > /app/docker-entrypoint.sh.lf \
    && mv /app/docker-entrypoint.sh.lf /app/docker-entrypoint.sh \
    && chmod +x /app/docker-entrypoint.sh \
    && mkdir -p /app/data/scans

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

ENTRYPOINT ["sh", "/app/docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
