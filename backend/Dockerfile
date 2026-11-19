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

RUN set -eux; \
    fetch() { \
      curl -fsSL --retry 3 -o "/tmp/$1.zip" "$2"; \
      unzip -o -q "/tmp/$1.zip" -d /tmp/"$1"; \
      install -m 0755 "/tmp/$1/$1" "/usr/local/bin/$1"; \
      rm -rf "/tmp/$1" "/tmp/$1.zip"; \
    }; \
    fetch subfinder "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_amd64.zip"; \
    fetch httpx "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_amd64.zip"; \
    fetch katana "https://github.com/projectdiscovery/katana/releases/download/${KATANA_VERSION}/katana_${KATANA_VERSION#v}_linux_amd64.zip"; \
    fetch nuclei "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip"; \
    subfinder -version; httpx -version; katana -version; nuclei -version

# Pre-download nuclei templates so the image works without extra setup.
RUN nuclei -update-templates || echo "nuclei templates will be fetched on first use"

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY app ./app
COPY alembic.ini ./
COPY migrations ./migrations

RUN mkdir -p /app/data/scans

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
