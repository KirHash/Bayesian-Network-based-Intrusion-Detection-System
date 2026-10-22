# Build from the project root:   docker build -f deploy/docker/Dockerfile -t bayesian-ids .
#
# bayesian_ids.pkl must exist before building (python train_model.py); the
# image carries the trained model, not the dataset.

# -- dashboard ---------------------------------------------------------------
FROM node:22-slim AS frontend

WORKDIR /build

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# -- server --------------------------------------------------------------------
FROM python:3.12-slim

# CAPTURE=true (the default) lets python sniff packets, which needs NET_RAW and NET_ADMIN when the
# container runs (see docker-compose.yml here). A server that only takes uploads and API input
# builds with CAPTURE=false, runs with no extra capabilities, and gives python no capture rights:
# a binary with file capabilities will not even start in a container that lacks them.
ARG CAPTURE=true

# tcpdump compiles capture filters; libcap2-bin gives python its capture rights
RUN apt-get update \
 && apt-get install -y --no-install-recommends tcpdump libpcap0.8 libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements-prod.txt ./
RUN pip install --no-cache-dir -r requirements-prod.txt

COPY *.py ./
COPY bayesian_ids.pkl model_card.json ./
COPY --from=frontend /build/dist ./frontend/dist

RUN useradd --system --create-home --home-dir /data ids \
 && mkdir -p /data/captures \
 && chown -R ids:ids /data \
 && if [ "$CAPTURE" = "true" ]; then \
      setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")"; \
    fi

USER ids

ENV IDS_DB=/data/ids.db \
    IDS_DATA_DIR=/data/captures \
    PYTHONUNBUFFERED=1

VOLUME /data

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/healthz', timeout=4).status == 200 else 1)"

# A reverse proxy (or the platform's load balancer) provides HTTPS. Accounts
# must exist before the server will listen beyond localhost:
#   docker compose run --rm ids python manage_users.py add alice --role admin
CMD ["python", "serve.py", "--host", "0.0.0.0", "--port", "8000", "--behind-proxy"]
