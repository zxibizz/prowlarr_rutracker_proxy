FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY proxy /app/proxy

ENV PROXY_PORT=8790 \
    STATE_DIR=/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Runs unprivileged and needs nothing writable except /data, so it fits a
# read-only root filesystem and Kubernetes' "restricted" Pod Security profile.
# The uid is numeric on purpose: runAsNonRoot can only verify a numeric USER.
RUN mkdir -p /data && chown 1000:1000 /data
USER 1000:1000

# The tracker session lives here; keep it on a volume so a restart does not
# force a fresh login.
VOLUME ["/data"]
EXPOSE 8790

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8790/healthz',timeout=9)"

CMD ["python3", "-m", "proxy"]
