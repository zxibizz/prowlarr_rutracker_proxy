FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY proxy /app/proxy

ENV PROXY_PORT=8790 \
    STATE_DIR=/data \
    PYTHONUNBUFFERED=1

# The tracker session lives here; keep it on a volume so a restart does not
# force a fresh login.
VOLUME ["/data"]
EXPOSE 8790

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8790/healthz',timeout=4)"

CMD ["python3", "-m", "proxy"]
