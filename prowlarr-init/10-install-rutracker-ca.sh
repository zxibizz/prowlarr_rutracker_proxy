#!/usr/bin/with-contenv bash
# Installs the proxy's CA into this container's trust store, on every start.
#
# Prowlarr runs on .NET, which on Linux reads the OpenSSL bundle rather than a
# store of its own, so update-ca-certificates is all that is needed. The CA is
# mounted read-only from the proxy's data volume, so it appears here as soon as
# the proxy has generated it.

set -eu

SOURCE=/rutracker-ca/ca.crt
TARGET=/usr/local/share/ca-certificates/rutracker-proxy-ca.crt

if [ ! -f "$SOURCE" ]; then
    echo "[rutracker-ca] $SOURCE is missing; start rutracker-proxy first, then restart this container"
    exit 0
fi

if cmp -s "$SOURCE" "$TARGET" 2>/dev/null; then
    echo "[rutracker-ca] already installed"
    exit 0
fi

install -m 0644 "$SOURCE" "$TARGET"
update-ca-certificates >/dev/null
echo "[rutracker-ca] installed $(openssl x509 -noout -subject -in "$TARGET" 2>/dev/null || echo "$TARGET")"
