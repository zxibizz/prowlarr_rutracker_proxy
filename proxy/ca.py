#!/usr/bin/env python3
"""The proxy's own certificate authority.

Prowlarr's RuTracker indexer is a C# indexer whose Base Url is a dropdown of the
site links compiled into it, so it cannot be pointed at a plain-http origin the
way a Cardigann definition can. The only way to see its traffic is to terminate
the TLS it opens with ``CONNECT rutracker.org:443``, which needs a certificate
Prowlarr trusts.

So this mints one. The CA is generated on first boot into a volume, never
committed, and only ever used for the hosts in ``MITM_HOSTS`` - everything else
is blind-tunnelled and keeps its real certificate.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

log = logging.getLogger("ca")

CA_VALIDITY_DAYS = 3650
LEAF_VALIDITY_DAYS = 90


class CertificateAuthority:
    """Generates the CA once, then mints and caches a leaf per intercepted host."""

    def __init__(self, ca_dir: str) -> None:
        self.dir = ca_dir
        self.cert_path = os.path.join(ca_dir, "ca.crt")
        self.key_path = os.path.join(ca_dir, "ca.key")
        self.leaf_key_path = os.path.join(ca_dir, "leaf.key")
        self.leaf_dir = os.path.join(ca_dir, "leaf")
        self._lock = threading.Lock()
        self._contexts: dict[str, ssl.SSLContext] = {}

        os.makedirs(self.leaf_dir, exist_ok=True)
        self._load_or_create_ca()
        self._load_or_create_leaf_key()

    # ------------------------------------------------------------------ CA
    def _load_or_create_ca(self) -> None:
        if os.path.exists(self.cert_path) and os.path.exists(self.key_path):
            with open(self.key_path, "rb") as handle:
                self.key = serialization.load_pem_private_key(handle.read(), password=None)
            with open(self.cert_path, "rb") as handle:
                self.cert = x509.load_pem_x509_certificate(handle.read())
            log.info("loaded CA from %s (subject %s)", self.dir, self.cert.subject.rfc4514_string())
            return

        log.info("generating a new CA in %s", self.dir)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "prowlarr-rutracker-proxy CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "prowlarr-rutracker-proxy"),
            ]
        )
        now = dt.datetime.now(dt.timezone.utc)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=CA_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        _write(self.key_path, self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ), mode=0o600)
        _write(self.cert_path, self.cert.public_bytes(serialization.Encoding.PEM), mode=0o644)

    def _load_or_create_leaf_key(self) -> None:
        """One key shared by every leaf: minting a cert then costs a signature, not a keygen."""
        if os.path.exists(self.leaf_key_path):
            with open(self.leaf_key_path, "rb") as handle:
                self.leaf_key = serialization.load_pem_private_key(handle.read(), password=None)
            return

        self.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _write(self.leaf_key_path, self.leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ), mode=0o600)

    @property
    def ca_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    # ------------------------------------------------------------------ leaves
    def context_for(self, hostname: str) -> ssl.SSLContext:
        hostname = hostname.lower()
        with self._lock:
            context = self._contexts.get(hostname)
            if context is not None:
                return context
            chain_path = self._mint(hostname)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            # Prowlarr's HttpClient speaks 1.1; offering h2 would only invite a
            # framing we do not implement.
            context.set_alpn_protocols(["http/1.1"])
            context.load_cert_chain(chain_path)
            self._contexts[hostname] = context
            return context

    def _mint(self, hostname: str) -> str:
        chain_path = os.path.join(self.leaf_dir, f"{hostname}.pem")
        if os.path.exists(chain_path) and _still_valid(chain_path):
            return chain_path

        try:
            alt: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            alt = x509.DNSName(hostname)

        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])]))
            .issuer_name(self.cert.subject)
            .public_key(self.leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=LEAF_VALIDITY_DAYS))
            .add_extension(x509.SubjectAlternativeName([alt]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")]), critical=False
            )
            .sign(self.key, hashes.SHA256())
        )

        blob = cert.public_bytes(serialization.Encoding.PEM) + self.leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        _write(chain_path, blob, mode=0o600)
        log.info("minted a leaf certificate for %s", hostname)
        return chain_path


def _still_valid(chain_path: str) -> bool:
    try:
        with open(chain_path, "rb") as handle:
            cert = x509.load_pem_x509_certificate(handle.read())
    except Exception:  # noqa: BLE001 - a corrupt cache entry is just re-minted
        return False
    return cert.not_valid_after_utc > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)


def _write(path: str, data: bytes, mode: int) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    os.chmod(path, mode)
