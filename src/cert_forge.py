"""
cert_forge: turn recon's captured TLS metadata into a fresh look-alike certificate.

recon records a target device's certificate components (subject/issuer DN, validity window,
and -- when available -- SANs and key parameters). This module rebuilds a *new* certificate
that mimics them: the same subject/issuer DN, the same validity DURATION (clamped to start
now so a clone is never born expired), cloned SANs, and a freshly generated keypair on every
call (keys are never reused across deployments -- that would itself be a fingerprint).

The clone is self-signed, which is realistic for the cheap IoT devices SOFAH targets (their
certs are self-signed too) and intentionally will not validate against public roots.
"""
from __future__ import annotations

import datetime
import ipaddress
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


# recon subject/issuer component name -> cryptography OID
_DN_OIDS = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "L": NameOID.LOCALITY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "C": NameOID.COUNTRY_NAME,
}

# ASN.1 time as recon stores it (X509.get_notBefore().decode() -> e.g. "20240101000000Z").
_ASN1_TIME = "%Y%m%d%H%M%SZ"
# Used when recon couldn't capture a validity window. ~13 months, a common device default.
_DEFAULT_VALIDITY = datetime.timedelta(days=397)


def _build_name(components: Optional[dict]) -> x509.Name:
    attrs = []
    for key, oid in _DN_OIDS.items():
        value = (components or {}).get(key)
        if value:
            attrs.append(x509.NameAttribute(oid, str(value)))
    if not attrs:
        # a certificate must carry *some* subject; fall back to a neutral CN
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, "localhost"))
    return x509.Name(attrs)


def _validity_duration(ssl_info: dict) -> datetime.timedelta:
    try:
        start = datetime.datetime.strptime(ssl_info.get("not_before"), _ASN1_TIME)
        end = datetime.datetime.strptime(ssl_info.get("not_after"), _ASN1_TIME)
        duration = end - start
        if duration > datetime.timedelta(0):
            return duration
    except (TypeError, ValueError):
        pass
    return _DEFAULT_VALIDITY


def _san_entries(ssl_info: dict) -> list:
    """Parse recon's ``subject_alt_names`` (e.g. ["DNS:a.b", "IP:1.2.3.4"]) into x509 names."""

    entries = []
    for raw in ssl_info.get("subject_alt_names") or []:
        text = str(raw).strip()
        kind, sep, value = text.partition(":")
        if sep:
            kind, value = kind.strip().upper(), value.strip()
        else:
            kind, value = "DNS", text  # bare value, no "DNS:"/"IP:" prefix
        if not value:
            continue
        if kind == "IP":
            try:
                entries.append(x509.IPAddress(ipaddress.ip_address(value)))
            except ValueError:
                continue
        else:
            entries.append(x509.DNSName(value))
    return entries


def _new_key(ssl_info: dict):
    """Fresh private key, matching the original's type/size when recon captured them."""

    if str(ssl_info.get("key_type", "")).upper() in ("EC", "ECDSA", "ELLIPTIC CURVE"):
        return ec.generate_private_key(ec.SECP256R1())
    size = ssl_info.get("key_size")
    size = size if isinstance(size, int) and size >= 2048 else 2048
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


def forge_cert(ssl_info: Optional[dict], self_signed: bool = True) -> tuple[bytes, bytes]:
    """
    Build a look-alike certificate from recon's captured ssl metadata.

    :param ssl_info: the per-port ``ssl`` dict recon emits (subject/issuer/not_before/
        not_after, optionally subject_alt_names/key_size/key_type). ``None``/empty is
        tolerated and yields a generic but valid self-signed cert.
    :type ssl_info: Optional[dict]
    :param self_signed: issuer == subject, signed by the cert's own key (default). Kept as a
        seam for a future per-deploy fake-CA mode.
    :type self_signed: bool
    :return: ``(cert_pem, key_pem)`` PEM-encoded bytes; a fresh keypair on every call.
    :rtype: tuple[bytes, bytes]
    """

    ssl_info = ssl_info or {}
    key = _new_key(ssl_info)

    subject = _build_name(ssl_info.get("subject"))
    issuer = subject if self_signed else _build_name(ssl_info.get("issuer"))

    # whole-second UTC start so the cloned duration is reproduced exactly (x509 stores seconds)
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None, microsecond=0)
    not_after = now + _validity_duration(ssl_info)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
    )

    sans = _san_entries(ssl_info)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem
