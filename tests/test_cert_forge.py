"""
Tests for cert_forge: given a recon-captured ``ssl`` dict, the forged certificate parses and
its subject/issuer/validity/SANs match the original, with a fresh keypair every call.
"""
import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_forge import forge_cert


SAMPLE = {
    "subject": {"CN": "device.local", "O": "ACME IoT", "C": "DE"},
    "issuer": {"CN": "device.local", "O": "ACME IoT"},
    "not_before": "20240101000000Z",
    "not_after": "20250101000000Z",   # 2024 is a leap year -> 366 days
    "subject_alt_names": ["DNS:device.local", "IP:192.0.2.10"],
}


def _forge(ssl_info):
    cert_pem, key_pem = forge_cert(ssl_info)
    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    return cert, key


def test_subject_is_cloned():
    cert, _ = _forge(SAMPLE)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "device.local"
    assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "ACME IoT"
    assert cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "DE"


def test_self_signed_issuer_equals_subject():
    cert, _ = _forge(SAMPLE)
    assert cert.issuer == cert.subject


def test_validity_duration_is_cloned_but_starts_now():
    cert, _ = _forge(SAMPLE)
    assert cert.not_valid_after - cert.not_valid_before == datetime.timedelta(days=366)
    # clamped to valid-now: a clone is never born expired or future-dated
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    assert cert.not_valid_before <= now < cert.not_valid_after


def test_sans_are_cloned():
    cert, _ = _forge(SAMPLE)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "device.local" in san.get_values_for_type(x509.DNSName)
    assert ipaddress.ip_address("192.0.2.10") in san.get_values_for_type(x509.IPAddress)


def test_fresh_keypair_each_call():
    _, k1 = _forge(SAMPLE)
    _, k2 = _forge(SAMPLE)
    # two clones of the same device must not share keys
    assert k1.private_numbers().d != k2.private_numbers().d


def test_missing_dates_fall_back_to_default_validity():
    cert, _ = _forge({"subject": {"CN": "x"}})
    assert cert.not_valid_after - cert.not_valid_before == datetime.timedelta(days=397)


def test_empty_ssl_info_still_produces_a_valid_self_signed_cert():
    cert, key = _forge({})
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)  # neutral fallback CN
    assert cert.issuer == cert.subject
    assert isinstance(key, rsa.RSAPrivateKey)


def test_rsa_key_size_is_honoured_when_captured():
    _, key = _forge({"subject": {"CN": "x"}, "key_size": 4096})
    assert key.key_size == 4096
