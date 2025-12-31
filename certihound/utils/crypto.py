"""Cryptographic utilities for certificate handling."""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate


def calculate_thumbprint(cert_bytes: bytes) -> str:
    """Calculate SHA-1 thumbprint of a certificate."""
    if not cert_bytes:
        return ""

    try:
        # Try DER format first
        cert = x509.load_der_x509_certificate(cert_bytes)
        fingerprint = cert.fingerprint(hashes.SHA1())
        return fingerprint.hex().upper()
    except Exception:
        try:
            # Try PEM format
            cert = x509.load_pem_x509_certificate(cert_bytes)
            fingerprint = cert.fingerprint(hashes.SHA1())
            return fingerprint.hex().upper()
        except Exception:
            # Fall back to raw hash
            return hashlib.sha1(cert_bytes).hexdigest().upper()


def parse_certificate(cert_bytes: bytes) -> Certificate | None:
    """Parse a certificate from bytes."""
    if not cert_bytes:
        return None

    try:
        return x509.load_der_x509_certificate(cert_bytes)
    except Exception:
        try:
            return x509.load_pem_x509_certificate(cert_bytes)
        except Exception:
            return None


def get_certificate_subject(cert_bytes: bytes) -> str:
    """Extract subject DN from certificate."""
    cert = parse_certificate(cert_bytes)
    if not cert:
        return ""

    try:
        return cert.subject.rfc4514_string()
    except Exception:
        return ""


def get_certificate_issuer(cert_bytes: bytes) -> str:
    """Extract issuer DN from certificate."""
    cert = parse_certificate(cert_bytes)
    if not cert:
        return ""

    try:
        return cert.issuer.rfc4514_string()
    except Exception:
        return ""


def get_certificate_serial(cert_bytes: bytes) -> str:
    """Extract serial number from certificate."""
    cert = parse_certificate(cert_bytes)
    if not cert:
        return ""

    try:
        return format(cert.serial_number, "X")
    except Exception:
        return ""


def get_certificate_validity(cert_bytes: bytes) -> tuple[str, str]:
    """Get certificate validity period (not_before, not_after)."""
    cert = parse_certificate(cert_bytes)
    if not cert:
        return ("", "")

    try:
        not_before = cert.not_valid_before_utc.isoformat() if cert.not_valid_before_utc else ""
        not_after = cert.not_valid_after_utc.isoformat() if cert.not_valid_after_utc else ""
        return (not_before, not_after)
    except Exception:
        return ("", "")


def has_basic_constraints(cert_bytes: bytes) -> tuple[bool, int | None]:
    """Check if certificate has Basic Constraints extension and path length."""
    cert = parse_certificate(cert_bytes)
    if not cert:
        return (False, None)

    try:
        bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return (True, bc_ext.value.path_length)
    except x509.ExtensionNotFound:
        return (False, None)
    except Exception:
        return (False, None)


def get_certificate_ekus(cert_bytes: bytes) -> list[str]:
    """Extract Extended Key Usage OIDs from certificate."""
    cert = parse_certificate(cert_bytes)
    if not cert:
        return []

    try:
        eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        return [eku.dotted_string for eku in eku_ext.value]
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []


def get_certificate_san(cert_bytes: bytes) -> list[dict]:
    """Extract Subject Alternative Names from certificate."""
    cert = parse_certificate(cert_bytes)
    if not cert:
        return []

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = []

        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append({"type": "DNS", "value": name.value})
            elif isinstance(name, x509.RFC822Name):
                sans.append({"type": "Email", "value": name.value})
            elif isinstance(name, x509.IPAddress):
                sans.append({"type": "IP", "value": str(name.value)})
            elif isinstance(name, x509.UniformResourceIdentifier):
                sans.append({"type": "URI", "value": name.value})
            elif isinstance(name, x509.DirectoryName):
                sans.append({"type": "DirectoryName", "value": name.value.rfc4514_string()})

        return sans
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []


def cert_to_pem(cert_bytes: bytes) -> str:
    """Convert certificate to PEM format."""
    cert = parse_certificate(cert_bytes)
    if not cert:
        return ""

    try:
        return cert.public_bytes(Encoding.PEM).decode("utf-8")
    except Exception:
        return ""


# Common OIDs
class OID:
    """Common OID constants."""

    # Extended Key Usage
    CLIENT_AUTHENTICATION = "1.3.6.1.5.5.7.3.2"
    SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
    PKINIT_CLIENT_AUTHENTICATION = "1.3.6.1.5.2.3.4"
    ANY_PURPOSE = "2.5.29.37.0"
    CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
    PKCS7_DATA = "1.2.840.113549.1.7.1"

    # Certificate Template
    CERTIFICATE_TEMPLATE = "1.3.6.1.4.1.311.21.7"

    # MS Specific
    MS_DS_ISSUER_CERTIFICATES = "1.3.6.1.4.1.311.21.17"
    MS_ENROLLMENT_AGENT = "1.3.6.1.4.1.311.20.2.1"

    # Authentication EKUs that allow domain authentication
    AUTH_EKUS = [
        CLIENT_AUTHENTICATION,
        SMART_CARD_LOGON,
        PKINIT_CLIENT_AUTHENTICATION,
        ANY_PURPOSE,
    ]
