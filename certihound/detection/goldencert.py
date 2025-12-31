"""Golden Certificate vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class GoldenCertResult:
    """Golden Certificate detection result."""

    ca_name: str
    ca_dn: str
    ca_computer_sid: str
    reasons: list[str]


def detect_goldencert(
    ca: "EnterpriseCA",
    ca_computer_compromised: bool = False,
) -> GoldenCertResult | None:
    """
    Detect Golden Certificate attack path.

    Golden Certificate attack:
    1. Attacker compromises the CA computer
    2. Extracts CA private key
    3. Can forge any certificate (including Domain Admin certs)
    4. These forged certs are trusted by the domain

    This detection is more of a documentation/path visualization
    rather than a misconfiguration detection.

    The edge is: Computer --GoldenCert--> Domain

    Returns GoldenCertResult if CA is vulnerable (always for Enterprise CAs).
    """
    if not ca.hosting_computer_sid:
        return None

    reasons = [
        "CA private key stored on hosting computer",
        "Compromising this computer allows forging any certificate",
        "Forged certificates trusted for domain authentication",
    ]

    return GoldenCertResult(
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        ca_computer_sid=ca.hosting_computer_sid,
        reasons=reasons,
    )


def get_goldencert_edge(ca: "EnterpriseCA", domain_sid: str) -> dict | None:
    """
    Generate GoldenCert edge for BloodHound.

    Edge: Computer (CA host) --GoldenCert--> Domain
    """
    if not ca.hosting_computer_sid:
        return None

    return {
        "StartNode": ca.hosting_computer_sid,
        "EndNode": domain_sid,
        "EdgeType": "GoldenCert",
        "EdgeProps": {
            "isacl": False,
            "caname": ca.cn,
            "cadistinguishedname": ca.distinguished_name,
        },
    }
