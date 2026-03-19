"""ESC8 (NTLM Relay to AD CS Web Enrollment) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class ESC8Result:
    """ESC8 detection result."""

    vulnerable: bool
    ca_name: str
    ca_dn: str
    web_enrollment_url: str
    reasons: list[str]


def detect_esc8(
    ca: "EnterpriseCA",
) -> ESC8Result | None:
    """
    Detect ESC8 vulnerability.

    ESC8: AD CS HTTP(S) web enrollment endpoints vulnerable to NTLM relay.

    When web enrollment is enabled without Extended Protection for
    Authentication (EPA/Channel Binding), an attacker can:
    1. Coerce a privileged account (e.g., DC machine account via PetitPotam)
    2. Relay the NTLM authentication to the web enrollment endpoint
    3. Request a certificate as the relayed account
    4. Use the certificate for domain authentication

    Detection via LDAP:
    - Check enrollment endpoints in msPKI-Enrollment-Servers
    - Check if CA has web enrollment flag enabled
    - The HTTP endpoint is typically: http(s)://<ca-hostname>/certsrv/

    Note: Full ESC8 validation requires network-level checks for EPA
    that cannot be done via LDAP alone. This detection flags CAs that
    have web enrollment configured.

    Returns ESC8Result if vulnerable, None otherwise.
    """
    if not ca.web_enrollment_enabled:
        return None

    reasons = [
        "CA has web enrollment (HTTP) endpoint enabled",
        "Web enrollment interfaces are vulnerable to NTLM relay if EPA is not enforced",
        "Attacker can coerce authentication (e.g., PetitPotam) and relay to enroll as victim",
    ]

    # Build the likely web enrollment URL
    hostname = ca.dns_hostname or ca.cn
    web_url = f"https://{hostname}/certsrv/"

    if ca.enrollment_endpoints:
        reasons.append(f"Enrollment endpoints configured: {len(ca.enrollment_endpoints)} found")
        web_url = ca.enrollment_endpoints[0]

    return ESC8Result(
        vulnerable=True,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        web_enrollment_url=web_url,
        reasons=reasons,
    )
