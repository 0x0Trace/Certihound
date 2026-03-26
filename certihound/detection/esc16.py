"""ESC16 (Security Extension Disabled on CA) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..acl.rights import is_low_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class ESC16Result:
    """ESC16 detection result.

    Unlike most ESC types, ESC16 is a CA-level misconfiguration.
    The edge goes from the Enterprise CA to the Domain, not from
    individual enrollment principals.

    Exploitation requires a separate prerequisite: GenericWrite or
    GenericAll on a target user's userPrincipalName, which is outside
    ADCS scope and must be evaluated via full AD graph analysis.
    """

    vulnerable: bool
    ca_name: str
    ca_dn: str
    template_name: str
    template_dn: str
    reasons: list[str]
    vulnerable_principals: list[str] = field(default_factory=list)


def detect_esc16(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    domain_sid: str,
    strong_cert_binding_enforced: bool = False,
) -> ESC16Result | None:
    """
    Detect ESC16 vulnerability.

    ESC16: The CA is configured to globally disable the SID security
    extension (szOID_NTDS_CA_SECURITY_EXT) for ALL issued certificates,
    regardless of template settings.

    This is similar to ESC9 but at the CA level. When the security
    extension is globally disabled:
    1. No certificates from this CA include the SID extension
    2. KDC falls back to UPN/SAN-based identity mapping
    3. Attacker with GenericWrite on a target's UPN can change it,
       request a cert, and authenticate as the target

    Requirements:
    1. CA has security extension disabled globally
    2. Template has authentication EKU
    3. No manager approval required
    4. Strong certificate binding NOT enforced
    5. Low-privileged principal has enrollment rights
    6. Template is published to the CA
    7. (Not checked here) Attacker has GenericWrite/GenericAll on a
       target user's userPrincipalName — this is a graph-level check

    Note: The edge is emitted from the Enterprise CA to the Domain,
    NOT from individual enrollment principals. This is because ESC16
    exploitation requires GenericWrite on a target's UPN, which we
    cannot determine from ADCS data alone.

    Returns ESC16Result if vulnerable, None otherwise.
    """
    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return None

    # Check if CA has security extension disabled
    if not ca.is_security_extension_disabled:
        return None

    # Strong binding enforcement mitigates this
    if strong_cert_binding_enforced:
        return None

    # Check authentication EKU
    if not template.has_authentication_eku:
        return None

    # Check manager approval
    if template.requires_manager_approval:
        return None

    # Verify at least one low-privileged principal can enroll
    # (the misconfiguration is only relevant if enrollment is possible)
    has_low_priv_enrollment = any(
        is_low_privileged_sid(sid, domain_sid)
        for sid in template.enrollment_principals
    )

    if not has_low_priv_enrollment:
        return None

    reasons = [
        "CA has szOID_NTDS_CA_SECURITY_EXT globally disabled",
        "No certificates from this CA include the SID security extension",
        "KDC falls back to UPN-based identity mapping",
        "Has authentication EKU",
        "Manager approval not required",
        "Strong certificate binding not enforced",
        "Exploitation requires GenericWrite on a target user's UPN",
    ]

    # Return without vulnerable_principals — the edge goes from
    # the Enterprise CA to the Domain (CA-level misconfiguration)
    return ESC16Result(
        vulnerable=True,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        template_name=template.cn,
        template_dn=template.distinguished_name,
        reasons=reasons,
    )
