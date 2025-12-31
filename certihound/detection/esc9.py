"""ESC9 (No Security Extension) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..acl.rights import is_low_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class ESC9Result:
    """ESC9 detection result."""

    vulnerable: bool
    template_name: str
    template_dn: str
    ca_name: str
    ca_dn: str
    vulnerable_principals: list[str]
    reasons: list[str]
    variant: str  # "a" (UPN) or "b" (DNS)


def detect_esc9(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    domain_sid: str,
    strong_cert_binding_enforced: bool = False,
) -> list[ESC9Result]:
    """
    Detect ESC9 vulnerability (both variants).

    ESC9 requires:
    1. CT_FLAG_NO_SECURITY_EXTENSION flag set (removes szOID_NTDS_CA_SECURITY_EXT)
    2. Strong certificate binding NOT enforced (StrongCertificateBindingEnforcement != 2)
    3. Authentication EKU
    4. No manager approval
    5. Low-privileged principal has enrollment rights
    6. Template is published to the CA

    ESC9a (UPN mapping): Template requires UPN in SAN, does NOT require DNS
    ESC9b (DNS mapping): Template requires DNS in SAN (computer accounts)

    When the security extension is missing and strong binding isn't enforced,
    an attacker can potentially impersonate another user.

    Returns list of ESC9Result if vulnerable.
    """
    results: list[ESC9Result] = []

    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return results

    # Check if strong certificate binding is enforced
    if strong_cert_binding_enforced:
        return results

    # Check NO_SECURITY_EXTENSION flag using the computed property
    if not template.no_security_extension:
        return results

    # Check authentication EKU
    if not template.has_authentication_eku:
        return results

    # Check manager approval
    if template.requires_manager_approval:
        return results

    # Check enrollment rights
    vulnerable_principals = []
    for principal_sid in template.enrollment_principals:
        if is_low_privileged_sid(principal_sid, domain_sid):
            vulnerable_principals.append(principal_sid)

    if not vulnerable_principals:
        return results

    base_reasons = [
        "CT_FLAG_NO_SECURITY_EXTENSION is set",
        "Strong certificate binding not enforced",
        "Has authentication EKU",
        "Manager approval not required",
        f"Low-privileged principals can enroll: {len(vulnerable_principals)} found",
    ]

    # ESC9a: UPN mapping (for user impersonation)
    # Template requires UPN in SAN, but NOT DNS
    if template.subject_alt_require_upn and not template.subject_alt_require_dns:
        results.append(ESC9Result(
            vulnerable=True,
            template_name=template.cn,
            template_dn=template.distinguished_name,
            ca_name=ca.cn,
            ca_dn=ca.distinguished_name,
            vulnerable_principals=vulnerable_principals,
            reasons=base_reasons + ["Template requires UPN in SAN (ESC9a)"],
            variant="a",
        ))

    # ESC9b: DNS mapping (for computer impersonation)
    # Template requires DNS in SAN
    if template.subject_alt_require_dns:
        results.append(ESC9Result(
            vulnerable=True,
            template_name=template.cn,
            template_dn=template.distinguished_name,
            ca_name=ca.cn,
            ca_dn=ca.distinguished_name,
            vulnerable_principals=vulnerable_principals,
            reasons=base_reasons + ["Template requires DNS in SAN (ESC9b)"],
            variant="b",
        ))

    return results
