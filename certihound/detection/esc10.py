"""ESC10 (Weak Certificate Mapping) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..acl.rights import is_low_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class ESC10Result:
    """ESC10 detection result."""

    vulnerable: bool
    template_name: str
    template_dn: str
    ca_name: str
    ca_dn: str
    vulnerable_principals: list[str]
    reasons: list[str]
    variant: str  # "a" or "b"


def detect_esc10(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    domain_sid: str,
    cert_mapping_methods: int = 0,
    strong_cert_binding_enforced: bool = False,
) -> list[ESC10Result]:
    """
    Detect ESC10 vulnerability (both variants).

    ESC10 (Weak Certificate Mapping - Schannel):
    - ESC10a: UPN mapping abuse (for user impersonation)
    - ESC10b: DNS mapping abuse (for computer impersonation)

    ESC10a requires:
    1. Template allows authentication
    2. Weak certificate mapping enabled (CertificateMappingMethods includes UPN mapping = 0x4)
    3. No strong certificate binding enforcement
    4. Template requires UPN in SAN but NOT DNS
    5. Low-privileged principal has enrollment rights

    ESC10b requires:
    1. Template allows authentication
    2. Weak certificate mapping enabled
    3. Template requires DNS in SAN
    4. Low-privileged principal has enrollment rights
    5. Template is published to the CA

    Returns list of ESC10Result if vulnerable.
    """
    results: list[ESC10Result] = []

    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
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

    # Certificate mapping flags
    UPN_MAPPING_FLAG = 0x4  # Schannel UPN mapping

    base_reasons = [
        "Has authentication EKU",
        "Manager approval not required",
        f"Low-privileged principals can enroll: {len(vulnerable_principals)} found",
    ]

    # ESC10a: UPN mapping (for user impersonation via Schannel)
    # Template requires UPN in SAN, does NOT require DNS
    if (cert_mapping_methods & UPN_MAPPING_FLAG) and not strong_cert_binding_enforced:
        if template.subject_alt_require_upn and not template.subject_alt_require_dns:
            results.append(ESC10Result(
                vulnerable=True,
                template_name=template.cn,
                template_dn=template.distinguished_name,
                ca_name=ca.cn,
                ca_dn=ca.distinguished_name,
                vulnerable_principals=vulnerable_principals,
                reasons=base_reasons + [
                    "Schannel UPN certificate mapping enabled",
                    "Strong certificate binding not enforced",
                    "Template requires UPN in SAN (ESC10a)",
                ],
                variant="a",
            ))

    # ESC10b: DNS mapping (for computer impersonation via Schannel)
    # Template requires DNS in SAN
    if (cert_mapping_methods & UPN_MAPPING_FLAG) and not strong_cert_binding_enforced:
        if template.subject_alt_require_dns:
            results.append(ESC10Result(
                vulnerable=True,
                template_name=template.cn,
                template_dn=template.distinguished_name,
                ca_name=ca.cn,
                ca_dn=ca.distinguished_name,
                vulnerable_principals=vulnerable_principals,
                reasons=base_reasons + [
                    "Schannel certificate mapping enabled",
                    "Strong certificate binding not enforced",
                    "Template requires DNS in SAN (ESC10b)",
                ],
                variant="b",
            ))

    return results


def check_certificate_mapping_methods(methods: int) -> dict[str, bool]:
    """
    Analyze CertificateMappingMethods registry value.

    Registry key: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel
    Value: CertificateMappingMethods

    Methods:
    - 0x0001: Subject/Issuer mapping
    - 0x0002: Issuer mapping
    - 0x0004: UPN mapping (SAN)
    - 0x0008: S4U2Self mapping
    """
    return {
        "subject_issuer_mapping": bool(methods & 0x0001),
        "issuer_mapping": bool(methods & 0x0002),
        "upn_mapping": bool(methods & 0x0004),
        "s4u2self_mapping": bool(methods & 0x0008),
    }
