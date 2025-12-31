"""ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..acl.rights import is_low_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class ESC6Result:
    """ESC6 detection result."""

    vulnerable: bool
    ca_name: str
    ca_dn: str
    template_name: str
    template_dn: str
    vulnerable_principals: list[str]
    reasons: list[str]
    variant: str  # "a" (Kerberos) or "b" (Schannel)


def detect_esc6(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    domain_sid: str,
    strong_cert_binding_enforced: bool = False,
    cert_mapping_methods: int = 0,
) -> list[ESC6Result]:
    """
    Detect ESC6 vulnerability (both variants).

    ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2 abuse):
    - ESC6a: Kerberos authentication (when no_security_extension or weak binding)
    - ESC6b: Schannel authentication (when UPN mapping enabled)

    Base requirements:
    1. CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled (in registry)
    2. Template has authentication EKU
    3. No manager approval required
    4. Low-privileged principal has enrollment rights
    5. Template is published to the CA

    ESC6a additional requirements:
    - Template has NO_SECURITY_EXTENSION flag OR strong binding not enforced

    ESC6b additional requirements:
    - Schannel UPN mapping enabled (CertificateMappingMethods & 0x4)

    Note: The EDITF_ATTRIBUTESUBJECTALTNAME2 flag allows requesters to specify
    a SAN in the CSR, even if the template doesn't allow it.

    Returns list of ESC6Result if vulnerable.
    """
    results: list[ESC6Result] = []

    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return results

    # Check if CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
    if not ca.is_user_specifies_san_enabled:
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
        "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
        "Template has authentication EKU",
        "Manager approval not required",
        f"Low-privileged principals can enroll: {len(vulnerable_principals)} found",
    ]

    # ESC6a: Kerberos authentication path
    # Requires NO_SECURITY_EXTENSION OR weak certificate binding
    if template.no_security_extension or not strong_cert_binding_enforced:
        reasons_6a = base_reasons.copy()
        if template.no_security_extension:
            reasons_6a.append("Template has NO_SECURITY_EXTENSION flag (ESC6a)")
        else:
            reasons_6a.append("Strong certificate binding not enforced (ESC6a)")

        results.append(ESC6Result(
            vulnerable=True,
            ca_name=ca.cn,
            ca_dn=ca.distinguished_name,
            template_name=template.cn,
            template_dn=template.distinguished_name,
            vulnerable_principals=vulnerable_principals,
            reasons=reasons_6a,
            variant="a",
        ))

    # ESC6b: Schannel authentication path
    # Requires Schannel UPN mapping enabled
    UPN_MAPPING_FLAG = 0x4
    if cert_mapping_methods & UPN_MAPPING_FLAG:
        results.append(ESC6Result(
            vulnerable=True,
            ca_name=ca.cn,
            ca_dn=ca.distinguished_name,
            template_name=template.cn,
            template_dn=template.distinguished_name,
            vulnerable_principals=vulnerable_principals,
            reasons=base_reasons + ["Schannel UPN mapping enabled (ESC6b)"],
            variant="b",
        ))

    return results


def check_esc6_ca_flag(edit_flags: int) -> bool:
    """
    Check if EDITF_ATTRIBUTESUBJECTALTNAME2 is set in CA EditFlags.

    EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
    """
    EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
    return bool(edit_flags & EDITF_ATTRIBUTESUBJECTALTNAME2)
