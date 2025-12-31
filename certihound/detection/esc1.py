"""ESC1 (Enrollee Supplies Subject) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..utils.crypto import OID
from ..acl.rights import is_low_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class ESC1Result:
    """ESC1 detection result."""

    vulnerable: bool
    template_name: str
    template_dn: str
    ca_name: str
    ca_dn: str
    vulnerable_principals: list[str]
    reasons: list[str]


def detect_esc1(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    domain_sid: str,
) -> ESC1Result | None:
    """
    Detect ESC1 vulnerability.

    ESC1 requires:
    1. ENROLLEE_SUPPLIES_SUBJECT flag set (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001)
    2. Client Authentication or Smart Card Logon EKU (or Any Purpose/No EKU)
    3. Manager approval NOT required
    4. No authorized signatures required (or <= 0)
    5. Low-privileged principal has enrollment rights
    6. Template is published to the CA

    Returns ESC1Result if vulnerable, None otherwise.
    """
    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return None

    reasons = []
    vulnerable_principals = []

    # Check condition 1: Enrollee supplies subject
    if not template.enrollee_supplies_subject:
        return None
    reasons.append("Enrollee can supply subject name (ENROLLEE_SUPPLIES_SUBJECT flag set)")

    # Check condition 2: Has authentication EKU
    if not template.has_authentication_eku:
        return None

    if not template.ekus:
        reasons.append("No EKUs specified (allows any purpose including authentication)")
    else:
        auth_ekus_present = []
        if OID.CLIENT_AUTHENTICATION in template.ekus:
            auth_ekus_present.append("Client Authentication")
        if OID.SMART_CARD_LOGON in template.ekus:
            auth_ekus_present.append("Smart Card Logon")
        if OID.PKINIT_CLIENT_AUTHENTICATION in template.ekus:
            auth_ekus_present.append("PKINIT Client Authentication")
        if OID.ANY_PURPOSE in template.ekus:
            auth_ekus_present.append("Any Purpose")
        reasons.append(f"Has authentication EKU: {', '.join(auth_ekus_present)}")

    # Check condition 3: No manager approval
    if template.requires_manager_approval:
        return None
    reasons.append("Manager approval not required")

    # Check condition 4: No authorized signatures
    if not template.no_signature_required:
        return None
    reasons.append("No authorized signatures required")

    # Check condition 5: Low-privileged principals have enrollment rights
    for principal_sid in template.enrollment_principals:
        if is_low_privileged_sid(principal_sid, domain_sid):
            vulnerable_principals.append(principal_sid)

    if not vulnerable_principals:
        return None
    reasons.append(f"Low-privileged principals can enroll: {len(vulnerable_principals)} found")

    return ESC1Result(
        vulnerable=True,
        template_name=template.cn,
        template_dn=template.distinguished_name,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        vulnerable_principals=vulnerable_principals,
        reasons=reasons,
    )


def check_esc1_conditions(template: "CertTemplate") -> dict[str, bool]:
    """
    Check individual ESC1 conditions without requiring CA or enrollment rights.
    Useful for preliminary analysis.
    """
    return {
        "enrollee_supplies_subject": template.enrollee_supplies_subject,
        "has_authentication_eku": template.has_authentication_eku,
        "no_manager_approval": not template.requires_manager_approval,
        "no_signature_required": template.no_signature_required,
    }
