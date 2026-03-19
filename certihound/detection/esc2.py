"""ESC2 (Any Purpose EKU / No EKU) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..utils.crypto import OID
from ..acl.rights import is_low_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class ESC2Result:
    """ESC2 detection result."""

    vulnerable: bool
    template_name: str
    template_dn: str
    ca_name: str
    ca_dn: str
    vulnerable_principals: list[str]
    reasons: list[str]


def detect_esc2(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    domain_sid: str,
) -> ESC2Result | None:
    """
    Detect ESC2 vulnerability.

    ESC2 requires:
    1. Template has Any Purpose EKU (2.5.29.37.0) OR no EKU at all
    2. Template does NOT have ENROLLEE_SUPPLIES_SUBJECT (that would be ESC1)
    3. Manager approval NOT required
    4. No authorized signatures required
    5. Low-privileged principal has enrollment rights
    6. Template is published to the CA

    Templates with Any Purpose EKU or no EKU can be used as enrollment
    agent certificates (like Certificate Request Agent), allowing the
    holder to request certificates on behalf of other users.

    Returns ESC2Result if vulnerable, None otherwise.
    """
    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return None

    reasons = []
    vulnerable_principals = []

    # Check condition 1: Has Any Purpose EKU or no EKU
    has_any_purpose = OID.ANY_PURPOSE in template.ekus
    has_no_eku = not template.ekus

    if not (has_any_purpose or has_no_eku):
        return None

    if has_no_eku:
        reasons.append("No EKUs specified (allows any purpose including enrollment agent)")
    else:
        reasons.append("Has Any Purpose EKU (2.5.29.37.0)")

    # Check condition 2: NOT enrollee supplies subject (that's ESC1)
    if template.enrollee_supplies_subject:
        return None

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

    return ESC2Result(
        vulnerable=True,
        template_name=template.cn,
        template_dn=template.distinguished_name,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        vulnerable_principals=vulnerable_principals,
        reasons=reasons,
    )
