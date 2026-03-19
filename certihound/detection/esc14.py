"""ESC14 (Weak Explicit Certificate Mappings) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..acl.rights import is_low_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class ESC14Result:
    """ESC14 detection result."""

    vulnerable: bool
    template_name: str
    template_dn: str
    ca_name: str
    ca_dn: str
    vulnerable_principals: list[str]
    reasons: list[str]


def detect_esc14(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    domain_sid: str,
    strong_cert_binding_enforced: bool = False,
    alt_security_identities_users: list[str] | None = None,
) -> ESC14Result | None:
    """
    Detect ESC14 vulnerability.

    ESC14: Weak or misconfigured explicit certificate mappings
    (altSecurityIdentities) on AD accounts allow certificates to
    authenticate as unintended users.

    Requirements:
    1. Template has authentication EKU
    2. No manager approval
    3. Strong certificate binding NOT enforced
    4. Users exist with weak altSecurityIdentities mappings
       (e.g., mapping by Issuer only without serial number)
    5. Low-privileged principal has enrollment rights
    6. Template is published to the CA

    When explicit mappings use weak binding (e.g., X509:<I> without
    <SR> or <SKI>), an attacker who can obtain a certificate from
    the same CA can authenticate as the mapped user.

    Returns ESC14Result if vulnerable, None otherwise.
    """
    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return None

    # Strong binding enforcement prevents this attack
    if strong_cert_binding_enforced:
        return None

    reasons = []
    vulnerable_principals = []

    # Check authentication EKU
    if not template.has_authentication_eku:
        return None

    # Check manager approval
    if template.requires_manager_approval:
        return None

    # Check enrollment rights
    for principal_sid in template.enrollment_principals:
        if is_low_privileged_sid(principal_sid, domain_sid):
            vulnerable_principals.append(principal_sid)

    if not vulnerable_principals:
        return None

    reasons.append("Has authentication EKU")
    reasons.append("Manager approval not required")
    reasons.append("Strong certificate binding not enforced")
    reasons.append(f"Low-privileged principals can enroll: {len(vulnerable_principals)} found")

    if alt_security_identities_users:
        reasons.append(
            f"Users with weak altSecurityIdentities mappings: "
            f"{len(alt_security_identities_users)} found"
        )

    return ESC14Result(
        vulnerable=True,
        template_name=template.cn,
        template_dn=template.distinguished_name,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        vulnerable_principals=vulnerable_principals,
        reasons=reasons,
    )
