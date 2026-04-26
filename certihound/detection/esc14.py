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
    strong_cert_binding_enforced: bool | None = None,
    alt_security_identities_users: list[str] | None = None,
) -> ESC14Result | None:
    """
    Detect ESC14 vulnerability.

    ESC14: Weak or misconfigured explicit certificate mappings
    (altSecurityIdentities) on AD accounts allow certificates to
    authenticate as unintended users.

    Requirements (all must hold to flag):
    1. Template is published to the CA
    2. Template has authentication EKU
    3. No manager approval
    4. Low-privileged principal has enrollment rights
    5. Strong certificate binding NOT enforced (DC registry value
       StrongCertificateBindingEnforcement != 2)
    6. At least one AD account has a weak altSecurityIdentities
       mapping (e.g., X509:<I>... without <SR>/<SKI>/<PN>)

    Conditions 5 and 6 are *external* signals that cannot be
    determined from the cert template alone. If the caller cannot
    supply them (None / empty), this function returns None — an
    auth-capable enrollable template is NOT, by itself, ESC14.

    Returns ESC14Result if vulnerable, None otherwise.
    """
    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return None

    # External preconditions must be known and unfavorable. If the caller
    # didn't (or couldn't) supply them, decline to flag — this is what
    # used to false-positive on every auth-capable enrollable template.
    if strong_cert_binding_enforced is None or strong_cert_binding_enforced:
        return None
    if not alt_security_identities_users:
        return None

    # Template-side preconditions
    if not template.has_authentication_eku:
        return None
    if template.requires_manager_approval:
        return None

    vulnerable_principals = [
        sid
        for sid in template.enrollment_principals
        if is_low_privileged_sid(sid, domain_sid)
    ]
    if not vulnerable_principals:
        return None

    reasons = [
        "Has authentication EKU",
        "Manager approval not required",
        "Strong certificate binding not enforced (DC StrongCertificateBindingEnforcement != 2)",
        f"Low-privileged principals can enroll: {len(vulnerable_principals)} found",
        f"AD accounts with weak altSecurityIdentities mappings: "
        f"{len(alt_security_identities_users)} found",
    ]

    return ESC14Result(
        vulnerable=True,
        template_name=template.cn,
        template_dn=template.distinguished_name,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        vulnerable_principals=vulnerable_principals,
        reasons=reasons,
    )
