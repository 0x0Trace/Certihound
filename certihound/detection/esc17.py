"""ESC17 (Server Authentication + Enrollee Supplies Subject) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..utils.crypto import OID
from ..acl.rights import is_low_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class ESC17Result:
    """ESC17 detection result."""

    vulnerable: bool
    template_name: str
    template_dn: str
    ca_name: str
    ca_dn: str
    vulnerable_principals: list[str]
    reasons: list[str]


def detect_esc17(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    domain_sid: str,
) -> ESC17Result | None:
    """
    Detect ESC17 vulnerability.

    ESC17 requires:
    1. ENROLLEE_SUPPLIES_SUBJECT flag set (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    2. Server Authentication EKU (1.3.6.1.5.5.7.3.1) or Any Purpose/No EKU
    3. Manager approval NOT required
    4. No authorized signatures required
    5. Low-privileged principal has enrollment rights
    6. Template is published to the CA

    ESC17 is similar to ESC1 but targets Server Authentication instead of
    Client Authentication. While ESC1 enables domain authentication
    impersonation, ESC17 enables TLS man-in-the-middle attacks against
    services that rely on the system-wide certificate store (e.g., WSUS).

    Attack scenario:
    1. Attacker enrolls for a certificate with Server Auth EKU for a
       target server's DNS name (e.g., WSUS server)
    2. Performs network-level interception (ARP spoofing, DNS poisoning)
    3. Presents the CA-trusted certificate to impersonate the server
    4. Captures NTLM authentication or injects malicious content

    This is particularly dangerous for WSUS because:
    - WSUS clients trust certificates from the enterprise CA
    - No certificate pinning or HSTS is implemented
    - Malicious updates execute with SYSTEM privileges

    Note: Templates that ALSO have Client Authentication EKU will be
    flagged by ESC1. ESC17 specifically targets templates where the
    EKU was "hardened" to only Server Authentication, which does NOT
    prevent abuse.

    Returns ESC17Result if vulnerable, None otherwise.
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

    # Check condition 2: Has Server Authentication EKU (or Any Purpose/No EKU)
    has_server_auth = False
    if not template.ekus:
        has_server_auth = True
        reasons.append("No EKUs specified (allows any purpose including Server Authentication)")
    else:
        server_auth_ekus = []
        if OID.SERVER_AUTHENTICATION in template.ekus:
            server_auth_ekus.append("Server Authentication")
            has_server_auth = True
        if OID.ANY_PURPOSE in template.ekus:
            server_auth_ekus.append("Any Purpose")
            has_server_auth = True
        if server_auth_ekus:
            reasons.append(f"Has Server Authentication EKU: {', '.join(server_auth_ekus)}")

    if not has_server_auth:
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
    reasons.append(
        "Enables TLS MITM attacks against services using system certificate store (e.g., WSUS)"
    )

    return ESC17Result(
        vulnerable=True,
        template_name=template.cn,
        template_dn=template.distinguished_name,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        vulnerable_principals=vulnerable_principals,
        reasons=reasons,
    )
