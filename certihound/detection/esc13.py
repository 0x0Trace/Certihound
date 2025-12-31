"""ESC13 (Issuance Policy OID Group Link) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..acl.rights import is_low_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class ESC13Result:
    """ESC13 detection result."""

    vulnerable: bool
    template_name: str
    template_dn: str
    ca_name: str
    ca_dn: str
    issuance_policy_oid: str
    linked_group_dn: str
    vulnerable_principals: list[str]
    reasons: list[str]


def detect_esc13(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    domain_sid: str,
    issuance_policies: dict[str, str] | None = None,  # OID -> linked group DN
) -> ESC13Result | None:
    """
    Detect ESC13 vulnerability.

    ESC13 requires:
    1. Template has an issuance policy OID
    2. That OID is linked to a group (via msDS-OIDToGroupLink)
    3. Certificate with this policy grants membership in linked group
    4. Low-privileged principal has enrollment rights
    5. Template is published to the CA

    Issuance policies are stored in:
    CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,{domain_dn}

    The msDS-OIDToGroupLink attribute links an OID to a security group.

    Returns ESC13Result if vulnerable, None otherwise.
    """
    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return None

    # ESC13 requires issuance policies to be collected
    if not issuance_policies:
        return None

    reasons = []
    vulnerable_principals = []

    # Check if template has any issuance policies linked to groups
    template_policies = template.application_policies  # msPKI-Certificate-Application-Policy

    linked_policy_oid = None
    linked_group_dn = None

    for policy_oid in template_policies:
        if policy_oid in issuance_policies:
            linked_policy_oid = policy_oid
            linked_group_dn = issuance_policies[policy_oid]
            break

    if not linked_policy_oid:
        return None

    reasons.append(f"Template has issuance policy OID: {linked_policy_oid}")
    reasons.append(f"OID is linked to group: {linked_group_dn}")

    # Check authentication EKU (needed for authentication-based group membership)
    if not template.has_authentication_eku:
        return None
    reasons.append("Has authentication EKU")

    # Check manager approval
    if template.requires_manager_approval:
        return None
    reasons.append("Manager approval not required")

    # Check enrollment rights
    for principal_sid in template.enrollment_principals:
        if is_low_privileged_sid(principal_sid, domain_sid):
            vulnerable_principals.append(principal_sid)

    if not vulnerable_principals:
        return None
    reasons.append(f"Low-privileged principals can enroll: {len(vulnerable_principals)} found")

    # At this point, linked_policy_oid and linked_group_dn are guaranteed to be set
    assert linked_group_dn is not None

    return ESC13Result(
        vulnerable=True,
        template_name=template.cn,
        template_dn=template.distinguished_name,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        issuance_policy_oid=linked_policy_oid,
        linked_group_dn=linked_group_dn,
        vulnerable_principals=vulnerable_principals,
        reasons=reasons,
    )


def enumerate_issuance_policies(connection) -> dict[str, str]:
    """
    Enumerate issuance policies with group links.

    Returns dict mapping OID to linked group DN.
    """
    from ldap3 import SUBTREE

    policies = {}

    oid_base = f"CN=OID,CN=Public Key Services,CN=Services,{connection.config.config_dn}"

    try:
        connection.search(
            search_base=oid_base,
            search_filter="(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))",
            attributes=["msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"],
            search_scope=SUBTREE,
        )

        for entry in connection.connection.entries:
            oid = str(entry["msPKI-Cert-Template-OID"]) if entry["msPKI-Cert-Template-OID"] else None
            group_link = (
                str(entry["msDS-OIDToGroupLink"]) if entry["msDS-OIDToGroupLink"] else None
            )

            if oid and group_link:
                policies[oid] = group_link

    except Exception:
        pass

    return policies
