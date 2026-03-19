"""ESC15 (EKUwu - Application Policy on Schema V1 Templates) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..acl.rights import is_low_privileged_sid, is_high_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA
    from ..acl.parser import SecurityDescriptorParser


@dataclass
class ESC15Result:
    """ESC15 detection result."""

    vulnerable: bool
    template_name: str
    template_dn: str
    ca_name: str
    ca_dn: str
    vulnerable_principals: list[dict]  # [{sid, rights}]
    reasons: list[str]


def detect_esc15(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    sd_parser: "SecurityDescriptorParser",
    domain_sid: str,
) -> ESC15Result | None:
    """
    Detect ESC15 vulnerability (EKUwu).

    ESC15: Schema Version 1 templates interpret the msPKI-RA-Application-Policies
    attribute differently than V2+ templates. In V1 templates, this attribute
    controls the Application Policies extension, which can include EKUs.

    An attacker with WriteProperty on msPKI-RA-Application-Policies of a V1
    template can:
    1. Set the attribute to include Client Authentication OID
    2. The issued certificate will contain the authentication EKU
    3. Use the certificate for domain authentication

    Requirements:
    1. Schema Version 1 template
    2. Low-privileged principal has WriteProperty on the template
       (specifically on msPKI-RA-Application-Policies)
    3. No manager approval required
    4. Template is published to the CA

    Returns ESC15Result if vulnerable, None otherwise.
    """
    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return None

    # ESC15 specifically targets Schema Version 1 templates
    if template.schema_version != 1:
        return None

    # Check manager approval
    if template.requires_manager_approval:
        return None

    reasons: list[str] = []
    vulnerable_principals: list[dict[str, str | list[str] | bool]] = []

    enrollment_rights = sd_parser.get_enrollment_rights()

    for rights in enrollment_rights:
        sid = rights.sid

        # Skip high-privileged principals
        if is_high_privileged_sid(sid, domain_sid):
            continue

        if not is_low_privileged_sid(sid, domain_sid):
            continue

        dangerous_rights = []

        # WriteProperty allows modifying msPKI-RA-Application-Policies
        if rights.write_property:
            dangerous_rights.append("WriteProperty")
        if rights.generic_all:
            dangerous_rights.append("GenericAll")
        if rights.generic_write:
            dangerous_rights.append("GenericWrite")
        if rights.write_dacl:
            dangerous_rights.append("WriteDacl")
        if rights.write_owner:
            dangerous_rights.append("WriteOwner")

        if dangerous_rights:
            vulnerable_principals.append({
                "sid": sid,
                "rights": dangerous_rights,
                "inherited": rights.inherited,
            })

    if not vulnerable_principals:
        return None

    reasons.append("Schema Version 1 template")
    reasons.append("V1 templates use msPKI-RA-Application-Policies for EKU extension")
    reasons.append("Manager approval not required")

    for vuln_principal in vulnerable_principals:
        rights_list = vuln_principal["rights"]
        if isinstance(rights_list, list):
            rights_str = ", ".join(str(r) for r in rights_list)
        else:
            rights_str = str(rights_list)
        inherited_str = " (inherited)" if vuln_principal.get("inherited") else ""
        reasons.append(f"{vuln_principal['sid']} has: {rights_str}{inherited_str}")

    return ESC15Result(
        vulnerable=True,
        template_name=template.cn,
        template_dn=template.distinguished_name,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        vulnerable_principals=vulnerable_principals,
        reasons=reasons,
    )
