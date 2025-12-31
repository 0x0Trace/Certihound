"""ESC4 (Template ACL Abuse) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..acl.rights import is_low_privileged_sid, is_high_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA
    from ..acl.parser import SecurityDescriptorParser


@dataclass
class ESC4Result:
    """ESC4 detection result."""

    vulnerable: bool
    template_name: str
    template_dn: str
    ca_name: str
    ca_dn: str
    vulnerable_principals: list[dict]  # [{sid, rights}]
    reasons: list[str]


def detect_esc4(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    sd_parser: "SecurityDescriptorParser",
    domain_sid: str,
) -> ESC4Result | None:
    """
    Detect ESC4 vulnerability.

    ESC4: Low-privileged user has write access to template, allowing them to:
    - Modify template to enable ESC1 conditions
    - Change enrollment requirements
    - Modify EKUs

    Dangerous rights:
    - WriteDacl (can grant themselves any rights)
    - WriteOwner (can take ownership and modify DACL)
    - GenericAll (full control)
    - GenericWrite (can modify all properties)
    - WriteProperty on dangerous attributes

    Returns ESC4Result if vulnerable, None otherwise.
    """
    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return None

    reasons: list[str] = []
    vulnerable_principals: list[dict[str, str | list[str] | bool]] = []

    # Get enrollment rights from security descriptor
    enrollment_rights = sd_parser.get_enrollment_rights()

    for rights in enrollment_rights:
        sid = rights.sid

        # Skip high-privileged principals
        if is_high_privileged_sid(sid, domain_sid):
            continue

        # Check for dangerous permissions
        dangerous_rights = []

        if rights.write_dacl:
            dangerous_rights.append("WriteDacl")
        if rights.write_owner:
            dangerous_rights.append("WriteOwner")
        if rights.generic_all:
            dangerous_rights.append("GenericAll")
        if rights.generic_write:
            dangerous_rights.append("GenericWrite")
        if rights.write_property:
            dangerous_rights.append("WriteProperty")

        if dangerous_rights:
            # Only flag if it's a low-privileged principal or unknown
            if is_low_privileged_sid(sid, domain_sid):
                vulnerable_principals.append({
                    "sid": sid,
                    "rights": dangerous_rights,
                    "inherited": rights.inherited,
                })

    if not vulnerable_principals:
        return None

    # Build reasons
    for vuln_principal in vulnerable_principals:
        rights_list = vuln_principal["rights"]
        if isinstance(rights_list, list):
            rights_str = ", ".join(str(r) for r in rights_list)
        else:
            rights_str = str(rights_list)
        inherited_str = " (inherited)" if vuln_principal["inherited"] else ""
        reasons.append(f"{vuln_principal['sid']} has: {rights_str}{inherited_str}")

    return ESC4Result(
        vulnerable=True,
        template_name=template.cn,
        template_dn=template.distinguished_name,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        vulnerable_principals=vulnerable_principals,
        reasons=reasons,
    )


def analyze_template_acl(
    template: "CertTemplate",
    sd_parser: "SecurityDescriptorParser",
    domain_sid: str,
) -> dict:
    """
    Analyze template ACL for potential issues.

    Returns a summary of ACL findings.
    """
    enrollment_rights = sd_parser.get_enrollment_rights()

    enrollment_principals: list[dict] = []
    write_principals: list[dict] = []
    dangerous_principals: list[str] = []

    for rights in enrollment_rights:
        sid = rights.sid
        is_low_priv = is_low_privileged_sid(sid, domain_sid)
        is_high_priv = is_high_privileged_sid(sid, domain_sid)

        if rights.can_enroll:
            enrollment_principals.append({
                "sid": sid,
                "is_low_privileged": is_low_priv,
                "is_high_privileged": is_high_priv,
            })

        if rights.has_dangerous_permissions:
            write_principals.append({
                "sid": sid,
                "rights": {
                    "write_dacl": rights.write_dacl,
                    "write_owner": rights.write_owner,
                    "generic_all": rights.generic_all,
                    "generic_write": rights.generic_write,
                    "write_property": rights.write_property,
                },
                "is_low_privileged": is_low_priv,
            })

            if is_low_priv:
                dangerous_principals.append(sid)

    return {
        "total_aces": len(enrollment_rights),
        "enrollment_principals": enrollment_principals,
        "write_principals": write_principals,
        "dangerous_principals": dangerous_principals,
    }
