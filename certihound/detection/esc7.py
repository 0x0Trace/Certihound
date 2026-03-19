"""ESC7 (Dangerous CA Permissions) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..acl.rights import AccessMask, is_low_privileged_sid, is_high_privileged_sid

if TYPE_CHECKING:
    from ..objects.enterpriseca import EnterpriseCA
    from ..acl.parser import SecurityDescriptorParser


# Extended right GUIDs for CA permissions
MANAGE_CA_GUID = "0e10c966-78fb-11d2-90d4-00c04f79dc55"
MANAGE_CERTIFICATES_GUID = "0e10c967-78fb-11d2-90d4-00c04f79dc55"


@dataclass
class ESC7Result:
    """ESC7 detection result."""

    vulnerable: bool
    ca_name: str
    ca_dn: str
    vulnerable_principals: list[dict]  # [{sid, rights}]
    reasons: list[str]


def detect_esc7(
    ca: "EnterpriseCA",
    sd_parser: "SecurityDescriptorParser",
    domain_sid: str,
) -> ESC7Result | None:
    """
    Detect ESC7 vulnerability.

    ESC7: Low-privileged user has ManageCA or ManageCertificates
    permissions on the CA object.

    ManageCA (CA Administrator) allows:
    - Self-assign Certificate Officer role
    - Enable/disable certificate templates
    - Modify CA configuration

    ManageCertificates (Certificate Officer) allows:
    - Approve/deny pending certificate requests
    - Issue certificates from pending requests

    Combined attack: Use ManageCA to grant ManageCertificates,
    then enable SubCA template, request a cert, approve it,
    and retrieve it for domain admin access.

    Returns ESC7Result if vulnerable, None otherwise.
    """
    reasons: list[str] = []
    vulnerable_principals: list[dict[str, str | list[str]]] = []

    sd = sd_parser.parse()
    if not sd.dacl:
        return None

    # Track permissions per SID
    permissions_by_sid: dict[str, list[str]] = {}

    for ace in sd.dacl.aces:
        if not ace.is_allow:
            continue

        sid = ace.sid

        # Skip high-privileged principals
        if is_high_privileged_sid(sid, domain_sid):
            continue

        # Skip non-low-privileged principals
        if not is_low_privileged_sid(sid, domain_sid):
            continue

        if sid not in permissions_by_sid:
            permissions_by_sid[sid] = []

        # Check for GenericAll (includes everything)
        if ace.access_mask & AccessMask.GENERIC_ALL:
            if "ManageCA" not in permissions_by_sid[sid]:
                permissions_by_sid[sid].append("ManageCA")
            if "ManageCertificates" not in permissions_by_sid[sid]:
                permissions_by_sid[sid].append("ManageCertificates")

        # Check for ManageCA extended right
        if ace.access_mask & AccessMask.DS_CONTROL_ACCESS:
            if ace.object_type == MANAGE_CA_GUID:
                if "ManageCA" not in permissions_by_sid[sid]:
                    permissions_by_sid[sid].append("ManageCA")
            elif ace.object_type == MANAGE_CERTIFICATES_GUID:
                if "ManageCertificates" not in permissions_by_sid[sid]:
                    permissions_by_sid[sid].append("ManageCertificates")
            elif not ace.object_type:
                # No object type = all extended rights
                if "ManageCA" not in permissions_by_sid[sid]:
                    permissions_by_sid[sid].append("ManageCA")
                if "ManageCertificates" not in permissions_by_sid[sid]:
                    permissions_by_sid[sid].append("ManageCertificates")

        # WriteDacl allows granting oneself ManageCA/ManageCertificates
        if ace.access_mask & AccessMask.WRITE_DAC:
            if "WriteDacl" not in permissions_by_sid[sid]:
                permissions_by_sid[sid].append("WriteDacl")

        # WriteOwner allows taking ownership then modifying DACL
        if ace.access_mask & AccessMask.WRITE_OWNER:
            if "WriteOwner" not in permissions_by_sid[sid]:
                permissions_by_sid[sid].append("WriteOwner")

    # Build results for principals with dangerous CA permissions
    for sid, perms in permissions_by_sid.items():
        if perms:
            vulnerable_principals.append({
                "sid": sid,
                "rights": perms,
            })

    if not vulnerable_principals:
        return None

    for vuln_principal in vulnerable_principals:
        rights_str = ", ".join(str(r) for r in vuln_principal["rights"])
        reasons.append(f"{vuln_principal['sid']} has: {rights_str} on CA")

    return ESC7Result(
        vulnerable=True,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        vulnerable_principals=vulnerable_principals,
        reasons=reasons,
    )
