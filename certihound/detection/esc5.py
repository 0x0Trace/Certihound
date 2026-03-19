"""ESC5 (Vulnerable PKI Object Access Control) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..acl.rights import is_low_privileged_sid, is_high_privileged_sid

if TYPE_CHECKING:
    from ..acl.parser import SecurityDescriptorParser


@dataclass
class ESC5Result:
    """ESC5 detection result."""

    vulnerable: bool
    object_name: str
    object_dn: str
    object_type: str  # "container", "ca", "ntauth", etc.
    vulnerable_principals: list[dict]  # [{sid, rights}]
    reasons: list[str]


def detect_esc5(
    object_name: str,
    object_dn: str,
    object_type: str,
    sd_parser: "SecurityDescriptorParser",
    domain_sid: str,
) -> ESC5Result | None:
    """
    Detect ESC5 vulnerability.

    ESC5: Low-privileged user has dangerous ACLs on PKI AD objects:
    - CN=Public Key Services container
    - CN=Certificate Templates container
    - CN=Certification Authorities container
    - CN=Enrollment Services container
    - CN=NTAuthCertificates object
    - CN=AIA container

    Control over these objects allows:
    - Adding rogue CAs to NTAuth store
    - Modifying CA trust relationships
    - Adding/removing certificate templates from CAs
    - Modifying AIA/CDP distribution points

    Dangerous rights:
    - WriteDacl
    - WriteOwner
    - GenericAll
    - GenericWrite
    - WriteProperty

    Returns ESC5Result if vulnerable, None otherwise.
    """
    reasons: list[str] = []
    vulnerable_principals: list[dict[str, str | list[str] | bool]] = []

    enrollment_rights = sd_parser.get_enrollment_rights()

    for rights in enrollment_rights:
        sid = rights.sid

        # Skip high-privileged principals
        if is_high_privileged_sid(sid, domain_sid):
            continue

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

        if dangerous_rights and is_low_privileged_sid(sid, domain_sid):
            vulnerable_principals.append({
                "sid": sid,
                "rights": dangerous_rights,
                "inherited": rights.inherited,
            })

    if not vulnerable_principals:
        return None

    for vuln_principal in vulnerable_principals:
        rights_list = vuln_principal["rights"]
        if isinstance(rights_list, list):
            rights_str = ", ".join(str(r) for r in rights_list)
        else:
            rights_str = str(rights_list)
        inherited_str = " (inherited)" if vuln_principal["inherited"] else ""
        reasons.append(
            f"{vuln_principal['sid']} has {rights_str} on {object_type} object{inherited_str}"
        )

    return ESC5Result(
        vulnerable=True,
        object_name=object_name,
        object_dn=object_dn,
        object_type=object_type,
        vulnerable_principals=vulnerable_principals,
        reasons=reasons,
    )
