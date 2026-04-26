"""ESC11 (NTLM Relay to AD CS RPC Endpoints) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..objects.enterpriseca import EnterpriseCA


# CA flag for enforcing encryption on ICPR requests
IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200


@dataclass
class ESC11Result:
    """ESC11 detection result."""

    vulnerable: bool
    ca_name: str
    ca_dn: str
    reasons: list[str]


def detect_esc11(
    ca: "EnterpriseCA",
) -> ESC11Result | None:
    """
    Detect ESC11 vulnerability.

    ESC11: AD CS RPC (ICPR) endpoints do not enforce encryption,
    allowing NTLM relay attacks.

    The IF_ENFORCEENCRYPTICERTREQUEST bit (0x200) lives in the CA's
    InterfaceFlags registry value (HKLM\\SYSTEM\\CurrentControlSet\\
    Services\\CertSvc\\Configuration\\<CA>\\InterfaceFlags), readable
    only via remote registry. It is NOT in the LDAP `flags` attribute
    on pKIEnrollmentService (which uses a different bit layout).

    When the bit is NOT set:
    1. Attacker can relay NTLM authentication to the RPC endpoint
    2. Request certificates as the relayed account
    3. Use the certificate for domain authentication

    This is similar to ESC8 but targets the RPC interface instead of HTTP.

    Returns ESC11Result if vulnerable, None when the bit is set OR when
    InterfaceFlags couldn't be retrieved (Unknown — never flag on guess).
    """
    # If InterfaceFlags couldn't be determined (e.g. RRP unreachable or
    # insufficient privileges), don't flag — we can't confirm the
    # misconfiguration exists, and the LDAP `flags` attribute is the
    # wrong source for this bit.
    if ca.interface_flags is None:
        return None

    # Check if encryption enforcement is missing
    if ca.interface_flags & IF_ENFORCEENCRYPTICERTREQUEST:
        return None

    reasons = [
        "CA does not enforce RPC encryption (IF_ENFORCEENCRYPTICERTREQUEST not set in InterfaceFlags)",
        "ICPR interface accepts unencrypted requests",
        "Attacker can relay NTLM authentication to RPC endpoint for certificate enrollment",
    ]

    return ESC11Result(
        vulnerable=True,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        reasons=reasons,
    )
