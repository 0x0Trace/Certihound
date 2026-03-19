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

    The IF_ENFORCEENCRYPTICERTREQUEST flag (0x200) in the CA's flags
    attribute controls whether RPC encryption is required. When this
    flag is NOT set:
    1. Attacker can relay NTLM authentication to the RPC endpoint
    2. Request certificates as the relayed account
    3. Use the certificate for domain authentication

    This is similar to ESC8 but targets the RPC interface instead of HTTP.

    Returns ESC11Result if vulnerable, None otherwise.
    """
    # Check if encryption enforcement is missing
    if ca.flags & IF_ENFORCEENCRYPTICERTREQUEST:
        return None

    reasons = [
        "CA does not enforce RPC encryption (IF_ENFORCEENCRYPTICERTREQUEST not set)",
        "ICPR interface accepts unencrypted requests",
        "Attacker can relay NTLM authentication to RPC endpoint for certificate enrollment",
    ]

    return ESC11Result(
        vulnerable=True,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        reasons=reasons,
    )
