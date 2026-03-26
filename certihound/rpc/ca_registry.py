"""Read CA configuration flags from remote registry (MS-RRP).

Uses impacket's Remote Registry Protocol to read Enterprise CA
configuration from the Windows registry on the CA host. This provides
flags that are NOT available via LDAP, including:

- EditFlags (EDITF_ATTRIBUTESUBJECTALTNAME2 for ESC6, security ext for ESC16)
- InterfaceFlags (IF_ENFORCEENCRYPTICERTREQUEST for ESC11)
- DisableExtensionList (szOID_NTDS_CA_SECURITY_EXT for ESC16)

Connects directly to \\pipe\\winreg (no admin required if Remote Registry
service is already running).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Registry paths relative to HKLM
_CERTSVC_BASE = r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"

# EditFlags bit definitions (from [MS-WCCE] 3.2.1.4.2.1.4)
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000  # ESC6
EDITF_ATTRIBUTEENDDATE = 0x00000020

# InterfaceFlags bit definitions
IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200  # ESC11 mitigation

# Security extension OID
SZOID_NTDS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2"


@dataclass
class CARegistryFlags:
    """CA configuration flags read from the registry."""

    ca_name: str
    hostname: str

    # Raw registry values
    edit_flags: int = 0
    interface_flags: int = 0

    # Parsed from EditFlags
    san_flag_enabled: bool = False  # EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)

    # Parsed from InterfaceFlags
    enforce_encrypt_rpc: bool = False  # IF_ENFORCEENCRYPTICERTREQUEST (ESC11)

    # Security extension disabled (ESC16) - read from registry
    security_extension_disabled: bool = False

    # Collection metadata
    success: bool = False
    error: str = ""


class CARegistryReader:
    """Read CA configuration from the Windows registry via RRP.

    Connects directly to \\pipe\\winreg named pipe over SMB, avoiding
    the need for admin rights (unlike RemoteOperations.enableRegistry()
    which tries to start the service via SCM).

    If the Remote Registry service is already running, any authenticated
    user can read the CA configuration keys.

    Args:
        smb_connection: An impacket SMBConnection to the CA host.
    """

    def __init__(self, smb_connection: Any):
        self._smb_conn = smb_connection
        self._dce = None

    def _connect(self) -> bool:
        """Connect directly to the remote registry named pipe."""
        try:
            from impacket.dcerpc.v5 import rrp, transport

            # Bind directly to \pipe\winreg — no SCM, no admin required
            # if the Remote Registry service is already running
            rpc_transport = transport.SMBTransport(
                self._smb_conn.getRemoteHost(),
                filename=r"\winreg",
                smb_connection=self._smb_conn,
            )

            self._dce = rpc_transport.get_dce_rpc()
            self._dce.connect()
            self._dce.bind(rrp.MSRPC_UUID_RRP)
            logger.debug("Connected to remote registry via \\pipe\\winreg")
            return True
        except Exception as e:
            logger.debug(f"Failed to connect to remote registry: {e}")
            self._dce = None
            return False

    def _disconnect(self) -> None:
        """Clean up RPC connection."""
        if self._dce:
            try:
                self._dce.disconnect()
            except Exception:
                pass
            self._dce = None

    def _read_dword(self, key_handle: Any, value_name: str) -> int | None:
        """Read a DWORD value from an open registry key."""
        from impacket.dcerpc.v5 import rrp

        try:
            _, value = rrp.hBaseRegQueryValue(self._dce, key_handle, value_name)
            if isinstance(value, int):
                return value
            return None
        except Exception as e:
            logger.debug(f"Failed to read {value_name}: {e}")
            return None

    def _read_string(self, key_handle: Any, value_name: str) -> str | None:
        """Read a string value from an open registry key."""
        from impacket.dcerpc.v5 import rrp

        try:
            _, value = rrp.hBaseRegQueryValue(self._dce, key_handle, value_name)
            if isinstance(value, str):
                return value.rstrip("\x00")
            return None
        except Exception:
            return None

    def read_ca_flags(self, ca_name: str, hostname: str = "") -> CARegistryFlags:
        """Read configuration flags for a specific CA.

        Args:
            ca_name: The CA common name (e.g., "corp-DC01-CA")
            hostname: The CA hostname for reference

        Returns:
            CARegistryFlags with the read values
        """
        from impacket.dcerpc.v5 import rrp

        result = CARegistryFlags(ca_name=ca_name, hostname=hostname)

        if not self._dce:
            if not self._connect():
                result.error = "Failed to connect to remote registry"
                return result

        try:
            hklm = rrp.hOpenLocalMachine(self._dce)["phKey"]

            # First, read the active policy module name
            ca_path = f"{_CERTSVC_BASE}\\{ca_name}"
            policy_module_name = "CertificateAuthority_MicrosoftDefault.Policy"

            try:
                pm_base_path = f"{ca_path}\\PolicyModules"
                pm_handle = rrp.hBaseRegOpenKey(self._dce, hklm, pm_base_path)["phkResult"]
                active = self._read_string(pm_handle, "Active")
                if active:
                    policy_module_name = active
                    logger.debug(f"Active policy module: {policy_module_name}")
                rrp.hBaseRegCloseKey(self._dce, pm_handle)
            except Exception:
                pass  # Use default policy module name

            # Read from PolicyModule key
            policy_path = f"{ca_path}\\PolicyModules\\{policy_module_name}"
            try:
                policy_handle = rrp.hBaseRegOpenKey(self._dce, hklm, policy_path)["phkResult"]

                # Read EditFlags
                edit_flags = self._read_dword(policy_handle, "EditFlags")
                logger.debug(
                    f"CA {ca_name} EditFlags: {edit_flags:#010x}"
                    if edit_flags is not None
                    else f"CA {ca_name} EditFlags: not found"
                )
                if edit_flags is not None:
                    result.edit_flags = edit_flags
                    result.san_flag_enabled = bool(
                        edit_flags & EDITF_ATTRIBUTESUBJECTALTNAME2
                    )

                # Read DisableExtensionList (note: no 'd' at end)
                # This is the registry value name used by Windows ADCS
                disable_ext_str = self._read_string(policy_handle, "DisableExtensionList")
                logger.debug(f"CA {ca_name} DisableExtensionList raw: {disable_ext_str!r}")
                if disable_ext_str:
                    # Parse null-separated OID list
                    disabled_oids = [
                        s for s in disable_ext_str.split("\x00") if s
                    ]
                    logger.debug(f"CA {ca_name} disabled OIDs: {disabled_oids}")
                    if SZOID_NTDS_CA_SECURITY_EXT in disabled_oids:
                        result.security_extension_disabled = True

                rrp.hBaseRegCloseKey(self._dce, policy_handle)
            except Exception as e:
                logger.debug(f"Failed to read policy module for {ca_name}: {e}")

            # Read InterfaceFlags from CA-level config
            try:
                ca_handle = rrp.hBaseRegOpenKey(self._dce, hklm, ca_path)["phkResult"]

                iface_flags = self._read_dword(ca_handle, "InterfaceFlags")
                if iface_flags is not None:
                    result.interface_flags = iface_flags
                    result.enforce_encrypt_rpc = bool(
                        iface_flags & IF_ENFORCEENCRYPTICERTREQUEST
                    )

                rrp.hBaseRegCloseKey(self._dce, ca_handle)
            except Exception as e:
                logger.debug(f"Failed to read CA config for {ca_name}: {e}")

            rrp.hBaseRegCloseKey(self._dce, hklm)
            result.success = True

        except Exception as e:
            result.error = str(e)
            logger.debug(f"Registry read failed for {ca_name}: {e}")

        return result

    def close(self) -> None:
        """Close the registry connection."""
        self._disconnect()

    def __enter__(self) -> "CARegistryReader":
        self._connect()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
