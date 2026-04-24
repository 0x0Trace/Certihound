"""LDAP connection handling for AD CS enumeration."""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Any

from ldap3 import (
    ALL,
    NTLM,
    SASL,
    SIMPLE,
    SUBTREE,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import LDAPException, LDAPBindError
from rich.console import Console

console = Console()


def _looks_like_ip(host: str) -> bool:
    """Return True if ``host`` is a literal IPv4/IPv6 address."""
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@dataclass
class LDAPConfig:
    """LDAP connection configuration."""

    domain: str
    username: str | None = None
    password: str | None = None
    dc_ip: str | None = None
    use_ldaps: bool = False
    use_kerberos: bool = False
    ca_cert: str | None = None
    port: int | None = None
    hashes: str | None = None  # "LMHASH:NTHASH" or ":NTHASH" or "NTHASH"

    @property
    def domain_dn(self) -> str:
        """Convert domain FQDN to distinguished name."""
        return ",".join(f"DC={part}" for part in self.domain.split("."))

    @property
    def config_dn(self) -> str:
        """Get configuration naming context DN."""
        return f"CN=Configuration,{self.domain_dn}"

    @property
    def server_address(self) -> str:
        """Get server address (DC IP or domain)."""
        return self.dc_ip or self.domain

    @property
    def server_port(self) -> int:
        """Get LDAP port."""
        if self.port:
            return self.port
        return 636 if self.use_ldaps else 389


class LDAPConnection:
    """Manages LDAP connections to Active Directory."""

    def __init__(self, config: LDAPConfig):
        self.config = config
        self._server: Server | None = None
        self._connection: Connection | None = None
        self._domain_sid: str | None = None

    @property
    def connection(self) -> Connection:
        """Get the active LDAP connection."""
        if not self._connection:
            raise RuntimeError("Not connected. Call connect() first.")
        return self._connection

    @property
    def domain_sid(self) -> str:
        """Get the domain SID."""
        if not self._domain_sid:
            self._domain_sid = self._get_domain_sid()
        return self._domain_sid

    def connect(self) -> bool:
        """Establish LDAP connection."""
        try:
            # Configure TLS if using LDAPS
            tls_config = None
            if self.config.use_ldaps:
                tls_config = Tls(
                    validate=ssl.CERT_REQUIRED if self.config.ca_cert else ssl.CERT_NONE,
                    ca_certs_file=self.config.ca_cert,
                )

            # Create server object
            self._server = Server(
                self.config.server_address,
                port=self.config.server_port,
                use_ssl=self.config.use_ldaps,
                tls=tls_config,
                get_info=ALL,
            )

            # Determine authentication method
            if self.config.use_kerberos:
                self._connection = self._connect_kerberos()
            elif self.config.username and (self.config.password or self.config.hashes):
                self._connection = self._connect_ntlm()
            else:
                raise ValueError("Either Kerberos or username + password/hash required")

            if not self._connection.bind():
                result = self._connection.result
                console.print(f"[red][-] Bind failed: {result}[/red]")

                # Check if LDAP signing is required
                if result.get("result") == 8 and "strongerAuthRequired" in str(result):
                    console.print(
                        "[yellow][!] The DC requires LDAP signing. Try using --ldaps flag:[/yellow]"
                    )
                    console.print(
                        f"[yellow]    certihound -d {self.config.domain} --ldaps ...[/yellow]"
                    )
                return False

            console.print(
                f"[green][+] Connected to {self.config.server_address}:{self.config.server_port}[/green]"
            )
            return True

        except LDAPBindError as e:
            console.print(f"[red][-] LDAP bind error: {e}[/red]")
            return False
        except LDAPException as e:
            console.print(f"[red][-] LDAP error: {e}[/red]")
            return False

    def _connect_ntlm(self) -> Connection:
        """Create connection with NTLM authentication (password or hash)."""
        # Format username as DOMAIN\user
        username = self.config.username or ""
        if "\\" not in username and "@" not in username:
            user = f"{self.config.domain}\\{username}"
        else:
            user = username

        # ldap3 NTLM accepts either a plaintext password, or a LM:NT hash pair
        # where each half is 32 hex chars. Normalize --hashes inputs here.
        if self.config.hashes:
            secret = self._format_ntlm_hash(self.config.hashes)
        else:
            secret = self.config.password

        return Connection(
            self._server,
            user=user,
            password=secret,
            authentication=NTLM,
            auto_bind=False,
        )

    @staticmethod
    def _format_ntlm_hash(raw: str) -> str:
        """Normalize a user-supplied hash to ldap3's ``LMHASH:NTHASH`` form."""
        empty_lm = "aad3b435b51404eeaad3b435b51404ee"
        parts = raw.split(":")
        if len(parts) == 1:
            nt = parts[0]
            lm = empty_lm
        else:
            lm = parts[0] or empty_lm
            nt = parts[1]
        return f"{lm}:{nt}"

    def _connect_kerberos(self) -> Connection:
        """Create connection with Kerberos authentication (SASL/GSSAPI).

        Requires the ``gssapi`` package (Linux/macOS) or ``winkerberos``
        (Windows). Install with ``pipx install 'certihound[kerberos]'`` or
        ``pipx inject certihound gssapi``.
        """
        try:
            import gssapi  # noqa: F401
        except ImportError:
            try:
                import winkerberos  # noqa: F401
            except ImportError:
                raise RuntimeError(
                    "Kerberos support requires the 'gssapi' (Linux/macOS) "
                    "or 'winkerberos' (Windows) package. "
                    "Install with: pipx inject certihound gssapi "
                    "(or: pipx install 'certihound[kerberos]')"
                ) from None

        # Activate the ldap3 shim that honors fully-qualified Kerberos
        # principals — this sidesteps MIT krb5's hostname canonicalization,
        # which is the usual cause of "Server not found in Kerberos database"
        # in pentest/lab environments (missing PTR records, host case
        # mismatches, realm != DNS suffix).
        from .kerberos_compat import install_kerberos_principal_shim

        install_kerberos_principal_shim()

        target = self._kerberos_target()
        return Connection(
            self._server,
            authentication=SASL,
            sasl_mechanism="GSSAPI",
            sasl_credentials=(target,) if target else None,
            auto_bind=False,
        )

    def _kerberos_target(self) -> str | None:
        """Return the Kerberos target for GSSAPI.

        When we can infer a DC FQDN, build a fully-qualified principal
        ``ldap/<dc-fqdn>@REALM``. The compat shim recognises the ``/`` and
        uses gssapi ``kerberos_principal`` NameType, skipping krb5's DNS
        canonicalization. For bare IPs we fall back to the domain so the
        user's ``[domain_realm]`` mapping in ``krb5.conf`` can resolve it.
        """
        addr = self.config.dc_ip or self.config.domain
        if not addr:
            return None
        realm = (self.config.domain or "").upper()
        if _looks_like_ip(addr):
            return self.config.domain or None
        host = addr.lower()
        if realm:
            return f"ldap/{host}@{realm}"
        return host

    def _get_domain_sid(self) -> str:
        """Retrieve domain SID from AD."""
        from ..utils.convert import bytes_to_sid

        self.connection.search(
            search_base=self.config.domain_dn,
            search_filter="(objectClass=domain)",
            search_scope=SUBTREE,
            attributes=["objectSid"],
        )

        if self.connection.entries:
            sid_bytes = self.connection.entries[0]["objectSid"].raw_values[0]
            return bytes_to_sid(sid_bytes)

        raise RuntimeError("Could not retrieve domain SID")

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str],
        search_scope: str = SUBTREE,
        controls: list | None = None,
    ) -> list[Any]:
        """Execute LDAP search query."""
        # Request SD_FLAGS control for nTSecurityDescriptor
        if "nTSecurityDescriptor" in attributes:
            # SD_FLAGS_OWNER | SD_FLAGS_GROUP | SD_FLAGS_DACL = 0x07
            # Encode as BER sequence with integer
            import struct
            sd_flags = 0x07
            # BER encode: sequence tag (0x30), length, integer tag (0x02), length, value
            sd_value = b"\x30\x03\x02\x01" + struct.pack("B", sd_flags)
            controls = controls or []
            controls.append(("1.2.840.113556.1.4.801", True, sd_value))

        try:
            self.connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=search_scope,
                attributes=attributes,
                controls=controls,
            )
        except Exception as e:
            console.print(f"[red][-] Search error: {e}[/red]")
            console.print(f"[red]    Base: {search_base}[/red]")
            console.print(f"[red]    Filter: {search_filter}[/red]")
            return []

        return list(self.connection.entries)

    def disconnect(self) -> None:
        """Close LDAP connection."""
        if self._connection:
            self._connection.unbind()
            self._connection = None
            console.print("[yellow][*] Disconnected from LDAP[/yellow]")

    def __enter__(self) -> "LDAPConnection":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.disconnect()
