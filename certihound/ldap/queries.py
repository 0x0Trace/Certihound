"""LDAP query definitions for AD CS enumeration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .connection import LDAPConnection


@dataclass
class QueryDefinition:
    """LDAP query definition."""

    filter: str
    base_template: str  # Use {config_dn} or {domain_dn} as placeholders
    attributes: list[str]


class ADCSQueries:
    """ADCS-specific LDAP queries."""

    # Certificate Template query
    CERT_TEMPLATE = QueryDefinition(
        filter="(objectClass=pKICertificateTemplate)",
        base_template="CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}",
        attributes=[
            "cn",
            "name",
            "displayName",
            "objectGUID",
            "distinguishedName",
            "nTSecurityDescriptor",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag",
            "msPKI-RA-Signature",
            "msPKI-Certificate-Application-Policy",
            "msPKI-RA-Application-Policies",
            "pKIExtendedKeyUsage",
            "pKIExpirationPeriod",
            "pKIOverlapPeriod",
            "msPKI-Template-Schema-Version",
            "msPKI-Template-Minor-Revision",
            "msPKI-Private-Key-Flag",
            "msPKI-Minimal-Key-Size",
            "msPKI-Cert-Template-OID",
            "flags",
            "revision",
            "whenCreated",
            "whenChanged",
        ],
    )

    # Enterprise CA query
    ENTERPRISE_CA = QueryDefinition(
        filter="(objectClass=pKIEnrollmentService)",
        base_template="CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}",
        attributes=[
            "cn",
            "name",
            "displayName",
            "objectGUID",
            "distinguishedName",
            "dNSHostName",
            "certificateTemplates",
            "cACertificate",
            "cACertificateDN",
            "nTSecurityDescriptor",
            "flags",
            "whenCreated",
            "whenChanged",
        ],
    )

    # Root CA query
    ROOT_CA = QueryDefinition(
        filter="(objectClass=certificationAuthority)",
        base_template="CN=Certification Authorities,CN=Public Key Services,CN=Services,{config_dn}",
        attributes=[
            "cn",
            "name",
            "objectGUID",
            "distinguishedName",
            "cACertificate",
            "certificateRevocationList",
            "authorityRevocationList",
            "whenCreated",
            "whenChanged",
        ],
    )

    # NTAuth Store query
    NTAUTH_STORE = QueryDefinition(
        filter="(cn=NTAuthCertificates)",
        base_template="CN=Public Key Services,CN=Services,{config_dn}",
        attributes=[
            "cn",
            "objectGUID",
            "distinguishedName",
            "cACertificate",
            "whenCreated",
            "whenChanged",
        ],
    )

    # AIA CA query
    AIA_CA = QueryDefinition(
        filter="(objectClass=certificationAuthority)",
        base_template="CN=AIA,CN=Public Key Services,CN=Services,{config_dn}",
        attributes=[
            "cn",
            "name",
            "objectGUID",
            "distinguishedName",
            "cACertificate",
            "whenCreated",
            "whenChanged",
        ],
    )

    # Domain query for SID retrieval
    DOMAIN = QueryDefinition(
        filter="(objectClass=domain)",
        base_template="{domain_dn}",
        attributes=[
            "objectSid",
            "distinguishedName",
            "name",
            "ms-DS-MachineAccountQuota",
        ],
    )

    def __init__(self, connection: LDAPConnection):
        self.connection = connection

    def _format_base(self, base_template: str) -> str:
        """Format base DN template with actual values."""
        return base_template.format(
            config_dn=self.connection.config.config_dn,
            domain_dn=self.connection.config.domain_dn,
        )

    def get_certificate_templates(self) -> list:
        """Enumerate all certificate templates."""
        return self.connection.search(
            search_base=self._format_base(self.CERT_TEMPLATE.base_template),
            search_filter=self.CERT_TEMPLATE.filter,
            attributes=self.CERT_TEMPLATE.attributes,
        )

    def get_enterprise_cas(self) -> list:
        """Enumerate all Enterprise CAs."""
        return self.connection.search(
            search_base=self._format_base(self.ENTERPRISE_CA.base_template),
            search_filter=self.ENTERPRISE_CA.filter,
            attributes=self.ENTERPRISE_CA.attributes,
        )

    def get_root_cas(self) -> list:
        """Enumerate all Root CAs."""
        return self.connection.search(
            search_base=self._format_base(self.ROOT_CA.base_template),
            search_filter=self.ROOT_CA.filter,
            attributes=self.ROOT_CA.attributes,
        )

    def get_ntauth_store(self) -> list:
        """Get NTAuth certificate store."""
        return self.connection.search(
            search_base=self._format_base(self.NTAUTH_STORE.base_template),
            search_filter=self.NTAUTH_STORE.filter,
            attributes=self.NTAUTH_STORE.attributes,
        )

    def get_aia_cas(self) -> list:
        """Enumerate all AIA CAs."""
        return self.connection.search(
            search_base=self._format_base(self.AIA_CA.base_template),
            search_filter=self.AIA_CA.filter,
            attributes=self.AIA_CA.attributes,
        )

    def get_domain_info(self) -> list:
        """Get domain information."""
        return self.connection.search(
            search_base=self._format_base(self.DOMAIN.base_template),
            search_filter=self.DOMAIN.filter,
            attributes=self.DOMAIN.attributes,
        )

    def enumerate_all(self) -> dict:
        """Enumerate all ADCS objects."""
        from rich.console import Console
        from rich.progress import Progress, SpinnerColumn, TextColumn

        console = Console()

        results: dict[str, list] = {
            "templates": [],
            "enterprise_cas": [],
            "root_cas": [],
            "ntauth_store": [],
            "aia_cas": [],
        }

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Enumerating ADCS objects...", total=5)

            progress.update(task, description="[cyan]Enumerating certificate templates...")
            results["templates"] = self.get_certificate_templates()
            progress.advance(task)

            progress.update(task, description="[cyan]Enumerating Enterprise CAs...")
            results["enterprise_cas"] = self.get_enterprise_cas()
            progress.advance(task)

            progress.update(task, description="[cyan]Enumerating Root CAs...")
            results["root_cas"] = self.get_root_cas()
            progress.advance(task)

            progress.update(task, description="[cyan]Enumerating NTAuth store...")
            results["ntauth_store"] = self.get_ntauth_store()
            progress.advance(task)

            progress.update(task, description="[cyan]Enumerating AIA CAs...")
            results["aia_cas"] = self.get_aia_cas()
            progress.advance(task)

        console.print(f"[green][+] Found {len(results['templates'])} certificate templates[/green]")
        console.print(f"[green][+] Found {len(results['enterprise_cas'])} Enterprise CAs[/green]")
        console.print(f"[green][+] Found {len(results['root_cas'])} Root CAs[/green]")
        console.print(f"[green][+] Found {len(results['ntauth_store'])} NTAuth store entries[/green]")
        console.print(f"[green][+] Found {len(results['aia_cas'])} AIA CAs[/green]")

        return results
