"""CertiHound CLI interface."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Literal, cast

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from . import __version__
from .config import Config, get_banner
from .ldap.connection import LDAPConfig, LDAPConnection
from .ldap.queries import ADCSQueries
from .ldap.parsers import LDAPResultParser
from .objects.certtemplate import CertTemplate
from .objects.enterpriseca import EnterpriseCA
from .objects.rootca import RootCA
from .objects.ntauthstore import NTAuthStore
from .objects.aiaca import AIACA
from .output.bloodhound import BloodHoundOutput
from .output.writer import OutputWriter

console = Console()


@click.command()
@click.option(
    "-d", "--domain",
    required=True,
    help="Target domain FQDN (e.g., corp.local)",
)
@click.option(
    "-u", "--username",
    help="Username for authentication",
)
@click.option(
    "-p", "--password",
    help="Password for authentication",
)
@click.option(
    "--dc",
    "dc_ip",
    help="Domain Controller IP or hostname",
)
@click.option(
    "-k", "--kerberos",
    "use_kerberos",
    is_flag=True,
    help="Use Kerberos authentication (ccache)",
)
@click.option(
    "--ldaps",
    "use_ldaps",
    is_flag=True,
    help="Use LDAPS (SSL/TLS)",
)
@click.option(
    "--ca-cert",
    "ca_cert",
    type=click.Path(exists=True),
    help="CA certificate file for LDAPS validation",
)
@click.option(
    "--port",
    "ldap_port",
    type=int,
    help="LDAP port (default: 389 or 636 for LDAPS)",
)
@click.option(
    "-o", "--output",
    "output_dir",
    default="./output",
    help="Output directory (default: ./output)",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "zip", "both"]),
    default="zip",
    help="Output format (default: zip)",
)
@click.option(
    "--enum-only",
    "enum_only",
    is_flag=True,
    help="Only enumerate, skip vulnerability detection",
)
@click.option(
    "-v", "--verbose",
    count=True,
    help="Increase verbosity (-v, -vv)",
)
@click.version_option(version=__version__)
def main(
    domain: str,
    username: str | None,
    password: str | None,
    dc_ip: str | None,
    use_kerberos: bool,
    use_ldaps: bool,
    ca_cert: str | None,
    ldap_port: int | None,
    output_dir: str,
    output_format: str,
    enum_only: bool,
    verbose: int,
) -> None:
    """
    CertiHound - Linux-native AD CS collector for BloodHound CE

    Enumerates Active Directory Certificate Services via LDAP and outputs
    BloodHound CE-compatible JSON for seamless graph visualization.
    """
    # Print banner
    console.print(get_banner(), style="cyan")

    # Build config
    config = Config(
        domain=domain,
        username=username,
        password=password,
        dc_ip=dc_ip,
        use_kerberos=use_kerberos,
        use_ldaps=use_ldaps,
        ca_cert=ca_cert,
        ldap_port=ldap_port,
        output_dir=output_dir,
        output_format=cast(Literal["json", "zip", "both"], output_format),
        enum_only=enum_only,
        verbose=verbose,
    )

    # Validate config
    errors = config.validate()
    if errors:
        for error in errors:
            console.print(f"[red][-] Error: {error}[/red]")
        sys.exit(1)

    # Create LDAP config
    ldap_config = LDAPConfig(
        domain=config.domain,
        username=config.username,
        password=config.password,
        dc_ip=config.dc_ip,
        use_ldaps=config.use_ldaps,
        use_kerberos=config.use_kerberos,
        ca_cert=config.ca_cert,
        port=config.ldap_port,
    )

    # Connect and enumerate
    try:
        with LDAPConnection(ldap_config) as conn:
            run_enumeration(conn, config)
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red][-] Error: {e}[/red]")
        if verbose >= 2:
            console.print_exception()
        sys.exit(1)


def run_enumeration(conn: LDAPConnection, config: Config) -> None:
    """Run the main enumeration process."""
    parser = LDAPResultParser()
    queries = ADCSQueries(conn)

    # Get domain info
    domain = config.domain.upper()
    domain_sid = conn.domain_sid
    console.print(f"[cyan][*] Domain SID: {domain_sid}[/cyan]")

    # Enumerate all ADCS objects
    console.print("\n[cyan][*] Starting ADCS enumeration...[/cyan]")
    raw_results = queries.enumerate_all()

    # Parse results into objects
    templates = []
    for entry in raw_results["templates"]:
        parsed = parser.parse_certificate_template(entry, domain, domain_sid)
        templates.append(CertTemplate.from_ldap_entry(parsed, domain, domain_sid))

    enterprise_cas = []
    for entry in raw_results["enterprise_cas"]:
        parsed = parser.parse_enterprise_ca(entry, domain, domain_sid)
        enterprise_cas.append(EnterpriseCA.from_ldap_entry(parsed, domain, domain_sid))

    root_cas = []
    for entry in raw_results["root_cas"]:
        parsed = parser.parse_root_ca(entry, domain, domain_sid)
        root_cas.append(RootCA.from_ldap_entry(parsed, domain, domain_sid))

    ntauth_stores = []
    for entry in raw_results["ntauth_store"]:
        parsed = parser.parse_ntauth_store(entry, domain, domain_sid)
        ntauth_stores.append(NTAuthStore.from_ldap_entry(parsed, domain, domain_sid))

    aia_cas = []
    for entry in raw_results["aia_cas"]:
        parsed = parser.parse_aia_ca(entry, domain, domain_sid)
        aia_cas.append(AIACA.from_ldap_entry(parsed, domain, domain_sid))

    # Create BloodHound output generator
    bh_output = BloodHoundOutput(domain, domain_sid, conn)
    bh_output.add_templates(templates)
    bh_output.add_enterprise_cas(enterprise_cas)
    bh_output.add_root_cas(root_cas)
    bh_output.add_ntauth_stores(ntauth_stores)
    bh_output.add_aia_cas(aia_cas)

    # Process ACLs
    console.print("\n[cyan][*] Processing ACLs...[/cyan]")
    bh_output.process_template_acls()
    bh_output.process_ca_acls()

    # Run vulnerability detection (unless enum-only)
    if not config.enum_only:
        console.print("\n[cyan][*] Running vulnerability detection...[/cyan]")
        bh_output.enumerate_issuance_policies()
        bh_output.detect_vulnerabilities()
        bh_output.generate_relationship_edges()

        # Print vulnerability summary
        if bh_output.vulnerabilities:
            print_vulnerability_summary(bh_output.vulnerabilities)
        else:
            console.print("[green][+] No vulnerabilities detected[/green]")
    else:
        console.print("[yellow][*] Skipping vulnerability detection (--enum-only)[/yellow]")
        bh_output.generate_relationship_edges()

    # Generate output
    console.print("\n[cyan][*] Generating BloodHound CE output...[/cyan]")
    output = bh_output.generate_output()

    # Write output files
    writer = OutputWriter(config.output_dir, domain)
    result = writer.write_all(output, config.output_format)

    # Print final summary
    print_summary(bh_output.get_summary(), result)


def print_vulnerability_summary(vulnerabilities: list[dict]) -> None:
    """Print vulnerability summary table."""
    console.print("\n")

    # Group by type
    by_type: dict[str, list[dict]] = {}
    for vuln in vulnerabilities:
        vtype = vuln["type"]
        if vtype not in by_type:
            by_type[vtype] = []
        by_type[vtype].append(vuln)

    table = Table(title="Vulnerabilities Detected", show_header=True, header_style="bold red")
    table.add_column("Type", style="red")
    table.add_column("Template", style="yellow")
    table.add_column("CA", style="cyan")
    table.add_column("Principals", style="green")

    for vtype, vulns in by_type.items():
        for vuln in vulns:
            principals = len(vuln.get("principals", []))
            table.add_row(
                vtype,
                vuln.get("template", "N/A"),
                vuln.get("ca", "N/A"),
                str(principals),
            )

    console.print(table)
    console.print(f"\n[red][!] Total: {len(vulnerabilities)} vulnerable configurations[/red]")


def print_summary(summary: dict, result: dict) -> None:
    """Print final summary."""
    console.print("\n")

    summary_text = f"""
Domain: {summary['domain']}

Objects Collected:
  Certificate Templates: {summary['templates']}
  Enterprise CAs: {summary['enterprise_cas']}
  Root CAs: {summary['root_cas']}
  NTAuth Stores: {summary['ntauth_stores']}
  AIA CAs: {summary['aia_cas']}

Analysis:
  Edges Generated: {summary['edges']}
  Vulnerable Templates: {summary.get('vulnerable_templates', 0)}
  Total Vulnerabilities: {summary['vulnerabilities']}
"""

    panel = Panel(
        summary_text.strip(),
        title="Collection Summary",
        border_style="green",
    )
    console.print(panel)

    console.print("\n[green][+] Collection complete![/green]")


if __name__ == "__main__":
    main()
