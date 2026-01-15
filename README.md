# CertiHound

Linux-native AD CS collector library for BloodHound CE. Enumerates Active Directory Certificate Services via LDAP and outputs BloodHound CE-compatible JSON for seamless graph visualization.

## Features

- **LDAP-based enumeration** - No Windows dependencies required
- **BloodHound CE compatible** - Direct JSON/ZIP import into BloodHound CE v6+
- **Library-first design** - Easy integration with NetExec, Impacket, and other tools
- **Multiple LDAP backends** - Works with ldap3, impacket, or any compatible adapter
- **Comprehensive coverage** - Certificate templates, Enterprise CAs, Root CAs, NTAuth stores, AIA CAs

## Installation

```bash
pip install certihound
```

Or from source:

```bash
git clone https://github.com/0x0Trace/certihound.git
cd certihound
pip install -e .
```

## Quick Start

### As a Library (Recommended)

```python
from certihound import ADCSCollector, BloodHoundCEExporter
from certihound.ldap.connection import LDAPConnection, LDAPConfig

# Setup connection
config = LDAPConfig(
    domain="corp.local",
    username="user",
    password="password",
    dc_ip="10.10.10.10",
    use_ldaps=True,
)

# Collect and export
with LDAPConnection(config) as conn:
    collector = ADCSCollector(conn)
    data = collector.collect_all()

    exporter = BloodHoundCEExporter(data.domain, data.domain_sid)
    result = exporter.export(data)
    result.write_zip("bloodhound_adcs.zip")
```

### Integration with NetExec

CertiHound integrates seamlessly with NetExec's LDAP protocol:

```python
from certihound import ADCSCollector, BloodHoundCEExporter, ImpacketLDAPAdapter

# In NetExec's ldap.py:
adapter = ImpacketLDAPAdapter(
    search_func=self.search,
    domain=self.domain,
    domain_sid=self.sid_domain,
)

collector = ADCSCollector.from_external(
    ldap_connection=adapter,
    domain=self.domain,
    domain_sid=self.sid_domain,
)
data = collector.collect_all()

exporter = BloodHoundCEExporter(data.domain, data.domain_sid)
result = exporter.export(data)
result.write_zip("adcs_bloodhound.zip")
```

### Integration with ldap3

```python
from ldap3 import Server, Connection, ALL
from certihound import ADCSCollector, BloodHoundCEExporter

# ldap3 connections work directly (no adapter needed)
server = Server('dc.corp.local', get_info=ALL)
conn = Connection(server, user='user@corp.local', password='password')
conn.bind()

collector = ADCSCollector.from_external(
    ldap_connection=conn,
    domain="corp.local",
    domain_sid="S-1-5-21-...",
)
data = collector.collect_all()

exporter = BloodHoundCEExporter(data.domain, data.domain_sid)
result = exporter.export(data)
result.write_zip("adcs_bloodhound.zip")
```

## Command Line Usage

```bash
# Basic enumeration
certihound -d corp.local -u 'user' -p 'password' -dc 10.10.10.10 -o output/

# With LDAPS
certihound -d corp.local -u 'user' -p 'password' --ldaps -o output/

# Kerberos authentication
certihound -d corp.local -k -o output/
```

## Output Files

CertiHound generates BloodHound CE v6 compatible files:

| File | Description |
|------|-------------|
| `certtemplates.json` | Certificate template nodes |
| `enterprisecas.json` | Enterprise CA nodes |
| `rootcas.json` | Root CA nodes |
| `ntauthstores.json` | NTAuth store nodes |
| `aiacas.json` | AIA CA nodes |

## API Reference

### Main Classes

| Class | Description |
|-------|-------------|
| `ADCSCollector` | Main collector for ADCS enumeration |
| `BloodHoundCEExporter` | Exports data to BloodHound CE format |
| `ImpacketLDAPAdapter` | Adapter for impacket-based LDAP (NetExec) |
| `LDAPConnection` | Standalone LDAP connection wrapper |
| `LDAPConfig` | Configuration for LDAP connections |

### Data Classes

| Class | Description |
|-------|-------------|
| `ADCSData` | Container for all collected ADCS data |
| `CertTemplate` | Certificate template model |
| `EnterpriseCA` | Enterprise CA model |
| `RootCA` | Root CA model |
| `NTAuthStore` | NTAuth store model |
| `AIACA` | AIA CA model |
| `ExportResult` | Export result with write methods |

### Usage Examples

```python
from certihound import (
    ADCSCollector,
    BloodHoundCEExporter,
    ImpacketLDAPAdapter,
    ADCSData,
    ExportResult,
)

# Collect data
collector = ADCSCollector.from_external(adapter, domain, domain_sid)
data: ADCSData = collector.collect_all()

# Access collected objects
print(f"Templates: {len(data.templates)}")
print(f"Enterprise CAs: {len(data.enterprise_cas)}")
print(f"Root CAs: {len(data.root_cas)}")

# Export to BloodHound
exporter = BloodHoundCEExporter(data.domain, data.domain_sid)
result: ExportResult = exporter.export(data)

# Write as ZIP (for BloodHound import)
result.write_zip("output.zip")

# Or get as dictionary
output_dict = result.to_dict()
```

## NetExec Integration

To use CertiHound with NetExec's `--bloodhound -c ADCS` option:

1. Install CertiHound: `pip install certihound`
2. The ADCS collection will be automatically available

```bash
# ADCS only collection
nxc ldap 10.10.10.10 -u user -p pass --bloodhound -c ADCS

# Full collection including ADCS
nxc ldap 10.10.10.10 -u user -p pass --bloodhound -c All --dns-server 10.10.10.10
```

## Dependencies

- **ldap3** - LDAP operations (standalone mode)
- **impacket** - Kerberos authentication & NetExec integration
- **cryptography** - Certificate parsing
- **pydantic** - Data validation

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black certihound/
ruff check certihound/

# Type checking
mypy certihound/
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Credits

- Inspired by [Certipy](https://github.com/ly4k/Certipy)
- BloodHound CE format based on [BloodHound](https://github.com/SpecterOps/BloodHound)
- ADCS research from [SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
