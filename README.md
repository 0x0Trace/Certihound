<h1 align="center">
  <br>
  CertiHound
  <br>
</h1>

<h4 align="center">Linux-native AD CS collector for BloodHound CE</h4>

<p align="center">
  <a href="https://pypi.org/project/certihound/">
    <img src="https://img.shields.io/pypi/v/certihound?style=flat-square&color=blue" alt="PyPI">
  </a>
  <a href="https://pypi.org/project/certihound/">
    <img src="https://img.shields.io/pypi/pyversions/certihound?style=flat-square" alt="Python Version">
  </a>
  <a href="https://github.com/0x0Trace/Certihound/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/0x0Trace/Certihound?style=flat-square" alt="License">
  </a>
  <a href="https://github.com/0x0Trace/Certihound/stargazers">
    <img src="https://img.shields.io/github/stars/0x0Trace/Certihound?style=flat-square" alt="Stars">
  </a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#bloodhound-integration">BloodHound</a> •
  <a href="#api-reference">API</a>
</p>

---

**CertiHound** enumerates Active Directory Certificate Services (AD CS) via LDAP and exports BloodHound CE-compatible data for attack path visualization. Identify ESC1-ESC13 vulnerabilities and visualize certificate-based attack paths.

## Screenshots

### ESC1 - Enrollee Supplies Subject Detection
<p align="center">
  <img src="docs/images/esc1-bloodhound.png" alt="ESC1 Detection in BloodHound" width="900">
</p>

*CertiHound detects ESC1 vulnerable templates and creates enrollment edges to Enterprise CAs, enabling attack path analysis in BloodHound CE.*

### ESC4 - Template ACL Abuse Detection
<p align="center">
  <img src="docs/images/esc4-bloodhound.png" alt="ESC4 Detection in BloodHound" width="900">
</p>

*WriteDacl, WriteOwner, and other dangerous permissions on certificate templates are identified and mapped as attack edges.*

---

## Features

| Feature | Description |
|---------|-------------|
| **Linux-Native** | No Windows dependencies - pure Python LDAP enumeration |
| **BloodHound CE v6+** | Direct JSON/ZIP import with full node and edge support |
| **Vulnerability Detection** | ESC1, ESC3, ESC4, ESC6, ESC9, ESC10, ESC13, GoldenCert |
| **Multiple Backends** | Works with ldap3, impacket, or any compatible LDAP adapter |
| **NetExec Integration** | Seamless integration with NetExec's `--bloodhound` option |
| **Comprehensive Coverage** | Certificate templates, Enterprise CAs, Root CAs, NTAuth, AIA CAs |

### Supported Vulnerabilities

| Vulnerability | Description |
|---------------|-------------|
| **ESC1** | Enrollee supplies subject with low-privilege enrollment |
| **ESC3** | Enrollment agent templates + vulnerable targets |
| **ESC4** | Dangerous ACL permissions on certificate templates |
| **ESC6** | EDITF_ATTRIBUTESUBJECTALTNAME2 on Enterprise CA |
| **ESC9** | No security extension + weak certificate mapping |
| **ESC10** | Weak certificate mapping without strong binding |
| **ESC13** | Issuance policy with OID group link abuse |
| **GoldenCert** | CA private key extraction from hosting computer |

---

## Installation

### From PyPI (Recommended)

```bash
pip install certihound
```

### From Source

```bash
git clone https://github.com/0x0Trace/certihound.git
cd certihound
pip install -e .
```

### Verify Installation

```bash
certihound --version
certihound --help
```

---

## Quick Start

### Command Line

```bash
# Basic enumeration with password authentication
certihound -d corp.local -u 'user' -p 'password' --dc 10.10.10.10 -o output/

# LDAPS (SSL/TLS) connection
certihound -d corp.local -u 'user' -p 'password' --dc 10.10.10.10 --ldaps -o output/

# Kerberos authentication (uses ccache)
certihound -d corp.local -k --dc 10.10.10.10 -o output/

# Output as ZIP (default) or JSON
certihound -d corp.local -u 'user' -p 'password' --dc 10.10.10.10 --format zip
certihound -d corp.local -u 'user' -p 'password' --dc 10.10.10.10 --format json
```

### Python Library

```python
from certihound import ADCSCollector, BloodHoundCEExporter
from certihound.ldap.connection import LDAPConnection, LDAPConfig

# Configure connection
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

---

## Usage

### CLI Options

```
Usage: certihound [OPTIONS]

Options:
  -d, --domain TEXT         Target domain FQDN (e.g., corp.local)  [required]
  -u, --username TEXT       Username for authentication
  -p, --password TEXT       Password for authentication
  --dc TEXT                 Domain Controller IP or hostname
  -k, --kerberos            Use Kerberos authentication (ccache)
  --ldaps                   Use LDAPS (SSL/TLS)
  --ca-cert PATH            CA certificate file for LDAPS validation
  --port INTEGER            LDAP port (default: 389 or 636 for LDAPS)
  -o, --output TEXT         Output directory (default: ./output)
  --format [json|zip|both]  Output format (default: zip)
  --enum-only               Only enumerate, skip vulnerability detection
  -v, --verbose             Increase verbosity (-v, -vv)
  --version                 Show the version and exit.
  --help                    Show this message and exit.
```

### Output Files

CertiHound generates BloodHound CE v6 compatible files:

| File | Description |
|------|-------------|
| `certtemplates.json` | Certificate template nodes with properties and edges |
| `enterprisecas.json` | Enterprise CA nodes with template publishing |
| `rootcas.json` | Root CA hierarchy nodes |
| `ntauthstores.json` | NTAuth store configuration |
| `aiacas.json` | AIA CA entries |

---

## BloodHound Integration

### Importing Data

1. Run CertiHound to generate the ZIP file
2. Open BloodHound CE
3. Click **Import** → Select the generated ZIP file
4. Use the built-in ADCS queries or create custom ones

### Example Cypher Queries

**Find ESC1 Vulnerable Templates:**
```cypher
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->
(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
WHERE ct.enrolleesuppliessubject = True
AND ct.authenticationenabled = True
RETURN p
```

**Find ESC4 Template ACL Abuse:**
```cypher
MATCH p = (principal)-[:WriteDacl|WriteOwner|GenericWrite|GenericAll|WriteAllProperties]->
(ct:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
WHERE NOT principal.objectid ENDS WITH '-512'
AND NOT principal.objectid ENDS WITH '-519'
AND NOT principal.objectid ENDS WITH '-544'
RETURN p
```

---

## NetExec Integration

CertiHound integrates with [NetExec](https://github.com/Pennyw0rth/NetExec) for ADCS enumeration:

```bash
# ADCS only collection
nxc ldap 10.10.10.10 -u user -p pass --bloodhound -c ADCS

# Full collection including ADCS
nxc ldap 10.10.10.10 -u user -p pass --bloodhound -c All --dns-server 10.10.10.10
```

### NetExec Integration Code

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

---

## API Reference

### Core Classes

| Class | Description |
|-------|-------------|
| `ADCSCollector` | Main collector for ADCS enumeration |
| `BloodHoundCEExporter` | Exports data to BloodHound CE format |
| `ImpacketLDAPAdapter` | Adapter for impacket-based LDAP (NetExec) |
| `LDAPConnection` | Standalone LDAP connection wrapper |
| `LDAPConfig` | Configuration dataclass for LDAP connections |

### Data Models

| Class | Description |
|-------|-------------|
| `ADCSData` | Container for all collected ADCS data |
| `CertTemplate` | Certificate template with properties and ACLs |
| `EnterpriseCA` | Enterprise CA with enabled templates |
| `RootCA` | Root CA node |
| `NTAuthStore` | NTAuth certificate store |
| `AIACA` | AIA CA entry |
| `ExportResult` | Export result with `write_zip()`, `write_json()`, `to_dict()` |

### Detection Functions

```python
from certihound import (
    detect_esc1,
    detect_esc3_agent,
    detect_esc3_target,
    detect_esc4,
    detect_esc6,
    detect_esc9,
    detect_esc10,
    detect_esc13,
)
```

### Usage Example

```python
from certihound import (
    ADCSCollector,
    BloodHoundCEExporter,
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

# Output options
result.write_zip("output.zip")      # ZIP for BloodHound import
result.write_json("output/")        # Individual JSON files
output_dict = result.to_dict()      # Python dictionary
```

---

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/0x0Trace/certihound.git
cd certihound

# Install with dev dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=certihound

# Run specific test file
pytest tests/test_detection.py -v
```

### Code Quality

```bash
# Format code
black certihound/

# Lint
ruff check certihound/

# Type checking
mypy certihound/
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `ldap3` | LDAP operations (standalone mode) |
| `impacket` | Kerberos authentication & NetExec integration |
| `cryptography` | Certificate parsing and analysis |
| `pydantic` | Data validation and models |
| `click` | CLI framework |
| `rich` | Terminal output formatting |

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Credits & References

- Inspired by [Certipy](https://github.com/ly4k/Certipy) by Oliver Lyak
- BloodHound CE format based on [BloodHound](https://github.com/SpecterOps/BloodHound) by SpecterOps
- ADCS vulnerability research: [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) by Will Schroeder & Lee Christensen

---

<p align="center">
  Made with :heart: for the security community
</p>
