<h1 align="center">
  <br>
  CertiHound
  <br>
</h1>

<h4 align="center">Colector de AD CS nativo de Linux para BloodHound CE</h4>

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
</p>

<p align="center">
  <a href="#features">Características</a> •
  <a href="#installation">Instalación</a> •
  <a href="#quick-start">Inicio Rápido</a> •
  <a href="#usage">Uso</a> •
  <a href="#bloodhound-integration">BloodHound</a> •
  <a href="#api-reference">API</a>
</p>

---

**CertiHound** enumera los Servicios de Certificados de Active Directory (AD CS) a través de LDAP y exporta datos compatibles con BloodHound CE para la visualización de rutas de ataque. Identifica vulnerabilidades ESC1-ESC17 y visualiza rutas de ataque basadas en certificados.

## Capturas de Pantalla

### ESC1 - Detección de Subject suministrado por el solicitante
<p align="center">
  <img src="docs/images/esc1-bloodhound.PNG" alt="ESC1 Detection in BloodHound" width="900">
</p>

*CertiHound detecta plantillas vulnerables a ESC1 y crea aristas de inscripción hacia las CA Empresariales, permitiendo el análisis de rutas de ataque en BloodHound CE.*

### ESC4 - Detección de abuso de ACL en plantillas
<p align="center">
  <img src="docs/images/esc4-bloodhound.PNG" alt="ESC4 Detection in BloodHound" width="900">
</p>

*Los permisos peligrosos como WriteDacl, WriteOwner y otros sobre las plantillas de certificados son identificados y mapeados como aristas de ataque.*

---

## Características

| Característica | Descripción |
|----------------|-------------|
| **Nativo de Linux** | Sin dependencias de Windows - enumeración LDAP pura en Python |
| **BloodHound CE v6+** | Importación directa de JSON/ZIP con soporte completo de nodos y aristas |
| **Detección de Vulnerabilidades** | ESC1-ESC11, ESC13-ESC17, GoldenCert |
| **Múltiples Backends** | Funciona con ldap3, impacket o cualquier adaptador LDAP compatible |
| **Integración con NetExec** | Integración fluida con la opción `--bloodhound` de NetExec |
| **Cobertura Exhaustiva** | Plantillas de certificados, CA Empresariales, CA Raíz, NTAuth, CA AIA |

### Vulnerabilidades Soportadas

| Vulnerabilidad | Descripción |
|-----------------|-------------|
| **ESC1** | El solicitante suministra el subject con inscripción de bajos privilegios |
| **ESC2** | Cualquier EKU de propósito o ausencia de EKU permite el abuso de agente de inscripción |
| **ESC3** | Plantillas de agente de inscripción + objetivos vulnerables |
| **ESC4** | Permisos de ACL peligrosos en plantillas de certificados |
| **ESC5** | Control de acceso vulnerable a objetos PKI en contenedores de AD |
| **ESC6** | EDITF_ATTRIBUTESUBJECTALTNAME2 en CA Empresarial |
| **ESC7** | Permisos peligrosos de la CA (ManageCA / ManageCertificates) |
| **ESC8** | Relay de NTLM a endpoints de inscripción web de AD CS (HTTP) |
| **ESC9** | Sin extensión de seguridad + mapeo de certificados débil |
| **ESC10** | Mapeo de certificados débil sin vinculación fuerte |
| **ESC11** | Relay de NTLM a endpoints RPC de AD CS (sin obligatoriedad de cifrado) |
| **ESC13** | Abuso de enlace de grupo OID en política de emisión |
| **ESC14** | Mapeos explícitos de certificados débiles (altSecurityIdentities) |
| **ESC15** | EKUwu - Abuso de política de aplicación en plantillas de Esquema V1 |
| **ESC16** | Extensión de seguridad desactivada globalmente en la CA |
| **ESC17** | EKU de Autenticación de Servidor + solicitante suministra subject (TLS MITM) |
| **GoldenCert** | Extracción de la clave privada de la CA desde el equipo anfitrión |

---

## Instalación

### Desde PyPI (Recomendado)

```bash
pipx install certihound
# O, si necesitas autenticación Kerberos (-k):
pipx install 'certihound[kerberos]'
# En una instalación existente, inyecta gssapi:
pipx inject certihound gssapi
```

### Desde el Código Fuente

```bash
git clone https://github.com/0x0Trace/certihound.git
cd certihound
pip install -e .            # core
pip install -e '.[kerberos]' # con soporte Kerberos
```

### Verificar Instalación

```bash
certihound --version
certihound --help
```

---

## Inicio Rápido

### Línea de Comandos

```bash
# Enumeración básica con autenticación de contraseña
certihound -d corp.local -u 'user' -p 'password' --dc 10.10.10.10 -o output/

# Pass-the-Hash (solo NTHASH, o LMHASH:NTHASH)
certihound -d corp.local -u 'user' -H :31d6cfe0d16ae931b73c59d7e0c089c0 --dc 10.10.10.10

# Conexión LDAPS (SSL/TLS)
certihound -d corp.local -u 'user' -p 'password' --dc 10.10.10.10 --ldaps -o output/

# Autenticación Kerberos (usa ccache; requiere el extra 'kerberos')
KRB5CCNAME=user.ccache certihound -d corp.local -k --dc dc01.corp.local -o output/

# Salida como ZIP (predeterminado) o JSON
certihound -d corp.local -u 'user' -p 'password' --dc 10.10.10.10 --format zip
certihound -d corp.local -u 'user' -p 'password' --dc 10.10.10.10 --format json
```

### Librería de Python

```python
from certihound import ADCSCollector, BloodHoundCEExporter
from certihound.ldap.connection import LDAPConnection, LDAPConfig

# Configurar conexión
config = LDAPConfig(
    domain="corp.local",
    username="user",
    password="password",
    dc_ip="10.10.10.10",
    use_ldaps=True,
)

# Recolectar y exportar
with LDAPConnection(config) as conn:
    collector = ADCSCollector(conn)
    data = collector.collect_all()

    exporter = BloodHoundCEExporter(data.domain, data.domain_sid)
    result = exporter.export(data)
    result.write_zip("bloodhound_adcs.zip")
```

---

## Uso

### Opciones de la CLI

```
Usage: certihound [OPTIONS]

Options:
  -d, --domain TEXT         FQDN del dominio objetivo (ej., corp.local)  [requerido]
  -u, --username TEXT       Nombre de usuario para autenticación
  -p, --password TEXT       Contraseña para autenticación
  -H, --hashes TEXT         Hash NTLM para pass-the-hash (LMHASH:NTHASH o NTHASH)
  --dc TEXT                 IP o hostname del Controlador de Dominio
  -k, --kerberos            Usar autenticación Kerberos (ccache)
  --ldaps                   Usar LDAPS (SSL/TLS)
  --ca-cert PATH            Archivo de certificado de la CA para validación LDAPS
  --port INTEGER            Puerto LDAP (predeterminado: 389 o 636 para LDAPS)
  -o, --output TEXT         Directorio de salida (predeterminado: ./output)
  --format [json|zip|both]  Formato de salida (predeterminado: zip)
  --enum-only               Solo enumerar, omitir detección de vulnerabilidades
  -v, --verbose             Aumentar verbosidad (-v, -vv)
  --version                 Mostrar la versión y salir.
  --help                    Mostrar este mensaje y salir.
```

### Archivos de Salida

CertiHound genera archivos compatibles con BloodHound CE v6:

| Archivo | Descripción |
|---------|-------------|
| `certtemplates.json` | Nodos de plantillas de certificados con propiedades y aristas |
| `enterprisecas.json` | Nodos de CA Empresariales con publicación de plantillas |
| `rootcas.json` | Nodos de jerarquía de CA Raíz |
| `ntauthstores.json` | Configuración del almacén NTAuth |
| `aiacas.json` | Entradas de CA AIA |

---

## Integración con BloodHound

### Importación de Datos

1. Ejecuta CertiHound para generar el archivo ZIP.
2. Abre BloodHound CE.
3. Haz clic en **Import** $\rightarrow$ Selecciona el archivo ZIP generado.
4. Usa las consultas de ADCS integradas o crea las tuyas propias.

### Ejemplos de Consultas Cypher

**Encontrar plantillas vulnerables a ESC1:**
```cypher
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->
(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
WHERE ct.enrolleesuppliessubject = True
AND ct.authenticationenabled = True
RETURN p
```

**Encontrar abuso de ACL de plantillas ESC4:**
```cypher
MATCH p = (principal)-[:WriteDacl|WriteOwner|GenericWrite|GenericAll|WriteAllProperties]->
(ct:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
WHERE NOT principal.objectid ENDS WITH '-512'
AND NOT principal.objectid ENDS WITH '-519'
AND NOT principal.objectid ENDS WITH '-544'
RETURN p
```

---

## Integración con NetExec

CertiHound se integra con [NetExec](https://github.com/Pennyw0rth/NetExec) para la enumeración de ADCS.

```bash
# Recolección solo de ADCS
nxc ldap 10.10.10.10 -u user -p pass --bloodhound -c ADCS

# Recolección completa incluyendo ADCS
nxc ldap 10.10.10.10 -u user -p pass --bloodhound -c All --dns-server 10.10.10.10
```

## Referencia de la API

### Clases Principales

| Clase | Descripción |
|-------|-------------|
| `ADCSCollector` | Colector principal para la enumeración de ADCS |
| `BloodHoundCEExporter` | Exporta datos al formato de BloodHound CE |
| `ImpacketLDAPAdapter` | Adaptador para LDAP basado en impacket (NetExec) |
| `LDAPConnection` | Wrapper independiente para conexiones LDAP |
| `LDAPConfig` | Dataclass de configuración para conexiones LDAP |

### Modelos de Datos

| Clase | Descripción |
|-------|-------------|
| `ADCSData` | Contenedor para todos los datos de ADCS recolectados |
| `CertTemplate` | Plantilla de certificado con propiedades y ACLs |
| `EnterpriseCA` | CA Empresarial con plantillas habilitadas |
| `RootCA` | Nodo de CA Raíz |
| `NTAuthStore` | Almacén de certificados NTAuth |
| `AIACA` | Entrada de CA AIA |
| `ExportResult` | Resultado de la exportación con `write_zip()`, `write_json()`, `to_dict()` |

### Funciones de Detección

```python
from certihound import (
    detect_esc1,
    detect_esc2,
    detect_esc3_agent,
    detect_esc3_target,
    detect_esc4,
    detect_esc5,
    detect_esc6,
    detect_esc7,
    detect_esc8,
    detect_esc9,
    detect_esc10,
    detect_esc11,
    detect_esc13,
    detect_esc14,
    detect_esc15,
    detect_esc16,
    detect_esc17,
)
```

### Ejemplo de Uso

```python
from certihound import (
    ADCSCollector,
    BloodHoundCEExporter,
    ADCSData,
    ExportResult,
)

# Recolectar datos
collector = ADCSCollector.from_external(adapter, domain, domain_sid)
data: ADCSData = collector.collect_all()

# Acceder a objetos recolectados
print(f"Templates: {len(data.templates)}")
print(f"Enterprise CAs: {len(data.enterprise_cas)}")
print(f"Root CAs: {len(data.root_cas)}")

# Exportar a BloodHound
exporter = BloodHoundCEExporter(data.domain, data.domain_sid)
result: ExportResult = exporter.export(data)

# Opciones de salida
result.write_zip("output.zip")      # ZIP para importación en BloodHound
result.write_json("output/")        # Archivos JSON individuales
output_dict = result.to_dict()      # Diccionario de Python
```

---

## Dependencias

| Paquete | Propósito |
|---------|---------|
| `ldap3` | Operaciones LDAP (modo independiente) |
| `impacket` | Autenticación Kerberos e integración con NetExec |
| `cryptography` | Análisis y parsing de certificados |
| `pydantic` | Validación de datos y modelos |
| `click` | Framework de CLI |
| `rich` | Formateo de salida de terminal |

---

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - consulta el archivo [LICENSE](LICENSE) para más detalles.

---

## Créditos y Referencias

- Inspirado en [Certipy](https://github.com/ly4k/Certipy) de Oliver Lyak
- Formato de BloodHound CE basado en [BloodHound](https://github.com/SpecterOps/BloodHound) de SpecterOps
- Investigación de vulnerabilidades ADCS: [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) por Will Schroeder & Lee Christensen
