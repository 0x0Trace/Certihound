"""Tests for vulnerability detection modules."""

import pytest
from certihound.objects.certtemplate import CertTemplate, EnrollmentFlags
from certihound.objects.enterpriseca import EnterpriseCA
from certihound.detection.esc1 import detect_esc1, check_esc1_conditions
from certihound.detection.esc3 import detect_esc3_agent, detect_esc3_target, find_esc3_chains
from certihound.detection.esc4 import detect_esc4
from certihound.detection.esc6 import detect_esc6
from certihound.detection.esc9 import detect_esc9
from certihound.detection.esc10 import detect_esc10
from certihound.detection.esc13 import detect_esc13
from certihound.detection.goldencert import detect_goldencert, get_goldencert_edge
from certihound.acl.rights import ADCSRights
from certihound.utils.crypto import OID


class TestESC1Detection:
    """Tests for ESC1 vulnerability detection."""

    def create_template(self, **kwargs) -> CertTemplate:
        """Create a test template with specified attributes."""
        defaults = {
            "cn": "TestTemplate",
            "name": "TestTemplate",
            "display_name": "Test Template",
            "object_guid": "12345678-1234-1234-1234-123456789012",
            "distinguished_name": "CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            "domain": "CORP.LOCAL",
            "domain_sid": "S-1-5-21-1234567890-1234567890-1234567890",
            "certificate_name_flag": 0,
            "enrollment_flag": 0,
            "ra_signature": 0,
            "ekus": [],
            "enrollment_principals": [],
        }
        defaults.update(kwargs)
        return CertTemplate(**defaults)

    def create_ca(self, templates: list[str] = None) -> EnterpriseCA:
        """Create a test CA with specified templates."""
        return EnterpriseCA(
            cn="TestCA",
            name="TestCA",
            object_guid="87654321-4321-4321-4321-210987654321",
            distinguished_name="CN=TestCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            domain="CORP.LOCAL",
            domain_sid="S-1-5-21-1234567890-1234567890-1234567890",
            certificate_templates=templates or ["TestTemplate"],
        )

    def test_esc1_vulnerable_template(self):
        """Test detection of a vulnerable ESC1 template."""
        domain_sid = "S-1-5-21-1234567890-1234567890-1234567890"

        template = self.create_template(
            certificate_name_flag=1,  # ENROLLEE_SUPPLIES_SUBJECT
            enrollment_flag=0,  # No manager approval
            ra_signature=0,  # No signature required
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{domain_sid}-513"],  # Domain Users
        )

        ca = self.create_ca()

        result = detect_esc1(template, ca, domain_sid)

        assert result is not None
        assert result.vulnerable is True
        assert len(result.vulnerable_principals) == 1
        assert "ENROLLEE_SUPPLIES_SUBJECT" in result.reasons[0]

    def test_esc1_no_enrollee_supplies_subject(self):
        """Test that template without ENROLLEE_SUPPLIES_SUBJECT is not vulnerable."""
        domain_sid = "S-1-5-21-1234567890-1234567890-1234567890"

        template = self.create_template(
            certificate_name_flag=0,  # No ENROLLEE_SUPPLIES_SUBJECT
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{domain_sid}-513"],
        )

        ca = self.create_ca()

        result = detect_esc1(template, ca, domain_sid)

        assert result is None

    def test_esc1_manager_approval_required(self):
        """Test that template with manager approval is not vulnerable."""
        domain_sid = "S-1-5-21-1234567890-1234567890-1234567890"

        template = self.create_template(
            certificate_name_flag=1,  # ENROLLEE_SUPPLIES_SUBJECT
            enrollment_flag=2,  # PEND_ALL_REQUESTS (manager approval)
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{domain_sid}-513"],
        )

        ca = self.create_ca()

        result = detect_esc1(template, ca, domain_sid)

        assert result is None

    def test_esc1_signature_required(self):
        """Test that template with signature requirement is not vulnerable."""
        domain_sid = "S-1-5-21-1234567890-1234567890-1234567890"

        template = self.create_template(
            certificate_name_flag=1,  # ENROLLEE_SUPPLIES_SUBJECT
            enrollment_flag=0,
            ra_signature=1,  # Signature required
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{domain_sid}-513"],
        )

        ca = self.create_ca()

        result = detect_esc1(template, ca, domain_sid)

        assert result is None

    def test_esc1_no_auth_eku(self):
        """Test that template without authentication EKU is not vulnerable."""
        domain_sid = "S-1-5-21-1234567890-1234567890-1234567890"

        template = self.create_template(
            certificate_name_flag=1,
            enrollment_flag=0,
            ra_signature=0,
            ekus=["1.2.3.4.5"],  # Some non-auth EKU
            enrollment_principals=[f"{domain_sid}-513"],
        )

        ca = self.create_ca()

        result = detect_esc1(template, ca, domain_sid)

        assert result is None

    def test_esc1_no_low_priv_enrollment(self):
        """Test that template with only high-priv enrollment is not vulnerable."""
        domain_sid = "S-1-5-21-1234567890-1234567890-1234567890"

        template = self.create_template(
            certificate_name_flag=1,
            enrollment_flag=0,
            ra_signature=0,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{domain_sid}-512"],  # Domain Admins
        )

        ca = self.create_ca()

        result = detect_esc1(template, ca, domain_sid)

        # Not vulnerable because only high-priv can enroll
        assert result is None

    def test_esc1_template_not_published(self):
        """Test that unpublished template is not vulnerable."""
        domain_sid = "S-1-5-21-1234567890-1234567890-1234567890"

        template = self.create_template(
            cn="NotPublished",
            certificate_name_flag=1,
            enrollment_flag=0,
            ra_signature=0,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{domain_sid}-513"],
        )

        ca = self.create_ca(templates=["OtherTemplate"])  # Different template

        result = detect_esc1(template, ca, domain_sid)

        assert result is None

    def test_check_esc1_conditions(self):
        """Test individual condition checking."""
        template = self.create_template(
            certificate_name_flag=1,
            enrollment_flag=2,  # Manager approval
            ra_signature=0,
            ekus=[OID.CLIENT_AUTHENTICATION],
        )

        conditions = check_esc1_conditions(template)

        assert conditions["enrollee_supplies_subject"] is True
        assert conditions["has_authentication_eku"] is True
        assert conditions["no_manager_approval"] is False  # Manager approval required
        assert conditions["no_signature_required"] is True


class TestCertTemplateModel:
    """Tests for CertTemplate model."""

    def test_computed_properties(self):
        """Test computed properties work correctly."""
        template = CertTemplate(
            cn="Test",
            name="Test",
            domain="CORP.LOCAL",
            domain_sid="S-1-5-21-1234567890-1234567890-1234567890",
            certificate_name_flag=0x02000001,  # ENROLLEE_SUPPLIES_SUBJECT + SUBJECT_ALT_REQUIRE_UPN
            enrollment_flag=2,  # PEND_ALL_REQUESTS
            ra_signature=0,
            ekus=[OID.CLIENT_AUTHENTICATION, OID.SMART_CARD_LOGON],
        )

        assert template.enrollee_supplies_subject is True
        assert template.requires_manager_approval is True
        assert template.subject_alt_require_upn is True
        assert template.has_authentication_eku is True
        assert template.no_signature_required is True

    def test_empty_ekus_allows_auth(self):
        """Test that empty EKUs means any purpose (including auth)."""
        template = CertTemplate(
            cn="Test",
            name="Test",
            domain="CORP.LOCAL",
            domain_sid="S-1-5-21-1234567890-1234567890-1234567890",
            ekus=[],
        )

        assert template.has_authentication_eku is True


class TestESC3Detection:
    """Tests for ESC3 vulnerability detection."""

    DOMAIN_SID = "S-1-5-21-1234567890-1234567890-1234567890"

    def create_template(self, **kwargs) -> CertTemplate:
        """Create a test template with specified attributes."""
        defaults = {
            "cn": "TestTemplate",
            "name": "TestTemplate",
            "display_name": "Test Template",
            "object_guid": "12345678-1234-1234-1234-123456789012",
            "distinguished_name": "CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            "domain": "CORP.LOCAL",
            "domain_sid": self.DOMAIN_SID,
            "certificate_name_flag": 0,
            "enrollment_flag": 0,
            "ra_signature": 0,
            "ekus": [],
            "enrollment_principals": [],
            "schema_version": 2,
        }
        defaults.update(kwargs)
        return CertTemplate(**defaults)

    def create_ca(self, templates: list[str] = None) -> EnterpriseCA:
        """Create a test CA with specified templates."""
        return EnterpriseCA(
            cn="TestCA",
            name="TestCA",
            object_guid="87654321-4321-4321-4321-210987654321",
            distinguished_name="CN=TestCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            domain="CORP.LOCAL",
            domain_sid=self.DOMAIN_SID,
            certificate_templates=templates or ["TestTemplate"],
        )

    def test_esc3_agent_vulnerable(self):
        """Test detection of vulnerable ESC3 agent template."""
        template = self.create_template(
            cn="EnrollmentAgent",
            ekus=[OID.CERTIFICATE_REQUEST_AGENT],
            enrollment_flag=0,  # No manager approval
            ra_signature=0,  # No signature required
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],  # Domain Users
        )
        ca = self.create_ca(templates=["EnrollmentAgent"])

        result = detect_esc3_agent(template, ca, self.DOMAIN_SID)

        assert result is not None
        assert result.vulnerable is True
        assert "Certificate Request Agent EKU" in result.reasons[0]
        assert len(result.vulnerable_principals) == 1

    def test_esc3_agent_no_agent_eku(self):
        """Test that template without Certificate Request Agent EKU is not agent-vulnerable."""
        template = self.create_template(
            ekus=[OID.CLIENT_AUTHENTICATION],  # Wrong EKU
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        result = detect_esc3_agent(template, ca, self.DOMAIN_SID)

        assert result is None

    def test_esc3_agent_manager_approval_required(self):
        """Test that agent template with manager approval is not vulnerable."""
        template = self.create_template(
            ekus=[OID.CERTIFICATE_REQUEST_AGENT],
            enrollment_flag=2,  # PEND_ALL_REQUESTS
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        result = detect_esc3_agent(template, ca, self.DOMAIN_SID)

        assert result is None

    def test_esc3_agent_signature_required(self):
        """Test that agent template with signature requirement is not vulnerable."""
        template = self.create_template(
            ekus=[OID.CERTIFICATE_REQUEST_AGENT],
            ra_signature=1,  # Signature required
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        result = detect_esc3_agent(template, ca, self.DOMAIN_SID)

        assert result is None

    def test_esc3_target_schema_v1_vulnerable(self):
        """Test detection of vulnerable ESC3 target template (schema v1)."""
        template = self.create_template(
            cn="UserTemplate",
            schema_version=1,  # Schema v1 accepts agent requests by default
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_flag=0,  # No manager approval
        )
        ca = self.create_ca(templates=["UserTemplate"])

        result = detect_esc3_target(template, ca)

        assert result is not None
        assert result.vulnerable is True
        assert "Schema version 1" in result.reasons[0]

    def test_esc3_target_ra_policy_vulnerable(self):
        """Test detection of vulnerable ESC3 target template (RA policy)."""
        template = self.create_template(
            cn="TargetTemplate",
            schema_version=2,
            ra_application_policies=[OID.CERTIFICATE_REQUEST_AGENT],  # Accepts agent requests
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_flag=0,
        )
        ca = self.create_ca(templates=["TargetTemplate"])

        result = detect_esc3_target(template, ca)

        assert result is not None
        assert result.vulnerable is True
        assert "RA Application Policy" in result.reasons[0]

    def test_esc3_target_no_auth_eku(self):
        """Test that target template without auth EKU is not vulnerable."""
        template = self.create_template(
            schema_version=1,
            ekus=["1.2.3.4.5"],  # Non-auth EKU
        )
        ca = self.create_ca()

        result = detect_esc3_target(template, ca)

        assert result is None

    def test_esc3_target_manager_approval(self):
        """Test that target template with manager approval is not vulnerable."""
        template = self.create_template(
            schema_version=1,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_flag=2,  # Manager approval
        )
        ca = self.create_ca()

        result = detect_esc3_target(template, ca)

        assert result is None

    def test_esc3_chain_detection(self):
        """Test complete ESC3 chain detection."""
        agent_template = self.create_template(
            cn="AgentTemplate",
            ekus=[OID.CERTIFICATE_REQUEST_AGENT],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        target_template = self.create_template(
            cn="TargetTemplate",
            schema_version=1,
            ekus=[OID.CLIENT_AUTHENTICATION],
        )
        ca = self.create_ca(templates=["AgentTemplate", "TargetTemplate"])

        chains = find_esc3_chains([agent_template, target_template], [ca], self.DOMAIN_SID)

        assert len(chains) == 1
        agent_result, target_results = chains[0]
        assert agent_result.template_name == "AgentTemplate"
        assert len(target_results) == 1
        assert target_results[0].template_name == "TargetTemplate"


class TestESC6Detection:
    """Tests for ESC6 vulnerability detection."""

    DOMAIN_SID = "S-1-5-21-1234567890-1234567890-1234567890"

    def create_template(self, **kwargs) -> CertTemplate:
        """Create a test template with specified attributes."""
        defaults = {
            "cn": "TestTemplate",
            "name": "TestTemplate",
            "display_name": "Test Template",
            "object_guid": "12345678-1234-1234-1234-123456789012",
            "distinguished_name": "CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            "domain": "CORP.LOCAL",
            "domain_sid": self.DOMAIN_SID,
            "certificate_name_flag": 0,
            "enrollment_flag": 0,
            "ra_signature": 0,
            "ekus": [],
            "enrollment_principals": [],
        }
        defaults.update(kwargs)
        return CertTemplate(**defaults)

    def create_ca(self, templates: list[str] = None, san_enabled: bool = True) -> EnterpriseCA:
        """Create a test CA with EDITF_ATTRIBUTESUBJECTALTNAME2 option."""
        return EnterpriseCA(
            cn="TestCA",
            name="TestCA",
            object_guid="87654321-4321-4321-4321-210987654321",
            distinguished_name="CN=TestCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            domain="CORP.LOCAL",
            domain_sid=self.DOMAIN_SID,
            certificate_templates=templates or ["TestTemplate"],
            is_user_specifies_san_enabled=san_enabled,
        )

    def test_esc6a_no_security_extension(self):
        """Test ESC6a detection with NO_SECURITY_EXTENSION flag."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,  # NO_SECURITY_EXTENSION
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca(san_enabled=True)

        results = detect_esc6(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=True)

        assert len(results) == 1
        assert results[0].variant == "a"
        assert "NO_SECURITY_EXTENSION" in results[0].reasons[-1]

    def test_esc6a_weak_binding(self):
        """Test ESC6a detection with weak certificate binding."""
        template = self.create_template(
            enrollment_flag=0,  # No NO_SECURITY_EXTENSION
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca(san_enabled=True)

        results = detect_esc6(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 1
        assert results[0].variant == "a"
        assert "Strong certificate binding not enforced" in results[0].reasons[-1]

    def test_esc6b_schannel_upn_mapping(self):
        """Test ESC6b detection with Schannel UPN mapping enabled."""
        template = self.create_template(
            enrollment_flag=0,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca(san_enabled=True)

        results = detect_esc6(
            template, ca, self.DOMAIN_SID,
            strong_cert_binding_enforced=True,  # ESC6a not triggered
            cert_mapping_methods=0x4,  # UPN mapping enabled
        )

        assert len(results) == 1
        assert results[0].variant == "b"
        assert "Schannel UPN mapping enabled" in results[0].reasons[-1]

    def test_esc6_both_variants(self):
        """Test that both ESC6a and ESC6b can be detected together."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca(san_enabled=True)

        results = detect_esc6(
            template, ca, self.DOMAIN_SID,
            strong_cert_binding_enforced=True,
            cert_mapping_methods=0x4,  # UPN mapping enabled
        )

        assert len(results) == 2
        variants = {r.variant for r in results}
        assert variants == {"a", "b"}

    def test_esc6_ca_san_not_enabled(self):
        """Test that ESC6 requires CA with EDITF_ATTRIBUTESUBJECTALTNAME2."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca(san_enabled=False)  # SAN not enabled on CA

        results = detect_esc6(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 0

    def test_esc6_no_auth_eku(self):
        """Test that ESC6 requires authentication EKU."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            ekus=["1.2.3.4.5"],  # Non-auth EKU
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca(san_enabled=True)

        results = detect_esc6(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 0

    def test_esc6_manager_approval(self):
        """Test that ESC6 requires no manager approval."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION | 2,  # NO_SECURITY_EXTENSION + PEND_ALL_REQUESTS
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca(san_enabled=True)

        results = detect_esc6(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 0

    def test_esc6_no_low_priv_enrollment(self):
        """Test that ESC6 requires low-privileged enrollment rights."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-512"],  # Domain Admins only
        )
        ca = self.create_ca(san_enabled=True)

        results = detect_esc6(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 0

    def test_esc6_template_not_published(self):
        """Test that ESC6 requires template published to CA."""
        template = self.create_template(
            cn="NotPublished",
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca(templates=["OtherTemplate"], san_enabled=True)

        results = detect_esc6(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 0


class TestESC9Detection:
    """Tests for ESC9 vulnerability detection."""

    DOMAIN_SID = "S-1-5-21-1234567890-1234567890-1234567890"

    def create_template(self, **kwargs) -> CertTemplate:
        """Create a test template with specified attributes."""
        defaults = {
            "cn": "TestTemplate",
            "name": "TestTemplate",
            "display_name": "Test Template",
            "object_guid": "12345678-1234-1234-1234-123456789012",
            "distinguished_name": "CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            "domain": "CORP.LOCAL",
            "domain_sid": self.DOMAIN_SID,
            "certificate_name_flag": 0,
            "enrollment_flag": 0,
            "ra_signature": 0,
            "ekus": [],
            "enrollment_principals": [],
        }
        defaults.update(kwargs)
        return CertTemplate(**defaults)

    def create_ca(self, templates: list[str] = None) -> EnterpriseCA:
        """Create a test CA."""
        return EnterpriseCA(
            cn="TestCA",
            name="TestCA",
            object_guid="87654321-4321-4321-4321-210987654321",
            distinguished_name="CN=TestCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            domain="CORP.LOCAL",
            domain_sid=self.DOMAIN_SID,
            certificate_templates=templates or ["TestTemplate"],
        )

    def test_esc9a_upn_mapping(self):
        """Test ESC9a detection (UPN in SAN for user impersonation)."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            certificate_name_flag=0x02000000,  # SUBJECT_ALT_REQUIRE_UPN
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc9(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 1
        assert results[0].variant == "a"
        assert "UPN in SAN" in results[0].reasons[-1]

    def test_esc9b_dns_mapping(self):
        """Test ESC9b detection (DNS in SAN for computer impersonation)."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            certificate_name_flag=0x08000000,  # SUBJECT_ALT_REQUIRE_DNS
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc9(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 1
        assert results[0].variant == "b"
        assert "DNS in SAN" in results[0].reasons[-1]

    def test_esc9_both_variants(self):
        """Test that both ESC9a and ESC9b can be detected when UPN and DNS required."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            certificate_name_flag=0x02000000 | 0x08000000,  # UPN + DNS
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc9(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        # ESC9a requires UPN but NOT DNS, so only ESC9b should trigger
        assert len(results) == 1
        assert results[0].variant == "b"

    def test_esc9_no_security_extension_required(self):
        """Test that ESC9 requires NO_SECURITY_EXTENSION flag."""
        template = self.create_template(
            enrollment_flag=0,  # No NO_SECURITY_EXTENSION
            certificate_name_flag=0x02000000,  # SUBJECT_ALT_REQUIRE_UPN
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc9(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 0

    def test_esc9_strong_binding_blocks(self):
        """Test that ESC9 is blocked when strong certificate binding is enforced."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            certificate_name_flag=0x02000000,  # SUBJECT_ALT_REQUIRE_UPN
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc9(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=True)

        assert len(results) == 0

    def test_esc9_no_auth_eku(self):
        """Test that ESC9 requires authentication EKU."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            certificate_name_flag=0x02000000,
            ekus=["1.2.3.4.5"],  # Non-auth EKU
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc9(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 0

    def test_esc9_manager_approval(self):
        """Test that ESC9 requires no manager approval."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION | 2,  # + PEND_ALL_REQUESTS
            certificate_name_flag=0x02000000,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc9(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 0

    def test_esc9_no_low_priv_enrollment(self):
        """Test that ESC9 requires low-privileged enrollment rights."""
        template = self.create_template(
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            certificate_name_flag=0x02000000,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-512"],  # Domain Admins only
        )
        ca = self.create_ca()

        results = detect_esc9(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 0

    def test_esc9_template_not_published(self):
        """Test that ESC9 requires template published to CA."""
        template = self.create_template(
            cn="NotPublished",
            enrollment_flag=EnrollmentFlags.NO_SECURITY_EXTENSION,
            certificate_name_flag=0x02000000,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca(templates=["OtherTemplate"])

        results = detect_esc9(template, ca, self.DOMAIN_SID, strong_cert_binding_enforced=False)

        assert len(results) == 0


class MockSecurityDescriptorParser:
    """Mock SecurityDescriptorParser for testing ESC4."""

    def __init__(self, rights: list[ADCSRights]):
        self._rights = rights

    def get_enrollment_rights(self) -> list[ADCSRights]:
        return self._rights


class TestESC4Detection:
    """Tests for ESC4 vulnerability detection."""

    DOMAIN_SID = "S-1-5-21-1234567890-1234567890-1234567890"

    def create_template(self, **kwargs) -> CertTemplate:
        """Create a test template with specified attributes."""
        defaults = {
            "cn": "TestTemplate",
            "name": "TestTemplate",
            "display_name": "Test Template",
            "object_guid": "12345678-1234-1234-1234-123456789012",
            "distinguished_name": "CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            "domain": "CORP.LOCAL",
            "domain_sid": self.DOMAIN_SID,
            "certificate_name_flag": 0,
            "enrollment_flag": 0,
            "ra_signature": 0,
            "ekus": [],
            "enrollment_principals": [],
        }
        defaults.update(kwargs)
        return CertTemplate(**defaults)

    def create_ca(self, templates: list[str] = None) -> EnterpriseCA:
        """Create a test CA."""
        return EnterpriseCA(
            cn="TestCA",
            name="TestCA",
            object_guid="87654321-4321-4321-4321-210987654321",
            distinguished_name="CN=TestCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            domain="CORP.LOCAL",
            domain_sid=self.DOMAIN_SID,
            certificate_templates=templates or ["TestTemplate"],
        )

    def test_esc4_write_dacl(self):
        """Test ESC4 detection with WriteDacl permission."""
        template = self.create_template()
        ca = self.create_ca()

        # Low-priv user has WriteDacl
        sd_parser = MockSecurityDescriptorParser([
            ADCSRights(
                sid=f"{self.DOMAIN_SID}-513",  # Domain Users
                write_dacl=True,
            )
        ])

        result = detect_esc4(template, ca, sd_parser, self.DOMAIN_SID)

        assert result is not None
        assert result.vulnerable is True
        assert len(result.vulnerable_principals) == 1
        assert "WriteDacl" in result.vulnerable_principals[0]["rights"]

    def test_esc4_write_owner(self):
        """Test ESC4 detection with WriteOwner permission."""
        template = self.create_template()
        ca = self.create_ca()

        sd_parser = MockSecurityDescriptorParser([
            ADCSRights(
                sid=f"{self.DOMAIN_SID}-513",
                write_owner=True,
            )
        ])

        result = detect_esc4(template, ca, sd_parser, self.DOMAIN_SID)

        assert result is not None
        assert "WriteOwner" in result.vulnerable_principals[0]["rights"]

    def test_esc4_generic_all(self):
        """Test ESC4 detection with GenericAll permission."""
        template = self.create_template()
        ca = self.create_ca()

        sd_parser = MockSecurityDescriptorParser([
            ADCSRights(
                sid=f"{self.DOMAIN_SID}-513",
                generic_all=True,
            )
        ])

        result = detect_esc4(template, ca, sd_parser, self.DOMAIN_SID)

        assert result is not None
        assert "GenericAll" in result.vulnerable_principals[0]["rights"]

    def test_esc4_generic_write(self):
        """Test ESC4 detection with GenericWrite permission."""
        template = self.create_template()
        ca = self.create_ca()

        sd_parser = MockSecurityDescriptorParser([
            ADCSRights(
                sid=f"{self.DOMAIN_SID}-513",
                generic_write=True,
            )
        ])

        result = detect_esc4(template, ca, sd_parser, self.DOMAIN_SID)

        assert result is not None
        assert "GenericWrite" in result.vulnerable_principals[0]["rights"]

    def test_esc4_write_property(self):
        """Test ESC4 detection with WriteProperty permission."""
        template = self.create_template()
        ca = self.create_ca()

        sd_parser = MockSecurityDescriptorParser([
            ADCSRights(
                sid=f"{self.DOMAIN_SID}-513",
                write_property=True,
            )
        ])

        result = detect_esc4(template, ca, sd_parser, self.DOMAIN_SID)

        assert result is not None
        assert "WriteProperty" in result.vulnerable_principals[0]["rights"]

    def test_esc4_multiple_dangerous_rights(self):
        """Test ESC4 detection with multiple dangerous permissions."""
        template = self.create_template()
        ca = self.create_ca()

        sd_parser = MockSecurityDescriptorParser([
            ADCSRights(
                sid=f"{self.DOMAIN_SID}-513",
                write_dacl=True,
                generic_write=True,
            )
        ])

        result = detect_esc4(template, ca, sd_parser, self.DOMAIN_SID)

        assert result is not None
        assert len(result.vulnerable_principals[0]["rights"]) == 2
        assert "WriteDacl" in result.vulnerable_principals[0]["rights"]
        assert "GenericWrite" in result.vulnerable_principals[0]["rights"]

    def test_esc4_high_priv_only(self):
        """Test that ESC4 ignores high-privileged principals."""
        template = self.create_template()
        ca = self.create_ca()

        # Only Domain Admins have write access
        sd_parser = MockSecurityDescriptorParser([
            ADCSRights(
                sid=f"{self.DOMAIN_SID}-512",  # Domain Admins
                generic_all=True,
            )
        ])

        result = detect_esc4(template, ca, sd_parser, self.DOMAIN_SID)

        assert result is None

    def test_esc4_no_dangerous_rights(self):
        """Test that ESC4 not triggered without dangerous permissions."""
        template = self.create_template()
        ca = self.create_ca()

        # Only enrollment rights, no write access
        sd_parser = MockSecurityDescriptorParser([
            ADCSRights(
                sid=f"{self.DOMAIN_SID}-513",
                enroll=True,
            )
        ])

        result = detect_esc4(template, ca, sd_parser, self.DOMAIN_SID)

        assert result is None

    def test_esc4_template_not_published(self):
        """Test that ESC4 requires template published to CA."""
        template = self.create_template(cn="NotPublished")
        ca = self.create_ca(templates=["OtherTemplate"])

        sd_parser = MockSecurityDescriptorParser([
            ADCSRights(
                sid=f"{self.DOMAIN_SID}-513",
                generic_all=True,
            )
        ])

        result = detect_esc4(template, ca, sd_parser, self.DOMAIN_SID)

        assert result is None

    def test_esc4_inherited_permission(self):
        """Test ESC4 tracks inherited permissions."""
        template = self.create_template()
        ca = self.create_ca()

        sd_parser = MockSecurityDescriptorParser([
            ADCSRights(
                sid=f"{self.DOMAIN_SID}-513",
                write_dacl=True,
                inherited=True,
            )
        ])

        result = detect_esc4(template, ca, sd_parser, self.DOMAIN_SID)

        assert result is not None
        assert result.vulnerable_principals[0]["inherited"] is True


class TestESC10Detection:
    """Tests for ESC10 vulnerability detection."""

    DOMAIN_SID = "S-1-5-21-1234567890-1234567890-1234567890"

    def create_template(self, **kwargs) -> CertTemplate:
        """Create a test template with specified attributes."""
        defaults = {
            "cn": "TestTemplate",
            "name": "TestTemplate",
            "display_name": "Test Template",
            "object_guid": "12345678-1234-1234-1234-123456789012",
            "distinguished_name": "CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            "domain": "CORP.LOCAL",
            "domain_sid": self.DOMAIN_SID,
            "certificate_name_flag": 0,
            "enrollment_flag": 0,
            "ra_signature": 0,
            "ekus": [],
            "enrollment_principals": [],
        }
        defaults.update(kwargs)
        return CertTemplate(**defaults)

    def create_ca(self, templates: list[str] = None) -> EnterpriseCA:
        """Create a test CA."""
        return EnterpriseCA(
            cn="TestCA",
            name="TestCA",
            object_guid="87654321-4321-4321-4321-210987654321",
            distinguished_name="CN=TestCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            domain="CORP.LOCAL",
            domain_sid=self.DOMAIN_SID,
            certificate_templates=templates or ["TestTemplate"],
        )

    def test_esc10a_upn_mapping(self):
        """Test ESC10a detection (UPN mapping for user impersonation)."""
        template = self.create_template(
            certificate_name_flag=0x02000000,  # SUBJECT_ALT_REQUIRE_UPN
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc10(
            template, ca, self.DOMAIN_SID,
            cert_mapping_methods=0x4,  # UPN mapping enabled
            strong_cert_binding_enforced=False,
        )

        assert len(results) == 1
        assert results[0].variant == "a"
        assert "UPN in SAN" in results[0].reasons[-1]

    def test_esc10b_dns_mapping(self):
        """Test ESC10b detection (DNS mapping for computer impersonation)."""
        template = self.create_template(
            certificate_name_flag=0x08000000,  # SUBJECT_ALT_REQUIRE_DNS
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc10(
            template, ca, self.DOMAIN_SID,
            cert_mapping_methods=0x4,  # UPN mapping enabled
            strong_cert_binding_enforced=False,
        )

        assert len(results) == 1
        assert results[0].variant == "b"
        assert "DNS in SAN" in results[0].reasons[-1]

    def test_esc10_both_variants(self):
        """Test that only ESC10b triggers when both UPN and DNS required."""
        template = self.create_template(
            certificate_name_flag=0x02000000 | 0x08000000,  # UPN + DNS
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc10(
            template, ca, self.DOMAIN_SID,
            cert_mapping_methods=0x4,
            strong_cert_binding_enforced=False,
        )

        # ESC10a requires UPN but NOT DNS, so only ESC10b should trigger
        assert len(results) == 1
        assert results[0].variant == "b"

    def test_esc10_no_upn_mapping(self):
        """Test that ESC10 requires UPN mapping flag."""
        template = self.create_template(
            certificate_name_flag=0x02000000,  # SUBJECT_ALT_REQUIRE_UPN
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc10(
            template, ca, self.DOMAIN_SID,
            cert_mapping_methods=0x0,  # No mapping enabled
            strong_cert_binding_enforced=False,
        )

        assert len(results) == 0

    def test_esc10_strong_binding_blocks(self):
        """Test that ESC10 is blocked when strong certificate binding is enforced."""
        template = self.create_template(
            certificate_name_flag=0x02000000,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc10(
            template, ca, self.DOMAIN_SID,
            cert_mapping_methods=0x4,
            strong_cert_binding_enforced=True,  # Strong binding blocks
        )

        assert len(results) == 0

    def test_esc10_no_auth_eku(self):
        """Test that ESC10 requires authentication EKU."""
        template = self.create_template(
            certificate_name_flag=0x02000000,
            ekus=["1.2.3.4.5"],  # Non-auth EKU
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc10(
            template, ca, self.DOMAIN_SID,
            cert_mapping_methods=0x4,
            strong_cert_binding_enforced=False,
        )

        assert len(results) == 0

    def test_esc10_manager_approval(self):
        """Test that ESC10 requires no manager approval."""
        template = self.create_template(
            certificate_name_flag=0x02000000,
            enrollment_flag=2,  # PEND_ALL_REQUESTS
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        results = detect_esc10(
            template, ca, self.DOMAIN_SID,
            cert_mapping_methods=0x4,
            strong_cert_binding_enforced=False,
        )

        assert len(results) == 0

    def test_esc10_no_low_priv_enrollment(self):
        """Test that ESC10 requires low-privileged enrollment rights."""
        template = self.create_template(
            certificate_name_flag=0x02000000,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-512"],  # Domain Admins only
        )
        ca = self.create_ca()

        results = detect_esc10(
            template, ca, self.DOMAIN_SID,
            cert_mapping_methods=0x4,
            strong_cert_binding_enforced=False,
        )

        assert len(results) == 0

    def test_esc10_template_not_published(self):
        """Test that ESC10 requires template published to CA."""
        template = self.create_template(
            cn="NotPublished",
            certificate_name_flag=0x02000000,
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca(templates=["OtherTemplate"])

        results = detect_esc10(
            template, ca, self.DOMAIN_SID,
            cert_mapping_methods=0x4,
            strong_cert_binding_enforced=False,
        )

        assert len(results) == 0


class TestESC13Detection:
    """Tests for ESC13 vulnerability detection."""

    DOMAIN_SID = "S-1-5-21-1234567890-1234567890-1234567890"

    def create_template(self, **kwargs) -> CertTemplate:
        """Create a test template with specified attributes."""
        defaults = {
            "cn": "TestTemplate",
            "name": "TestTemplate",
            "display_name": "Test Template",
            "object_guid": "12345678-1234-1234-1234-123456789012",
            "distinguished_name": "CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            "domain": "CORP.LOCAL",
            "domain_sid": self.DOMAIN_SID,
            "certificate_name_flag": 0,
            "enrollment_flag": 0,
            "ra_signature": 0,
            "ekus": [],
            "application_policies": [],
            "enrollment_principals": [],
        }
        defaults.update(kwargs)
        return CertTemplate(**defaults)

    def create_ca(self, templates: list[str] = None) -> EnterpriseCA:
        """Create a test CA."""
        return EnterpriseCA(
            cn="TestCA",
            name="TestCA",
            object_guid="87654321-4321-4321-4321-210987654321",
            distinguished_name="CN=TestCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            domain="CORP.LOCAL",
            domain_sid=self.DOMAIN_SID,
            certificate_templates=templates or ["TestTemplate"],
        )

    def test_esc13_vulnerable(self):
        """Test ESC13 detection with linked issuance policy."""
        policy_oid = "1.3.6.1.4.1.311.21.8.123456"
        linked_group = "CN=HighPrivGroup,CN=Users,DC=corp,DC=local"

        template = self.create_template(
            application_policies=[policy_oid],
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        issuance_policies = {policy_oid: linked_group}

        result = detect_esc13(template, ca, self.DOMAIN_SID, issuance_policies)

        assert result is not None
        assert result.vulnerable is True
        assert result.issuance_policy_oid == policy_oid
        assert result.linked_group_dn == linked_group
        assert "issuance policy OID" in result.reasons[0]

    def test_esc13_no_linked_policy(self):
        """Test that ESC13 requires policy linked to group."""
        policy_oid = "1.3.6.1.4.1.311.21.8.123456"
        other_policy = "1.3.6.1.4.1.311.21.8.999999"

        template = self.create_template(
            application_policies=[policy_oid],
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        # Different policy is linked, not the one in template
        issuance_policies = {other_policy: "CN=SomeGroup,DC=corp,DC=local"}

        result = detect_esc13(template, ca, self.DOMAIN_SID, issuance_policies)

        assert result is None

    def test_esc13_no_policies(self):
        """Test that ESC13 requires issuance policies dict."""
        template = self.create_template(
            application_policies=["1.3.6.1.4.1.311.21.8.123456"],
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        result = detect_esc13(template, ca, self.DOMAIN_SID, issuance_policies=None)

        assert result is None

    def test_esc13_empty_policies(self):
        """Test that ESC13 requires non-empty issuance policies."""
        template = self.create_template(
            application_policies=["1.3.6.1.4.1.311.21.8.123456"],
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        result = detect_esc13(template, ca, self.DOMAIN_SID, issuance_policies={})

        assert result is None

    def test_esc13_no_auth_eku(self):
        """Test that ESC13 requires authentication EKU."""
        policy_oid = "1.3.6.1.4.1.311.21.8.123456"

        template = self.create_template(
            application_policies=[policy_oid],
            ekus=["1.2.3.4.5"],  # Non-auth EKU
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        issuance_policies = {policy_oid: "CN=Group,DC=corp,DC=local"}

        result = detect_esc13(template, ca, self.DOMAIN_SID, issuance_policies)

        assert result is None

    def test_esc13_manager_approval(self):
        """Test that ESC13 requires no manager approval."""
        policy_oid = "1.3.6.1.4.1.311.21.8.123456"

        template = self.create_template(
            application_policies=[policy_oid],
            enrollment_flag=2,  # PEND_ALL_REQUESTS
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        issuance_policies = {policy_oid: "CN=Group,DC=corp,DC=local"}

        result = detect_esc13(template, ca, self.DOMAIN_SID, issuance_policies)

        assert result is None

    def test_esc13_no_low_priv_enrollment(self):
        """Test that ESC13 requires low-privileged enrollment rights."""
        policy_oid = "1.3.6.1.4.1.311.21.8.123456"

        template = self.create_template(
            application_policies=[policy_oid],
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-512"],  # Domain Admins only
        )
        ca = self.create_ca()

        issuance_policies = {policy_oid: "CN=Group,DC=corp,DC=local"}

        result = detect_esc13(template, ca, self.DOMAIN_SID, issuance_policies)

        assert result is None

    def test_esc13_template_not_published(self):
        """Test that ESC13 requires template published to CA."""
        policy_oid = "1.3.6.1.4.1.311.21.8.123456"

        template = self.create_template(
            cn="NotPublished",
            application_policies=[policy_oid],
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca(templates=["OtherTemplate"])

        issuance_policies = {policy_oid: "CN=Group,DC=corp,DC=local"}

        result = detect_esc13(template, ca, self.DOMAIN_SID, issuance_policies)

        assert result is None

    def test_esc13_multiple_policies_first_match(self):
        """Test ESC13 finds first matching linked policy."""
        policy_oid1 = "1.3.6.1.4.1.311.21.8.111111"
        policy_oid2 = "1.3.6.1.4.1.311.21.8.222222"
        linked_group = "CN=FirstGroup,DC=corp,DC=local"

        template = self.create_template(
            application_policies=[policy_oid1, policy_oid2],
            ekus=[OID.CLIENT_AUTHENTICATION],
            enrollment_principals=[f"{self.DOMAIN_SID}-513"],
        )
        ca = self.create_ca()

        # First policy is linked
        issuance_policies = {policy_oid1: linked_group}

        result = detect_esc13(template, ca, self.DOMAIN_SID, issuance_policies)

        assert result is not None
        assert result.issuance_policy_oid == policy_oid1
        assert result.linked_group_dn == linked_group


class TestGoldenCertDetection:
    """Tests for GoldenCert vulnerability detection."""

    DOMAIN_SID = "S-1-5-21-1234567890-1234567890-1234567890"

    def create_ca(self, hosting_computer_sid: str = None) -> EnterpriseCA:
        """Create a test CA with optional hosting computer."""
        return EnterpriseCA(
            cn="TestCA",
            name="TestCA",
            object_guid="87654321-4321-4321-4321-210987654321",
            distinguished_name="CN=TestCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local",
            domain="CORP.LOCAL",
            domain_sid=self.DOMAIN_SID,
            certificate_templates=["TestTemplate"],
            hosting_computer_sid=hosting_computer_sid,
        )

    def test_goldencert_with_hosting_computer(self):
        """Test GoldenCert detection when CA has hosting computer."""
        computer_sid = f"{self.DOMAIN_SID}-1001"
        ca = self.create_ca(hosting_computer_sid=computer_sid)

        result = detect_goldencert(ca)

        assert result is not None
        assert result.ca_name == "TestCA"
        assert result.ca_computer_sid == computer_sid
        assert len(result.reasons) == 3
        assert "CA private key" in result.reasons[0]

    def test_goldencert_no_hosting_computer(self):
        """Test GoldenCert not detected when no hosting computer SID."""
        ca = self.create_ca(hosting_computer_sid="")

        result = detect_goldencert(ca)

        assert result is None

    def test_goldencert_edge_generation(self):
        """Test GoldenCert edge generation."""
        computer_sid = f"{self.DOMAIN_SID}-1001"
        ca = self.create_ca(hosting_computer_sid=computer_sid)

        edge = get_goldencert_edge(ca, self.DOMAIN_SID)

        assert edge is not None
        assert edge["StartNode"] == computer_sid
        assert edge["EndNode"] == self.DOMAIN_SID
        assert edge["EdgeType"] == "GoldenCert"
        assert edge["EdgeProps"]["caname"] == "TestCA"
        assert edge["EdgeProps"]["isacl"] is False

    def test_goldencert_edge_no_hosting_computer(self):
        """Test GoldenCert edge not generated without hosting computer."""
        ca = self.create_ca(hosting_computer_sid="")

        edge = get_goldencert_edge(ca, self.DOMAIN_SID)

        assert edge is None

    def test_goldencert_edge_props(self):
        """Test GoldenCert edge properties contain CA info."""
        computer_sid = f"{self.DOMAIN_SID}-1001"
        ca = self.create_ca(hosting_computer_sid=computer_sid)

        edge = get_goldencert_edge(ca, self.DOMAIN_SID)

        assert "cadistinguishedname" in edge["EdgeProps"]
        assert "CN=TestCA" in edge["EdgeProps"]["cadistinguishedname"]
