"""ESC3 (Enrollment Agent) vulnerability detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..utils.crypto import OID
from ..acl.rights import is_low_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA


@dataclass
class ESC3AgentResult:
    """ESC3 agent template detection result."""

    vulnerable: bool
    template_name: str
    template_dn: str
    ca_name: str
    ca_dn: str
    vulnerable_principals: list[str]
    reasons: list[str]


@dataclass
class ESC3TargetResult:
    """ESC3 target template detection result."""

    vulnerable: bool
    template_name: str
    template_dn: str
    ca_name: str
    ca_dn: str
    reasons: list[str]


def detect_esc3_agent(
    template: "CertTemplate",
    ca: "EnterpriseCA",
    domain_sid: str,
) -> ESC3AgentResult | None:
    """
    Detect ESC3 agent template.

    ESC3 Agent Template requires:
    1. Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1)
    2. No manager approval
    3. No authorized signatures required
    4. Low-privileged principal has enrollment rights
    5. Template is published to the CA

    Returns ESC3AgentResult if vulnerable, None otherwise.
    """
    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return None

    reasons = []
    vulnerable_principals = []

    # Check condition 1: Has Certificate Request Agent EKU
    if not template.has_enrollment_agent_eku:
        return None
    reasons.append("Has Certificate Request Agent EKU")

    # Check condition 2: No manager approval
    if template.requires_manager_approval:
        return None
    reasons.append("Manager approval not required")

    # Check condition 3: No authorized signatures
    if not template.no_signature_required:
        return None
    reasons.append("No authorized signatures required")

    # Check condition 4: Low-privileged principals have enrollment rights
    for principal_sid in template.enrollment_principals:
        if is_low_privileged_sid(principal_sid, domain_sid):
            vulnerable_principals.append(principal_sid)

    if not vulnerable_principals:
        return None
    reasons.append(f"Low-privileged principals can enroll: {len(vulnerable_principals)} found")

    return ESC3AgentResult(
        vulnerable=True,
        template_name=template.cn,
        template_dn=template.distinguished_name,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        vulnerable_principals=vulnerable_principals,
        reasons=reasons,
    )


def detect_esc3_target(
    template: "CertTemplate",
    ca: "EnterpriseCA",
) -> ESC3TargetResult | None:
    """
    Detect ESC3 target template.

    ESC3 Target Template requires:
    1. Schema version 1 OR has Application Policy requiring Certificate Request Agent
    2. Authentication EKU
    3. No manager approval
    4. Template is published to the CA

    Returns ESC3TargetResult if vulnerable, None otherwise.
    """
    # Check if template is published to this CA
    if template.cn not in ca.certificate_templates:
        return None

    reasons = []

    # Check condition 1: Accepts enrollment agent requests
    accepts_agent = False
    if template.schema_version == 1:
        accepts_agent = True
        reasons.append("Schema version 1 (accepts enrollment agent requests by default)")
    elif OID.CERTIFICATE_REQUEST_AGENT in template.ra_application_policies:
        accepts_agent = True
        reasons.append("RA Application Policy includes Certificate Request Agent")

    if not accepts_agent:
        return None

    # Check condition 2: Has authentication EKU
    if not template.has_authentication_eku:
        return None
    reasons.append("Has authentication EKU")

    # Check condition 3: No manager approval
    if template.requires_manager_approval:
        return None
    reasons.append("Manager approval not required")

    return ESC3TargetResult(
        vulnerable=True,
        template_name=template.cn,
        template_dn=template.distinguished_name,
        ca_name=ca.cn,
        ca_dn=ca.distinguished_name,
        reasons=reasons,
    )


def find_esc3_chains(
    templates: list["CertTemplate"],
    cas: list["EnterpriseCA"],
    domain_sid: str,
) -> list[tuple[ESC3AgentResult, list[ESC3TargetResult]]]:
    """
    Find complete ESC3 attack chains (agent template + target templates).

    Returns list of (agent_result, [target_results]) tuples.
    """
    chains = []

    for ca in cas:
        agent_templates = []
        target_templates = []

        for template in templates:
            agent_result = detect_esc3_agent(template, ca, domain_sid)
            if agent_result:
                agent_templates.append(agent_result)

            target_result = detect_esc3_target(template, ca)
            if target_result:
                target_templates.append(target_result)

        # Each agent template can be paired with all target templates on same CA
        for agent in agent_templates:
            if target_templates:
                chains.append((agent, target_templates))

    return chains
