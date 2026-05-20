"""Compare expected Security Group state (from CFN) vs actual state (from EC2 API).

Detects:
- Extra ingress rules (added outside CFN)
- Extra egress rules (added outside CFN)

Uses set difference operations for O(n) comparison performance.
Rules are compared by: (ip_protocol, from_port, to_port, cidr/source_sg/prefix_list).
Description is NOT compared (cosmetic).
"""

import logging
from dataclasses import dataclass, field

from cfn_drift_extended.collectors.sg_collector import (
    ActualSecurityGroupState,
    SecurityGroupRule,
)
from cfn_drift_extended.models import DriftFinding, DriftType, ResourceAudit, Severity

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExpectedSecurityGroupState:
    """What CloudFormation declares for a Security Group."""

    group_id: str
    group_name: str
    stack_name: str
    ingress_rules: tuple[SecurityGroupRule, ...] = field(default_factory=tuple)
    egress_rules: tuple[SecurityGroupRule, ...] = field(default_factory=tuple)


def _rule_key(rule: SecurityGroupRule) -> tuple:
    """Create a comparison key for a rule, excluding description (cosmetic)."""
    return (
        rule.ip_protocol,
        rule.from_port,
        rule.to_port,
        rule.cidr_ipv4,
        rule.cidr_ipv6,
        rule.source_security_group_id,
        rule.prefix_list_id,
    )


class SgComparator:
    """Compares expected vs actual Security Group rules to find additive drift.

    Detects:
    - Additions: rules present in AWS but not in CFN template

    Removals are handled by native CloudFormation drift detection.
    """

    _RESOURCE_TYPE = "AWS::EC2::SecurityGroup"

    def compare(
        self, expected: ExpectedSecurityGroupState, actual: ActualSecurityGroupState
    ) -> ResourceAudit:
        """Compare a single security group's expected state against its actual state.

        Uses set operations for efficient O(n) comparison.
        Returns a ResourceAudit with any additive drift findings.
        """
        findings: list[DriftFinding] = []

        findings.extend(self._find_extra_ingress(expected, actual))
        findings.extend(self._find_extra_egress(expected, actual))

        return ResourceAudit(
            resource_type=self._RESOURCE_TYPE,
            resource_id=expected.group_id,
            stack_name=expected.stack_name,
            in_sync=len(findings) == 0,
            findings=tuple(findings),
        )

    def _find_extra_ingress(
        self, expected: ExpectedSecurityGroupState, actual: ActualSecurityGroupState
    ) -> list[DriftFinding]:
        """Find ingress rules that exist on the group but aren't in the CFN template."""
        expected_keys = {_rule_key(r) for r in expected.ingress_rules}
        extra_rules = [r for r in actual.ingress_rules if _rule_key(r) not in expected_keys]

        findings: list[DriftFinding] = []
        for rule in sorted(extra_rules, key=_rule_key):
            source = (
                rule.cidr_ipv4 or rule.cidr_ipv6
                or rule.source_security_group_id or rule.prefix_list_id
            )
            findings.append(
                DriftFinding(
                    resource_type=self._RESOURCE_TYPE,
                    resource_id=expected.group_id,
                    stack_name=expected.stack_name,
                    drift_type=DriftType.SECURITY_GROUP_INGRESS_ADDED,
                    severity=Severity.HIGH,
                    description=(
                        f"Ingress rule ({rule.ip_protocol} "
                        f"{rule.from_port}-{rule.to_port} {source}) "
                        f"exists on security group "
                        f"'{expected.group_id}' but is not declared "
                        f"in the CloudFormation template for stack "
                        f"'{expected.stack_name}'"
                    ),
                    expected=[_rule_key(r) for r in expected.ingress_rules],
                    actual=[_rule_key(r) for r in actual.ingress_rules],
                    extra=_rule_key(rule),
                )
            )
        return findings

    def _find_extra_egress(
        self, expected: ExpectedSecurityGroupState, actual: ActualSecurityGroupState
    ) -> list[DriftFinding]:
        """Find egress rules that exist on the group but aren't in the CFN template."""
        expected_keys = {_rule_key(r) for r in expected.egress_rules}
        extra_rules = [r for r in actual.egress_rules if _rule_key(r) not in expected_keys]

        findings: list[DriftFinding] = []
        for rule in sorted(extra_rules, key=_rule_key):
            source = (
                rule.cidr_ipv4 or rule.cidr_ipv6
                or rule.source_security_group_id or rule.prefix_list_id
            )
            findings.append(
                DriftFinding(
                    resource_type=self._RESOURCE_TYPE,
                    resource_id=expected.group_id,
                    stack_name=expected.stack_name,
                    drift_type=DriftType.SECURITY_GROUP_EGRESS_ADDED,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Egress rule ({rule.ip_protocol} "
                        f"{rule.from_port}-{rule.to_port} {source}) "
                        f"exists on security group "
                        f"'{expected.group_id}' but is not declared "
                        f"in the CloudFormation template for stack "
                        f"'{expected.stack_name}'"
                    ),
                    expected=[_rule_key(r) for r in expected.egress_rules],
                    actual=[_rule_key(r) for r in actual.egress_rules],
                    extra=_rule_key(rule),
                )
            )
        return findings
