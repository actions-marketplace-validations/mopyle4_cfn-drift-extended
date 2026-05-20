"""Unit tests for the Security Groups comparator."""

from cfn_drift_extended.collectors.sg_collector import (
    ActualSecurityGroupState,
    SecurityGroupRule,
)
from cfn_drift_extended.comparators.sg_comparator import (
    ExpectedSecurityGroupState,
    SgComparator,
)
from cfn_drift_extended.models import DriftType, Severity


class TestSgComparator:
    """Tests for SgComparator.compare()."""

    def setup_method(self) -> None:
        self.comparator = SgComparator()

    def test_no_drift_when_in_sync(self) -> None:
        rule = SecurityGroupRule(
            ip_protocol="tcp", from_port=443, to_port=443, cidr_ipv4="10.0.0.0/8"
        )
        expected = ExpectedSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            stack_name="my-stack",
            ingress_rules=(rule,),
            egress_rules=(),
        )
        actual = ActualSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            ingress_rules=(rule,),
            egress_rules=(),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_detects_extra_ingress_rule(self) -> None:
        expected_rule = SecurityGroupRule(
            ip_protocol="tcp", from_port=443, to_port=443, cidr_ipv4="10.0.0.0/8"
        )
        extra_rule = SecurityGroupRule(
            ip_protocol="tcp", from_port=22, to_port=22, cidr_ipv4="0.0.0.0/0"
        )
        expected = ExpectedSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            stack_name="my-stack",
            ingress_rules=(expected_rule,),
        )
        actual = ActualSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            ingress_rules=(expected_rule, extra_rule),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        assert audit.findings[0].drift_type == DriftType.SECURITY_GROUP_INGRESS_ADDED
        assert audit.findings[0].severity == Severity.HIGH

    def test_detects_extra_egress_rule(self) -> None:
        extra_rule = SecurityGroupRule(
            ip_protocol="tcp", from_port=5432, to_port=5432, cidr_ipv4="10.1.0.0/16"
        )
        expected = ExpectedSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            stack_name="my-stack",
            egress_rules=(),
        )
        actual = ActualSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            egress_rules=(extra_rule,),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        assert audit.findings[0].drift_type == DriftType.SECURITY_GROUP_EGRESS_ADDED
        assert audit.findings[0].severity == Severity.MEDIUM

    def test_detects_multiple_findings(self) -> None:
        extra_ingress = SecurityGroupRule(
            ip_protocol="tcp", from_port=22, to_port=22, cidr_ipv4="0.0.0.0/0"
        )
        extra_egress = SecurityGroupRule(
            ip_protocol="tcp", from_port=3306, to_port=3306, cidr_ipv4="10.0.0.0/8"
        )
        expected = ExpectedSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            stack_name="my-stack",
        )
        actual = ActualSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            ingress_rules=(extra_ingress,),
            egress_rules=(extra_egress,),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 2

    def test_no_drift_when_actual_has_fewer_rules(self) -> None:
        """Removals are not flagged (handled by native CFN drift detection)."""
        rule = SecurityGroupRule(
            ip_protocol="tcp", from_port=443, to_port=443, cidr_ipv4="10.0.0.0/8"
        )
        expected = ExpectedSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            stack_name="my-stack",
            ingress_rules=(rule,),
        )
        actual = ActualSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            ingress_rules=(),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_description_not_compared(self) -> None:
        """Description is cosmetic and should not trigger drift."""
        expected_rule = SecurityGroupRule(
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_ipv4="10.0.0.0/8",
            description="Original description",
        )
        actual_rule = SecurityGroupRule(
            ip_protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_ipv4="10.0.0.0/8",
            description="Modified description",
        )
        expected = ExpectedSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            stack_name="my-stack",
            ingress_rules=(expected_rule,),
        )
        actual = ActualSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            ingress_rules=(actual_rule,),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_empty_rules_no_false_positives(self) -> None:
        """Empty rules on both sides should not produce findings."""
        expected = ExpectedSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            stack_name="my-stack",
        )
        actual = ActualSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_findings_are_sorted(self) -> None:
        """Extra rules should be reported in a deterministic order."""
        rule_a = SecurityGroupRule(
            ip_protocol="tcp", from_port=22, to_port=22, cidr_ipv4="10.0.0.0/8"
        )
        rule_b = SecurityGroupRule(
            ip_protocol="tcp", from_port=80, to_port=80, cidr_ipv4="10.0.0.0/8"
        )
        rule_c = SecurityGroupRule(
            ip_protocol="tcp", from_port=443, to_port=443, cidr_ipv4="10.0.0.0/8"
        )
        expected = ExpectedSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            stack_name="my-stack",
        )
        actual = ActualSecurityGroupState(
            group_id="sg-123",
            group_name="my-sg",
            ingress_rules=(rule_c, rule_a, rule_b),
        )
        audit = self.comparator.compare(expected, actual)
        # Should be sorted by rule key (protocol, from_port, to_port, ...)
        ports = [f.extra[1] for f in audit.findings]
        assert ports == [22, 80, 443]
