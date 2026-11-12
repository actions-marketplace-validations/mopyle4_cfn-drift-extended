"""Unit tests for the Security Groups comparator."""

from typing import Any

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.cfn_sg_extractor import CfnSgExtractor
from cfn_drift_extended.collectors.sg_collector import (
    ActualSecurityGroupState,
    SecurityGroupRule,
    SgCollector,
)
from cfn_drift_extended.comparators.sg_comparator import (
    ExpectedSecurityGroupState,
    SgComparator,
)
from cfn_drift_extended.models import DriftFinding, DriftType, Severity


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


# --- Default egress rule handling (moto end-to-end) ---

_REGION = "us-east-1"
_STACK = "app-stack"
_HTTPS_TO_PRIVATE = {
    "IpProtocol": "tcp",
    "FromPort": 443,
    "ToPort": 443,
    "CidrIp": "10.0.0.0/8",
}
_DEFAULT_EGRESS_KEY = ("-1", None, None, "0.0.0.0/0", None, None, None)
_HTTPS_EGRESS_KEY = ("tcp", 443, 443, "10.0.0.0/8", None, None, None)


def _create_live_sg(ec2_client: Any) -> str:
    """Create a VPC security group; moto adds the default allow-all egress rule."""
    vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    return ec2_client.create_security_group(
        GroupName="app-sg", Description="App security group", VpcId=vpc_id
    )["GroupId"]


def _authorize_https_egress(ec2_client: Any, group_id: str) -> None:
    """Add a tcp 443 -> 10.0.0.0/8 egress rule to the live group."""
    ec2_client.authorize_security_group_egress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }
        ],
    )


def _sg_resource(**properties: Any) -> dict[str, Any]:
    """Build an AWS::EC2::SecurityGroup template resource."""
    return {
        "Type": "AWS::EC2::SecurityGroup",
        "Properties": {"GroupDescription": "App security group", **properties},
    }


def _egress_findings(
    resources: dict[str, Any], group_id: str, session: boto3.Session
) -> list[DriftFinding]:
    """Run extractor -> collector -> comparator and return egress findings."""
    expected = CfnSgExtractor().extract_security_groups(
        resources, _STACK, {"AppSg": group_id}
    )[0]
    actual = SgCollector(region=_REGION, session=session).get_security_group_state(group_id)
    assert actual is not None
    audit = SgComparator().compare(expected, actual)
    return [
        f for f in audit.findings if f.drift_type == DriftType.SECURITY_GROUP_EGRESS_ADDED
    ]


@mock_aws
def test_compare_default_egress_without_inline_egress_not_reported() -> None:
    session = boto3.Session(region_name=_REGION)
    group_id = _create_live_sg(session.client("ec2"))

    findings = _egress_findings({"AppSg": _sg_resource()}, group_id, session)

    assert findings == []


@mock_aws
def test_compare_extra_egress_without_inline_egress_reports_only_extra() -> None:
    session = boto3.Session(region_name=_REGION)
    ec2 = session.client("ec2")
    group_id = _create_live_sg(ec2)
    _authorize_https_egress(ec2, group_id)

    findings = _egress_findings({"AppSg": _sg_resource()}, group_id, session)

    assert len(findings) == 1
    assert findings[0].extra == _HTTPS_EGRESS_KEY


@mock_aws
def test_compare_default_egress_with_inline_egress_reported() -> None:
    session = boto3.Session(region_name=_REGION)
    ec2 = session.client("ec2")
    group_id = _create_live_sg(ec2)
    _authorize_https_egress(ec2, group_id)
    resources = {"AppSg": _sg_resource(SecurityGroupEgress=[_HTTPS_TO_PRIVATE])}

    findings = _egress_findings(resources, group_id, session)

    assert len(findings) == 1
    assert findings[0].extra == _DEFAULT_EGRESS_KEY
    assert findings[0].severity == Severity.MEDIUM


@mock_aws
def test_compare_default_egress_with_standalone_egress_not_reported() -> None:
    session = boto3.Session(region_name=_REGION)
    ec2 = session.client("ec2")
    group_id = _create_live_sg(ec2)
    _authorize_https_egress(ec2, group_id)
    resources = {
        "AppSg": _sg_resource(),
        "AppSgHttpsEgress": {
            "Type": "AWS::EC2::SecurityGroupEgress",
            "Properties": {"GroupId": {"Ref": "AppSg"}, **_HTTPS_TO_PRIVATE},
        },
    }

    findings = _egress_findings(resources, group_id, session)

    assert findings == []


def test_compare_ipv6_default_egress_without_inline_egress_not_reported() -> None:
    default_v6 = SecurityGroupRule(
        ip_protocol="-1", from_port=None, to_port=None, cidr_ipv6="::/0"
    )
    expected = ExpectedSecurityGroupState(
        group_id="sg-123", group_name="my-sg", stack_name="my-stack"
    )
    actual = ActualSecurityGroupState(
        group_id="sg-123", group_name="my-sg", egress_rules=(default_v6,)
    )

    audit = SgComparator().compare(expected, actual)

    assert audit.in_sync is True


def test_compare_allow_all_ingress_still_reported() -> None:
    allow_all_in = SecurityGroupRule(
        ip_protocol="-1", from_port=None, to_port=None, cidr_ipv4="0.0.0.0/0"
    )
    expected = ExpectedSecurityGroupState(
        group_id="sg-123", group_name="my-sg", stack_name="my-stack"
    )
    actual = ActualSecurityGroupState(
        group_id="sg-123", group_name="my-sg", ingress_rules=(allow_all_in,)
    )

    audit = SgComparator().compare(expected, actual)

    assert len(audit.findings) == 1
    assert audit.findings[0].drift_type == DriftType.SECURITY_GROUP_INGRESS_ADDED
