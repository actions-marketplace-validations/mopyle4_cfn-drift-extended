"""Unit tests for the Security Groups collector."""

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.sg_collector import SgCollector


def _create_vpc_and_sg(
    ec2_client, group_name: str = "test-sg"
) -> tuple[str, str]:
    """Create a VPC and security group, return (vpc_id, group_id)."""
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    sg = ec2_client.create_security_group(
        GroupName=group_name,
        Description="Test security group",
        VpcId=vpc_id,
    )
    group_id = sg["GroupId"]
    return vpc_id, group_id


@mock_aws
def test_get_security_group_state_basic() -> None:
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    _, group_id = _create_vpc_and_sg(ec2)

    collector = SgCollector(region="us-east-1", session=session)
    state = collector.get_security_group_state(group_id)

    assert state is not None
    assert state.group_id == group_id
    assert state.group_name == "test-sg"
    assert isinstance(state.ingress_rules, tuple)
    assert isinstance(state.egress_rules, tuple)


@mock_aws
def test_get_security_group_state_with_ingress_rules() -> None:
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    _, group_id = _create_vpc_and_sg(ec2)

    ec2.authorize_security_group_ingress(
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

    collector = SgCollector(region="us-east-1", session=session)
    state = collector.get_security_group_state(group_id)

    assert state is not None
    assert len(state.ingress_rules) == 1
    rule = state.ingress_rules[0]
    assert rule.ip_protocol == "tcp"
    assert rule.from_port == 443
    assert rule.to_port == 443
    assert rule.cidr_ipv4 == "10.0.0.0/8"


@mock_aws
def test_get_security_group_state_with_egress_rules() -> None:
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    _, group_id = _create_vpc_and_sg(ec2)

    # Add a custom egress rule
    ec2.authorize_security_group_egress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [{"CidrIp": "10.1.0.0/16"}],
            }
        ],
    )

    collector = SgCollector(region="us-east-1", session=session)
    state = collector.get_security_group_state(group_id)

    assert state is not None
    # Default egress rule (all traffic) + our custom rule
    assert len(state.egress_rules) >= 1
    # Find our custom rule
    custom_rules = [r for r in state.egress_rules if r.from_port == 5432]
    assert len(custom_rules) == 1
    assert custom_rules[0].cidr_ipv4 == "10.1.0.0/16"


@mock_aws
def test_get_security_group_state_nonexistent() -> None:
    session = boto3.Session(region_name="us-east-1")
    collector = SgCollector(region="us-east-1", session=session)
    assert collector.get_security_group_state("sg-nonexistent123") is None


@mock_aws
def test_get_security_group_state_multiple_ip_ranges() -> None:
    """Multiple CIDR ranges in one permission expand to multiple rules."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    _, group_id = _create_vpc_and_sg(ec2)

    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [
                    {"CidrIp": "10.0.0.0/8"},
                    {"CidrIp": "172.16.0.0/12"},
                ],
            }
        ],
    )

    collector = SgCollector(region="us-east-1", session=session)
    state = collector.get_security_group_state(group_id)

    assert state is not None
    assert len(state.ingress_rules) == 2


@mock_aws
def test_returns_immutable_tuples() -> None:
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    _, group_id = _create_vpc_and_sg(ec2)

    collector = SgCollector(region="us-east-1", session=session)
    state = collector.get_security_group_state(group_id)

    assert state is not None
    assert isinstance(state.ingress_rules, tuple)
    assert isinstance(state.egress_rules, tuple)
