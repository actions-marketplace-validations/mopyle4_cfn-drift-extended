"""Error path and edge case tests for Security Groups collector."""

import logging
from unittest.mock import patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from cfn_drift_extended.collectors.sg_collector import SgCollector


@mock_aws
def test_permission_denied_returns_none(caplog: logging.LogRecord) -> None:
    """Permission denied should return None and log an error."""
    session = boto3.Session(region_name="us-east-1")
    collector = SgCollector(region="us-east-1", session=session)

    # Patch the client to raise AccessDenied
    error_response = {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}}
    with patch.object(
        collector._ec2, "describe_security_groups",
        side_effect=ClientError(error_response, "DescribeSecurityGroups"),
    ), caplog.at_level(logging.ERROR):
        result = collector.get_security_group_state("sg-12345")

    assert result is None
    assert "Permission denied" in caplog.text


@mock_aws
def test_unexpected_error_returns_none(caplog: logging.LogRecord) -> None:
    """Unexpected ClientError should return None and log."""
    session = boto3.Session(region_name="us-east-1")
    collector = SgCollector(region="us-east-1", session=session)

    error_response = {"Error": {"Code": "InternalError", "Message": "oops"}}
    with patch.object(
        collector._ec2, "describe_security_groups",
        side_effect=ClientError(error_response, "DescribeSecurityGroups"),
    ), caplog.at_level(logging.ERROR):
        result = collector.get_security_group_state("sg-12345")

    assert result is None
    assert "Unexpected error" in caplog.text


@mock_aws
def test_empty_security_groups_response() -> None:
    """Empty SecurityGroups list in response should return None."""
    session = boto3.Session(region_name="us-east-1")
    collector = SgCollector(region="us-east-1", session=session)

    with patch.object(
        collector._ec2, "describe_security_groups",
        return_value={"SecurityGroups": []},
    ):
        result = collector.get_security_group_state("sg-12345")

    assert result is None


@mock_aws
def test_security_group_with_ipv6_rules() -> None:
    """IPv6 CIDR ranges should be properly extracted."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    sg = ec2.create_security_group(
        GroupName="ipv6-sg",
        Description="Test IPv6",
        VpcId=vpc["Vpc"]["VpcId"],
    )
    group_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        ],
    )

    collector = SgCollector(region="us-east-1", session=session)
    state = collector.get_security_group_state(group_id)

    assert state is not None
    assert len(state.ingress_rules) == 1
    assert state.ingress_rules[0].cidr_ipv6 == "::/0"
    assert state.ingress_rules[0].cidr_ipv4 is None


@mock_aws
def test_security_group_with_sg_reference() -> None:
    """Security group references should be properly extracted."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg1 = ec2.create_security_group(
        GroupName="source-sg", Description="Source", VpcId=vpc_id
    )
    sg2 = ec2.create_security_group(
        GroupName="target-sg", Description="Target", VpcId=vpc_id
    )
    source_id = sg1["GroupId"]
    target_id = sg2["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=target_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "UserIdGroupPairs": [{"GroupId": source_id}],
            }
        ],
    )

    collector = SgCollector(region="us-east-1", session=session)
    state = collector.get_security_group_state(target_id)

    assert state is not None
    assert len(state.ingress_rules) == 1
    assert state.ingress_rules[0].source_security_group_id == source_id


@mock_aws
def test_default_session_creation() -> None:
    """Collector should create a default session if none provided."""
    collector = SgCollector(region="us-east-1")
    assert collector._session is not None
    assert collector._ec2 is not None
