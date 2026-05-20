"""Unit tests for the CloudFormation collector."""

import json

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.cfn_collector import CfnCollector
from tests.conftest import TEMPLATE_ONE_ROLE


def _make_template_with_role(role_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "AppRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    },
                }
            },
        }
    )


@mock_aws
def test_list_stacks_by_prefix() -> None:
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")
    cfn.create_stack(
        StackName="my-app-dev",
        TemplateBody=_make_template_with_role("dev-role"),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    cfn.create_stack(
        StackName="my-app-prod",
        TemplateBody=_make_template_with_role("prod-role"),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )

    collector = CfnCollector(region="us-east-1", session=session)
    stacks = collector.list_stacks_by_prefix("my-app")

    assert len(stacks) == 2
    assert "my-app-dev" in stacks
    assert "my-app-prod" in stacks


@mock_aws
def test_list_stacks_empty() -> None:
    session = boto3.Session(region_name="us-east-1")
    collector = CfnCollector(region="us-east-1", session=session)
    assert collector.list_stacks_by_prefix("nonexistent") == []


@mock_aws
def test_get_iam_roles_extracts_policies() -> None:
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")
    cfn.create_stack(
        StackName="test-stack",
        TemplateBody=TEMPLATE_ONE_ROLE,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )

    collector = CfnCollector(region="us-east-1", session=session)
    roles = collector.get_iam_roles_from_stack("test-stack")

    assert len(roles) == 1
    role = roles[0]
    assert role.role_name == "tax-reconciliation-tool-orchestrator"
    assert "DynamoDBReadWrite" in role.inline_policy_names
    assert (
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        in role.managed_policy_arns
    )


@mock_aws
def test_get_iam_roles_extracts_policy_documents() -> None:
    """Inline policy documents should be extracted for content comparison."""
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")
    cfn.create_stack(
        StackName="test-stack",
        TemplateBody=TEMPLATE_ONE_ROLE,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )

    collector = CfnCollector(region="us-east-1", session=session)
    roles = collector.get_iam_roles_from_stack("test-stack")

    assert len(roles[0].inline_policy_documents) == 1
    name, doc = roles[0].inline_policy_documents[0]
    assert name == "DynamoDBReadWrite"
    assert "Statement" in doc


@mock_aws
def test_get_iam_roles_nonexistent_stack() -> None:
    session = boto3.Session(region_name="us-east-1")
    collector = CfnCollector(region="us-east-1", session=session)
    assert collector.get_iam_roles_from_stack("does-not-exist") == []


@mock_aws
def test_extract_handles_malformed_policies() -> None:
    """Test extraction methods directly with malformed inputs."""
    session = boto3.Session(region_name="us-east-1")
    collector = CfnCollector(region="us-east-1", session=session)

    # Non-list Policies
    assert collector._extract_inline_policy_names({"Policies": "not-a-list"}) == []
    assert collector._extract_inline_policy_names({}) == []

    # Valid + invalid entries
    props = {
        "Policies": [
            {"PolicyName": "Valid", "PolicyDocument": {}},
            "not-a-dict",
            {"PolicyName": 123},
        ]
    }
    assert collector._extract_inline_policy_names(props) == ["Valid"]


@mock_aws
def test_resolve_intrinsic_ref() -> None:
    """Test intrinsic function resolution for Ref."""
    session = boto3.Session(region_name="us-east-1")
    collector = CfnCollector(region="us-east-1", session=session)

    # When resource doesn't exist, returns None
    result = collector._resolve_intrinsic({"Ref": "SomePolicy"}, "nonexistent-stack")
    assert result is None


@mock_aws
def test_resolve_intrinsic_getatt() -> None:
    """Test intrinsic function resolution for Fn::GetAtt."""
    session = boto3.Session(region_name="us-east-1")
    collector = CfnCollector(region="us-east-1", session=session)

    result = collector._resolve_intrinsic(
        {"Fn::GetAtt": ["SomePolicy", "Arn"]}, "nonexistent-stack"
    )
    assert result is None


@mock_aws
def test_resolve_intrinsic_unknown() -> None:
    """Unknown intrinsics return None."""
    session = boto3.Session(region_name="us-east-1")
    collector = CfnCollector(region="us-east-1", session=session)

    result = collector._resolve_intrinsic({"Fn::Sub": "something"}, "stack")
    assert result is None


@mock_aws
def test_collects_external_iam_policy_resources() -> None:
    """AWS::IAM::Policy resources should be associated with their target roles."""
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": "external-policy-role",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    },
                },
                "MyRoleDefaultPolicy": {
                    "Type": "AWS::IAM::Policy",
                    "Properties": {
                        "PolicyName": "MyRoleDefaultPolicy1234",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                }
                            ],
                        },
                        "Roles": [{"Ref": "MyRole"}],
                    },
                },
            },
        }
    )

    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")
    cfn.create_stack(
        StackName="ext-policy-stack",
        TemplateBody=template,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )

    collector = CfnCollector(region="us-east-1", session=session)
    roles = collector.get_iam_roles_from_stack("ext-policy-stack")

    assert len(roles) == 1
    role = roles[0]
    # The external policy should be included in the role's expected state
    assert "MyRoleDefaultPolicy1234" in role.inline_policy_names


@mock_aws
def test_external_policy_not_reported_as_drift() -> None:
    """CDK-style external policies should NOT cause false-positive drift."""
    from cfn_drift_extended.collectors.iam_collector import ActualRoleState
    from cfn_drift_extended.comparators.iam_comparator import IamComparator

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": "cdk-pattern-role",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    },
                },
                "MyRoleDefaultPolicy": {
                    "Type": "AWS::IAM::Policy",
                    "Properties": {
                        "PolicyName": "DefaultPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sqs:SendMessage",
                                    "Resource": "*",
                                }
                            ],
                        },
                        "Roles": [{"Ref": "MyRole"}],
                    },
                },
            },
        }
    )

    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")
    cfn.create_stack(
        StackName="cdk-pattern-stack",
        TemplateBody=template,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )

    collector = CfnCollector(region="us-east-1", session=session)
    roles = collector.get_iam_roles_from_stack("cdk-pattern-stack")
    expected = roles[0]

    # Simulate what IAM would show: the role has the DefaultPolicy inline
    actual = ActualRoleState(
        role_name="cdk-pattern-role",
        inline_policy_names=("DefaultPolicy",),
        managed_policy_arns=(),
    )

    comparator = IamComparator()
    audit = comparator.compare(expected, actual)

    # Should be in sync — the external policy is accounted for
    assert audit.in_sync is True
