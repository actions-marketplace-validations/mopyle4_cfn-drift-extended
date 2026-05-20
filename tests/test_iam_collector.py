"""Unit tests for the IAM collector."""

import json

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.iam_collector import IamCollector

_VALID_POLICY_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ],
    }
)


def _create_role(iam_client, role_name: str) -> None:  # type: ignore[no-untyped-def]
    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )


@mock_aws
def test_get_role_state_basic() -> None:
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    _create_role(iam, "test-role")

    collector = IamCollector(region="us-east-1", session=session)
    state = collector.get_role_state("test-role")

    assert state is not None
    assert state.role_name == "test-role"
    assert state.inline_policy_names == ()
    assert state.managed_policy_arns == ()
    assert state.inline_policy_documents == ()


@mock_aws
def test_get_role_state_with_inline_policies() -> None:
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    _create_role(iam, "test-role")
    iam.put_role_policy(
        RoleName="test-role", PolicyName="inline-1", PolicyDocument=_VALID_POLICY_DOC
    )

    collector = IamCollector(region="us-east-1", session=session)
    state = collector.get_role_state("test-role")

    assert state is not None
    assert "inline-1" in state.inline_policy_names
    # Should also have the document
    assert len(state.inline_policy_documents) == 1
    name, doc = state.inline_policy_documents[0]
    assert name == "inline-1"
    assert "Statement" in doc


@mock_aws
def test_get_role_state_with_managed_policies() -> None:
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    _create_role(iam, "test-role")
    response = iam.create_policy(
        PolicyName="custom-policy", PolicyDocument=_VALID_POLICY_DOC
    )
    policy_arn = response["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="test-role", PolicyArn=policy_arn)

    collector = IamCollector(region="us-east-1", session=session)
    state = collector.get_role_state("test-role")

    assert state is not None
    assert policy_arn in state.managed_policy_arns


@mock_aws
def test_get_role_state_nonexistent() -> None:
    session = boto3.Session(region_name="us-east-1")
    collector = IamCollector(region="us-east-1", session=session)
    assert collector.get_role_state("does-not-exist") is None


@mock_aws
def test_returns_immutable_tuples() -> None:
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    _create_role(iam, "test-role")

    collector = IamCollector(region="us-east-1", session=session)
    state = collector.get_role_state("test-role")

    assert state is not None
    assert isinstance(state.inline_policy_names, tuple)
    assert isinstance(state.managed_policy_arns, tuple)
    assert isinstance(state.inline_policy_documents, tuple)
