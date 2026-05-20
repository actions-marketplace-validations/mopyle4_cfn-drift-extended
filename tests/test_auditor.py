"""Integration tests for the Auditor using moto mocks."""

import json

import boto3
from moto import mock_aws

from cfn_drift_extended.auditor import Auditor
from cfn_drift_extended.models import DriftType
from tests.conftest import TEMPLATE_ONE_ROLE, TEMPLATE_ROLE_NO_POLICIES


@mock_aws
def test_no_drift_clean_stack() -> None:
    region = "us-east-1"
    session = boto3.Session(region_name=region)
    cfn = session.client("cloudformation")
    cfn.create_stack(
        StackName="tax-reconciliation-tool-dev",
        TemplateBody=TEMPLATE_ONE_ROLE,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )

    auditor = Auditor(region=region, session=session)
    report = auditor.audit_stacks(stack_prefix="tax-reconciliation-tool")

    assert report.stacks_scanned == 1
    assert report.resources_scanned == 1
    assert report.has_drift is False
    assert report.account_id != ""
    assert report.region == "us-east-1"
    assert report.tool_version == "0.1.0"
    assert report.timestamp != ""


@mock_aws
def test_detects_manually_attached_managed_policy() -> None:
    region = "us-east-1"
    session = boto3.Session(region_name=region)
    cfn = session.client("cloudformation")
    iam = session.client("iam")

    cfn.create_stack(
        StackName="tax-reconciliation-tool-dev",
        TemplateBody=TEMPLATE_ONE_ROLE,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )

    account_id = session.client("sts").get_caller_identity()["Account"]
    extra_arn = f"arn:aws:iam::{account_id}:policy/ManualBroadAccess"
    iam.create_policy(
        PolicyName="ManualBroadAccess",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "dynamodb:Query", "Resource": "*"}
                ],
            }
        ),
    )
    iam.attach_role_policy(
        RoleName="tax-reconciliation-tool-orchestrator", PolicyArn=extra_arn
    )

    auditor = Auditor(region=region, session=session)
    report = auditor.audit_stacks(stack_prefix="tax-reconciliation-tool")

    assert report.has_drift is True
    assert len(report.findings) == 1
    assert report.findings[0].drift_type == DriftType.MANAGED_POLICY_ATTACHED


@mock_aws
def test_detects_manually_added_inline_policy() -> None:
    region = "us-east-1"
    session = boto3.Session(region_name=region)
    cfn = session.client("cloudformation")
    iam = session.client("iam")

    cfn.create_stack(
        StackName="tax-reconciliation-tool-dev",
        TemplateBody=TEMPLATE_ONE_ROLE,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    iam.put_role_policy(
        RoleName="tax-reconciliation-tool-orchestrator",
        PolicyName="QuickFixDynamoQuery",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "dynamodb:Query", "Resource": "*"}
                ],
            }
        ),
    )

    auditor = Auditor(region=region, session=session)
    report = auditor.audit_stacks(stack_prefix="tax-reconciliation-tool")

    assert report.has_drift is True
    assert report.findings[0].drift_type == DriftType.INLINE_POLICY_ADDED
    assert report.findings[0].extra == "QuickFixDynamoQuery"


@mock_aws
def test_no_stacks_found() -> None:
    region = "us-east-1"
    session = boto3.Session(region_name=region)
    auditor = Auditor(region=region, session=session)
    report = auditor.audit_stacks(stack_prefix="nonexistent-prefix")
    assert report.stacks_scanned == 0
    assert report.has_drift is False


@mock_aws
def test_stack_name_exact_match() -> None:
    """Test --stack-name exact match mode."""
    region = "us-east-1"
    session = boto3.Session(region_name=region)
    cfn = session.client("cloudformation")
    cfn.create_stack(
        StackName="my-specific-stack",
        TemplateBody=TEMPLATE_ROLE_NO_POLICIES,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )

    auditor = Auditor(region=region, session=session)
    report = auditor.audit_stacks(stack_names=["my-specific-stack"])

    assert report.stacks_scanned == 1
    assert report.resources_scanned == 1


@mock_aws
def test_max_workers_parameter() -> None:
    region = "us-east-1"
    session = boto3.Session(region_name=region)
    auditor = Auditor(region=region, session=session, max_workers=1)
    report = auditor.audit_stacks(stack_prefix="nonexistent")
    assert report.stacks_scanned == 0
