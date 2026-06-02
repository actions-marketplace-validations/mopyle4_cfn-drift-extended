"""Tests for the orphan detection orchestrator wiring."""

from unittest.mock import patch

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.provenance_lookup import StackOwner
from cfn_drift_extended.models import Provenance
from cfn_drift_extended.orphan_auditor import ALL_ORPHAN_SERVICES, OrphanAuditor


def test_build_detector_tasks_registers_all_services() -> None:
    """All five services are wired up when no filter is supplied."""
    auditor = OrphanAuditor(region="us-east-1")
    tasks = auditor._build_detector_tasks(frozenset())

    assert set(tasks) == set(ALL_ORPHAN_SERVICES)
    assert set(tasks) == {"iam", "sg", "lambda", "sqs", "sns"}


def test_build_detector_tasks_respects_service_filter() -> None:
    """Only requested services get a detector task."""
    auditor = OrphanAuditor(
        region="us-east-1", services=frozenset({"iam", "sg", "lambda"})
    )
    tasks = auditor._build_detector_tasks(frozenset())

    assert set(tasks) == {"iam", "sg", "lambda"}


@mock_aws
def test_detect_orphans_runs_new_detectors() -> None:
    """End-to-end: IAM, SG, and Lambda orphans are detected with empty index."""
    session = boto3.Session(region_name="us-east-1")

    # An unmanaged IAM role.
    session.client("iam").create_role(
        RoleName="loose-role", AssumeRolePolicyDocument="{}"
    )

    # An unmanaged security group (in addition to the default group).
    ec2 = session.client("ec2")
    vpc_id = ec2.describe_vpcs(
        Filters=[{"Name": "isDefault", "Values": ["true"]}]
    )["Vpcs"][0]["VpcId"]
    ec2.create_security_group(
        GroupName="loose-sg", Description="loose", VpcId=vpc_id
    )

    auditor = OrphanAuditor(
        region="us-east-1", services=frozenset({"iam", "sg", "lambda"})
    )
    report = auditor.detect_orphans()

    orphan_types = {f.orphan_type.value for f in report.findings}
    assert "iam_role_orphaned" in orphan_types
    assert "security_group_orphaned" in orphan_types
    assert report.orphans_found >= 2
    assert not report.errors


@mock_aws
def test_sqs_orphan_with_no_cfn_tag_classified_as_non_iac() -> None:
    """A queue with no aws:cloudformation:stack-name tag is NON_IAC."""
    session = boto3.Session(region_name="us-east-1")
    sqs = session.client("sqs")
    sqs.create_queue(QueueName="cli-created-queue")

    auditor = OrphanAuditor(
        region="us-east-1", services=frozenset({"sqs"})
    )
    report = auditor.detect_orphans()

    sqs_findings = [
        f for f in report.findings if f.resource_type == "AWS::SQS::Queue"
    ]
    assert len(sqs_findings) == 1
    assert sqs_findings[0].provenance == Provenance.NON_IAC
    assert sqs_findings[0].originating_stack_name is None


@mock_aws
def test_sqs_orphan_with_cfn_tag_classified_as_cfn_orphan() -> None:
    """A queue tagged for a no-longer-indexed stack is CFN_ORPHAN_DELETED_STACK.

    Tag-tier resolution: the bulk RGT API returns the queue with its
    aws:cloudformation:stack-name tag, so the resolver short-circuits before
    falling back to DescribeStackResources.
    """
    session = boto3.Session(region_name="us-east-1")
    sqs = session.client("sqs")
    result = sqs.create_queue(QueueName="left-behind-queue")
    queue_url = result["QueueUrl"]

    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    sqs.tag_queue(
        QueueUrl=queue_url,
        Tags={"aws:cloudformation:stack-name": "deleted-fixture-stack"},
    )

    auditor = OrphanAuditor(
        region="us-east-1", services=frozenset({"sqs"})
    )
    report = auditor.detect_orphans()

    sqs_findings = [
        f for f in report.findings if f.resource_id == queue_arn
    ]
    assert len(sqs_findings) == 1
    assert sqs_findings[0].provenance == Provenance.CFN_ORPHAN_DELETED_STACK
    assert sqs_findings[0].originating_stack_name == "deleted-fixture-stack"


@mock_aws
def test_iam_orphan_resolved_via_describe_stack_resources() -> None:
    """When the tag tier returns nothing, the CFN-API fallback resolves provenance.

    moto's RGT API does not surface IAM principals, so this test verifies
    the second-tier ``DescribeStackResources --physical-resource-id`` path:
    a patched resolver returns a stack owner for the role, and the auditor
    classifies it as CFN_ORPHAN_DELETED_STACK.
    """
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_role(RoleName="retained-role", AssumeRolePolicyDocument="{}")
    role_arn = iam.get_role(RoleName="retained-role")["Role"]["Arn"]

    auditor = OrphanAuditor(
        region="us-east-1", services=frozenset({"iam"})
    )

    # Patch the second-tier lookup to simulate CFN finding the deleted-stack
    # entry for this role.
    fake_owner = StackOwner(
        stack_name="deleted-iam-stack",
        stack_id=(
            "arn:aws:cloudformation:us-east-1:123456789012:stack/"
            "deleted-iam-stack/abcd"
        ),
    )

    def fake_describe(_cfn, physical_id: str):
        if physical_id == role_arn:
            return fake_owner
        return None

    with patch(
        "cfn_drift_extended.collectors.provenance_lookup."
        "_describe_stack_for_resource",
        side_effect=fake_describe,
    ):
        report = auditor.detect_orphans()

    iam_findings = [
        f for f in report.findings if f.resource_type == "AWS::IAM::Role"
    ]
    assert len(iam_findings) == 1
    assert iam_findings[0].provenance == Provenance.CFN_ORPHAN_DELETED_STACK
    assert iam_findings[0].originating_stack_name == "deleted-iam-stack"


@mock_aws
def test_iam_orphan_with_no_cfn_record_classified_as_non_iac() -> None:
    """A role unknown to CloudFormation is NON_IAC."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_role(RoleName="loose-role", AssumeRolePolicyDocument="{}")

    auditor = OrphanAuditor(
        region="us-east-1", services=frozenset({"iam"})
    )
    report = auditor.detect_orphans()

    iam_findings = [
        f for f in report.findings if f.resource_type == "AWS::IAM::Role"
    ]
    assert len(iam_findings) == 1
    assert iam_findings[0].provenance == Provenance.NON_IAC
    assert iam_findings[0].originating_stack_name is None
