"""Tests for the CLI interface."""

import json

import boto3
from click.testing import CliRunner
from moto import mock_aws

from cfn_drift_extended.cli import main

TEMPLATE_SIMPLE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AppRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "cli-test-role",
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
def test_audit_no_drift_exits_zero() -> None:
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")
    cfn.create_stack(
        StackName="cli-test-stack",
        TemplateBody=TEMPLATE_SIMPLE,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["audit", "--stack-prefix", "cli-test", "--region", "us-east-1"]
    )
    assert result.exit_code == 0
    assert "No additive drift detected" in result.output


@mock_aws
def test_audit_with_drift_exits_nonzero() -> None:
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")
    iam = session.client("iam")
    cfn.create_stack(
        StackName="cli-test-stack",
        TemplateBody=TEMPLATE_SIMPLE,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    iam.put_role_policy(
        RoleName="cli-test-role",
        PolicyName="ManualPolicy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                ],
            }
        ),
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["audit", "--stack-prefix", "cli-test", "--region", "us-east-1"]
    )
    assert result.exit_code == 1
    assert "ManualPolicy" in result.output


@mock_aws
def test_audit_no_fail_on_drift_exits_zero() -> None:
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")
    iam = session.client("iam")
    cfn.create_stack(
        StackName="cli-test-stack",
        TemplateBody=TEMPLATE_SIMPLE,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    iam.put_role_policy(
        RoleName="cli-test-role",
        PolicyName="ManualPolicy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                ],
            }
        ),
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["audit", "--stack-prefix", "cli-test", "--region", "us-east-1", "--no-fail-on-drift"],
    )
    assert result.exit_code == 0


def test_version_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_invalid_region() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["audit", "--stack-prefix", "test", "--region", "invalid-region"]
    )
    assert result.exit_code != 0


def test_no_filter_provided() -> None:
    """Must provide either --stack-prefix or --stack-name."""
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "--region", "us-east-1"])
    assert result.exit_code == 2
    assert "Must provide" in result.output


@mock_aws
def test_stack_name_option() -> None:
    """--stack-name should be accepted as a valid argument."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["audit", "--stack-name", "my-stack", "--region", "us-east-1"],
        catch_exceptions=False,
    )
    # No matching stacks found = exit 0 (no drift), not an error
    assert result.exit_code == 0


@mock_aws
def test_tag_option_valid() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "audit", "--stack-prefix", "test",
            "--tag", "Environment=Production",
            "--region", "us-east-1",
        ],
        catch_exceptions=False,
    )
    # No stacks found = exit 0 (no drift), not an error
    assert result.exit_code == 0


def test_tag_option_invalid_format() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "audit", "--stack-prefix", "test",
            "--tag", "InvalidNoEquals",
            "--region", "us-east-1",
        ],
    )
    assert result.exit_code == 2
    assert "Invalid tag format" in result.output


def test_help_text() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "--help"])
    assert result.exit_code == 0
    assert "--stack-prefix" in result.output
    assert "--stack-name" in result.output
    assert "--tag" in result.output
    assert "--profile" in result.output
    assert "--max-workers" in result.output


@mock_aws
def test_json_output(tmp_path) -> None:  # type: ignore[no-untyped-def]
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")
    cfn.create_stack(
        StackName="cli-test-stack",
        TemplateBody=TEMPLATE_SIMPLE,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    output_file = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "audit", "--stack-prefix", "cli-test",
            "--region", "us-east-1",
            "--output-json", str(output_file),
        ],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert data["stacks_scanned"] == 1
    assert "account_id" in data
    assert "timestamp" in data
    assert "tool_version" in data
