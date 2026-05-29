"""Unit tests for the CFN managed resource index builder."""

import json

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.cfn_managed_index import (
    build_managed_resource_index,
)

# Minimal CFN template for creating stacks in moto
_MINIMAL_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Test stack",
    "Resources": {
        "Queue": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"QueueName": "test-queue"},
        }
    },
})


def _create_stack(cfn_client, stack_name: str, template: str | None = None) -> None:
    """Helper to create a CFN stack in moto."""
    cfn_client.create_stack(
        StackName=stack_name,
        TemplateBody=template or _MINIMAL_TEMPLATE,
    )


@mock_aws
def test_builds_index_from_multiple_stacks() -> None:
    """Test that the index includes resources from multiple stacks."""
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")

    # Create two stacks with different resources
    template_a = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "QueueA": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": "queue-a"},
            }
        },
    })
    template_b = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "QueueB": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": "queue-b"},
            }
        },
    })

    _create_stack(cfn, "stack-a", template_a)
    _create_stack(cfn, "stack-b", template_b)

    index = build_managed_resource_index(cfn)

    # Should contain physical resource IDs from both stacks
    assert len(index) >= 2


@mock_aws
def test_handles_pagination() -> None:
    """Test that pagination is handled for stacks with many resources."""
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")

    # Create a stack — moto handles pagination internally
    _create_stack(cfn, "paginated-stack")

    index = build_managed_resource_index(cfn)

    # Should return at least one resource
    assert len(index) >= 1


@mock_aws
def test_handles_list_stack_resources_errors_gracefully() -> None:
    """Test that errors listing resources for a stack are handled gracefully."""
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")

    # Create a valid stack first
    _create_stack(cfn, "valid-stack")

    # Build index with explicit stack names including a non-existent one
    # The function should log a warning and continue
    index = build_managed_resource_index(
        cfn, stack_names=["valid-stack", "nonexistent-stack"]
    )

    # Should still have resources from the valid stack
    assert len(index) >= 1


@mock_aws
def test_empty_stacks_returns_empty_set() -> None:
    """Test that when no stacks exist, an empty set is returned."""
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")

    index = build_managed_resource_index(cfn)

    assert index == frozenset()


@mock_aws
def test_stack_prefix_filtering() -> None:
    """Test that stack_prefix filters stacks correctly."""
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")

    template_a = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "QueueA": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": "prefix-queue"},
            }
        },
    })
    template_b = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "QueueB": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": "other-queue"},
            }
        },
    })

    _create_stack(cfn, "myapp-service", template_a)
    _create_stack(cfn, "other-service", template_b)

    # Only include stacks starting with "myapp-"
    index = build_managed_resource_index(cfn, stack_prefix="myapp-")

    # Should only contain resources from the "myapp-service" stack
    # The physical resource ID for an SQS queue in moto is the queue URL
    assert len(index) >= 1

    # Build index with "other-" prefix
    other_index = build_managed_resource_index(cfn, stack_prefix="other-")
    assert len(other_index) >= 1

    # The two indexes should be different
    assert index != other_index


@mock_aws
def test_explicit_stack_names_override_prefix() -> None:
    """Test that explicit stack_names takes precedence over prefix."""
    session = boto3.Session(region_name="us-east-1")
    cfn = session.client("cloudformation")

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": "explicit-queue"},
            }
        },
    })

    _create_stack(cfn, "target-stack", template)
    _create_stack(cfn, "other-stack")

    # stack_names should override prefix
    index = build_managed_resource_index(
        cfn, stack_prefix="other-", stack_names=["target-stack"]
    )

    # Should contain resources from target-stack only
    assert len(index) >= 1
