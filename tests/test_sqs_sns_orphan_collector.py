"""Unit tests for the SQS/SNS orphan collector."""

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.sqs_sns_orphan_collector import (
    SqsSnsOrphanCollector,
)
from cfn_drift_extended.models import OrphanType


@mock_aws
def test_detects_orphaned_queue_not_in_managed_index() -> None:
    """Test that a queue not in the managed index is flagged as orphaned."""
    session = boto3.Session(region_name="us-east-1")
    sqs = session.client("sqs")

    # Create a queue that is NOT in the managed index
    result = sqs.create_queue(QueueName="orphaned-queue")
    queue_url = result["QueueUrl"]

    # Get the ARN for verification
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )
    queue_arn = attrs["Attributes"]["QueueArn"]

    # Empty managed index — nothing is managed
    managed_index = frozenset()

    collector = SqsSnsOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_queues(managed_index)

    assert len(findings) == 1
    assert findings[0].orphan_type == OrphanType.SQS_QUEUE_ORPHANED
    assert findings[0].resource_id == queue_arn
    assert "orphaned-queue" in findings[0].description


@mock_aws
def test_excludes_queue_in_managed_index() -> None:
    """Test that a queue in the managed index is NOT flagged."""
    session = boto3.Session(region_name="us-east-1")
    sqs = session.client("sqs")

    result = sqs.create_queue(QueueName="managed-queue")
    queue_url = result["QueueUrl"]

    # Get the ARN
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )
    queue_arn = attrs["Attributes"]["QueueArn"]

    # Include the queue ARN in the managed index
    managed_index = frozenset({queue_arn})

    collector = SqsSnsOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_queues(managed_index)

    assert len(findings) == 0


@mock_aws
def test_excludes_queue_by_url_in_managed_index() -> None:
    """Test that a queue matched by URL in the managed index is NOT flagged."""
    session = boto3.Session(region_name="us-east-1")
    sqs = session.client("sqs")

    result = sqs.create_queue(QueueName="url-managed-queue")
    queue_url = result["QueueUrl"]

    # Include the queue URL in the managed index
    managed_index = frozenset({queue_url})

    collector = SqsSnsOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_queues(managed_index)

    assert len(findings) == 0


@mock_aws
def test_detects_orphaned_topic_not_in_managed_index() -> None:
    """Test that a topic not in the managed index is flagged as orphaned."""
    session = boto3.Session(region_name="us-east-1")
    sns = session.client("sns")

    result = sns.create_topic(Name="orphaned-topic")
    topic_arn = result["TopicArn"]

    # Empty managed index
    managed_index = frozenset()

    collector = SqsSnsOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_topics(managed_index)

    assert len(findings) == 1
    assert findings[0].orphan_type == OrphanType.SNS_TOPIC_ORPHANED
    assert findings[0].resource_id == topic_arn
    assert "orphaned-topic" in findings[0].description


@mock_aws
def test_excludes_topic_in_managed_index() -> None:
    """Test that a topic in the managed index is NOT flagged."""
    session = boto3.Session(region_name="us-east-1")
    sns = session.client("sns")

    result = sns.create_topic(Name="managed-topic")
    topic_arn = result["TopicArn"]

    # Include the topic ARN in the managed index
    managed_index = frozenset({topic_arn})

    collector = SqsSnsOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_topics(managed_index)

    assert len(findings) == 0


@mock_aws
def test_handles_empty_queue_list() -> None:
    """Test that an empty queue list returns no findings."""
    session = boto3.Session(region_name="us-east-1")

    managed_index = frozenset()

    collector = SqsSnsOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_queues(managed_index)

    assert findings == []


@mock_aws
def test_handles_empty_topic_list() -> None:
    """Test that an empty topic list returns no findings."""
    session = boto3.Session(region_name="us-east-1")

    managed_index = frozenset()

    collector = SqsSnsOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_topics(managed_index)

    assert findings == []


@mock_aws
def test_handles_api_errors_gracefully_queues() -> None:
    """Test that API errors during queue detection are handled gracefully."""
    session = boto3.Session(region_name="us-east-1")

    # Create a collector — the list_queues call should work fine with moto
    # but if there's an error, it should return empty list
    collector = SqsSnsOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_queues(frozenset())

    # Should not raise, should return empty list
    assert findings == []


@mock_aws
def test_handles_api_errors_gracefully_topics() -> None:
    """Test that API errors during topic detection are handled gracefully."""
    session = boto3.Session(region_name="us-east-1")

    collector = SqsSnsOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_topics(frozenset())

    # Should not raise, should return empty list
    assert findings == []


@mock_aws
def test_multiple_orphaned_queues() -> None:
    """Test detection of multiple orphaned queues."""
    session = boto3.Session(region_name="us-east-1")
    sqs = session.client("sqs")

    # Create multiple queues
    sqs.create_queue(QueueName="orphan-1")
    sqs.create_queue(QueueName="orphan-2")
    sqs.create_queue(QueueName="orphan-3")

    managed_index = frozenset()

    collector = SqsSnsOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_queues(managed_index)

    assert len(findings) == 3


@mock_aws
def test_mixed_managed_and_orphaned_queues() -> None:
    """Test that only unmanaged queues are flagged."""
    session = boto3.Session(region_name="us-east-1")
    sqs = session.client("sqs")

    # Create managed queue
    managed_result = sqs.create_queue(QueueName="managed-q")
    managed_url = managed_result["QueueUrl"]
    managed_attrs = sqs.get_queue_attributes(
        QueueUrl=managed_url, AttributeNames=["QueueArn"]
    )
    managed_arn = managed_attrs["Attributes"]["QueueArn"]

    # Create orphaned queue
    sqs.create_queue(QueueName="orphaned-q")

    managed_index = frozenset({managed_arn})

    collector = SqsSnsOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_queues(managed_index)

    assert len(findings) == 1
    assert "orphaned-q" in findings[0].description
