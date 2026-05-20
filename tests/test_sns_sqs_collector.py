"""Unit tests for the SNS/SQS collector."""

import json

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.sns_sqs_collector import SnsSqsCollector


@mock_aws
def test_get_queue_state_basic() -> None:
    session = boto3.Session(region_name="us-east-1")
    sqs = session.client("sqs")
    result = sqs.create_queue(QueueName="test-queue")
    queue_url = result["QueueUrl"]

    collector = SnsSqsCollector(region="us-east-1", session=session)
    state = collector.get_queue_state(queue_url)

    assert state is not None
    assert state.queue_url == queue_url
    assert state.queue_arn != ""
    assert state.policy is None
    assert state.redrive_policy is None


@mock_aws
def test_get_queue_state_with_policy() -> None:
    session = boto3.Session(region_name="us-east-1")
    sqs = session.client("sqs")
    result = sqs.create_queue(QueueName="test-queue")
    queue_url = result["QueueUrl"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSNS",
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": "*",
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={"Policy": json.dumps(policy)},
    )

    collector = SnsSqsCollector(region="us-east-1", session=session)
    state = collector.get_queue_state(queue_url)

    assert state is not None
    assert state.policy is not None
    assert len(state.policy["Statement"]) == 1
    assert state.policy["Statement"][0]["Sid"] == "AllowSNS"


@mock_aws
def test_get_queue_state_with_redrive_policy() -> None:
    session = boto3.Session(region_name="us-east-1")
    sqs = session.client("sqs")

    # Create DLQ first
    dlq_result = sqs.create_queue(QueueName="test-dlq")
    dlq_url = dlq_result["QueueUrl"]
    dlq_attrs = sqs.get_queue_attributes(
        QueueUrl=dlq_url, AttributeNames=["QueueArn"]
    )
    dlq_arn = dlq_attrs["Attributes"]["QueueArn"]

    # Create main queue with redrive policy
    result = sqs.create_queue(
        QueueName="test-queue",
        Attributes={
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "3"}
            )
        },
    )
    queue_url = result["QueueUrl"]

    collector = SnsSqsCollector(region="us-east-1", session=session)
    state = collector.get_queue_state(queue_url)

    assert state is not None
    assert state.redrive_policy is not None
    assert state.redrive_policy["deadLetterTargetArn"] == dlq_arn


@mock_aws
def test_get_queue_state_nonexistent() -> None:
    session = boto3.Session(region_name="us-east-1")
    collector = SnsSqsCollector(region="us-east-1", session=session)
    state = collector.get_queue_state(
        "https://sqs.us-east-1.amazonaws.com/123456789012/nonexistent"
    )
    assert state is None


@mock_aws
def test_get_topic_state_basic() -> None:
    session = boto3.Session(region_name="us-east-1")
    sns = session.client("sns")
    result = sns.create_topic(Name="test-topic")
    topic_arn = result["TopicArn"]

    collector = SnsSqsCollector(region="us-east-1", session=session)
    state = collector.get_topic_state(topic_arn)

    assert state is not None
    assert state.topic_arn == topic_arn
    assert state.subscriptions == ()


@mock_aws
def test_get_topic_state_with_subscriptions() -> None:
    session = boto3.Session(region_name="us-east-1")
    sns = session.client("sns")
    result = sns.create_topic(Name="test-topic")
    topic_arn = result["TopicArn"]

    # Create a subscription
    sns.subscribe(
        TopicArn=topic_arn,
        Protocol="email",
        Endpoint="test@example.com",
    )

    collector = SnsSqsCollector(region="us-east-1", session=session)
    state = collector.get_topic_state(topic_arn)

    assert state is not None
    assert len(state.subscriptions) == 1
    assert state.subscriptions[0].protocol == "email"
    assert state.subscriptions[0].endpoint == "test@example.com"


@mock_aws
def test_get_topic_state_nonexistent() -> None:
    session = boto3.Session(region_name="us-east-1")
    collector = SnsSqsCollector(region="us-east-1", session=session)
    state = collector.get_topic_state(
        "arn:aws:sns:us-east-1:123456789012:nonexistent"
    )
    assert state is None


@mock_aws
def test_get_topic_state_with_policy() -> None:
    session = boto3.Session(region_name="us-east-1")
    sns = session.client("sns")
    result = sns.create_topic(Name="test-topic")
    topic_arn = result["TopicArn"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPublish",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "sns:Publish",
                "Resource": topic_arn,
            }
        ],
    }
    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="Policy",
        AttributeValue=json.dumps(policy),
    )

    collector = SnsSqsCollector(region="us-east-1", session=session)
    state = collector.get_topic_state(topic_arn)

    assert state is not None
    assert state.policy is not None
    assert len(state.policy["Statement"]) >= 1
