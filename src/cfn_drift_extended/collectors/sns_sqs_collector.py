"""Collect actual SNS/SQS state from AWS.

Required IAM permissions (least privilege):
- sqs:GetQueueAttributes
- sns:GetTopicAttributes
- sns:ListSubscriptionsByTopic
"""

import json
import logging
from dataclasses import dataclass, field

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Retry configuration with adaptive mode and jitter
_BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
)


@dataclass(frozen=True, slots=True)
class ActualSqsQueueState:
    """What actually exists on an SQS queue in AWS.

    Frozen dataclass for immutability and memory efficiency (slots).
    """

    queue_url: str
    queue_arn: str
    policy: dict | None = None
    redrive_policy: dict | None = None


@dataclass(frozen=True, slots=True)
class SnsSubscription:
    """A single SNS subscription."""

    protocol: str
    endpoint: str
    subscription_arn: str


@dataclass(frozen=True, slots=True)
class ActualSnsTopicState:
    """What actually exists on an SNS topic in AWS.

    Frozen dataclass for immutability and memory efficiency (slots).
    """

    topic_arn: str
    policy: dict | None = None
    subscriptions: tuple[SnsSubscription, ...] = field(default_factory=tuple)


class SnsSqsCollector:
    """Collects actual SNS/SQS state from the AWS APIs.

    Features:
    - Adaptive retry with exponential backoff
    - Pagination on subscription listing
    - Read-only API calls (least privilege)
    - Returns None on access errors (graceful degradation)
    """

    def __init__(self, region: str, session: boto3.Session | None = None) -> None:
        self._session = session or boto3.Session(region_name=region)
        self._sqs = self._session.client("sqs", config=_BOTO_CONFIG)
        self._sns = self._session.client("sns", config=_BOTO_CONFIG)

    def get_queue_state(self, queue_url: str) -> ActualSqsQueueState | None:
        """Get the actual state of an SQS queue.

        Returns None if the queue doesn't exist or cannot be accessed.
        """
        try:
            response = self._sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=["Policy", "RedrivePolicy", "QueueArn"],
            )
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in (
                "AWS.SimpleQueueService.NonExistentQueue",
                "QueueDoesNotExist",
            ):
                logger.warning("SQS queue '%s' does not exist", queue_url)
            elif error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied accessing SQS queue '%s'. "
                    "Ensure sqs:GetQueueAttributes permission is granted.",
                    queue_url,
                )
            else:
                logger.error(
                    "Unexpected error fetching SQS queue '%s': %s",
                    queue_url,
                    error_code,
                )
            return None

        attrs = response.get("Attributes", {})
        queue_arn = attrs.get("QueueArn", "")

        policy_str = attrs.get("Policy")
        policy = json.loads(policy_str) if policy_str else None

        redrive_str = attrs.get("RedrivePolicy")
        redrive_policy = json.loads(redrive_str) if redrive_str else None

        return ActualSqsQueueState(
            queue_url=queue_url,
            queue_arn=queue_arn,
            policy=policy,
            redrive_policy=redrive_policy,
        )

    def get_topic_state(self, topic_arn: str) -> ActualSnsTopicState | None:
        """Get the actual state of an SNS topic.

        Returns None if the topic doesn't exist or cannot be accessed.
        """
        try:
            response = self._sns.get_topic_attributes(TopicArn=topic_arn)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NotFound":
                logger.warning("SNS topic '%s' does not exist", topic_arn)
            elif error_code in ("AccessDenied", "AccessDeniedException", "AuthorizationError"):
                logger.error(
                    "Permission denied accessing SNS topic '%s'. "
                    "Ensure sns:GetTopicAttributes permission is granted.",
                    topic_arn,
                )
            else:
                logger.error(
                    "Unexpected error fetching SNS topic '%s': %s",
                    topic_arn,
                    error_code,
                )
            return None

        attrs = response.get("Attributes", {})
        policy_str = attrs.get("Policy")
        policy = json.loads(policy_str) if policy_str else None

        subscriptions = self._list_subscriptions(topic_arn)

        return ActualSnsTopicState(
            topic_arn=topic_arn,
            policy=policy,
            subscriptions=tuple(subscriptions),
        )

    def _list_subscriptions(self, topic_arn: str) -> list[SnsSubscription]:
        """List all subscriptions for a topic using pagination."""
        subscriptions: list[SnsSubscription] = []
        try:
            paginator = self._sns.get_paginator("list_subscriptions_by_topic")
            for page in paginator.paginate(TopicArn=topic_arn):
                for sub in page.get("Subscriptions", []):
                    sub_arn = sub.get("SubscriptionArn", "")
                    # Skip pending confirmations
                    if sub_arn == "PendingConfirmation":
                        continue
                    subscriptions.append(
                        SnsSubscription(
                            protocol=sub.get("Protocol", ""),
                            endpoint=sub.get("Endpoint", ""),
                            subscription_arn=sub_arn,
                        )
                    )
        except ClientError as e:
            logger.error(
                "Failed to list subscriptions for topic '%s': %s",
                topic_arn,
                e.response["Error"]["Code"],
            )
        return subscriptions
