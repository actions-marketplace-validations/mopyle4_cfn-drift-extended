"""Detect orphaned SQS queues and SNS topics not managed by CloudFormation.

Compares all queues/topics in the account against the CFN managed resource index.
Resources not in the index are flagged as potentially orphaned.

Required IAM permissions (least privilege):
- sqs:ListQueues
- sqs:GetQueueAttributes
- sns:ListTopics
"""

import logging
from datetime import UTC, datetime

import boto3
from botocore.exceptions import ClientError

from cfn_drift_extended.collectors._aws import BOTO_CONFIG
from cfn_drift_extended.collectors.cfn_managed_index import ManagedIndex
from cfn_drift_extended.collectors.orphan_filters import is_excluded_queue
from cfn_drift_extended.models import OrphanFinding, OrphanType, Severity

logger = logging.getLogger(__name__)


class SqsSnsOrphanCollector:
    """Detects orphaned SQS queues and SNS topics.

    Compares all queues/topics in the region against the CFN managed index.
    Resources not in the index (and not excluded by filters) are reported
    as orphaned.
    """

    def __init__(self, session: boto3.Session, region: str) -> None:
        self._session = session
        self._region = region
        self._sqs = session.client("sqs", config=BOTO_CONFIG)
        self._sns = session.client("sns", config=BOTO_CONFIG)

    def detect_orphaned_queues(
        self, managed_index: ManagedIndex | frozenset[str]
    ) -> list[OrphanFinding]:
        """Detect SQS queues not managed by any CloudFormation stack.

        Args:
            managed_index: ManagedIndex (or a plain set, for backward
                compatibility with tests) of physical resource IDs managed
                by CloudFormation.

        Returns:
            List of OrphanFinding for each orphaned queue.
        """
        findings: list[OrphanFinding] = []
        queue_urls = self._list_all_queues()

        for queue_url in queue_urls:
            # Check exclusion filters
            if is_excluded_queue(queue_url):
                continue

            # Get queue ARN and attributes for matching
            queue_arn, created_timestamp, approx_messages = (
                self._get_queue_details(queue_url)
            )
            if queue_arn is None:
                continue

            # Extract queue name from URL for display
            queue_name = queue_url.rstrip("/").rsplit("/", maxsplit=1)[-1]

            # Check if queue URL or ARN is in the managed index
            if queue_url in managed_index or queue_arn in managed_index:
                continue

            # Also check by queue name (some stacks use name as physical ID)
            if queue_name in managed_index:
                continue

            created_date = None
            if created_timestamp:
                try:
                    created_date = datetime.fromtimestamp(
                        int(created_timestamp), tz=UTC
                    ).isoformat()
                except (ValueError, OSError):
                    pass

            description = f"SQS queue '{queue_name}' is not managed by any CFN stack"
            if approx_messages:
                description += f" (approx {approx_messages} messages)"

            findings.append(
                OrphanFinding(
                    resource_type="AWS::SQS::Queue",
                    resource_id=queue_arn or queue_url,
                    orphan_type=OrphanType.SQS_QUEUE_ORPHANED,
                    severity=Severity.MEDIUM,
                    description=description,
                    created_date=created_date,
                    last_used=None,
                    region=self._region,
                )
            )

        return findings

    def detect_orphaned_topics(
        self, managed_index: ManagedIndex | frozenset[str]
    ) -> list[OrphanFinding]:
        """Detect SNS topics not managed by any CloudFormation stack.

        Args:
            managed_index: ManagedIndex (or a plain set, for backward
                compatibility with tests) of physical resource IDs managed
                by CloudFormation.

        Returns:
            List of OrphanFinding for each orphaned topic.
        """
        findings: list[OrphanFinding] = []
        topic_arns = self._list_all_topics()

        for topic_arn in topic_arns:
            # Check if topic ARN is in the managed index
            if topic_arn in managed_index:
                continue

            # Extract topic name from ARN for display
            topic_name = topic_arn.rsplit(":", maxsplit=1)[-1]

            # Also check by topic name
            if topic_name in managed_index:
                continue

            findings.append(
                OrphanFinding(
                    resource_type="AWS::SNS::Topic",
                    resource_id=topic_arn,
                    orphan_type=OrphanType.SNS_TOPIC_ORPHANED,
                    severity=Severity.LOW,
                    description=(
                        f"SNS topic '{topic_name}' is not managed by any CFN stack"
                    ),
                    created_date=None,
                    last_used=None,
                    region=self._region,
                )
            )

        return findings

    def _list_all_queues(self) -> list[str]:
        """List all SQS queue URLs in the region using pagination."""
        queue_urls: list[str] = []
        try:
            next_token = None
            while True:
                kwargs: dict = {}
                if next_token:
                    kwargs["NextToken"] = next_token
                response = self._sqs.list_queues(**kwargs)
                queue_urls.extend(response.get("QueueUrls", []))
                next_token = response.get("NextToken")
                if not next_token:
                    break
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error("Failed to list SQS queues: %s", error_code)

        return queue_urls

    def _list_all_topics(self) -> list[str]:
        """List all SNS topic ARNs in the region using pagination."""
        topic_arns: list[str] = []
        try:
            paginator = self._sns.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page.get("Topics", []):
                    arn = topic.get("TopicArn", "")
                    if arn:
                        topic_arns.append(arn)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error("Failed to list SNS topics: %s", error_code)

        return topic_arns

    def _get_queue_details(
        self, queue_url: str
    ) -> tuple[str | None, str | None, str | None]:
        """Get queue ARN, creation timestamp, and approximate message count.

        Returns (queue_arn, created_timestamp, approx_messages) or
        (None, None, None) on error.
        """
        try:
            response = self._sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=[
                    "QueueArn",
                    "CreatedTimestamp",
                    "ApproximateNumberOfMessages",
                ],
            )
            attrs = response.get("Attributes", {})
            return (
                attrs.get("QueueArn"),
                attrs.get("CreatedTimestamp"),
                attrs.get("ApproximateNumberOfMessages"),
            )
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.warning(
                "Failed to get attributes for queue '%s': %s",
                queue_url,
                error_code,
            )
            return None, None, None
