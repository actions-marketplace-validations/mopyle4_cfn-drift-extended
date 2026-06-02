"""Detect orphaned Lambda functions not managed by CloudFormation.

Compares all Lambda functions in the region against the CFN managed resource
index. Functions not in the index (and not excluded by filters) are flagged as
potentially orphaned. For each candidate orphan, the CloudWatch ``Invocations``
metric is consulted so that staleness reflects both modification *and*
invocation activity (a function can be modified recently but never invoked).

Required IAM permissions (least privilege):
- lambda:ListFunctions
- cloudwatch:GetMetricStatistics
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import ClientError

from cfn_drift_extended.collectors._aws import BOTO_CONFIG
from cfn_drift_extended.collectors._datetime_utils import (
    days_since,
    format_datetime,
)
from cfn_drift_extended.collectors.cfn_managed_index import ManagedIndex
from cfn_drift_extended.collectors.orphan_filters import is_excluded_lambda
from cfn_drift_extended.models import OrphanFinding, OrphanType, Severity

logger = logging.getLogger(__name__)

# Functions not modified or invoked for longer than this are flagged as stale.
_STALE_THRESHOLD_DAYS = 90

# CloudWatch lookback window for Invocations. We look back slightly longer than
# the stale threshold so a single missed daily datapoint doesn't change the
# verdict.
_INVOCATION_LOOKBACK_DAYS = _STALE_THRESHOLD_DAYS + 1
# One day in seconds — coarse-grained period keeps the response payload small.
_METRIC_PERIOD_SECONDS = 86_400


class LambdaOrphanCollector:
    """Detects orphaned Lambda functions.

    Compares all functions in the region against the CFN managed index.
    Functions not in the index (and not excluded by filters) are reported as
    orphaned. Staleness combines the ``LastModified`` field with the CloudWatch
    ``Invocations`` metric.
    """

    def __init__(self, session: boto3.Session, region: str) -> None:
        self._session = session
        self._region = region
        self._lambda = session.client("lambda", config=BOTO_CONFIG)
        self._cloudwatch = session.client("cloudwatch", config=BOTO_CONFIG)

    def detect_orphaned_functions(
        self, managed_index: ManagedIndex | frozenset[str]
    ) -> list[OrphanFinding]:
        """Detect Lambda functions not managed by any CloudFormation stack.

        Args:
            managed_index: ManagedIndex (or a plain set, for backward
                compatibility with tests) of physical resource IDs managed
                by CloudFormation.

        Returns:
            List of OrphanFinding for each orphaned function.
        """
        findings: list[OrphanFinding] = []
        functions = self._list_all_functions()

        for function in functions:
            function_name = function.get("FunctionName", "")
            function_arn = function.get("FunctionArn", "")

            if not function_name:
                continue

            # Check exclusion filters (CDK custom resources, log retention, etc.)
            if is_excluded_lambda(function_name):
                continue

            # Skip functions managed by CFN (matched by name or ARN)
            if function_name in managed_index or function_arn in managed_index:
                continue

            last_modified = function.get("LastModified")
            last_modified_iso = format_datetime(last_modified)
            modified_stale_days = days_since(last_modified)

            # Consult CloudWatch only for candidate orphans to keep cost down.
            last_invocation = self._get_last_invocation(function_name)
            last_invocation_iso = (
                last_invocation.isoformat() if last_invocation else None
            )

            description = self._build_description(
                function_name=function_name,
                modified_stale_days=modified_stale_days,
                last_invocation=last_invocation,
            )

            findings.append(
                OrphanFinding(
                    resource_type="AWS::Lambda::Function",
                    resource_id=function_arn or function_name,
                    orphan_type=OrphanType.LAMBDA_FUNCTION_ORPHANED,
                    severity=Severity.MEDIUM,
                    description=description,
                    created_date=last_modified_iso,
                    last_used=last_invocation_iso or last_modified_iso,
                    region=self._region,
                )
            )

        return findings

    def _list_all_functions(self) -> list[dict[str, Any]]:
        """List all Lambda functions in the region using pagination."""
        functions: list[dict[str, Any]] = []
        try:
            paginator = self._lambda.get_paginator("list_functions")
            for page in paginator.paginate():
                functions.extend(page.get("Functions", []))
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error("Failed to list Lambda functions: %s", error_code)

        return functions

    def _get_last_invocation(self, function_name: str) -> datetime | None:
        """Return the most recent invocation time, or None if never invoked.

        Uses CloudWatch ``AWS/Lambda`` ``Invocations`` metric over the
        configured lookback window. The latest datapoint with a non-zero
        sample is treated as the last invocation. Returns None if there are
        no datapoints (function not invoked within the window) or the call
        fails.
        """
        end = datetime.now(UTC)
        start = end - timedelta(days=_INVOCATION_LOOKBACK_DAYS)
        try:
            response = self._cloudwatch.get_metric_statistics(
                Namespace="AWS/Lambda",
                MetricName="Invocations",
                Dimensions=[
                    {"Name": "FunctionName", "Value": function_name},
                ],
                StartTime=start,
                EndTime=end,
                Period=_METRIC_PERIOD_SECONDS,
                Statistics=["Sum"],
            )
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.warning(
                "Failed to fetch invocation metrics for %s: %s",
                function_name,
                error_code,
            )
            return None

        datapoints = [
            dp for dp in response.get("Datapoints", []) if dp.get("Sum", 0) > 0
        ]
        if not datapoints:
            return None

        latest = max(datapoints, key=lambda dp: dp["Timestamp"])
        timestamp: datetime = latest["Timestamp"]
        # Normalize to timezone-aware UTC for consistent ISO formatting.
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        return timestamp

    @staticmethod
    def _build_description(
        function_name: str,
        modified_stale_days: int | None,
        last_invocation: datetime | None,
    ) -> str:
        """Construct the human-readable finding description."""
        description = (
            f"Lambda function '{function_name}' is not managed by any CFN stack"
        )

        modified_stale = (
            modified_stale_days is not None
            and modified_stale_days > _STALE_THRESHOLD_DAYS
        )
        if modified_stale:
            description += f" (not modified for {modified_stale_days} days)"

        if last_invocation is None:
            description += (
                f"; not invoked in the last {_INVOCATION_LOOKBACK_DAYS} days"
            )
        else:
            invocation_days_ago = max(
                (datetime.now(UTC) - last_invocation).days, 0
            )
            if invocation_days_ago > _STALE_THRESHOLD_DAYS:
                description += (
                    f"; last invoked {invocation_days_ago} days ago"
                )

        return description
