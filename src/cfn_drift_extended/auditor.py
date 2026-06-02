"""Core audit orchestrator that ties collectors and comparators together.

Follows the Single Responsibility Principle: this module only orchestrates
the audit pipeline (collect → compare → aggregate). It delegates all
AWS interaction to collectors and all comparison logic to comparators.
"""

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from cfn_drift_extended import __version__
from cfn_drift_extended._auditor_utils import build_session, get_account_id
from cfn_drift_extended.collectors.cfn_collector import CfnCollector, ExpectedRoleState
from cfn_drift_extended.collectors.cfn_dynamodb_extractor import CfnDynamoDBExtractor
from cfn_drift_extended.collectors.cfn_eventbridge_extractor import CfnEventBridgeExtractor
from cfn_drift_extended.collectors.cfn_lambda_extractor import CfnLambdaExtractor
from cfn_drift_extended.collectors.cfn_s3_extractor import CfnS3Extractor
from cfn_drift_extended.collectors.cfn_sg_extractor import CfnSgExtractor
from cfn_drift_extended.collectors.cfn_sns_sqs_extractor import CfnSnsSqsExtractor
from cfn_drift_extended.collectors.dynamodb_collector import DynamoDBCollector
from cfn_drift_extended.collectors.eventbridge_collector import EventBridgeCollector
from cfn_drift_extended.collectors.iam_collector import IamCollector
from cfn_drift_extended.collectors.lambda_collector import LambdaCollector
from cfn_drift_extended.collectors.s3_collector import S3Collector
from cfn_drift_extended.collectors.sg_collector import SgCollector
from cfn_drift_extended.collectors.sns_sqs_collector import SnsSqsCollector
from cfn_drift_extended.comparators.dynamodb_comparator import DynamoDBComparator
from cfn_drift_extended.comparators.eventbridge_comparator import (
    EventBridgeComparator,
)
from cfn_drift_extended.comparators.iam_comparator import IamComparator
from cfn_drift_extended.comparators.lambda_comparator import LambdaComparator
from cfn_drift_extended.comparators.s3_comparator import S3Comparator
from cfn_drift_extended.comparators.sg_comparator import SgComparator
from cfn_drift_extended.comparators.sns_sqs_comparator import (
    SnsSqsComparator,
)
from cfn_drift_extended.exceptions import AWSPermissionError
from cfn_drift_extended.models import AuditReport, ResourceAudit

logger = logging.getLogger(__name__)

# Default concurrency for parallel resource auditing
_DEFAULT_MAX_WORKERS = 10

# All supported service names
ALL_SERVICES = frozenset({"iam", "sg", "sns", "sqs", "eventbridge", "lambda", "s3", "dynamodb"})


# Paths that indicate AWS service-linked roles (not user-managed)
_SERVICE_LINKED_ROLE_PREFIXES = (
    "aws-service-role/",
    "AWSServiceRoleFor",
)


class Auditor:
    """Orchestrates the full audit pipeline: collect → compare → report.

    Supports parallel resource auditing for performance on stacks with many resources.
    Thread safety: the mutable AuditReport is NOT passed into parallel workers.
    Workers return immutable ResourceAudit objects; errors are collected separately.
    """

    def __init__(
        self,
        region: str,
        session: boto3.Session | None = None,
        max_workers: int = _DEFAULT_MAX_WORKERS,
        profile: str | None = None,
        services: frozenset[str] | None = None,
    ) -> None:
        self._session = build_session(region, profile, session)

        self._region = region
        self._max_workers = max_workers
        self._services = services or ALL_SERVICES

        # Core collector (always needed for stack discovery and templates)
        self._cfn_collector = CfnCollector(region=region, session=self._session)

        # Service-specific collectors and comparators (lazy init based on services)
        if "iam" in self._services:
            self._iam_collector = IamCollector(region=region, session=self._session)
            self._iam_comparator = IamComparator()

        if "sg" in self._services:
            self._sg_collector = SgCollector(region=region, session=self._session)
            self._sg_comparator = SgComparator()
            self._sg_extractor = CfnSgExtractor()

        if "sns" in self._services or "sqs" in self._services:
            self._sns_sqs_collector = SnsSqsCollector(
                region=region, session=self._session
            )
            self._sns_sqs_comparator = SnsSqsComparator()
            self._sns_sqs_extractor = CfnSnsSqsExtractor()

        if "eventbridge" in self._services:
            self._eventbridge_collector = EventBridgeCollector(
                region=region, session=self._session
            )
            self._eventbridge_comparator = EventBridgeComparator()
            self._eventbridge_extractor = CfnEventBridgeExtractor()

        if "lambda" in self._services:
            self._lambda_collector = LambdaCollector(region=region, session=self._session)
            self._lambda_comparator = LambdaComparator()
            self._lambda_extractor = CfnLambdaExtractor()

        if "s3" in self._services:
            self._s3_collector = S3Collector(region=region, session=self._session)
            self._s3_comparator = S3Comparator()
            self._s3_extractor = CfnS3Extractor()

        if "dynamodb" in self._services:
            self._dynamodb_collector = DynamoDBCollector(region=region, session=self._session)
            self._dynamodb_comparator = DynamoDBComparator()
            self._dynamodb_extractor = CfnDynamoDBExtractor()

    def audit_stacks(
        self,
        stack_prefix: str = "",
        stack_names: list[str] | None = None,
        tag_filter: dict[str, str] | None = None,
    ) -> AuditReport:
        """Run the full additive drift audit across all enabled services.

        Args:
            stack_prefix: Only stacks whose names start with this prefix are audited.
            stack_names: Explicit list of stack names (overrides prefix).
            tag_filter: Only audit stacks with these tags.

        Returns:
            An AuditReport summarizing all findings.

        Raises:
            AWSPermissionError: If the caller lacks required permissions.
        """
        report = AuditReport(
            tool_version=__version__,
            region=self._region,
            timestamp=datetime.now(UTC).isoformat(),
        )

        # Resolve account ID for report metadata
        report.account_id = get_account_id(self._session)

        # Discover stacks
        try:
            matched_stacks = self._cfn_collector.list_stacks_by_prefix(
                stack_prefix, stack_names=stack_names, tag_filter=tag_filter
            )
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "AccessDeniedException"):
                raise AWSPermissionError(
                    "Cannot list CloudFormation stacks. "
                    "Ensure the IAM principal has cloudformation:ListStacks permission.",
                    details=str(e),
                ) from e
            raise

        report.stacks_scanned = len(matched_stacks)

        if not matched_stacks:
            logger.warning("No stacks found matching the filter criteria")
            return report

        # Collect expected state and audit each stack
        all_audits: list[ResourceAudit] = []
        all_errors: list[str] = []
        total_resources = 0

        for stack_name in matched_stacks:
            audits, errors, resource_count = self._audit_stack(stack_name)
            all_audits.extend(audits)
            all_errors.extend(errors)
            total_resources += resource_count

        report.resources_scanned = total_resources
        report.audits = all_audits
        report.findings = [f for audit in all_audits for f in audit.findings]
        report.resources_with_drift = sum(
            1 for audit in all_audits if not audit.in_sync
        )
        report.errors = all_errors

        return report

    def _audit_stack(
        self, stack_name: str
    ) -> tuple[list[ResourceAudit], list[str], int]:
        """Audit a single stack across all enabled services.

        Returns:
            Tuple of (audits, errors, resource_count).
        """
        audits: list[ResourceAudit] = []
        errors: list[str] = []
        resource_count = 0

        # IAM audit (uses existing recursive template extraction)
        if "iam" in self._services:
            iam_audits, iam_errors, iam_count = self._audit_iam(stack_name)
            audits.extend(iam_audits)
            errors.extend(iam_errors)
            resource_count += iam_count

        # For SG, SNS/SQS, EventBridge, Lambda, S3, DynamoDB we need the template and physical IDs
        needs_template = bool(
            {"sg", "sns", "sqs", "eventbridge", "lambda", "s3", "dynamodb"} & self._services
        )
        if not needs_template:
            return audits, errors, resource_count

        # Get template resources and physical IDs
        template_body = self._cfn_collector._get_template(stack_name)
        if not template_body:
            return audits, errors, resource_count

        resources = template_body.get("Resources", {})
        if not isinstance(resources, dict):
            return audits, errors, resource_count

        physical_ids = self._resolve_physical_ids(stack_name, resources)

        # Security Groups audit
        if "sg" in self._services:
            sg_audits, sg_errors, sg_count = self._audit_security_groups(
                resources, stack_name, physical_ids
            )
            audits.extend(sg_audits)
            errors.extend(sg_errors)
            resource_count += sg_count

        # SQS audit
        if "sqs" in self._services:
            sqs_audits, sqs_errors, sqs_count = self._audit_sqs(
                resources, stack_name, physical_ids
            )
            audits.extend(sqs_audits)
            errors.extend(sqs_errors)
            resource_count += sqs_count

        # SNS audit
        if "sns" in self._services:
            sns_audits, sns_errors, sns_count = self._audit_sns(
                resources, stack_name, physical_ids
            )
            audits.extend(sns_audits)
            errors.extend(sns_errors)
            resource_count += sns_count

        # EventBridge audit
        if "eventbridge" in self._services:
            eb_audits, eb_errors, eb_count = self._audit_eventbridge(
                resources, stack_name, physical_ids
            )
            audits.extend(eb_audits)
            errors.extend(eb_errors)
            resource_count += eb_count

        # Lambda audit
        if "lambda" in self._services:
            lambda_audits, lambda_errors, lambda_count = self._audit_lambda(
                resources, stack_name, physical_ids
            )
            audits.extend(lambda_audits)
            errors.extend(lambda_errors)
            resource_count += lambda_count

        # S3 audit
        if "s3" in self._services:
            s3_audits, s3_errors, s3_count = self._audit_s3(
                resources, stack_name, physical_ids
            )
            audits.extend(s3_audits)
            errors.extend(s3_errors)
            resource_count += s3_count

        # DynamoDB audit
        if "dynamodb" in self._services:
            ddb_audits, ddb_errors, ddb_count = self._audit_dynamodb(
                resources, stack_name, physical_ids
            )
            audits.extend(ddb_audits)
            errors.extend(ddb_errors)
            resource_count += ddb_count

        return audits, errors, resource_count

    def _audit_iam(
        self, stack_name: str
    ) -> tuple[list[ResourceAudit], list[str], int]:
        """Audit IAM roles for a stack."""
        all_expected_roles = self._cfn_collector.get_iam_roles_from_stack(stack_name)
        if not all_expected_roles:
            return [], [], 0

        audits, errors = self._audit_roles_parallel(all_expected_roles)
        return audits, errors, len(all_expected_roles)

    def _audit_security_groups(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> tuple[list[ResourceAudit], list[str], int]:
        return self._audit_resource_set(
            label="SG",
            id_attr="group_id",
            extracted=self._sg_extractor.extract_security_groups(
                resources, stack_name, physical_ids
            ),
            fetch_actual=self._sg_collector.get_security_group_state,
            compare=self._sg_comparator.compare,
            stack_name=stack_name,
        )

    def _audit_sqs(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> tuple[list[ResourceAudit], list[str], int]:
        return self._audit_resource_set(
            label="SQS queue",
            id_attr="queue_url",
            extracted=self._sns_sqs_extractor.extract_sqs_queues(
                resources, stack_name, physical_ids
            ),
            fetch_actual=self._sns_sqs_collector.get_queue_state,
            compare=self._sns_sqs_comparator.compare_sqs,
            stack_name=stack_name,
            skip_when_id_missing=True,
        )

    def _audit_sns(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> tuple[list[ResourceAudit], list[str], int]:
        return self._audit_resource_set(
            label="SNS topic",
            id_attr="topic_arn",
            extracted=self._sns_sqs_extractor.extract_sns_topics(
                resources, stack_name, physical_ids
            ),
            fetch_actual=self._sns_sqs_collector.get_topic_state,
            compare=self._sns_sqs_comparator.compare_sns,
            stack_name=stack_name,
            skip_when_id_missing=True,
        )

    def _audit_eventbridge(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> tuple[list[ResourceAudit], list[str], int]:
        return self._audit_resource_set(
            label="event bus",
            id_attr="event_bus_name",
            extracted=self._eventbridge_extractor.extract_event_buses(
                resources, stack_name, physical_ids
            ),
            fetch_actual=self._eventbridge_collector.get_event_bus_state,
            compare=self._eventbridge_comparator.compare,
            stack_name=stack_name,
        )

    def _audit_lambda(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> tuple[list[ResourceAudit], list[str], int]:
        return self._audit_resource_set(
            label="Lambda function",
            id_attr="function_name",
            extracted=self._lambda_extractor.extract_functions(
                resources, stack_name, physical_ids
            ),
            fetch_actual=self._lambda_collector.get_function_state,
            compare=self._lambda_comparator.compare,
            stack_name=stack_name,
        )

    def _audit_s3(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> tuple[list[ResourceAudit], list[str], int]:
        return self._audit_resource_set(
            label="S3 bucket",
            id_attr="bucket_name",
            extracted=self._s3_extractor.extract_buckets(
                resources, stack_name, physical_ids
            ),
            fetch_actual=self._s3_collector.get_bucket_state,
            compare=self._s3_comparator.compare,
            stack_name=stack_name,
        )

    def _audit_dynamodb(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> tuple[list[ResourceAudit], list[str], int]:
        return self._audit_resource_set(
            label="DynamoDB table",
            id_attr="table_name",
            extracted=self._dynamodb_extractor.extract_tables(
                resources, stack_name, physical_ids
            ),
            fetch_actual=self._dynamodb_collector.get_table_state,
            compare=self._dynamodb_comparator.compare,
            stack_name=stack_name,
        )

    @staticmethod
    def _audit_resource_set(
        *,
        label: str,
        id_attr: str,
        extracted: list[Any],
        fetch_actual: Callable[[str], Any],
        compare: Callable[[Any, Any], ResourceAudit],
        stack_name: str,
        skip_when_id_missing: bool = False,
    ) -> tuple[list[ResourceAudit], list[str], int]:
        """Run the per-service audit loop shared by every non-IAM service.

        Each enabled service follows the same shape: a CFN extractor returns
        an "expected" list, a service collector fetches the live state by id,
        and a comparator produces the ResourceAudit. The variation between
        services is fully captured by ``label``, ``id_attr``, and the three
        callables — the loop body itself is identical.
        """
        if not extracted:
            return [], [], 0

        audits: list[ResourceAudit] = []
        errors: list[str] = []

        for expected in extracted:
            identifier = getattr(expected, id_attr, None)
            try:
                if skip_when_id_missing and not identifier:
                    continue
                actual = fetch_actual(identifier)
                if actual is None:
                    logger.warning(
                        "%s '%s' in stack '%s' not found — skipping",
                        label,
                        identifier,
                        stack_name,
                    )
                    continue
                audits.append(compare(expected, actual))
            except Exception as e:
                msg = (
                    f"Error auditing {label} '{identifier}' "
                    f"in stack '{stack_name}': {e}"
                )
                logger.error(msg)
                errors.append(msg)

        return audits, errors, len(extracted)

    def _resolve_physical_ids(
        self, stack_name: str, resources: dict[str, Any]
    ) -> dict[str, str]:
        """Resolve physical resource IDs for all resources in a stack.

        Returns a mapping of logical ID → physical resource ID.
        Also includes AWS pseudo-parameters for intrinsic resolution.
        """
        physical_ids: dict[str, str] = {}
        try:
            paginator = self._cfn_collector._cfn.get_paginator(
                "list_stack_resources"
            )
            for page in paginator.paginate(StackName=stack_name):
                for summary in page.get("StackResourceSummaries", []):
                    logical_id = summary.get("LogicalResourceId", "")
                    physical_id = summary.get("PhysicalResourceId", "")
                    if logical_id and physical_id:
                        physical_ids[logical_id] = physical_id
        except ClientError as e:
            logger.warning(
                "Could not list resources for stack '%s': %s",
                stack_name,
                e.response["Error"]["Code"],
            )

        # Add pseudo-parameters for Fn::Sub resolution
        physical_ids["AWS::Region"] = self._region
        physical_ids["AWS::StackName"] = stack_name
        physical_ids["AWS::AccountId"] = get_account_id(self._session)
        physical_ids["AWS::URLSuffix"] = "amazonaws.com"
        physical_ids["AWS::Partition"] = "aws"

        return physical_ids

    def _audit_roles_parallel(
        self, expected_roles: list[ExpectedRoleState]
    ) -> tuple[list[ResourceAudit], list[str]]:
        """Audit multiple roles concurrently using a thread pool.

        Thread-safe: each worker returns an immutable ResourceAudit.
        Errors are collected in a separate list, not mutated on a shared object.

        Returns:
            Tuple of (audits, errors).
        """
        audits: list[ResourceAudit] = []
        errors: list[str] = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            future_to_role = {
                executor.submit(self._audit_single_role, expected): expected
                for expected in expected_roles
            }

            for future in as_completed(future_to_role):
                expected = future_to_role[future]
                try:
                    audit = future.result()
                    if audit is not None:
                        audits.append(audit)
                except Exception as e:
                    error_msg = (
                        f"Error auditing role '{expected.role_name}' "
                        f"in stack '{expected.stack_name}': {e}"
                    )
                    logger.error(error_msg)
                    errors.append(error_msg)

        return audits, errors

    def _audit_single_role(self, expected: ExpectedRoleState) -> ResourceAudit | None:
        """Audit a single IAM role against its expected state.

        Skips service-linked roles (created by AWS services, not user-managed).
        """
        # Skip service-linked roles — they're AWS-managed, not user drift
        if any(
            expected.role_name.startswith(prefix)
            for prefix in _SERVICE_LINKED_ROLE_PREFIXES
        ):
            logger.debug(
                "Skipping service-linked role '%s' in stack '%s'",
                expected.role_name,
                expected.stack_name,
            )
            return None

        actual = self._iam_collector.get_role_state(expected.role_name)
        if actual is None:
            logger.warning(
                "Role '%s' declared in stack '%s' not found in IAM — skipping",
                expected.role_name,
                expected.stack_name,
            )
            return None

        return self._iam_comparator.compare(expected, actual)
