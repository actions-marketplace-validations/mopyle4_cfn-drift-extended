"""Orphan detection orchestrator.

Coordinates the detection of resources that exist in AWS but are not managed
by any CloudFormation stack. Builds a managed resource index first, then
runs service-specific orphan detectors in parallel.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

import boto3
from botocore.config import Config

from cfn_drift_extended import __version__
from cfn_drift_extended.collectors.cfn_managed_index import (
    build_managed_resource_index,
)
from cfn_drift_extended.collectors.sqs_sns_orphan_collector import (
    SqsSnsOrphanCollector,
)
from cfn_drift_extended.models import OrphanFinding, OrphanReport

logger = logging.getLogger(__name__)

_BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
)

# All supported orphan detection services
ALL_ORPHAN_SERVICES = frozenset({"iam", "sg", "lambda", "sqs", "sns"})

_DEFAULT_MAX_WORKERS = 10


class OrphanAuditor:
    """Orchestrates orphan detection across multiple AWS services.

    Builds a CFN managed resource index, then runs enabled orphan detectors
    in parallel using a thread pool.
    """

    def __init__(
        self,
        region: str,
        profile: str | None = None,
        services: frozenset[str] | None = None,
        max_workers: int = _DEFAULT_MAX_WORKERS,
    ) -> None:
        if profile:
            self._session = boto3.Session(
                region_name=region, profile_name=profile
            )
        else:
            self._session = boto3.Session(region_name=region)

        self._region = region
        self._max_workers = max_workers
        self._services = services or ALL_ORPHAN_SERVICES

    def detect_orphans(
        self,
        stack_prefix: str = "",
        stack_names: list[str] | None = None,
    ) -> OrphanReport:
        """Run orphan detection across all enabled services.

        Args:
            stack_prefix: Only consider stacks with this prefix for the index.
            stack_names: Explicit list of stack names for the index.

        Returns:
            An OrphanReport summarizing all findings.
        """
        report = OrphanReport(
            tool_version=__version__,
            region=self._region,
            timestamp=datetime.now(UTC).isoformat(),
        )

        # Resolve account ID
        report.account_id = self._get_account_id()

        # Build the managed resource index
        cfn_client = self._session.client("cloudformation", config=_BOTO_CONFIG)
        managed_index = build_managed_resource_index(
            cfn_client,
            stack_prefix=stack_prefix,
            stack_names=stack_names,
        )

        # Run orphan detectors in parallel
        all_findings: list[OrphanFinding] = []
        all_errors: list[str] = []
        resources_scanned = 0

        detectors = self._build_detector_tasks(managed_index)

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            future_to_name = {
                executor.submit(task): name
                for name, task in detectors.items()
            }

            for future in as_completed(future_to_name):
                service_name = future_to_name[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                    resources_scanned += len(findings)
                except Exception as e:
                    error_msg = (
                        f"Error running orphan detection for '{service_name}': {e}"
                    )
                    logger.error(error_msg)
                    all_errors.append(error_msg)

        report.resources_scanned = len(managed_index) + len(all_findings)
        report.orphans_found = len(all_findings)
        report.findings = all_findings
        report.errors = all_errors
        report.filters_applied = self._get_applied_filters()

        return report

    def _build_detector_tasks(
        self, managed_index: frozenset[str]
    ) -> dict[str, callable]:
        """Build a mapping of service name → detection callable."""
        tasks: dict[str, callable] = {}

        if "sqs" in self._services:
            collector = SqsSnsOrphanCollector(
                session=self._session, region=self._region
            )
            tasks["sqs"] = lambda c=collector: c.detect_orphaned_queues(managed_index)

        if "sns" in self._services:
            collector = SqsSnsOrphanCollector(
                session=self._session, region=self._region
            )
            tasks["sns"] = lambda c=collector: c.detect_orphaned_topics(managed_index)

        return tasks

    def _get_applied_filters(self) -> list[str]:
        """Return a list of filter descriptions that were applied."""
        filters: list[str] = []
        if "sqs" in self._services:
            filters.append("Excluded FIFO DLQ queues (-dlq.fifo, -deadletter.fifo)")
        if "iam" in self._services:
            filters.append(
                "Excluded service-linked roles, AWS-reserved roles, CDK bootstrap roles"
            )
        if "sg" in self._services:
            filters.append("Excluded default security groups")
        if "lambda" in self._services:
            filters.append("Excluded CDK custom resource handlers")
        return filters

    def _get_account_id(self) -> str:
        """Get the AWS account ID for report metadata."""
        try:
            sts = self._session.client("sts", config=_BOTO_CONFIG)
            return sts.get_caller_identity()["Account"]
        except Exception:
            logger.debug("Could not determine account ID")
            return "unknown"
