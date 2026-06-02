"""Orphan detection orchestrator.

Coordinates the detection of resources that exist in AWS but are not managed
by any CloudFormation stack. Builds a managed resource index first, then
runs service-specific orphan detectors in parallel.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

from cfn_drift_extended import __version__
from cfn_drift_extended._auditor_utils import build_session, get_account_id
from cfn_drift_extended.collectors._aws import BOTO_CONFIG
from cfn_drift_extended.collectors.cfn_managed_index import (
    ManagedIndex,
    ManagedRef,
    build_managed_resource_index,
)
from cfn_drift_extended.collectors.iam_orphan_collector import IamOrphanCollector
from cfn_drift_extended.collectors.lambda_orphan_collector import (
    LambdaOrphanCollector,
)
from cfn_drift_extended.collectors.provenance_lookup import (
    ProvenanceResolver,
)
from cfn_drift_extended.collectors.sg_orphan_collector import SgOrphanCollector
from cfn_drift_extended.collectors.sqs_sns_orphan_collector import (
    SqsSnsOrphanCollector,
)
from cfn_drift_extended.models import (
    OrphanFinding,
    OrphanReport,
    Provenance,
    Severity,
)

logger = logging.getLogger(__name__)

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
        self._session = build_session(region, profile)
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
        report.account_id = get_account_id(self._session)

        # Build the managed resource index
        cfn_client = self._session.client("cloudformation", config=BOTO_CONFIG)
        managed_index = build_managed_resource_index(
            cfn_client,
            stack_prefix=stack_prefix,
            stack_names=stack_names,
        )

        # Two-tier provenance resolver: bulk tag prefetch + per-resource
        # CFN DescribeStackResources fallback. The reserved
        # aws:cloudformation:stack-name tag does not propagate to all
        # resource types (verified empirically for IAM/SQS/SG/Lambda),
        # so the tag tier alone is insufficient.
        resolver = ProvenanceResolver(self._session, self._region)
        resolver.prefetch_tagged_resources()

        # Run orphan detectors in parallel
        all_findings: list[OrphanFinding] = []
        all_errors: list[str] = []

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
                except Exception as e:
                    error_msg = (
                        f"Error running orphan detection for '{service_name}': {e}"
                    )
                    logger.error(error_msg)
                    all_errors.append(error_msg)

        # Classify provenance via the resolver. For each candidate, ask
        # CloudFormation directly which stack (if any) owns the resource.
        all_findings = self._classify_provenance(
            all_findings, managed_index, resolver, all_errors
        )

        report.resources_scanned = len(managed_index) + len(all_findings)
        report.orphans_found = len(all_findings)
        report.findings = all_findings
        report.errors = all_errors
        report.filters_applied = self._get_applied_filters()

        return report

    def _classify_provenance(
        self,
        findings: list[OrphanFinding],
        managed_index: ManagedIndex,
        resolver: ProvenanceResolver,
        errors: list[str],
    ) -> list[OrphanFinding]:
        """Annotate each finding with provenance, dropping active-stack hits.

        For each candidate orphan:
        - Resolver returns a stack that IS in the managed index → tool gap
          (cross-region, prefix filter, race). Log a warning and exclude.
        - Resolver returns any other stack → CFN orphan from a deleted (or
          out-of-scope) stack. Severity is escalated to HIGH.
        - Resolver returns None → NON_IAC. CloudFormation has no record of
          this resource (and it's not tagged), so it was created outside CFN.
        """
        active_stacks = managed_index.active_stack_names
        classified: list[OrphanFinding] = []

        # Resolve all candidates in parallel — much faster than sequentially
        # calling DescribeStackResources for each.
        owner_map = resolver.resolve_many(
            [f.resource_id for f in findings]
        )

        for finding in findings:
            # Three potential signals, in priority order:
            #   1. Managed-index entry from a DELETE_COMPLETE stack — the
            #      authoritative deleted-stack-residue case (DELETE_SKIPPED
            #      via list-stack-resources on the deleted stack ARN).
            #      CFN stores the PhysicalResourceId, which for IAM is the
            #      role name and for SQS is the queue URL — so we try the
            #      finding's resource_id as-is and also a name extracted
            #      from the ARN/URL.
            deleted_ref = self._find_deleted_ref(finding, managed_index)
            owner = owner_map.get(finding.resource_id)

            if owner is not None and owner.stack_name in active_stacks:
                msg = (
                    f"Skipped {finding.resource_type} {finding.resource_id}: "
                    f"CloudFormation reports it as part of active stack "
                    f"'{owner.stack_name}' (managed index gap, likely "
                    f"cross-region or prefix filter)"
                )
                logger.warning(msg)
                errors.append(msg)
                continue

            provenance: Provenance
            originating_stack: str | None = None
            severity = finding.severity

            if deleted_ref is not None:
                provenance = Provenance.CFN_ORPHAN_DELETED_STACK
                originating_stack = deleted_ref.stack_name
                severity = Severity.HIGH
            elif owner is not None:
                provenance = Provenance.CFN_ORPHAN_DELETED_STACK
                originating_stack = owner.stack_name
                severity = Severity.HIGH
            else:
                provenance = Provenance.NON_IAC

            classified.append(
                finding.model_copy(
                    update={
                        "provenance": provenance,
                        "originating_stack_name": originating_stack,
                        "severity": severity,
                    }
                )
            )

        return classified

    @staticmethod
    def _find_deleted_ref(
        finding: OrphanFinding, managed_index: ManagedIndex
    ) -> ManagedRef | None:
        """Match a finding to a managed-index ref under any id form.

        CloudFormation's PhysicalResourceId varies by service:
        - IAM Role: role name (e.g., 'my-role')
        - SQS Queue: queue URL (e.g., 'https://sqs.../my-q')
        - SNS Topic: topic ARN
        - Lambda Function: function name
        - EC2 SecurityGroup: group id
        Detectors generally use the most specific identifier (usually ARN).
        Build a small set of candidate keys and check each against the index.
        """
        rid = finding.resource_id
        candidates: list[str] = [rid]

        if rid.startswith("arn:"):
            # IAM role: arn:aws:iam::ACCT:role/NAME -> NAME
            if ":role/" in rid:
                candidates.append(rid.rsplit("/", 1)[-1])
            # SQS queue: arn:aws:sqs:REGION:ACCT:QUEUENAME -> URL form
            elif rid.startswith("arn:aws:sqs:") or ":sqs:" in rid:
                parts = rid.split(":")
                if len(parts) >= 6:
                    region, account, queue_name = parts[3], parts[4], parts[5]
                    candidates.append(
                        f"https://sqs.{region}.amazonaws.com/{account}/{queue_name}"
                    )
                    candidates.append(queue_name)
            # Lambda function: arn:aws:lambda:REGION:ACCT:function:NAME
            elif ":function:" in rid:
                candidates.append(rid.split(":function:", 1)[1])

        for key in candidates:
            ref = managed_index.get_ref(key)
            if ref is not None:
                return ref
        return None

    def _build_detector_tasks(
        self, managed_index: ManagedIndex | frozenset[str]
    ) -> dict[str, callable]:
        """Build a mapping of service name → detection callable."""
        tasks: dict[str, callable] = {}

        if "iam" in self._services:
            iam_collector = IamOrphanCollector(
                session=self._session, region=self._region
            )
            tasks["iam"] = (
                lambda collector=iam_collector: collector.detect_orphaned_roles(
                    managed_index
                )
            )

        if "sg" in self._services:
            sg_collector = SgOrphanCollector(
                session=self._session, region=self._region
            )
            tasks["sg"] = (
                lambda collector=sg_collector: (
                    collector.detect_orphaned_security_groups(managed_index)
                )
            )

        if "lambda" in self._services:
            lambda_collector = LambdaOrphanCollector(
                session=self._session, region=self._region
            )
            tasks["lambda"] = (
                lambda collector=lambda_collector: (
                    collector.detect_orphaned_functions(managed_index)
                )
            )

        if "sqs" in self._services:
            sqs_collector = SqsSnsOrphanCollector(
                session=self._session, region=self._region
            )
            tasks["sqs"] = (
                lambda collector=sqs_collector: collector.detect_orphaned_queues(
                    managed_index
                )
            )

        if "sns" in self._services:
            sns_collector = SqsSnsOrphanCollector(
                session=self._session, region=self._region
            )
            tasks["sns"] = (
                lambda collector=sns_collector: collector.detect_orphaned_topics(
                    managed_index
                )
            )

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
