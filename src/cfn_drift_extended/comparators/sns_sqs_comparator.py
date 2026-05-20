"""Compare expected SNS/SQS state (from CFN) vs actual state (from AWS APIs).

Detects:
- Extra policy statements on SQS queues (added outside CFN)
- Extra policy statements on SNS topics (added outside CFN)
- Extra subscriptions on SNS topics (added outside CFN)

Uses set difference operations for O(n) comparison performance.
"""

import json
import logging
from dataclasses import dataclass, field

from cfn_drift_extended.collectors.sns_sqs_collector import (
    ActualSnsTopicState,
    ActualSqsQueueState,
    SnsSubscription,
)
from cfn_drift_extended.models import DriftFinding, DriftType, ResourceAudit, Severity

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExpectedSqsQueueState:
    """What CloudFormation declares for an SQS queue."""

    queue_url: str
    queue_arn: str
    stack_name: str
    policy: dict | None = None
    redrive_policy: dict | None = None


@dataclass(frozen=True, slots=True)
class ExpectedSnsTopicState:
    """What CloudFormation declares for an SNS topic."""

    topic_arn: str
    stack_name: str
    policy: dict | None = None
    subscriptions: tuple[SnsSubscription, ...] = field(default_factory=tuple)


class SnsSqsComparator:
    """Compares expected vs actual SNS/SQS state to find additive drift.

    Detects:
    - Additions: policy statements or subscriptions present in AWS but not in CFN

    Removals are handled by native CloudFormation drift detection.
    """

    _SQS_RESOURCE_TYPE = "AWS::SQS::Queue"
    _SNS_RESOURCE_TYPE = "AWS::SNS::Topic"

    def compare_sqs(
        self, expected: ExpectedSqsQueueState, actual: ActualSqsQueueState
    ) -> ResourceAudit:
        """Compare a single SQS queue's expected state against its actual state.

        Returns a ResourceAudit with any additive drift findings.
        """
        findings: list[DriftFinding] = []
        findings.extend(self._find_extra_sqs_statements(expected, actual))

        return ResourceAudit(
            resource_type=self._SQS_RESOURCE_TYPE,
            resource_id=expected.queue_arn,
            stack_name=expected.stack_name,
            in_sync=len(findings) == 0,
            findings=tuple(findings),
        )

    def compare_sns(
        self, expected: ExpectedSnsTopicState, actual: ActualSnsTopicState
    ) -> ResourceAudit:
        """Compare a single SNS topic's expected state against its actual state.

        Returns a ResourceAudit with any additive drift findings.
        """
        findings: list[DriftFinding] = []
        findings.extend(self._find_extra_sns_statements(expected, actual))
        findings.extend(self._find_extra_subscriptions(expected, actual))

        return ResourceAudit(
            resource_type=self._SNS_RESOURCE_TYPE,
            resource_id=expected.topic_arn,
            stack_name=expected.stack_name,
            in_sync=len(findings) == 0,
            findings=tuple(findings),
        )

    def _find_extra_sqs_statements(
        self, expected: ExpectedSqsQueueState, actual: ActualSqsQueueState
    ) -> list[DriftFinding]:
        """Find policy statements on the queue that aren't in the CFN template."""
        expected_stmts = self._get_statements(expected.policy)
        actual_stmts = self._get_statements(actual.policy)

        expected_normalized = {
            json.dumps(s, sort_keys=True) for s in expected_stmts
        }
        extra = [
            s for s in actual_stmts
            if json.dumps(s, sort_keys=True) not in expected_normalized
        ]

        return [
            DriftFinding(
                resource_type=self._SQS_RESOURCE_TYPE,
                resource_id=expected.queue_arn,
                stack_name=expected.stack_name,
                drift_type=DriftType.SQS_POLICY_STATEMENT_ADDED,
                severity=Severity.HIGH,
                description=(
                    f"Policy statement with Sid '{stmt.get('Sid', '<no-sid>')}' "
                    f"exists on SQS queue '{expected.queue_arn}' but is not "
                    f"declared in the CloudFormation template for stack "
                    f"'{expected.stack_name}'"
                ),
                expected=expected_stmts,
                actual=actual_stmts,
                extra=stmt,
            )
            for stmt in extra
        ]

    def _find_extra_sns_statements(
        self, expected: ExpectedSnsTopicState, actual: ActualSnsTopicState
    ) -> list[DriftFinding]:
        """Find policy statements on the topic that aren't in the CFN template."""
        expected_stmts = self._get_statements(expected.policy)
        actual_stmts = self._get_statements(actual.policy)

        expected_normalized = {
            json.dumps(s, sort_keys=True) for s in expected_stmts
        }
        extra = [
            s for s in actual_stmts
            if json.dumps(s, sort_keys=True) not in expected_normalized
        ]

        return [
            DriftFinding(
                resource_type=self._SNS_RESOURCE_TYPE,
                resource_id=expected.topic_arn,
                stack_name=expected.stack_name,
                drift_type=DriftType.SNS_POLICY_STATEMENT_ADDED,
                severity=Severity.HIGH,
                description=(
                    f"Policy statement with Sid '{stmt.get('Sid', '<no-sid>')}' "
                    f"exists on SNS topic '{expected.topic_arn}' but is not "
                    f"declared in the CloudFormation template for stack "
                    f"'{expected.stack_name}'"
                ),
                expected=expected_stmts,
                actual=actual_stmts,
                extra=stmt,
            )
            for stmt in extra
        ]

    def _find_extra_subscriptions(
        self, expected: ExpectedSnsTopicState, actual: ActualSnsTopicState
    ) -> list[DriftFinding]:
        """Find subscriptions on the topic that aren't in the CFN template."""
        expected_keys = {
            (s.protocol, s.endpoint) for s in expected.subscriptions
        }
        extra = [
            s for s in actual.subscriptions
            if (s.protocol, s.endpoint) not in expected_keys
        ]

        return [
            DriftFinding(
                resource_type=self._SNS_RESOURCE_TYPE,
                resource_id=expected.topic_arn,
                stack_name=expected.stack_name,
                drift_type=DriftType.SNS_SUBSCRIPTION_ADDED,
                severity=Severity.MEDIUM,
                description=(
                    f"Subscription ({sub.protocol}:{sub.endpoint}) "
                    f"exists on SNS topic '{expected.topic_arn}' but is not "
                    f"declared in the CloudFormation template for stack "
                    f"'{expected.stack_name}'"
                ),
                expected=[(s.protocol, s.endpoint) for s in expected.subscriptions],
                actual=[(s.protocol, s.endpoint) for s in actual.subscriptions],
                extra=(sub.protocol, sub.endpoint),
            )
            for sub in sorted(extra, key=lambda s: (s.protocol, s.endpoint))
        ]

    def _get_statements(self, policy: dict | None) -> list[dict]:
        """Extract Statement list from a policy document."""
        if not policy:
            return []
        stmts = policy.get("Statement", [])
        if not isinstance(stmts, list):
            return []
        return stmts
