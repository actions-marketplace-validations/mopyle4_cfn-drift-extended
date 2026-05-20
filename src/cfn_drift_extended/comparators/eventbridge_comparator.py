"""Compare expected EventBridge state (from CFN) vs actual state (from Events API).

Detects:
- Extra rules on CFN-managed event buses (added outside CFN)

Uses set difference operations for O(n) comparison performance.
Rules are compared by name (physical resource ID from CFN).
"""

import logging
from dataclasses import dataclass, field

from cfn_drift_extended.collectors.eventbridge_collector import (
    ActualEventBusState,
    EventBridgeRule,
)
from cfn_drift_extended.models import DriftFinding, DriftType, ResourceAudit, Severity

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExpectedEventBusState:
    """What CloudFormation declares for an EventBridge event bus."""

    event_bus_name: str
    event_bus_arn: str
    stack_name: str
    rules: tuple[EventBridgeRule, ...] = field(default_factory=tuple)


class EventBridgeComparator:
    """Compares expected vs actual EventBridge rules to find additive drift.

    Detects:
    - Additions: rules present on the bus but not in any CFN template

    Removals are handled by native CloudFormation drift detection.
    """

    _RESOURCE_TYPE = "AWS::Events::Rule"

    def compare(
        self, expected: ExpectedEventBusState, actual: ActualEventBusState
    ) -> ResourceAudit:
        """Compare a single event bus's expected state against its actual state.

        Uses set operations for efficient O(n) comparison.
        Returns a ResourceAudit with any additive drift findings.
        """
        findings: list[DriftFinding] = []
        findings.extend(self._find_extra_rules(expected, actual))

        return ResourceAudit(
            resource_type=self._RESOURCE_TYPE,
            resource_id=expected.event_bus_name,
            stack_name=expected.stack_name,
            in_sync=len(findings) == 0,
            findings=tuple(findings),
        )

    def _find_extra_rules(
        self, expected: ExpectedEventBusState, actual: ActualEventBusState
    ) -> list[DriftFinding]:
        """Find rules that exist on the bus but aren't in the CFN template."""
        expected_rule_names = {rule.name for rule in expected.rules}
        extra_rules = [
            rule for rule in actual.rules if rule.name not in expected_rule_names
        ]

        return [
            DriftFinding(
                resource_type=self._RESOURCE_TYPE,
                resource_id=expected.event_bus_name,
                stack_name=expected.stack_name,
                drift_type=DriftType.EVENTBRIDGE_RULE_ADDED,
                severity=Severity.MEDIUM,
                description=(
                    f"Rule '{rule.name}' exists on event bus "
                    f"'{expected.event_bus_name}' but is not declared in the "
                    f"CloudFormation template for stack '{expected.stack_name}'"
                ),
                expected=sorted(expected_rule_names),
                actual=sorted(r.name for r in actual.rules),
                extra=rule.name,
            )
            for rule in sorted(extra_rules, key=lambda r: r.name)
        ]
