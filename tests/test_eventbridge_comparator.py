"""Unit tests for the EventBridge comparator."""

from cfn_drift_extended.collectors.eventbridge_collector import (
    ActualEventBusState,
    EventBridgeRule,
)
from cfn_drift_extended.comparators.eventbridge_comparator import (
    EventBridgeComparator,
    ExpectedEventBusState,
)
from cfn_drift_extended.models import DriftType, Severity


class TestEventBridgeComparator:
    """Tests for EventBridgeComparator.compare()."""

    def setup_method(self) -> None:
        self.comparator = EventBridgeComparator()

    def test_no_drift_when_in_sync(self) -> None:
        rule = EventBridgeRule(
            name="my-rule",
            state="ENABLED",
            event_pattern={"source": ["aws.ec2"]},
        )
        expected = ExpectedEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
            stack_name="my-stack",
            rules=(rule,),
        )
        actual = ActualEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
            rules=(rule,),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_detects_extra_rule(self) -> None:
        expected_rule = EventBridgeRule(
            name="expected-rule", state="ENABLED"
        )
        extra_rule = EventBridgeRule(
            name="sneaky-rule",
            state="ENABLED",
            event_pattern={"source": ["custom.app"]},
            targets=("arn:aws:lambda:us-east-1:123:function:exfil",),
        )
        expected = ExpectedEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
            stack_name="my-stack",
            rules=(expected_rule,),
        )
        actual = ActualEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
            rules=(expected_rule, extra_rule),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        assert audit.findings[0].drift_type == DriftType.EVENTBRIDGE_RULE_ADDED
        assert audit.findings[0].severity == Severity.MEDIUM
        assert audit.findings[0].extra == "sneaky-rule"

    def test_detects_multiple_extra_rules(self) -> None:
        extra_a = EventBridgeRule(name="extra-a", state="ENABLED")
        extra_b = EventBridgeRule(name="extra-b", state="DISABLED")
        expected = ExpectedEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
            stack_name="my-stack",
        )
        actual = ActualEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
            rules=(extra_a, extra_b),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 2

    def test_no_drift_when_actual_has_fewer_rules(self) -> None:
        """Removals are not flagged (handled by native CFN drift detection)."""
        rule = EventBridgeRule(name="my-rule", state="ENABLED")
        expected = ExpectedEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
            stack_name="my-stack",
            rules=(rule,),
        )
        actual = ActualEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
            rules=(),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_empty_rules_no_false_positives(self) -> None:
        expected = ExpectedEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
            stack_name="my-stack",
        )
        actual = ActualEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_findings_are_sorted_by_name(self) -> None:
        extra_z = EventBridgeRule(name="z-rule", state="ENABLED")
        extra_a = EventBridgeRule(name="a-rule", state="ENABLED")
        extra_m = EventBridgeRule(name="m-rule", state="ENABLED")
        expected = ExpectedEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
            stack_name="my-stack",
        )
        actual = ActualEventBusState(
            event_bus_name="default",
            event_bus_arn="arn:aws:events:us-east-1:123:event-bus/default",
            rules=(extra_z, extra_a, extra_m),
        )
        audit = self.comparator.compare(expected, actual)
        extras = [f.extra for f in audit.findings]
        assert extras == ["a-rule", "m-rule", "z-rule"]
