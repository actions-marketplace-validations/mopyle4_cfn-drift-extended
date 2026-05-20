"""Extract expected EventBridge state from CloudFormation stack templates.

Handles:
- AWS::Events::Rule resources (event pattern, schedule, targets)

Required IAM permissions (least privilege):
- cloudformation:GetTemplate (already required by CfnCollector)
- cloudformation:DescribeStackResource (already required by CfnCollector)
"""

import logging
from typing import Any

from cfn_drift_extended.collectors.eventbridge_collector import EventBridgeRule
from cfn_drift_extended.comparators.eventbridge_comparator import ExpectedEventBusState

logger = logging.getLogger(__name__)


class CfnEventBridgeExtractor:
    """Extracts expected EventBridge state from CFN template resources."""

    def extract_event_buses(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> list[ExpectedEventBusState]:
        """Extract expected EventBridge state from a stack's template resources.

        Groups rules by their target event bus and returns one
        ExpectedEventBusState per bus.

        Args:
            resources: The Resources section of the CFN template.
            stack_name: Name of the stack.
            physical_ids: Mapping of logical ID → physical resource ID.

        Returns:
            List of ExpectedEventBusState for each event bus referenced.
        """
        # Group rules by event bus name
        bus_rules: dict[str, list[EventBridgeRule]] = {}

        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::Events::Rule":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                continue

            # Determine which bus this rule belongs to
            event_bus_name = self._resolve_bus_name(
                properties.get("EventBusName"), physical_ids
            )

            # Rule name: prefer explicit Name property, fall back to physical ID
            explicit_name = properties.get("Name")
            if isinstance(explicit_name, str):
                rule_name = explicit_name
            else:
                rule_name = physical_ids.get(logical_id, logical_id)

            # Extract event pattern
            event_pattern = properties.get("EventPattern")
            if isinstance(event_pattern, str):
                import json

                try:
                    event_pattern = json.loads(event_pattern)
                except (ValueError, TypeError):
                    event_pattern = None

            # Extract schedule expression
            schedule_expression = properties.get("ScheduleExpression")
            if not isinstance(schedule_expression, str):
                schedule_expression = None

            # Extract target ARNs
            targets = self._extract_target_arns(properties.get("Targets", []))

            # State
            state = properties.get("State", "ENABLED")
            if not isinstance(state, str):
                state = "ENABLED"

            rule = EventBridgeRule(
                name=rule_name,
                state=state,
                event_pattern=event_pattern if isinstance(event_pattern, dict) else None,
                schedule_expression=schedule_expression,
                targets=tuple(targets),
            )

            bus_rules.setdefault(event_bus_name, []).append(rule)

        # Build ExpectedEventBusState for each bus
        results: list[ExpectedEventBusState] = []
        for bus_name, rules in bus_rules.items():
            results.append(
                ExpectedEventBusState(
                    event_bus_name=bus_name,
                    event_bus_arn="",  # ARN resolved at comparison time
                    stack_name=stack_name,
                    rules=tuple(rules),
                )
            )

        return results

    def _resolve_bus_name(
        self, bus_value: Any, physical_ids: dict[str, str]
    ) -> str:
        """Resolve the event bus name from a property value.

        If not specified, defaults to 'default' bus.
        """
        if bus_value is None:
            return "default"
        if isinstance(bus_value, str):
            return bus_value
        if isinstance(bus_value, dict):
            if "Ref" in bus_value:
                ref = bus_value["Ref"]
                if isinstance(ref, str):
                    return physical_ids.get(ref, ref)
            if "Fn::GetAtt" in bus_value:
                get_att = bus_value["Fn::GetAtt"]
                if isinstance(get_att, list) and len(get_att) >= 1:
                    logical_id = get_att[0]
                    return physical_ids.get(logical_id, logical_id)
        return "default"

    def _extract_target_arns(self, targets: Any) -> list[str]:
        """Extract target ARNs from the Targets property."""
        if not isinstance(targets, list):
            return []

        arns: list[str] = []
        for target in targets:
            if not isinstance(target, dict):
                continue
            arn = target.get("Arn")
            if isinstance(arn, str):
                arns.append(arn)
            elif isinstance(arn, dict):
                # Resolve Fn::GetAtt or Ref
                if "Fn::GetAtt" in arn:
                    get_att = arn["Fn::GetAtt"]
                    if isinstance(get_att, list) and len(get_att) >= 2:
                        arns.append(f"{get_att[0]}.{get_att[1]}")
                elif "Ref" in arn:
                    ref = arn["Ref"]
                    if isinstance(ref, str):
                        arns.append(ref)
        return arns
