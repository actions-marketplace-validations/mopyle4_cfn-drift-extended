"""Collect actual EventBridge state from AWS.

Required IAM permissions (least privilege):
- events:ListRules
- events:ListTargetsByRule
"""

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
class EventBridgeRule:
    """A single EventBridge rule."""

    name: str
    state: str  # ENABLED | DISABLED
    event_pattern: dict | None = None
    schedule_expression: str | None = None
    targets: tuple[str, ...] = field(default_factory=tuple)  # target ARNs


@dataclass(frozen=True, slots=True)
class ActualEventBusState:
    """What actually exists on an EventBridge event bus in AWS.

    Frozen dataclass for immutability and memory efficiency (slots).
    """

    event_bus_name: str
    event_bus_arn: str
    rules: tuple[EventBridgeRule, ...] = field(default_factory=tuple)


class EventBridgeCollector:
    """Collects actual EventBridge state from the AWS Events API.

    Features:
    - Adaptive retry with exponential backoff
    - Pagination on list operations
    - Read-only API calls (least privilege)
    - Returns None on access errors (graceful degradation)
    """

    def __init__(self, region: str, session: boto3.Session | None = None) -> None:
        self._session = session or boto3.Session(region_name=region)
        self._events = self._session.client("events", config=_BOTO_CONFIG)

    def get_event_bus_state(self, event_bus_name: str) -> ActualEventBusState | None:
        """Get the actual state of an EventBridge event bus.

        Returns None if the bus doesn't exist or cannot be accessed.
        """
        # Resolve the event bus ARN
        event_bus_arn = self._get_event_bus_arn(event_bus_name)
        if event_bus_arn is None:
            return None

        rules = self._list_rules(event_bus_name)
        if rules is None:
            return None

        return ActualEventBusState(
            event_bus_name=event_bus_name,
            event_bus_arn=event_bus_arn,
            rules=tuple(rules),
        )

    def _get_event_bus_arn(self, event_bus_name: str) -> str | None:
        """Get the ARN of an event bus."""
        try:
            response = self._events.describe_event_bus(Name=event_bus_name)
            return response.get("Arn", "")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ResourceNotFoundException":
                logger.warning("Event bus '%s' does not exist", event_bus_name)
            elif error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied accessing event bus '%s'. "
                    "Ensure events:DescribeEventBus permission is granted.",
                    event_bus_name,
                )
            else:
                logger.error(
                    "Unexpected error fetching event bus '%s': %s",
                    event_bus_name,
                    error_code,
                )
            return None

    def _list_rules(self, event_bus_name: str) -> list[EventBridgeRule] | None:
        """List all rules on an event bus using pagination."""
        rules: list[EventBridgeRule] = []
        try:
            paginator = self._events.get_paginator("list_rules")
            for page in paginator.paginate(EventBusName=event_bus_name):
                for rule_data in page.get("Rules", []):
                    rule_name = rule_data.get("Name", "")
                    targets = self._list_targets(rule_name, event_bus_name)

                    # Parse event pattern if present
                    event_pattern_str = rule_data.get("EventPattern")
                    event_pattern = None
                    if event_pattern_str:
                        import json

                        try:
                            event_pattern = json.loads(event_pattern_str)
                        except (json.JSONDecodeError, TypeError):
                            event_pattern = None

                    rules.append(
                        EventBridgeRule(
                            name=rule_name,
                            state=rule_data.get("State", "ENABLED"),
                            event_pattern=event_pattern,
                            schedule_expression=rule_data.get("ScheduleExpression"),
                            targets=tuple(targets),
                        )
                    )
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied listing rules for event bus '%s'. "
                    "Ensure events:ListRules permission is granted.",
                    event_bus_name,
                )
            else:
                logger.error(
                    "Unexpected error listing rules for event bus '%s': %s",
                    event_bus_name,
                    error_code,
                )
            return None
        return rules

    def _list_targets(self, rule_name: str, event_bus_name: str) -> list[str]:
        """List target ARNs for a rule using pagination."""
        target_arns: list[str] = []
        try:
            paginator = self._events.get_paginator("list_targets_by_rule")
            for page in paginator.paginate(
                Rule=rule_name, EventBusName=event_bus_name
            ):
                for target in page.get("Targets", []):
                    arn = target.get("Arn", "")
                    if arn:
                        target_arns.append(arn)
        except ClientError as e:
            logger.error(
                "Failed to list targets for rule '%s': %s",
                rule_name,
                e.response["Error"]["Code"],
            )
        return target_arns
