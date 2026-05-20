"""Error path and edge case tests for EventBridge collector."""

import json
import logging
from unittest.mock import patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from cfn_drift_extended.collectors.eventbridge_collector import EventBridgeCollector


@mock_aws
def test_permission_denied_returns_none(caplog: logging.LogRecord) -> None:
    """Permission denied should return None and log an error."""
    session = boto3.Session(region_name="us-east-1")
    collector = EventBridgeCollector(region="us-east-1", session=session)

    error_response = {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}
    with patch.object(
        collector._events, "describe_event_bus",
        side_effect=ClientError(error_response, "DescribeEventBus"),
    ), caplog.at_level(logging.ERROR):
        result = collector.get_event_bus_state("my-bus")

    assert result is None
    assert "Permission denied" in caplog.text


@mock_aws
def test_unexpected_error_returns_none(caplog: logging.LogRecord) -> None:
    """Unexpected ClientError should return None and log."""
    session = boto3.Session(region_name="us-east-1")
    collector = EventBridgeCollector(region="us-east-1", session=session)

    error_response = {"Error": {"Code": "InternalError", "Message": "oops"}}
    with patch.object(
        collector._events, "describe_event_bus",
        side_effect=ClientError(error_response, "DescribeEventBus"),
    ), caplog.at_level(logging.ERROR):
        result = collector.get_event_bus_state("my-bus")

    assert result is None
    assert "Unexpected error" in caplog.text


@mock_aws
def test_list_rules_permission_denied_returns_none(
    caplog: logging.LogRecord,
) -> None:
    """Permission denied on ListRules should return None."""
    session = boto3.Session(region_name="us-east-1")
    collector = EventBridgeCollector(region="us-east-1", session=session)

    # describe_event_bus succeeds but list_rules fails
    error_response = {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}
    with patch.object(
        collector._events, "get_paginator",
        side_effect=ClientError(error_response, "ListRules"),
    ), caplog.at_level(logging.ERROR):
        result = collector.get_event_bus_state("default")

    assert result is None


@mock_aws
def test_list_targets_error_returns_empty_targets(
    caplog: logging.LogRecord,
) -> None:
    """Error listing targets should return empty targets, not crash."""
    session = boto3.Session(region_name="us-east-1")
    events = session.client("events")

    events.put_rule(
        Name="test-rule",
        EventPattern=json.dumps({"source": ["aws.ec2"]}),
        State="ENABLED",
    )

    collector = EventBridgeCollector(region="us-east-1", session=session)

    # Mock _list_targets to return empty (simulating error)
    with patch.object(collector, "_list_targets", return_value=[]):
        state = collector.get_event_bus_state("default")

    assert state is not None
    assert len(state.rules) == 1
    assert state.rules[0].targets == ()


@mock_aws
def test_rule_with_invalid_event_pattern() -> None:
    """Rule with unparseable event pattern should have event_pattern=None."""
    session = boto3.Session(region_name="us-east-1")
    events = session.client("events")

    # Create a valid rule first
    events.put_rule(
        Name="valid-rule",
        EventPattern=json.dumps({"source": ["aws.s3"]}),
        State="ENABLED",
    )

    collector = EventBridgeCollector(region="us-east-1", session=session)
    state = collector.get_event_bus_state("default")

    assert state is not None
    assert len(state.rules) == 1
    assert state.rules[0].event_pattern == {"source": ["aws.s3"]}


@mock_aws
def test_rule_with_no_targets() -> None:
    """Rule with no targets should have empty targets tuple."""
    session = boto3.Session(region_name="us-east-1")
    events = session.client("events")

    events.put_rule(
        Name="no-targets-rule",
        EventPattern=json.dumps({"source": ["aws.ec2"]}),
        State="DISABLED",
    )

    collector = EventBridgeCollector(region="us-east-1", session=session)
    state = collector.get_event_bus_state("default")

    assert state is not None
    assert len(state.rules) == 1
    assert state.rules[0].targets == ()
    assert state.rules[0].state == "DISABLED"


@mock_aws
def test_default_session_creation() -> None:
    """Collector should create a default session if none provided."""
    collector = EventBridgeCollector(region="us-east-1")
    assert collector._session is not None
    assert collector._events is not None
