"""Unit tests for the EventBridge collector."""

import json

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.eventbridge_collector import EventBridgeCollector


@mock_aws
def test_get_event_bus_state_default_bus() -> None:
    session = boto3.Session(region_name="us-east-1")

    collector = EventBridgeCollector(region="us-east-1", session=session)
    state = collector.get_event_bus_state("default")

    assert state is not None
    assert state.event_bus_name == "default"
    assert state.event_bus_arn != ""
    assert state.rules == ()


@mock_aws
def test_get_event_bus_state_custom_bus() -> None:
    session = boto3.Session(region_name="us-east-1")
    events = session.client("events")
    events.create_event_bus(Name="my-custom-bus")

    collector = EventBridgeCollector(region="us-east-1", session=session)
    state = collector.get_event_bus_state("my-custom-bus")

    assert state is not None
    assert state.event_bus_name == "my-custom-bus"
    assert "my-custom-bus" in state.event_bus_arn


@mock_aws
def test_get_event_bus_state_with_rules() -> None:
    session = boto3.Session(region_name="us-east-1")
    events = session.client("events")

    # Create a rule on the default bus
    events.put_rule(
        Name="my-rule",
        EventPattern=json.dumps({"source": ["aws.ec2"]}),
        State="ENABLED",
    )
    events.put_targets(
        Rule="my-rule",
        Targets=[{"Id": "target-1", "Arn": "arn:aws:lambda:us-east-1:123:function:handler"}],
    )

    collector = EventBridgeCollector(region="us-east-1", session=session)
    state = collector.get_event_bus_state("default")

    assert state is not None
    assert len(state.rules) == 1
    assert state.rules[0].name == "my-rule"
    assert state.rules[0].state == "ENABLED"
    assert state.rules[0].event_pattern == {"source": ["aws.ec2"]}
    assert len(state.rules[0].targets) == 1
    assert "lambda" in state.rules[0].targets[0]


@mock_aws
def test_get_event_bus_state_with_schedule_rule() -> None:
    session = boto3.Session(region_name="us-east-1")
    events = session.client("events")

    events.put_rule(
        Name="scheduled-rule",
        ScheduleExpression="rate(5 minutes)",
        State="ENABLED",
    )

    collector = EventBridgeCollector(region="us-east-1", session=session)
    state = collector.get_event_bus_state("default")

    assert state is not None
    assert len(state.rules) == 1
    assert state.rules[0].name == "scheduled-rule"
    assert state.rules[0].schedule_expression == "rate(5 minutes)"
    assert state.rules[0].event_pattern is None


@mock_aws
def test_get_event_bus_state_nonexistent() -> None:
    session = boto3.Session(region_name="us-east-1")
    collector = EventBridgeCollector(region="us-east-1", session=session)
    state = collector.get_event_bus_state("nonexistent-bus")
    assert state is None


@mock_aws
def test_get_event_bus_state_multiple_rules() -> None:
    session = boto3.Session(region_name="us-east-1")
    events = session.client("events")

    events.put_rule(
        Name="rule-a",
        EventPattern=json.dumps({"source": ["aws.s3"]}),
        State="ENABLED",
    )
    events.put_rule(
        Name="rule-b",
        EventPattern=json.dumps({"source": ["aws.ec2"]}),
        State="DISABLED",
    )

    collector = EventBridgeCollector(region="us-east-1", session=session)
    state = collector.get_event_bus_state("default")

    assert state is not None
    assert len(state.rules) == 2
    rule_names = {r.name for r in state.rules}
    assert rule_names == {"rule-a", "rule-b"}


@mock_aws
def test_returns_immutable_tuples() -> None:
    session = boto3.Session(region_name="us-east-1")
    events = session.client("events")
    events.put_rule(
        Name="test-rule",
        EventPattern=json.dumps({"source": ["aws.ec2"]}),
        State="ENABLED",
    )

    collector = EventBridgeCollector(region="us-east-1", session=session)
    state = collector.get_event_bus_state("default")

    assert state is not None
    assert isinstance(state.rules, tuple)
    assert isinstance(state.rules[0].targets, tuple)
