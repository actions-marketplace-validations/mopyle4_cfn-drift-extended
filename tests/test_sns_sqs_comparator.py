"""Unit tests for the SNS/SQS comparator."""

from cfn_drift_extended.collectors.sns_sqs_collector import (
    ActualSnsTopicState,
    ActualSqsQueueState,
    SnsSubscription,
)
from cfn_drift_extended.comparators.sns_sqs_comparator import (
    ExpectedSnsTopicState,
    ExpectedSqsQueueState,
    SnsSqsComparator,
)
from cfn_drift_extended.models import DriftType, Severity


class TestSnsSqsComparatorSqs:
    """Tests for SnsSqsComparator.compare_sqs()."""

    def setup_method(self) -> None:
        self.comparator = SnsSqsComparator()

    def test_no_drift_when_in_sync(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "stmt1", "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}
            ],
        }
        expected = ExpectedSqsQueueState(
            queue_url="https://sqs.us-east-1.amazonaws.com/123/q",
            queue_arn="arn:aws:sqs:us-east-1:123:q",
            stack_name="my-stack",
            policy=policy,
        )
        actual = ActualSqsQueueState(
            queue_url="https://sqs.us-east-1.amazonaws.com/123/q",
            queue_arn="arn:aws:sqs:us-east-1:123:q",
            policy=policy,
        )
        audit = self.comparator.compare_sqs(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_detects_extra_policy_statement(self) -> None:
        expected_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "stmt1", "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}
            ],
        }
        actual_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "stmt1", "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"},
                {"Sid": "sneaky", "Effect": "Allow", "Action": "sqs:*", "Resource": "*"},
            ],
        }
        expected = ExpectedSqsQueueState(
            queue_url="https://sqs.us-east-1.amazonaws.com/123/q",
            queue_arn="arn:aws:sqs:us-east-1:123:q",
            stack_name="my-stack",
            policy=expected_policy,
        )
        actual = ActualSqsQueueState(
            queue_url="https://sqs.us-east-1.amazonaws.com/123/q",
            queue_arn="arn:aws:sqs:us-east-1:123:q",
            policy=actual_policy,
        )
        audit = self.comparator.compare_sqs(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        assert audit.findings[0].drift_type == DriftType.SQS_POLICY_STATEMENT_ADDED
        assert audit.findings[0].severity == Severity.HIGH
        assert audit.findings[0].extra["Sid"] == "sneaky"

    def test_no_drift_when_no_policies(self) -> None:
        expected = ExpectedSqsQueueState(
            queue_url="https://sqs.us-east-1.amazonaws.com/123/q",
            queue_arn="arn:aws:sqs:us-east-1:123:q",
            stack_name="my-stack",
            policy=None,
        )
        actual = ActualSqsQueueState(
            queue_url="https://sqs.us-east-1.amazonaws.com/123/q",
            queue_arn="arn:aws:sqs:us-east-1:123:q",
            policy=None,
        )
        audit = self.comparator.compare_sqs(expected, actual)
        assert audit.in_sync is True

    def test_detects_policy_added_when_expected_none(self) -> None:
        actual_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "new", "Effect": "Allow", "Action": "sqs:*", "Resource": "*"}
            ],
        }
        expected = ExpectedSqsQueueState(
            queue_url="https://sqs.us-east-1.amazonaws.com/123/q",
            queue_arn="arn:aws:sqs:us-east-1:123:q",
            stack_name="my-stack",
            policy=None,
        )
        actual = ActualSqsQueueState(
            queue_url="https://sqs.us-east-1.amazonaws.com/123/q",
            queue_arn="arn:aws:sqs:us-east-1:123:q",
            policy=actual_policy,
        )
        audit = self.comparator.compare_sqs(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        assert audit.findings[0].drift_type == DriftType.SQS_POLICY_STATEMENT_ADDED

    def test_multiple_extra_statements(self) -> None:
        actual_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "extra1", "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"},
                {
                    "Sid": "extra2",
                    "Effect": "Allow",
                    "Action": "sqs:ReceiveMessage",
                    "Resource": "*",
                },
            ],
        }
        expected = ExpectedSqsQueueState(
            queue_url="https://sqs.us-east-1.amazonaws.com/123/q",
            queue_arn="arn:aws:sqs:us-east-1:123:q",
            stack_name="my-stack",
            policy=None,
        )
        actual = ActualSqsQueueState(
            queue_url="https://sqs.us-east-1.amazonaws.com/123/q",
            queue_arn="arn:aws:sqs:us-east-1:123:q",
            policy=actual_policy,
        )
        audit = self.comparator.compare_sqs(expected, actual)
        assert len(audit.findings) == 2


class TestSnsSqsComparatorSns:
    """Tests for SnsSqsComparator.compare_sns()."""

    def setup_method(self) -> None:
        self.comparator = SnsSqsComparator()

    def test_no_drift_when_in_sync(self) -> None:
        sub = SnsSubscription(
            protocol="email", endpoint="test@example.com", subscription_arn="arn:sub:1"
        )
        expected = ExpectedSnsTopicState(
            topic_arn="arn:aws:sns:us-east-1:123:topic",
            stack_name="my-stack",
            subscriptions=(sub,),
        )
        actual = ActualSnsTopicState(
            topic_arn="arn:aws:sns:us-east-1:123:topic",
            subscriptions=(sub,),
        )
        audit = self.comparator.compare_sns(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_detects_extra_subscription(self) -> None:
        expected_sub = SnsSubscription(
            protocol="email", endpoint="expected@example.com", subscription_arn="arn:sub:1"
        )
        extra_sub = SnsSubscription(
            protocol="sqs",
            endpoint="arn:aws:sqs:us-east-1:123:sneaky-queue",
            subscription_arn="arn:sub:2",
        )
        expected = ExpectedSnsTopicState(
            topic_arn="arn:aws:sns:us-east-1:123:topic",
            stack_name="my-stack",
            subscriptions=(expected_sub,),
        )
        actual = ActualSnsTopicState(
            topic_arn="arn:aws:sns:us-east-1:123:topic",
            subscriptions=(expected_sub, extra_sub),
        )
        audit = self.comparator.compare_sns(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        assert audit.findings[0].drift_type == DriftType.SNS_SUBSCRIPTION_ADDED
        assert audit.findings[0].severity == Severity.MEDIUM

    def test_detects_extra_sns_policy_statement(self) -> None:
        expected_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "default", "Effect": "Allow", "Action": "sns:Publish", "Resource": "*"}
            ],
        }
        actual_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "default", "Effect": "Allow", "Action": "sns:Publish", "Resource": "*"},
                {"Sid": "sneaky", "Effect": "Allow", "Action": "sns:*", "Resource": "*"},
            ],
        }
        expected = ExpectedSnsTopicState(
            topic_arn="arn:aws:sns:us-east-1:123:topic",
            stack_name="my-stack",
            policy=expected_policy,
        )
        actual = ActualSnsTopicState(
            topic_arn="arn:aws:sns:us-east-1:123:topic",
            policy=actual_policy,
        )
        audit = self.comparator.compare_sns(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        assert audit.findings[0].drift_type == DriftType.SNS_POLICY_STATEMENT_ADDED
        assert audit.findings[0].severity == Severity.HIGH

    def test_no_drift_empty_subscriptions(self) -> None:
        expected = ExpectedSnsTopicState(
            topic_arn="arn:aws:sns:us-east-1:123:topic",
            stack_name="my-stack",
        )
        actual = ActualSnsTopicState(
            topic_arn="arn:aws:sns:us-east-1:123:topic",
        )
        audit = self.comparator.compare_sns(expected, actual)
        assert audit.in_sync is True

    def test_multiple_findings_policy_and_subscription(self) -> None:
        actual_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "extra", "Effect": "Allow", "Action": "sns:*", "Resource": "*"}
            ],
        }
        extra_sub = SnsSubscription(
            protocol="lambda",
            endpoint="arn:aws:lambda:us-east-1:123:function:sneaky",
            subscription_arn="arn:sub:1",
        )
        expected = ExpectedSnsTopicState(
            topic_arn="arn:aws:sns:us-east-1:123:topic",
            stack_name="my-stack",
            policy=None,
        )
        actual = ActualSnsTopicState(
            topic_arn="arn:aws:sns:us-east-1:123:topic",
            policy=actual_policy,
            subscriptions=(extra_sub,),
        )
        audit = self.comparator.compare_sns(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 2
        drift_types = {f.drift_type for f in audit.findings}
        assert DriftType.SNS_POLICY_STATEMENT_ADDED in drift_types
        assert DriftType.SNS_SUBSCRIPTION_ADDED in drift_types
