"""Extract expected SNS/SQS state from CloudFormation stack templates.

Handles:
- AWS::SQS::Queue resources
- AWS::SQS::QueuePolicy resources (resource policies)
- AWS::SNS::Topic resources
- AWS::SNS::TopicPolicy resources (resource policies)
- AWS::SNS::Subscription resources

Required IAM permissions (least privilege):
- cloudformation:GetTemplate (already required by CfnCollector)
- cloudformation:DescribeStackResource (already required by CfnCollector)
"""

import logging
from typing import Any

from cfn_drift_extended.collectors.sns_sqs_collector import SnsSubscription
from cfn_drift_extended.comparators.sns_sqs_comparator import (
    ExpectedSnsTopicState,
    ExpectedSqsQueueState,
)

logger = logging.getLogger(__name__)


class CfnSnsSqsExtractor:
    """Extracts expected SNS/SQS state from CFN template resources."""

    def extract_sqs_queues(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> list[ExpectedSqsQueueState]:
        """Extract expected SQS queue state from a stack's template resources.

        Args:
            resources: The Resources section of the CFN template.
            stack_name: Name of the stack.
            physical_ids: Mapping of logical ID → physical resource ID.

        Returns:
            List of ExpectedSqsQueueState for each queue in the template.
        """
        # Collect queue policies (separate resources that target queues)
        queue_policies: dict[str, dict] = {}
        self._collect_queue_policies(resources, queue_policies, physical_ids)

        results: list[ExpectedSqsQueueState] = []
        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::SQS::Queue":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                properties = {}

            # Physical ID for SQS queues is the queue URL
            queue_url = physical_ids.get(logical_id, "")
            # Queue ARN is typically derived from the URL or physical_ids
            queue_arn = self._derive_queue_arn(queue_url, logical_id, stack_name)

            # Redrive policy from queue properties
            redrive_policy = properties.get("RedrivePolicy")
            if isinstance(redrive_policy, str):
                import json

                try:
                    redrive_policy = json.loads(redrive_policy)
                except (ValueError, TypeError):
                    redrive_policy = None

            # Policy from QueuePolicy resource
            policy = queue_policies.get(logical_id) or queue_policies.get(queue_url)

            results.append(
                ExpectedSqsQueueState(
                    queue_url=queue_url,
                    queue_arn=queue_arn,
                    stack_name=stack_name,
                    policy=policy,
                    redrive_policy=redrive_policy if isinstance(redrive_policy, dict) else None,
                )
            )

        return results

    def extract_sns_topics(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> list[ExpectedSnsTopicState]:
        """Extract expected SNS topic state from a stack's template resources.

        Args:
            resources: The Resources section of the CFN template.
            stack_name: Name of the stack.
            physical_ids: Mapping of logical ID → physical resource ID.

        Returns:
            List of ExpectedSnsTopicState for each topic in the template.
        """
        # Collect topic policies
        topic_policies: dict[str, dict] = {}
        self._collect_topic_policies(resources, topic_policies, physical_ids)

        # Collect subscriptions
        topic_subscriptions: dict[str, list[SnsSubscription]] = {}
        self._collect_subscriptions(resources, topic_subscriptions, physical_ids)

        results: list[ExpectedSnsTopicState] = []
        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::SNS::Topic":
                continue

            # Physical ID for SNS topics is the topic ARN
            topic_arn = physical_ids.get(logical_id, "")

            policy = topic_policies.get(logical_id) or topic_policies.get(topic_arn)
            subs = (
                topic_subscriptions.get(logical_id, [])
                + topic_subscriptions.get(topic_arn, [])
            )

            results.append(
                ExpectedSnsTopicState(
                    topic_arn=topic_arn,
                    stack_name=stack_name,
                    policy=policy,
                    subscriptions=tuple(subs),
                )
            )

        return results

    def _collect_queue_policies(
        self,
        resources: dict[str, Any],
        queue_policies: dict[str, dict],
        physical_ids: dict[str, str],
    ) -> None:
        """Collect AWS::SQS::QueuePolicy resources and map to target queues."""
        for _logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::SQS::QueuePolicy":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                continue

            policy_doc = properties.get("PolicyDocument")
            if not isinstance(policy_doc, dict):
                continue

            # Resolve intrinsics in the policy document
            resolved_policy = self._resolve_intrinsics(policy_doc, physical_ids)

            queues = properties.get("Queues", [])
            if not isinstance(queues, list):
                continue

            for queue_ref in queues:
                queue_key = self._resolve_ref(queue_ref, physical_ids)
                if queue_key:
                    # Store under both logical ID and physical ID
                    queue_policies[queue_key] = resolved_policy
                    # If queue_key is a logical ID, also store under its physical ID
                    if queue_key in physical_ids:
                        queue_policies[physical_ids[queue_key]] = resolved_policy

    def _collect_topic_policies(
        self,
        resources: dict[str, Any],
        topic_policies: dict[str, dict],
        physical_ids: dict[str, str],
    ) -> None:
        """Collect AWS::SNS::TopicPolicy resources and map to target topics."""
        for _logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::SNS::TopicPolicy":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                continue

            policy_doc = properties.get("PolicyDocument")
            if not isinstance(policy_doc, dict):
                continue

            # Resolve intrinsics in the policy document
            resolved_policy = self._resolve_intrinsics(policy_doc, physical_ids)

            topics = properties.get("Topics", [])
            if not isinstance(topics, list):
                continue

            for topic_ref in topics:
                topic_key = self._resolve_ref(topic_ref, physical_ids)
                if topic_key:
                    # Store under both logical ID and physical ID
                    topic_policies[topic_key] = resolved_policy
                    # If topic_key is a logical ID, also store under its physical ID
                    if topic_key in physical_ids:
                        topic_policies[physical_ids[topic_key]] = resolved_policy

    def _collect_subscriptions(
        self,
        resources: dict[str, Any],
        topic_subscriptions: dict[str, list[SnsSubscription]],
        physical_ids: dict[str, str],
    ) -> None:
        """Collect AWS::SNS::Subscription resources and map to target topics."""
        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::SNS::Subscription":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                continue

            topic_ref = self._resolve_ref(properties.get("TopicArn"), physical_ids)
            protocol = properties.get("Protocol", "")
            endpoint = properties.get("Endpoint", "")

            if not topic_ref or not protocol or not endpoint:
                continue

            # Resolve endpoint through physical_ids if it's a Ref or GetAtt
            if isinstance(endpoint, dict):
                resolved_endpoint = self._resolve_intrinsics(endpoint, physical_ids)
                endpoint = resolved_endpoint if isinstance(resolved_endpoint, str) else ""

            sub = SnsSubscription(
                protocol=protocol if isinstance(protocol, str) else "",
                endpoint=endpoint if isinstance(endpoint, str) else "",
                subscription_arn=physical_ids.get(logical_id, ""),
            )

            # Store under both logical ID and physical ID of the topic
            topic_subscriptions.setdefault(topic_ref, []).append(sub)
            if topic_ref in physical_ids:
                physical_topic = physical_ids[topic_ref]
                topic_subscriptions.setdefault(physical_topic, []).append(sub)

    def _resolve_ref(self, value: Any, physical_ids: dict[str, str] | None = None) -> str | None:
        """Resolve a Ref or plain string value, optionally through physical_ids."""
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            if "Ref" in value:
                ref = value["Ref"]
                if isinstance(ref, str):
                    # If physical_ids provided, resolve to physical ID
                    if physical_ids and ref in physical_ids:
                        return physical_ids[ref]
                    return ref
            if "Fn::GetAtt" in value:
                get_att = value["Fn::GetAtt"]
                if isinstance(get_att, list) and len(get_att) >= 1:
                    logical_id = get_att[0]
                    if isinstance(logical_id, str):
                        # For GetAtt, we can't resolve the attribute but we
                        # can return the physical ID of the resource
                        if physical_ids and logical_id in physical_ids:
                            return physical_ids[logical_id]
                        return logical_id
        return None

    def _resolve_intrinsics(self, obj: Any, physical_ids: dict[str, str]) -> Any:
        """Recursively resolve Ref, Fn::GetAtt, and Fn::Sub intrinsics."""
        if isinstance(obj, dict):
            if "Ref" in obj and len(obj) == 1:
                ref = obj["Ref"]
                if isinstance(ref, str) and ref in physical_ids:
                    return physical_ids[ref]
                return obj
            if "Fn::GetAtt" in obj and len(obj) == 1:
                get_att = obj["Fn::GetAtt"]
                resolved = self._resolve_get_att(get_att, physical_ids)
                if resolved:
                    return resolved
                return obj
            if "Fn::Sub" in obj and len(obj) == 1:
                sub_value = obj["Fn::Sub"]
                if isinstance(sub_value, str):
                    resolved = self._resolve_sub(sub_value, physical_ids)
                    if resolved != sub_value:
                        return resolved
                return obj
            return {k: self._resolve_intrinsics(v, physical_ids) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._resolve_intrinsics(item, physical_ids) for item in obj]
        return obj

    def _resolve_sub(self, template: str, physical_ids: dict[str, str]) -> str:
        """Resolve ${AWS::*} pseudo-parameters and ${Resource} refs in Fn::Sub."""
        import re

        # Resolve ${LogicalId} references
        def replace_ref(match: re.Match) -> str:
            ref_name = match.group(1)
            if ref_name in physical_ids:
                return physical_ids[ref_name]
            # Handle pseudo-parameters by looking for them in physical_ids
            # (the auditor may have resolved them)
            return match.group(0)

        result = re.sub(r'\$\{([^}]+)\}', replace_ref, template)
        return result

    def _resolve_get_att(
        self, get_att: Any, physical_ids: dict[str, str]
    ) -> str | None:
        """Resolve Fn::GetAtt to a value using physical_ids.

        Handles both list format ["Resource", "Attr"] and string format "Resource.Attr".
        For SQS queues, GetAtt with .Arn derives the ARN from the queue URL.
        """
        logical_id: str | None = None
        attr: str | None = None

        if isinstance(get_att, list) and len(get_att) >= 2:
            logical_id = get_att[0] if isinstance(get_att[0], str) else None
            attr = get_att[1] if isinstance(get_att[1], str) else None
        elif isinstance(get_att, str) and "." in get_att:
            parts = get_att.split(".", 1)
            logical_id = parts[0]
            attr = parts[1]

        if not logical_id or logical_id not in physical_ids:
            return None

        physical_id = physical_ids[logical_id]

        # For .Arn attribute on SQS queues (physical ID is URL, need ARN)
        if attr == "Arn" and "sqs" in physical_id and "amazonaws.com" in physical_id:
            return self._derive_queue_arn(physical_id, logical_id, "")

        # For other resources, physical ID is often the ARN itself
        return physical_id

    def _derive_queue_arn(
        self, queue_url: str, logical_id: str, stack_name: str
    ) -> str:
        """Derive a queue ARN from the queue URL or logical ID."""
        if queue_url and "amazonaws.com" in queue_url:
            # URL format: https://sqs.{region}.amazonaws.com/{account}/{name}
            parts = queue_url.rstrip("/").split("/")
            if len(parts) >= 5:
                region = queue_url.split(".")[1] if "." in queue_url else "us-east-1"
                account = parts[-2]
                name = parts[-1]
                return f"arn:aws:sqs:{region}:{account}:{name}"
        return f"{stack_name}-{logical_id}"
