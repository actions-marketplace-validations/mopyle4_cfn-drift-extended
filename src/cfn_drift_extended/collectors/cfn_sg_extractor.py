"""Extract expected Security Group state from CloudFormation stack templates.

Handles:
- AWS::EC2::SecurityGroup resources (inline ingress/egress rules)
- AWS::EC2::SecurityGroupIngress standalone resources
- AWS::EC2::SecurityGroupEgress standalone resources

Required IAM permissions (least privilege):
- cloudformation:GetTemplate (already required by CfnCollector)
- cloudformation:DescribeStackResource (already required by CfnCollector)
"""

import logging
from typing import Any

from cfn_drift_extended.collectors.sg_collector import SecurityGroupRule
from cfn_drift_extended.comparators.sg_comparator import ExpectedSecurityGroupState

logger = logging.getLogger(__name__)


class CfnSgExtractor:
    """Extracts expected Security Group state from CFN template resources."""

    def extract_security_groups(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> list[ExpectedSecurityGroupState]:
        """Extract expected SG state from a stack's template resources.

        Args:
            resources: The Resources section of the CFN template.
            stack_name: Name of the stack.
            physical_ids: Mapping of logical ID → physical resource ID.

        Returns:
            List of ExpectedSecurityGroupState for each SG in the template.
        """
        # First pass: collect standalone ingress/egress resources
        standalone_ingress: dict[str, list[SecurityGroupRule]] = {}
        standalone_egress: dict[str, list[SecurityGroupRule]] = {}
        self._collect_standalone_rules(
            resources, standalone_ingress, standalone_egress, physical_ids
        )

        # Second pass: process SecurityGroup resources
        results: list[ExpectedSecurityGroupState] = []
        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::EC2::SecurityGroup":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                continue

            group_id = physical_ids.get(logical_id, f"{stack_name}-{logical_id}")
            group_name = properties.get("GroupName", logical_id)

            ingress_rules = self._extract_inline_rules(
                properties.get("SecurityGroupIngress", [])
            )
            egress_rules = self._extract_inline_rules(
                properties.get("SecurityGroupEgress", [])
            )

            # Merge standalone rules that reference this group
            ingress_rules.extend(standalone_ingress.get(logical_id, []))
            ingress_rules.extend(standalone_ingress.get(group_id, []))
            egress_rules.extend(standalone_egress.get(logical_id, []))
            egress_rules.extend(standalone_egress.get(group_id, []))

            results.append(
                ExpectedSecurityGroupState(
                    group_id=group_id,
                    group_name=group_name if isinstance(group_name, str) else logical_id,
                    stack_name=stack_name,
                    ingress_rules=tuple(ingress_rules),
                    egress_rules=tuple(egress_rules),
                )
            )

        return results

    def _collect_standalone_rules(
        self,
        resources: dict[str, Any],
        standalone_ingress: dict[str, list[SecurityGroupRule]],
        standalone_egress: dict[str, list[SecurityGroupRule]],
        physical_ids: dict[str, str],
    ) -> None:
        """Collect standalone SecurityGroupIngress/Egress resources."""
        for _logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue

            resource_type = resource_def.get("Type")
            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                continue

            if resource_type == "AWS::EC2::SecurityGroupIngress":
                group_ref = self._resolve_group_ref(
                    properties.get("GroupId"), physical_ids
                )
                if group_ref:
                    rule = self._extract_single_rule(properties)
                    if rule:
                        standalone_ingress.setdefault(group_ref, []).append(rule)

            elif resource_type == "AWS::EC2::SecurityGroupEgress":
                group_ref = self._resolve_group_ref(
                    properties.get("GroupId"), physical_ids
                )
                if group_ref:
                    rule = self._extract_single_rule(properties)
                    if rule:
                        standalone_egress.setdefault(group_ref, []).append(rule)

    def _resolve_group_ref(
        self, group_id_value: Any, physical_ids: dict[str, str]
    ) -> str | None:
        """Resolve a GroupId reference to a logical or physical ID."""
        if isinstance(group_id_value, str):
            return group_id_value
        if isinstance(group_id_value, dict):
            if "Ref" in group_id_value:
                return group_id_value["Ref"]
            if "Fn::GetAtt" in group_id_value:
                get_att = group_id_value["Fn::GetAtt"]
                if isinstance(get_att, list) and len(get_att) >= 1:
                    return get_att[0]
        return None

    def _extract_inline_rules(
        self, rules_list: Any
    ) -> list[SecurityGroupRule]:
        """Extract SecurityGroupRule objects from inline rule definitions."""
        if not isinstance(rules_list, list):
            return []

        rules: list[SecurityGroupRule] = []
        for rule_def in rules_list:
            if not isinstance(rule_def, dict):
                continue
            rule = self._extract_single_rule(rule_def)
            if rule:
                rules.append(rule)
        return rules

    def _extract_single_rule(self, rule_def: dict[str, Any]) -> SecurityGroupRule | None:
        """Extract a single SecurityGroupRule from a rule definition."""
        ip_protocol = rule_def.get("IpProtocol", "-1")
        if not isinstance(ip_protocol, str):
            ip_protocol = str(ip_protocol)

        from_port = rule_def.get("FromPort")
        to_port = rule_def.get("ToPort")

        # Normalize port values
        if isinstance(from_port, str):
            try:
                from_port = int(from_port)
            except ValueError:
                from_port = None
        if isinstance(to_port, str):
            try:
                to_port = int(to_port)
            except ValueError:
                to_port = None

        cidr_ipv4 = rule_def.get("CidrIp") or rule_def.get("CidrIpv4")
        cidr_ipv6 = rule_def.get("CidrIpv6")
        source_sg = rule_def.get("SourceSecurityGroupId")
        prefix_list = rule_def.get("SourcePrefixListId")

        # Resolve Ref in source SG
        if isinstance(source_sg, dict) and "Ref" in source_sg:
            source_sg = source_sg["Ref"]

        return SecurityGroupRule(
            ip_protocol=ip_protocol,
            from_port=from_port,
            to_port=to_port,
            cidr_ipv4=cidr_ipv4 if isinstance(cidr_ipv4, str) else None,
            cidr_ipv6=cidr_ipv6 if isinstance(cidr_ipv6, str) else None,
            source_security_group_id=source_sg if isinstance(source_sg, str) else None,
            prefix_list_id=prefix_list if isinstance(prefix_list, str) else None,
        )
