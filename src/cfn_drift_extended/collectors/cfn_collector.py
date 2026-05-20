"""Extract expected IAM state from CloudFormation stack templates.

Handles nested stacks (recursive), intrinsic function resolution for
ManagedPolicyArns, and proper retry/backoff configuration.

Required IAM permissions (least privilege):
- cloudformation:ListStacks
- cloudformation:GetTemplate
- cloudformation:DescribeStackResource
- cloudformation:ListStackResources
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Only scan stacks in terminal successful states
_ACTIVE_STACK_STATUSES = (
    "CREATE_COMPLETE",
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE",
    "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE",
)

# Retry configuration with adaptive mode and jitter
_BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
)


@dataclass(frozen=True, slots=True)
class ExpectedRoleState:
    """What CloudFormation declares for an IAM role.

    Frozen dataclass for immutability and memory efficiency (slots).
    """

    role_name: str
    logical_id: str
    stack_name: str
    inline_policy_names: tuple[str, ...] = field(default_factory=tuple)
    inline_policy_documents: tuple[tuple[str, dict[str, Any]], ...] = field(
        default_factory=tuple
    )
    managed_policy_arns: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class _ExternalPolicies:
    """Policies from AWS::IAM::Policy and AWS::IAM::ManagedPolicy resources.

    These are separate CFN resources that reference a role, rather than
    being declared inline on the role's Properties. CDK uses this pattern
    extensively for default policies.
    """

    inline_policy_names: list[str] = field(default_factory=list)
    inline_policy_documents: list[tuple[str, dict[str, Any]]] = field(
        default_factory=list
    )
    managed_policy_arns: list[str] = field(default_factory=list)


class CfnCollector:
    """Collects expected resource state from CloudFormation stack templates.

    Features:
    - Recursive nested stack traversal
    - Intrinsic function resolution for ManagedPolicyArns
    - Adaptive retry with exponential backoff
    - Read-only API calls (least privilege)

    Design note: We use TemplateStage="Processed" which means Conditions
    have been evaluated and excluded resources won't appear. This is
    intentional — we only want to compare against resources that CFN
    actually deployed.
    """

    def __init__(self, region: str, session: boto3.Session | None = None) -> None:
        self._session = session or boto3.Session(region_name=region)
        self._cfn = self._session.client("cloudformation", config=_BOTO_CONFIG)

    def list_stacks_by_prefix(
        self,
        prefix: str,
        stack_names: list[str] | None = None,
        tag_filter: dict[str, str] | None = None,
    ) -> list[str]:
        """List active stack names matching the given prefix or exact names.

        Args:
            prefix: Stack name prefix to match.
            stack_names: Optional list of exact stack names (overrides prefix).
            tag_filter: Optional tag key-value pairs to filter by.

        Uses pagination to handle accounts with many stacks efficiently.
        Filters server-side by status, client-side by prefix/name/tags.
        """
        if stack_names:
            return self._validate_stack_names(stack_names)

        matched: list[str] = []
        paginator = self._cfn.get_paginator("list_stacks")

        try:
            for page in paginator.paginate(
                StackStatusFilter=list(_ACTIVE_STACK_STATUSES)
            ):
                for summary in page.get("StackSummaries", []):
                    name = summary["StackName"]
                    if name.startswith(prefix):
                        matched.append(name)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied listing stacks. "
                    "Ensure cloudformation:ListStacks permission is granted."
                )
            raise

        # Apply tag filter if specified
        if tag_filter and matched:
            matched = self._filter_by_tags(matched, tag_filter)

        logger.info("Found %d stacks matching prefix '%s'", len(matched), prefix)
        return matched

    def get_iam_roles_from_stack(
        self, stack_name: str, *, recurse_nested: bool = True
    ) -> list[ExpectedRoleState]:
        """Extract expected IAM role state from a stack's template.

        Args:
            stack_name: The stack to inspect.
            recurse_nested: If True, also inspect nested stacks recursively.

        Returns an empty list if the template cannot be retrieved or parsed.
        """
        roles: list[ExpectedRoleState] = []
        self._collect_roles_recursive(stack_name, roles, recurse_nested, depth=0)
        return roles

    def _collect_roles_recursive(
        self,
        stack_name: str,
        roles: list[ExpectedRoleState],
        recurse_nested: bool,
        depth: int,
    ) -> None:
        """Recursively collect IAM roles from a stack and its nested stacks."""
        if depth > 10:
            logger.warning(
                "Nested stack depth exceeded 10 for '%s' — stopping recursion",
                stack_name,
            )
            return

        template_body = self._get_template(stack_name)
        if not template_body:
            return

        resources = template_body.get("Resources", {})
        if not isinstance(resources, dict):
            logger.warning("Stack '%s' has invalid Resources section", stack_name)
            return

        # First pass: collect all AWS::IAM::Policy and AWS::IAM::ManagedPolicy
        # resources so we can associate them with roles
        external_policies = self._collect_external_policies(resources, stack_name)

        # Second pass: process roles and nested stacks
        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue

            resource_type = resource_def.get("Type")

            # Handle nested stacks
            if resource_type == "AWS::CloudFormation::Stack" and recurse_nested:
                nested_stack_name = self._resolve_nested_stack_name(
                    logical_id, stack_name
                )
                if nested_stack_name:
                    self._collect_roles_recursive(
                        nested_stack_name, roles, recurse_nested, depth + 1
                    )
                continue

            if resource_type != "AWS::IAM::Role":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                logger.warning(
                    "Role '%s' in stack '%s' has invalid Properties",
                    logical_id,
                    stack_name,
                )
                continue

            role_name = self._resolve_role_name(logical_id, stack_name, properties)

            # Inline policies from the role's Policies property
            inline_names = self._extract_inline_policy_names(properties)
            inline_docs = self._extract_inline_policy_documents(properties, stack_name)

            # Also include policies from separate AWS::IAM::Policy resources
            # that reference this role
            ext = external_policies.get(logical_id, _ExternalPolicies())
            all_inline_names = list(inline_names) + list(ext.inline_policy_names)
            all_inline_docs = list(inline_docs) + list(ext.inline_policy_documents)

            # Managed policy ARNs from the role + external ManagedPolicy resources
            managed_arns = self._resolve_managed_policy_arns(
                logical_id, stack_name, properties
            )
            all_managed_arns = list(managed_arns) + list(ext.managed_policy_arns)

            roles.append(
                ExpectedRoleState(
                    role_name=role_name,
                    logical_id=logical_id,
                    stack_name=stack_name,
                    inline_policy_names=tuple(all_inline_names),
                    inline_policy_documents=tuple(all_inline_docs),
                    managed_policy_arns=tuple(all_managed_arns),
                )
            )

        logger.debug(
            "Collected %d IAM roles from stack '%s' (depth=%d)",
            len(roles),
            stack_name,
            depth,
        )

    def _collect_external_policies(
        self, resources: dict[str, Any], stack_name: str
    ) -> dict[str, _ExternalPolicies]:
        """Scan for AWS::IAM::Policy and AWS::IAM::ManagedPolicy resources.

        CDK generates these as separate resources that reference roles via
        the Roles property. We need to associate them with their target roles
        to avoid false-positive drift findings.

        Returns a dict mapping role logical IDs to their external policies.
        """
        role_policies: dict[str, _ExternalPolicies] = {}

        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue

            resource_type = resource_def.get("Type")
            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                continue

            if resource_type == "AWS::IAM::Policy":
                self._process_iam_policy_resource(
                    properties, role_policies, stack_name
                )
            elif resource_type == "AWS::IAM::ManagedPolicy":
                self._process_managed_policy_resource(
                    logical_id, properties, role_policies, stack_name
                )

        return role_policies

    def _process_iam_policy_resource(
        self,
        properties: dict[str, Any],
        role_policies: dict[str, _ExternalPolicies],
        stack_name: str,
    ) -> None:
        """Process an AWS::IAM::Policy resource and associate with target roles.

        AWS::IAM::Policy creates an inline policy on the referenced roles.
        """
        policy_name = properties.get("PolicyName")
        if not isinstance(policy_name, str):
            return

        policy_document = properties.get("PolicyDocument")
        roles_refs = properties.get("Roles", [])
        if not isinstance(roles_refs, list):
            return

        # Extract role logical IDs from the Roles array
        target_role_ids = self._extract_role_refs(roles_refs)

        for role_logical_id in target_role_ids:
            if role_logical_id not in role_policies:
                role_policies[role_logical_id] = _ExternalPolicies()

            role_policies[role_logical_id].inline_policy_names.append(policy_name)

            if isinstance(policy_document, dict):
                resolved_doc = self._resolve_intrinsics_in_doc(
                    policy_document, stack_name
                )
                role_policies[role_logical_id].inline_policy_documents.append(
                    (policy_name, resolved_doc)
                )

    def _process_managed_policy_resource(
        self,
        logical_id: str,
        properties: dict[str, Any],
        role_policies: dict[str, _ExternalPolicies],
        stack_name: str,
    ) -> None:
        """Process an AWS::IAM::ManagedPolicy resource and associate with target roles.

        AWS::IAM::ManagedPolicy creates a managed policy and attaches it to roles.
        """
        roles_refs = properties.get("Roles", [])
        if not isinstance(roles_refs, list):
            return

        # Resolve the managed policy ARN
        policy_arn = self._get_physical_resource_id(logical_id, stack_name)

        target_role_ids = self._extract_role_refs(roles_refs)

        for role_logical_id in target_role_ids:
            if role_logical_id not in role_policies:
                role_policies[role_logical_id] = _ExternalPolicies()

            if policy_arn:
                role_policies[role_logical_id].managed_policy_arns.append(policy_arn)

    def _extract_role_refs(self, roles_refs: list[Any]) -> list[str]:
        """Extract role logical IDs from a Roles array.

        Handles:
        - {"Ref": "RoleLogicalId"} — the standard CDK pattern
        - Plain strings (rare but possible in processed templates)
        """
        role_ids: list[str] = []
        for ref in roles_refs:
            if isinstance(ref, dict) and "Ref" in ref:
                ref_value = ref["Ref"]
                if isinstance(ref_value, str):
                    role_ids.append(ref_value)
            elif isinstance(ref, str):
                # In processed templates, Ref may already be resolved to the
                # physical role name — but we need logical IDs for matching.
                # This case is uncommon; log and skip.
                logger.debug(
                    "Roles array contains plain string '%s' — cannot map to logical ID",
                    ref,
                )
        return role_ids

    def _resolve_nested_stack_name(
        self, logical_id: str, parent_stack_name: str
    ) -> str | None:
        """Resolve the physical stack name of a nested stack resource."""
        try:
            response = self._cfn.describe_stack_resource(
                StackName=parent_stack_name, LogicalResourceId=logical_id
            )
            physical_id = response["StackResourceDetail"]["PhysicalResourceId"]
            # Physical ID for nested stacks is the stack ARN or name
            # Extract stack name from ARN if needed
            if physical_id.startswith("arn:"):
                # arn:aws:cloudformation:region:account:stack/name/id
                parts = physical_id.split("/")
                return parts[1] if len(parts) >= 2 else None
            return physical_id
        except ClientError as e:
            logger.warning(
                "Could not resolve nested stack '%s' in '%s': %s",
                logical_id,
                parent_stack_name,
                e.response["Error"]["Code"],
            )
            return None

    def _get_template(self, stack_name: str) -> dict[str, Any] | None:
        """Retrieve and parse the stack template (handles both JSON and YAML)."""
        try:
            response = self._cfn.get_template(
                StackName=stack_name, TemplateStage="Processed"
            )
            body = response["TemplateBody"]
            # boto3 may return the body as a dict (already parsed) or as a string
            if isinstance(body, dict):
                return body  # type: ignore[return-value]
            if isinstance(body, str):
                return self._parse_template_string(body, stack_name)
            return None
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied getting template for stack '%s'. "
                    "Ensure cloudformation:GetTemplate permission is granted.",
                    stack_name,
                )
            else:
                logger.error(
                    "Failed to get template for stack '%s': %s",
                    stack_name,
                    error_code,
                )
            return None
        except (KeyError, TypeError) as e:
            logger.error(
                "Failed to parse template for stack '%s': %s", stack_name, e
            )
            return None

    def _parse_template_string(
        self, body: str, stack_name: str
    ) -> dict[str, Any] | None:
        """Parse a template string as JSON or YAML with CFN intrinsic support."""
        # Try JSON first (faster)
        try:
            return json.loads(body)  # type: ignore[no-any-return]
        except json.JSONDecodeError:
            pass

        # YAML with CloudFormation intrinsic function support
        try:
            import yaml

            # Create a loader that handles CFN tags like !Ref, !Sub, !GetAtt, etc.
            class CfnLoader(yaml.SafeLoader):
                pass

            def _cfn_tag_constructor(loader: yaml.SafeLoader, tag: str, node: yaml.Node) -> Any:
                """Convert CFN YAML tags to their JSON-equivalent dict form."""
                tag_name = tag.lstrip("!")
                if isinstance(node, yaml.ScalarNode):
                    value = loader.construct_scalar(node)
                    # !Ref Value -> {"Ref": "Value"}
                    if tag_name == "Ref":
                        return {"Ref": value}
                    # !Sub "string" -> {"Fn::Sub": "string"}
                    return {f"Fn::{tag_name}": value}
                elif isinstance(node, yaml.SequenceNode):
                    value = loader.construct_sequence(node)
                    # !GetAtt [Resource, Attr] -> {"Fn::GetAtt": [...]}
                    return {f"Fn::{tag_name}": value}
                elif isinstance(node, yaml.MappingNode):
                    value = loader.construct_mapping(node)
                    return {f"Fn::{tag_name}": value}
                return {f"Fn::{tag_name}": loader.construct_scalar(node)}

            # Register handlers for all common CFN intrinsic functions
            cfn_tags = [
                "Ref", "Sub", "GetAtt", "Join", "Select", "Split",
                "If", "Equals", "And", "Or", "Not", "Condition",
                "FindInMap", "Base64", "Cidr", "GetAZs",
                "ImportValue", "Transform",
            ]
            for tag in cfn_tags:
                CfnLoader.add_multi_constructor(
                    f"!{tag}",
                    lambda loader, suffix, node, t=tag: _cfn_tag_constructor(
                        loader, t, node
                    ),
                )
                # Also handle the tag without multi-constructor for exact matches
                CfnLoader.add_constructor(
                    f"!{tag}",
                    lambda loader, node, t=tag: _cfn_tag_constructor(loader, t, node),
                )

            result = yaml.load(body, Loader=CfnLoader)  # noqa: S506
            if isinstance(result, dict):
                return result
            return None
        except ImportError:
            logger.error(
                "Template for stack '%s' is YAML but PyYAML is not installed. "
                "Install with: pip install pyyaml",
                stack_name,
            )
            return None
        except Exception as e:
            logger.error(
                "Failed to parse YAML template for stack '%s': %s",
                stack_name,
                e,
            )
            return None

    def _resolve_role_name(
        self, logical_id: str, stack_name: str, properties: dict[str, Any]
    ) -> str:
        """Resolve the physical role name from template properties or stack resources."""
        role_name = properties.get("RoleName")
        if isinstance(role_name, str):
            return role_name

        # Look up the physical resource ID via the CFN API
        try:
            response = self._cfn.describe_stack_resource(
                StackName=stack_name, LogicalResourceId=logical_id
            )
            return response["StackResourceDetail"]["PhysicalResourceId"]
        except ClientError as e:
            logger.warning(
                "Could not resolve physical name for %s in %s: %s",
                logical_id,
                stack_name,
                e.response["Error"]["Code"],
            )
            return f"{stack_name}-{logical_id}"

    def _resolve_managed_policy_arns(
        self, logical_id: str, stack_name: str, properties: dict[str, Any]
    ) -> list[str]:
        """Resolve managed policy ARNs, handling intrinsic functions.

        Handles:
        - Literal string ARNs
        - {"Ref": "LogicalId"} references to AWS::IAM::ManagedPolicy resources
        - {"Fn::GetAtt": [...]} references
        - Any unresolvable intrinsic is looked up via DescribeStackResource

        In the processed template, most intrinsics are already resolved.
        This handles the remaining edge cases.
        """
        arns_raw = properties.get("ManagedPolicyArns", [])
        if not isinstance(arns_raw, list):
            return []

        resolved: list[str] = []
        for item in arns_raw:
            if isinstance(item, str):
                resolved.append(item)
            elif isinstance(item, dict):
                # Attempt to resolve intrinsic function
                arn = self._resolve_intrinsic(item, stack_name)
                if arn:
                    resolved.append(arn)
                else:
                    logger.debug(
                        "Could not resolve intrinsic in ManagedPolicyArns "
                        "for %s in %s: %s",
                        logical_id,
                        stack_name,
                        item,
                    )
        return resolved

    def _resolve_intrinsic(
        self, intrinsic: dict[str, Any], stack_name: str
    ) -> str | None:
        """Attempt to resolve a CloudFormation intrinsic function to a string value."""
        # Handle {"Ref": "LogicalId"}
        if "Ref" in intrinsic:
            ref_id = intrinsic["Ref"]
            if isinstance(ref_id, str):
                return self._get_physical_resource_id(ref_id, stack_name)

        # Handle {"Fn::GetAtt": ["LogicalId", "Arn"]}
        if "Fn::GetAtt" in intrinsic:
            get_att = intrinsic["Fn::GetAtt"]
            if isinstance(get_att, list) and len(get_att) >= 1:
                logical_id = get_att[0]
                if isinstance(logical_id, str):
                    return self._get_physical_resource_id(logical_id, stack_name)

        return None

    def _get_physical_resource_id(
        self, logical_id: str, stack_name: str
    ) -> str | None:
        """Look up the physical resource ID for a logical resource."""
        try:
            response = self._cfn.describe_stack_resource(
                StackName=stack_name, LogicalResourceId=logical_id
            )
            return response["StackResourceDetail"]["PhysicalResourceId"]
        except ClientError:
            return None

    def _extract_inline_policy_names(self, properties: dict[str, Any]) -> list[str]:
        """Extract inline policy names from role properties."""
        policies = properties.get("Policies", [])
        if not isinstance(policies, list):
            return []
        return [
            p["PolicyName"]
            for p in policies
            if isinstance(p, dict) and isinstance(p.get("PolicyName"), str)
        ]

    def _extract_inline_policy_documents(
        self, properties: dict[str, Any], stack_name: str
    ) -> list[tuple[str, dict[str, Any]]]:
        """Extract inline policy name-document pairs for content comparison.

        Resolves Fn::Sub intrinsics in policy documents using stack context
        so that document comparison against the live IAM state works correctly.
        """
        policies = properties.get("Policies", [])
        if not isinstance(policies, list):
            return []
        results: list[tuple[str, dict[str, Any]]] = []
        for p in policies:
            if not isinstance(p, dict):
                continue
            name = p.get("PolicyName")
            doc = p.get("PolicyDocument")
            if isinstance(name, str) and isinstance(doc, dict):
                # Resolve any Fn::Sub intrinsics in the document
                resolved_doc = self._resolve_intrinsics_in_doc(doc, stack_name)
                results.append((name, resolved_doc))
        return results

    def _resolve_intrinsics_in_doc(
        self, obj: Any, stack_name: str
    ) -> Any:
        """Recursively resolve CloudFormation intrinsics in a policy document.

        Handles Fn::Sub by replacing pseudo-parameters with actual values.
        This allows accurate comparison against the deployed policy.
        """
        if isinstance(obj, dict):
            # Handle {"Fn::Sub": "string with ${AWS::Region}"}
            if "Fn::Sub" in obj:
                sub_value = obj["Fn::Sub"]
                if isinstance(sub_value, str):
                    return self._resolve_sub_string(sub_value, stack_name)
                # Fn::Sub with a list [template, {var: value}] — just use template
                if isinstance(sub_value, list) and len(sub_value) >= 1:
                    template = sub_value[0]
                    if isinstance(template, str):
                        return self._resolve_sub_string(template, stack_name)
                return obj
            # Handle {"Ref": "AWS::Region"} etc.
            if "Ref" in obj:
                ref_value = obj["Ref"]
                resolved = self._resolve_pseudo_param(ref_value, stack_name)
                if resolved is not None:
                    return resolved
                return obj
            # Recurse into dict values
            return {k: self._resolve_intrinsics_in_doc(v, stack_name) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._resolve_intrinsics_in_doc(item, stack_name) for item in obj]
        return obj

    def _resolve_sub_string(self, template: str, stack_name: str) -> str:
        """Resolve ${AWS::*} pseudo-parameters in a Fn::Sub template string."""

        # Get stack metadata for resolution
        region, account_id, stack_id = self._get_stack_context(stack_name)

        replacements = {
            "${AWS::Region}": region,
            "${AWS::AccountId}": account_id,
            "${AWS::StackName}": stack_name,
            "${AWS::StackId}": stack_id,
            "${AWS::URLSuffix}": "amazonaws.com",
            "${AWS::Partition}": "aws",
            "${AWS::NoValue}": "",
        }

        result = template
        for placeholder, value in replacements.items():
            result = result.replace(placeholder, value)

        # Any remaining ${...} references to logical resources — leave as-is
        # (they'll cause a mismatch, which is correct since we can't resolve them)
        return result

    def _resolve_pseudo_param(self, ref: str, stack_name: str) -> str | None:
        """Resolve AWS pseudo-parameter Refs."""
        if not isinstance(ref, str):
            return None
        region, account_id, stack_id = self._get_stack_context(stack_name)
        pseudo_params = {
            "AWS::Region": region,
            "AWS::AccountId": account_id,
            "AWS::StackName": stack_name,
            "AWS::StackId": stack_id,
            "AWS::URLSuffix": "amazonaws.com",
            "AWS::Partition": "aws",
        }
        return pseudo_params.get(ref)

    def _get_stack_context(self, stack_name: str) -> tuple[str, str, str]:
        """Get region, account ID, and stack ID for intrinsic resolution.

        Caches the result to avoid repeated API calls.
        """
        if not hasattr(self, "_stack_context_cache"):
            self._stack_context_cache: dict[str, tuple[str, str, str]] = {}

        if stack_name not in self._stack_context_cache:
            region = self._session.region_name or "us-east-1"
            account_id = "unknown"
            stack_id = stack_name

            try:
                response = self._cfn.describe_stacks(StackName=stack_name)
                stacks = response.get("Stacks", [])
                if stacks:
                    stack_id = stacks[0].get("StackId", stack_name)
            except ClientError:
                pass

            try:
                sts = self._session.client("sts")
                account_id = sts.get_caller_identity()["Account"]
            except Exception:
                pass

            self._stack_context_cache[stack_name] = (region, account_id, stack_id)

        return self._stack_context_cache[stack_name]

    def _validate_stack_names(self, stack_names: list[str]) -> list[str]:
        """Validate that the given stack names exist and are active."""
        valid: list[str] = []
        for name in stack_names:
            try:
                response = self._cfn.describe_stacks(StackName=name)
                stacks = response.get("Stacks", [])
                if stacks:
                    status = stacks[0].get("StackStatus", "")
                    if status in _ACTIVE_STACK_STATUSES:
                        valid.append(name)
                    else:
                        logger.warning(
                            "Stack '%s' is in status '%s' — skipping", name, status
                        )
            except ClientError as e:
                logger.warning(
                    "Stack '%s' not found: %s", name, e.response["Error"]["Code"]
                )
        return valid

    def _filter_by_tags(
        self, stack_names: list[str], tag_filter: dict[str, str]
    ) -> list[str]:
        """Filter stacks by tag key-value pairs."""
        filtered: list[str] = []
        for name in stack_names:
            try:
                response = self._cfn.describe_stacks(StackName=name)
                stacks = response.get("Stacks", [])
                if not stacks:
                    continue
                tags = {
                    t["Key"]: t["Value"]
                    for t in stacks[0].get("Tags", [])
                }
                if all(tags.get(k) == v for k, v in tag_filter.items()):
                    filtered.append(name)
            except ClientError:
                continue
        return filtered
