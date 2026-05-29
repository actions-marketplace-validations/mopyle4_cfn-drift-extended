"""Build an index of all resources managed by CloudFormation.

This module enumerates all active stacks and collects their physical resource IDs
into a set. Resources in this set are "managed" — anything NOT in this set is
potentially orphaned.

Required IAM permissions (least privilege):
- cloudformation:ListStacks
- cloudformation:ListStackResources
"""

import logging

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Active stack statuses — stacks in these states own resources
_ACTIVE_STACK_STATUSES = [
    "CREATE_COMPLETE",
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE",
    "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE",
    "ROLLBACK_COMPLETE",
]


def build_managed_resource_index(
    cfn_client,
    stack_prefix: str = "",
    stack_names: list[str] | None = None,
) -> frozenset[str]:
    """Build a set of all physical resource IDs managed by CloudFormation.

    Enumerates active stacks (optionally filtered by prefix or explicit names),
    then collects all PhysicalResourceId values from each stack's resources.

    Args:
        cfn_client: A boto3 CloudFormation client.
        stack_prefix: Only include stacks whose names start with this prefix.
        stack_names: Explicit list of stack names to include (overrides prefix).

    Returns:
        A frozenset of all managed physical resource IDs.
    """
    managed_ids: set[str] = set()
    stacks = _discover_stacks(cfn_client, stack_prefix, stack_names)

    for stack_name in stacks:
        resource_ids = _list_stack_resource_ids(cfn_client, stack_name)
        managed_ids.update(resource_ids)

    logger.info(
        "Built managed resource index: %d resources across %d stacks",
        len(managed_ids),
        len(stacks),
    )
    return frozenset(managed_ids)


def _discover_stacks(
    cfn_client,
    stack_prefix: str,
    stack_names: list[str] | None,
) -> list[str]:
    """Discover active stacks, optionally filtered by prefix or explicit names."""
    if stack_names:
        return list(stack_names)

    stacks: list[str] = []
    try:
        paginator = cfn_client.get_paginator("list_stacks")
        for page in paginator.paginate(StackStatusFilter=_ACTIVE_STACK_STATUSES):
            for summary in page.get("StackSummaries", []):
                name = summary.get("StackName", "")
                if stack_prefix and not name.startswith(stack_prefix):
                    continue
                stacks.append(name)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error("Failed to list stacks: %s", error_code)

    return stacks


def _list_stack_resource_ids(cfn_client, stack_name: str) -> list[str]:
    """List all physical resource IDs for a single stack.

    Handles pagination and errors gracefully (logs and continues).
    """
    resource_ids: list[str] = []
    try:
        paginator = cfn_client.get_paginator("list_stack_resources")
        for page in paginator.paginate(StackName=stack_name):
            for summary in page.get("StackResourceSummaries", []):
                physical_id = summary.get("PhysicalResourceId", "")
                if physical_id:
                    resource_ids.append(physical_id)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.warning(
            "Failed to list resources for stack '%s': %s",
            stack_name,
            error_code,
        )

    return resource_ids
