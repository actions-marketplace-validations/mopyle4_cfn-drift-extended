"""Build an index of all resources managed by CloudFormation.

This module enumerates active (and optionally recently-deleted) stacks and
returns a ``ManagedIndex`` keyed by ``PhysicalResourceId``. Each entry carries
the originating stack name and status so detectors can distinguish
"managed by an active stack" from "left behind by a deleted stack."

Resources whose physical ID is not in the index are candidates for the
provenance lookup (see ``provenance_lookup.py``).

Required IAM permissions (least privilege):
- cloudformation:ListStacks
- cloudformation:ListStackResources
- cloudformation:DescribeStacks  (only when including deleted stacks)
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Active stack statuses — stacks in these states own resources.
_ACTIVE_STACK_STATUSES: list[str] = [
    "CREATE_COMPLETE",
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE",
    "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE",
    "ROLLBACK_COMPLETE",
]

_DELETED_STACK_STATUS = "DELETE_COMPLETE"


@dataclass(frozen=True)
class ManagedRef:
    """A resource's reference to its originating CloudFormation stack."""

    physical_id: str
    stack_name: str
    stack_status: str
    stack_deleted_at: datetime | None = None


class ManagedIndex:
    """Lookup of physical resource IDs to their originating stack.

    Behaves like a set for ``in`` checks, so existing detector code that does
    ``physical_id in managed_index`` continues to work.
    """

    def __init__(self, refs: list[ManagedRef]) -> None:
        # If the same physical ID appears in both an active and a deleted stack,
        # prefer the active one — a resource still managed by an active stack
        # is never orphaned, regardless of an old deleted-stack reference.
        self._by_id: dict[str, ManagedRef] = {}
        for ref in refs:
            existing = self._by_id.get(ref.physical_id)
            if existing is None or (
                existing.stack_status == _DELETED_STACK_STATUS
                and ref.stack_status != _DELETED_STACK_STATUS
            ):
                self._by_id[ref.physical_id] = ref

        self._active_stack_names: frozenset[str] = frozenset(
            ref.stack_name
            for ref in refs
            if ref.stack_status != _DELETED_STACK_STATUS
        )

    def __contains__(self, key: object) -> bool:
        """True for resources in an *active* stack only.

        Deleted-stack retained resources are intentionally excluded so that
        detectors continue to flag them as orphans; the auditor then
        classifies their provenance using ``get_ref``.
        """
        if not isinstance(key, str):
            return False
        ref = self._by_id.get(key)
        return ref is not None and ref.stack_status != _DELETED_STACK_STATUS

    def __len__(self) -> int:
        return len(self._by_id)

    def __iter__(self) -> Any:
        return iter(self._by_id)

    def get_ref(self, key: str) -> ManagedRef | None:
        """Return the ManagedRef for ``key``, or None if unknown."""
        return self._by_id.get(key)

    @property
    def active_stack_names(self) -> frozenset[str]:
        """Names of all active (non-deleted) stacks contributing to the index."""
        return self._active_stack_names


def build_managed_resource_index(
    cfn_client: Any,
    stack_prefix: str = "",
    stack_names: list[str] | None = None,
    include_deleted_window_days: int | None = 90,
    max_deleted_stacks: int | None = None,
) -> ManagedIndex:
    """Build a ``ManagedIndex`` of resources managed by CloudFormation.

    Args:
        cfn_client: A boto3 CloudFormation client.
        stack_prefix: Only include stacks whose names start with this prefix.
        stack_names: Explicit list of stack names to include (overrides prefix).
        include_deleted_window_days: If set, also include resources from
            stacks in ``DELETE_COMPLETE`` status whose deletion time is within
            this many days. Defaults to 90 (matches CloudFormation's deleted
            stack metadata retention). Pass ``None`` to skip deleted stacks.
        max_deleted_stacks: Maximum number of deleted stacks to enumerate
            for the index. Caps the scan for accounts with thousands of
            deleted stacks. Pass ``None`` for no limit. Defaults to None.

    Returns:
        A ``ManagedIndex`` containing all managed physical resource IDs.
    """
    refs: list[ManagedRef] = []

    statuses_to_query = list(_ACTIVE_STACK_STATUSES)
    if include_deleted_window_days is not None:
        statuses_to_query.append(_DELETED_STACK_STATUS)

    discovered = _discover_stacks(
        cfn_client,
        stack_prefix=stack_prefix,
        stack_names=stack_names,
        statuses=statuses_to_query,
        deleted_window_days=include_deleted_window_days,
        max_deleted_stacks=max_deleted_stacks,
    )

    for key in discovered:
        for physical_id, retained in _list_stack_resource_ids(
            cfn_client, key.list_resources_arg
        ):
            # For deleted stacks, only retained resources should appear in the
            # index — DELETE_COMPLETE resources are gone from AWS, but
            # DELETE_SKIPPED ones (DeletionPolicy: Retain) are the leaked
            # orphans we want to flag.
            if key.status == _DELETED_STACK_STATUS and not retained:
                continue
            refs.append(
                ManagedRef(
                    physical_id=physical_id,
                    stack_name=key.name,
                    stack_status=key.status,
                    stack_deleted_at=key.deletion_time,
                )
            )

    index = ManagedIndex(refs)
    deleted_count = sum(
        1 for k in discovered if k.status == _DELETED_STACK_STATUS
    )
    was_capped = (
        max_deleted_stacks is not None and deleted_count >= max_deleted_stacks
    )
    if was_capped:
        logger.warning(
            "Deleted-stack scan capped at %d stacks (--max-deleted-stacks). "
            "Some orphan provenance may be classified as UNKNOWN.",
            max_deleted_stacks,
        )
    logger.info(
        "Built managed resource index: %d resources across %d stacks "
        "(deleted window: %s days, deleted stacks scanned: %d%s)",
        len(index),
        len({r.stack_name for r in refs}),
        include_deleted_window_days,
        deleted_count,
        " [CAPPED]" if was_capped else "",
    )
    return index


@dataclass(frozen=True)
class _StackKey:
    """Identifier for a stack in the listing result.

    For active stacks the name is enough. Deleted stacks must be referenced
    by their full StackId (ARN) when calling ListStackResources, since the
    stack name is no longer unique once the stack is deleted.
    """

    name: str
    list_resources_arg: str  # name for active stacks, StackId for deleted
    status: str
    deletion_time: datetime | None


def _discover_stacks(
    cfn_client: Any,
    stack_prefix: str,
    stack_names: list[str] | None,
    statuses: list[str],
    deleted_window_days: int | None,
    max_deleted_stacks: int | None = None,
) -> list[_StackKey]:
    """Return identifiers for each stack to enumerate."""
    if stack_names:
        return [
            _StackKey(name=n, list_resources_arg=n, status="EXPLICIT", deletion_time=None)
            for n in stack_names
        ]

    cutoff: datetime | None = None
    if deleted_window_days is not None:
        cutoff = datetime.now(UTC) - timedelta(days=deleted_window_days)

    discovered: list[_StackKey] = []
    deleted_count = 0
    try:
        paginator = cfn_client.get_paginator("list_stacks")
        for page in paginator.paginate(StackStatusFilter=statuses):
            for summary in page.get("StackSummaries", []):
                name = summary.get("StackName", "")
                if not name:
                    continue
                if stack_prefix and not name.startswith(stack_prefix):
                    continue

                status = summary.get("StackStatus", "")
                deletion_time = summary.get("DeletionTime")
                stack_id = summary.get("StackId", "")

                if status == _DELETED_STACK_STATUS:
                    if cutoff is None or not isinstance(deletion_time, datetime):
                        continue
                    deleted_at = (
                        deletion_time
                        if deletion_time.tzinfo
                        else deletion_time.replace(tzinfo=UTC)
                    )
                    if deleted_at < cutoff:
                        continue
                    if not stack_id:
                        # Cannot list resources without the StackId, skip.
                        continue
                    # Enforce deleted-stack cap for scale
                    if (
                        max_deleted_stacks is not None
                        and deleted_count >= max_deleted_stacks
                    ):
                        continue
                    deleted_count += 1
                    discovered.append(
                        _StackKey(
                            name=name,
                            list_resources_arg=stack_id,
                            status=status,
                            deletion_time=deleted_at,
                        )
                    )
                else:
                    discovered.append(
                        _StackKey(
                            name=name,
                            list_resources_arg=name,
                            status=status,
                            deletion_time=None,
                        )
                    )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error("Failed to list stacks: %s", error_code)

    return discovered


def _list_stack_resource_ids(
    cfn_client: Any, stack_ref: str
) -> list[tuple[str, bool]]:
    """List ``(physical_id, was_retained)`` for a single stack.

    ``stack_ref`` is a stack name for active stacks or a StackId/ARN for
    deleted stacks (CloudFormation requires the ARN once the stack name
    is no longer unique). ``was_retained`` is True for resources whose
    DeletionPolicy caused them to survive stack deletion (status
    ``DELETE_SKIPPED``); for active stacks it is always False.

    Handles pagination and errors gracefully (logs and continues).
    """
    results: list[tuple[str, bool]] = []
    try:
        paginator = cfn_client.get_paginator("list_stack_resources")
        for page in paginator.paginate(StackName=stack_ref):
            for summary in page.get("StackResourceSummaries", []):
                physical_id = summary.get("PhysicalResourceId", "")
                status = summary.get("ResourceStatus", "")
                if physical_id:
                    results.append((physical_id, status == "DELETE_SKIPPED"))
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.warning(
            "Failed to list resources for stack '%s': %s",
            stack_ref,
            error_code,
        )

    return results
