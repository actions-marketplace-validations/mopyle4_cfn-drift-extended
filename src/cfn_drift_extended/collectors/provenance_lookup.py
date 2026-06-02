"""Look up the originating CloudFormation stack for live AWS resources.

The provenance signal we want for each candidate orphan is "which CFN stack
created this resource, if any?" — needed to distinguish a leaked Retained
resource from a deleted stack (high-priority cleanup) from a console/CLI
resource that was never under CFN management (informational).

Two empirically-validated AWS signals exist; this module uses both:

1. Reserved ``aws:cloudformation:stack-name`` tag (bulk, cheap)
   ----------------------------------------------------------
   CloudFormation auto-applies the reserved ``aws:cloudformation:*`` tags
   to many resource types it creates (CloudWatch log groups, S3 buckets,
   SSM parameters, and others). The ``aws:`` prefix is server-enforced,
   so the tag's presence is a trustworthy provenance signal even after the
   originating stack is deleted.

   In live testing we confirmed the tag does NOT propagate for IAM Role,
   SQS Queue, SNS Topic, EC2 Security Group, or Lambda Function. Tag
   propagation "varies by resource type" (per AWS docs) and these types
   are simply not in the auto-tag set. So the tag is a useful accelerator
   for the resource types that have it, but it cannot be the only signal.

2. ``cloudformation:DescribeStackResources --physical-resource-id`` (fallback)
   ------------------------------------------------------------------------
   CloudFormation's own service maintains an authoritative mapping of
   resource → stack and exposes it via this API. It works without any
   tag dependency, for active stacks AND for deleted stacks within
   CloudFormation's ~90-day retention window. This is the durable,
   server-authoritative provenance lookup.

   Cost: one CFN API call per candidate orphan that wasn't already
   resolved by the tag tier. Run via a thread pool with a small in-memory
   cache.

Required IAM permissions (least privilege, all read-only):
- tag:GetResources                (resourcegroupstaggingapi)
- cloudformation:DescribeStackResources
- (per-service list-tags is not required — RGT API covers tagged resources)
"""

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError

from cfn_drift_extended.collectors._aws import BOTO_CONFIG

logger = logging.getLogger(__name__)

CFN_STACK_NAME_TAG = "aws:cloudformation:stack-name"

# Sentinel returned by DescribeStackResources when CFN has no record of
# the resource. We cache these too so we don't re-call for known
# non-CFN resources.
_NO_OWNING_STACK = ""


@dataclass(frozen=True)
class StackOwner:
    """The CloudFormation stack that owns a resource, if any."""

    stack_name: str
    # ``stack_id`` is the stack's full ARN. For deleted stacks this is the
    # only way to refer to the stack — names get reused once a stack is
    # deleted, so the ARN is the stable identifier.
    stack_id: str


class ProvenanceResolver:
    """Two-tier provenance lookup for candidate orphan resources.

    Usage:
        resolver = ProvenanceResolver(session, region)
        resolver.prefetch_tagged_resources()  # one bulk RGT call
        owner = resolver.resolve(physical_id)  # tag hit OR CFN API fallback
    """

    def __init__(
        self,
        session: boto3.Session,
        region: str,
        max_workers: int = 8,
    ) -> None:
        self._session = session
        self._region = region
        self._max_workers = max_workers
        self._cfn = session.client("cloudformation", config=BOTO_CONFIG)
        self._tag_owners: dict[str, StackOwner] = {}
        self._tag_owners_loaded = False
        # Cache of physical_id -> StackOwner|None for the DescribeStackResources
        # fallback. None means "no CFN record."
        self._cfn_lookup_cache: dict[str, StackOwner | None] = {}

    def prefetch_tagged_resources(self) -> None:
        """Populate the tag-based owner map with one bulk RGT API call."""
        if self._tag_owners_loaded:
            return
        self._tag_owners = _bulk_lookup_cfn_tag_owners(
            self._session, self._region
        )
        self._tag_owners_loaded = True

    def resolve(self, physical_id: str) -> StackOwner | None:
        """Return the owning stack for ``physical_id``, or None if not CFN.

        Tries the prefetched tag map first (cheap), then falls back to
        ``cloudformation:DescribeStackResources --physical-resource-id``.
        """
        # Tag tier first.
        owner = self._tag_owners.get(physical_id)
        if owner is not None:
            return owner

        # CFN API fallback, with caching.
        if physical_id in self._cfn_lookup_cache:
            return self._cfn_lookup_cache[physical_id]

        owner = _describe_stack_for_resource(self._cfn, physical_id)
        self._cfn_lookup_cache[physical_id] = owner
        return owner

    def resolve_many(self, physical_ids: list[str]) -> dict[str, StackOwner | None]:
        """Resolve a batch in parallel.

        Returns a dict mapping each input id to its owning stack or None.
        """
        results: dict[str, StackOwner | None] = {}
        # Pre-fill from tag tier without spawning threads for those.
        unresolved: list[str] = []
        for pid in physical_ids:
            owner = self._tag_owners.get(pid)
            if owner is not None:
                results[pid] = owner
            elif pid in self._cfn_lookup_cache:
                results[pid] = self._cfn_lookup_cache[pid]
            else:
                unresolved.append(pid)

        if unresolved:
            with ThreadPoolExecutor(max_workers=self._max_workers) as ex:
                for pid, owner in zip(
                    unresolved,
                    ex.map(
                        lambda p: _describe_stack_for_resource(self._cfn, p),
                        unresolved,
                    ),
                    strict=True,
                ):
                    self._cfn_lookup_cache[pid] = owner
                    results[pid] = owner

        return results


def _bulk_lookup_cfn_tag_owners(
    session: boto3.Session, region: str
) -> dict[str, StackOwner]:
    """Return ``{arn-or-id: StackOwner}`` from one bulk RGT API call."""
    owners: dict[str, StackOwner] = {}
    try:
        rgt = session.client("resourcegroupstaggingapi", config=BOTO_CONFIG)
        paginator = rgt.get_paginator("get_resources")
        for page in paginator.paginate(
            TagFilters=[{"Key": CFN_STACK_NAME_TAG}],
        ):
            for entry in page.get("ResourceTagMappingList", []):
                arn = entry.get("ResourceARN", "")
                if not arn:
                    continue
                tags = entry.get("Tags", [])
                stack_name = _stack_name_from_tags(tags)
                stack_id = _stack_id_from_tags(tags)
                if stack_name:
                    owners[arn] = StackOwner(
                        stack_name=stack_name,
                        stack_id=stack_id or "",
                    )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.warning(
            "ResourceGroupsTaggingAPI lookup failed in %s: %s",
            region,
            error_code,
        )

    logger.info(
        "Provenance (tag tier): %d resources tagged with %s in %s",
        len(owners),
        CFN_STACK_NAME_TAG,
        region,
    )
    return owners


def _describe_stack_for_resource(
    cfn_client: Any, physical_id: str
) -> StackOwner | None:
    """Look up the owning stack for a physical resource id via CFN API.

    Returns None if CloudFormation has no record of the resource (which
    means it was either never CFN-managed, or its originating stack has
    aged out beyond the ~90-day retention).
    """
    try:
        response = cfn_client.describe_stack_resources(
            PhysicalResourceId=physical_id
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        # ValidationError with "Stack for X does not exist" is the normal
        # "not CFN-managed" answer; demote to debug to avoid noise.
        if error_code == "ValidationError":
            logger.debug(
                "DescribeStackResources: no stack for %s", physical_id
            )
            return None
        logger.warning(
            "DescribeStackResources failed for %s: %s", physical_id, error_code
        )
        return None

    resources = response.get("StackResources", [])
    if not resources:
        return None

    # All entries point to the same stack — pick the first.
    first = resources[0]
    return StackOwner(
        stack_name=first.get("StackName", ""),
        stack_id=first.get("StackId", ""),
    )


def _stack_name_from_tags(tags: list[dict[str, Any]]) -> str | None:
    """Extract the CFN stack-name tag value from a list of tag dicts."""
    for tag in tags:
        if tag.get("Key") == CFN_STACK_NAME_TAG:
            value = tag.get("Value")
            return str(value) if value else None
    return None


def _stack_id_from_tags(tags: list[dict[str, Any]]) -> str | None:
    """Extract the CFN stack-id tag value from a list of tag dicts."""
    for tag in tags:
        if tag.get("Key") == "aws:cloudformation:stack-id":
            value = tag.get("Value")
            return str(value) if value else None
    return None
