"""Detect orphaned IAM roles not managed by CloudFormation.

Compares all IAM roles in the account against the CFN managed resource index.
Roles not in the index (and not excluded by filters) are flagged as potentially
orphaned. Roles unused for more than 90 days are noted as stale in the finding
description.

Note: IAM is a global service. The region parameter is accepted for session
consistency and report metadata but does not affect IAM API behavior.

Required IAM permissions (least privilege):
- iam:ListRoles
"""

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from cfn_drift_extended.collectors._aws import BOTO_CONFIG
from cfn_drift_extended.collectors._datetime_utils import (
    days_since,
    format_datetime,
)
from cfn_drift_extended.collectors.cfn_managed_index import ManagedIndex
from cfn_drift_extended.collectors.orphan_filters import is_excluded_iam_role
from cfn_drift_extended.models import OrphanFinding, OrphanType, Severity

logger = logging.getLogger(__name__)

# Roles unused for longer than this are flagged as stale in the description.
_STALE_THRESHOLD_DAYS = 90


class IamOrphanCollector:
    """Detects orphaned IAM roles.

    Compares all roles in the account against the CFN managed index. Roles not
    in the index (and not excluded by filters) are reported as orphaned. The
    ``RoleLastUsed.LastUsedDate`` field is used to surface staleness.
    """

    def __init__(self, session: boto3.Session, region: str) -> None:
        self._session = session
        self._region = region
        self._iam = session.client("iam", config=BOTO_CONFIG)

    def detect_orphaned_roles(
        self, managed_index: ManagedIndex | frozenset[str]
    ) -> list[OrphanFinding]:
        """Detect IAM roles not managed by any CloudFormation stack.

        Args:
            managed_index: ManagedIndex (or a plain set, for backward
                compatibility with tests) of physical resource IDs managed
                by CloudFormation.

        Returns:
            List of OrphanFinding for each orphaned role.
        """
        findings: list[OrphanFinding] = []
        roles = self._list_all_roles()

        for role in roles:
            role_name = role.get("RoleName", "")
            role_path = role.get("Path", "/")
            role_arn = role.get("Arn", "")

            if not role_name:
                continue

            # Check exclusion filters (service-linked, AWS-reserved, CDK, etc.)
            if is_excluded_iam_role(role_name, role_path):
                continue

            # Skip roles managed by CFN (matched by name or ARN)
            if role_name in managed_index or role_arn in managed_index:
                continue

            created_date = format_datetime(role.get("CreateDate"))
            last_used, stale_days = self._extract_last_used(role)

            description = (
                f"IAM role '{role_name}' is not managed by any CFN stack"
            )
            if stale_days is not None and stale_days > _STALE_THRESHOLD_DAYS:
                description += f" (unused for {stale_days} days)"
            elif last_used is None:
                description += " (never used)"

            findings.append(
                OrphanFinding(
                    resource_type="AWS::IAM::Role",
                    resource_id=role_arn or role_name,
                    orphan_type=OrphanType.IAM_ROLE_ORPHANED,
                    severity=Severity.HIGH,
                    description=description,
                    created_date=created_date,
                    last_used=last_used,
                    region=self._region,
                )
            )

        return findings

    def _list_all_roles(self) -> list[dict[str, Any]]:
        """List all IAM roles in the account using pagination."""
        roles: list[dict[str, Any]] = []
        try:
            paginator = self._iam.get_paginator("list_roles")
            for page in paginator.paginate():
                roles.extend(dict(role) for role in page.get("Roles", []))
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error("Failed to list IAM roles: %s", error_code)

        return roles

    @staticmethod
    def _extract_last_used(
        role: dict[str, Any],
    ) -> tuple[str | None, int | None]:
        """Extract the last-used ISO timestamp and days since last use.

        Returns (last_used_iso, days_since_last_use). Both are None when the
        role has never been used.
        """
        role_last_used = role.get("RoleLastUsed") or {}
        last_used_date = role_last_used.get("LastUsedDate")
        if not last_used_date:
            return None, None

        return format_datetime(last_used_date), days_since(last_used_date)
