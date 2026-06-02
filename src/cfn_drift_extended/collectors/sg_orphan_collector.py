"""Detect orphaned Security Groups not managed by CloudFormation.

Compares all security groups in the region against the CFN managed resource
index. Groups not in the index (and not excluded by filters) are flagged as
potentially orphaned.

Required IAM permissions (least privilege):
- ec2:DescribeSecurityGroups
- ec2:DescribeVpcs
"""

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from cfn_drift_extended.collectors._aws import BOTO_CONFIG
from cfn_drift_extended.collectors.cfn_managed_index import ManagedIndex
from cfn_drift_extended.collectors.orphan_filters import is_excluded_security_group
from cfn_drift_extended.models import OrphanFinding, OrphanType, Severity

logger = logging.getLogger(__name__)


class SgOrphanCollector:
    """Detects orphaned Security Groups.

    Compares all security groups in the region against the CFN managed index.
    Groups not in the index (and not excluded by filters) are reported as
    orphaned.
    """

    def __init__(self, session: boto3.Session, region: str) -> None:
        self._session = session
        self._region = region
        self._ec2 = session.client("ec2", config=BOTO_CONFIG)

    def detect_orphaned_security_groups(
        self, managed_index: ManagedIndex | frozenset[str]
    ) -> list[OrphanFinding]:
        """Detect Security Groups not managed by any CloudFormation stack.

        Args:
            managed_index: ManagedIndex (or a plain set, for backward
                compatibility with tests) of physical resource IDs managed
                by CloudFormation.

        Returns:
            List of OrphanFinding for each orphaned security group.
        """
        findings: list[OrphanFinding] = []
        default_vpc_id = self._get_default_vpc_id()
        groups = self._list_all_security_groups()

        for group in groups:
            group_id = group.get("GroupId", "")
            group_name = group.get("GroupName", "")
            vpc_id = group.get("VpcId", "")

            if not group_id:
                continue

            # Check exclusion filters (default groups, etc.)
            if is_excluded_security_group(group_name, vpc_id, default_vpc_id):
                continue

            # Skip groups managed by CFN (matched by physical ID)
            if group_id in managed_index:
                continue

            description = (
                f"Security group '{group_name}' ({group_id}) is not managed "
                f"by any CFN stack"
            )
            if vpc_id:
                description += f" in VPC {vpc_id}"

            findings.append(
                OrphanFinding(
                    resource_type="AWS::EC2::SecurityGroup",
                    resource_id=group_id,
                    orphan_type=OrphanType.SECURITY_GROUP_ORPHANED,
                    severity=Severity.MEDIUM,
                    description=description,
                    created_date=None,
                    last_used=None,
                    region=self._region,
                )
            )

        return findings

    def _list_all_security_groups(self) -> list[dict[str, Any]]:
        """List all security groups in the region using pagination."""
        groups: list[dict[str, Any]] = []
        try:
            paginator = self._ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                groups.extend(page.get("SecurityGroups", []))
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error("Failed to describe security groups: %s", error_code)

        return groups

    def _get_default_vpc_id(self) -> str | None:
        """Return the default VPC ID for the region, or None if unavailable."""
        try:
            response = self._ec2.describe_vpcs(
                Filters=[{"Name": "isDefault", "Values": ["true"]}]
            )
            vpcs = response.get("Vpcs", [])
            if vpcs:
                vpc_id = vpcs[0].get("VpcId")
                return str(vpc_id) if vpc_id else None
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.warning("Failed to describe default VPC: %s", error_code)

        return None
