"""Collect actual Security Group state from AWS.

Required IAM permissions (least privilege):
- ec2:DescribeSecurityGroups
- ec2:DescribeSecurityGroupRules
"""

import logging
from dataclasses import dataclass, field

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Retry configuration with adaptive mode and jitter
_BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
)


@dataclass(frozen=True, slots=True)
class SecurityGroupRule:
    """A single security group rule, comparable by protocol/port/source."""

    ip_protocol: str
    from_port: int | None
    to_port: int | None
    cidr_ipv4: str | None = None
    cidr_ipv6: str | None = None
    source_security_group_id: str | None = None
    prefix_list_id: str | None = None
    description: str | None = None


@dataclass(frozen=True, slots=True)
class ActualSecurityGroupState:
    """What actually exists on a Security Group in AWS.

    Frozen dataclass for immutability and memory efficiency (slots).
    """

    group_id: str
    group_name: str
    ingress_rules: tuple[SecurityGroupRule, ...] = field(default_factory=tuple)
    egress_rules: tuple[SecurityGroupRule, ...] = field(default_factory=tuple)


class SgCollector:
    """Collects actual Security Group state from the AWS EC2 API.

    Features:
    - Adaptive retry with exponential backoff
    - Read-only API calls (least privilege)
    - Returns None on access errors (graceful degradation)
    """

    def __init__(self, region: str, session: boto3.Session | None = None) -> None:
        self._session = session or boto3.Session(region_name=region)
        self._ec2 = self._session.client("ec2", config=_BOTO_CONFIG)

    def get_security_group_state(self, group_id: str) -> ActualSecurityGroupState | None:
        """Get the actual state of a Security Group.

        Returns None if the group doesn't exist or cannot be accessed.
        Logs specific error details for debugging.
        """
        try:
            response = self._ec2.describe_security_groups(GroupIds=[group_id])
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "InvalidGroup.NotFound":
                logger.warning("Security group '%s' does not exist", group_id)
            elif error_code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                logger.error(
                    "Permission denied accessing security group '%s'. "
                    "Ensure ec2:DescribeSecurityGroups permission is granted.",
                    group_id,
                )
            else:
                logger.error(
                    "Unexpected error fetching security group '%s': %s",
                    group_id,
                    error_code,
                )
            return None

        groups = response.get("SecurityGroups", [])
        if not groups:
            logger.warning("Security group '%s' not found in response", group_id)
            return None

        sg = groups[0]
        ingress_rules = self._extract_rules(sg.get("IpPermissions", []))
        egress_rules = self._extract_rules(sg.get("IpPermissionsEgress", []))

        return ActualSecurityGroupState(
            group_id=group_id,
            group_name=sg.get("GroupName", ""),
            ingress_rules=tuple(ingress_rules),
            egress_rules=tuple(egress_rules),
        )

    def _extract_rules(self, ip_permissions: list[dict]) -> list[SecurityGroupRule]:
        """Extract SecurityGroupRule objects from EC2 IpPermissions format.

        Each IpPermission can have multiple IP ranges, IPv6 ranges,
        security group references, and prefix lists. We expand each into
        individual SecurityGroupRule objects for set-based comparison.
        """
        rules: list[SecurityGroupRule] = []

        for perm in ip_permissions:
            ip_protocol = perm.get("IpProtocol", "-1")
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")

            # Expand IPv4 ranges
            for ip_range in perm.get("IpRanges", []):
                rules.append(
                    SecurityGroupRule(
                        ip_protocol=ip_protocol,
                        from_port=from_port,
                        to_port=to_port,
                        cidr_ipv4=ip_range.get("CidrIp"),
                        description=ip_range.get("Description"),
                    )
                )

            # Expand IPv6 ranges
            for ip_range in perm.get("Ipv6Ranges", []):
                rules.append(
                    SecurityGroupRule(
                        ip_protocol=ip_protocol,
                        from_port=from_port,
                        to_port=to_port,
                        cidr_ipv6=ip_range.get("CidrIpv6"),
                        description=ip_range.get("Description"),
                    )
                )

            # Expand security group references
            for sg_ref in perm.get("UserIdGroupPairs", []):
                rules.append(
                    SecurityGroupRule(
                        ip_protocol=ip_protocol,
                        from_port=from_port,
                        to_port=to_port,
                        source_security_group_id=sg_ref.get("GroupId"),
                        description=sg_ref.get("Description"),
                    )
                )

            # Expand prefix list references
            for pl_ref in perm.get("PrefixListIds", []):
                rules.append(
                    SecurityGroupRule(
                        ip_protocol=ip_protocol,
                        from_port=from_port,
                        to_port=to_port,
                        prefix_list_id=pl_ref.get("PrefixListId"),
                        description=pl_ref.get("Description"),
                    )
                )

        return rules
