"""Exclusion filters for orphan detection.

These filters prevent false positives by excluding resources that are
legitimately unmanaged by CloudFormation (service-linked roles, default
security groups, CDK bootstrap resources, etc.).
"""


def is_excluded_iam_role(role_name: str, role_path: str) -> bool:
    """Check if an IAM role should be excluded from orphan detection.

    Excludes:
    - Service-linked roles (path contains /aws-service-role/)
    - AWS-managed/reserved roles (path contains /aws-reserved/)
    - CDK bootstrap roles (name contains 'cdk-')
    - OrganizationAccountAccessRole (created by AWS Organizations)
    """
    # Service-linked roles are created and managed by AWS services
    if "/aws-service-role/" in role_path:
        return True

    # AWS-reserved roles are internal AWS infrastructure
    if "/aws-reserved/" in role_path:
        return True

    # CDK bootstrap roles are infrastructure, not application resources
    if "cdk-" in role_name.lower():
        return True

    # Organization access role is created by AWS Organizations
    if role_name == "OrganizationAccountAccessRole":
        return True

    return False


def is_excluded_security_group(
    sg_name: str, vpc_id: str, default_vpc_id: str | None
) -> bool:
    """Check if a security group should be excluded from orphan detection.

    Excludes:
    - Groups named "default" (every VPC has one, cannot be deleted)
    - Groups in the default VPC with name "default"
    """
    # Default security groups cannot be deleted and always exist
    if sg_name == "default":
        return True

    # Default VPC's default group is always present
    if default_vpc_id and vpc_id == default_vpc_id and sg_name == "default":
        return True

    return False


def is_excluded_lambda(function_name: str) -> bool:
    """Check if a Lambda function should be excluded from orphan detection.

    Excludes:
    - CDK custom resource handlers (name contains 'Custom::' or 'LogRetention')
    - CloudFormation custom resource providers
    """
    # CDK custom resource handlers are infrastructure
    if "Custom::" in function_name:
        return True

    # Log retention custom resource handlers
    if "LogRetention" in function_name:
        return True

    return False


def is_excluded_queue(queue_url: str) -> bool:
    """Check if an SQS queue should be excluded from orphan detection.

    Excludes:
    - DLQ queues of managed queues (heuristic: name ends with -dlq.fifo
      or -deadletter.fifo)
    """
    # Extract queue name from URL (last path segment)
    queue_name = queue_url.rstrip("/").rsplit("/", maxsplit=1)[-1]
    queue_name_lower = queue_name.lower()

    # FIFO DLQs that are likely paired with managed queues
    if queue_name_lower.endswith("-dlq.fifo"):
        return True

    if queue_name_lower.endswith("-deadletter.fifo"):
        return True

    return False
