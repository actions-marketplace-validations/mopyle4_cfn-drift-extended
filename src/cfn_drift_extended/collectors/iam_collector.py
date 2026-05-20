"""Collect actual IAM role state from AWS.

Note: IAM is a global service. The region parameter is accepted for
session consistency but does not affect IAM API behavior.

Required IAM permissions (least privilege):
- iam:GetRole
- iam:ListRolePolicies
- iam:ListAttachedRolePolicies
- iam:GetRolePolicy (for inline policy document comparison)
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Retry configuration with adaptive mode and jitter
_BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
)


@dataclass(frozen=True, slots=True)
class ActualRoleState:
    """What actually exists on an IAM role in AWS.

    Frozen dataclass for immutability and memory efficiency (slots).
    """

    role_name: str
    inline_policy_names: tuple[str, ...] = field(default_factory=tuple)
    inline_policy_documents: tuple[tuple[str, dict[str, Any]], ...] = field(
        default_factory=tuple
    )
    managed_policy_arns: tuple[str, ...] = field(default_factory=tuple)


class IamCollector:
    """Collects actual IAM role state from the AWS IAM API.

    Features:
    - Adaptive retry with exponential backoff
    - Fetches inline policy documents for content comparison
    - Read-only API calls (least privilege)

    Note: IAM is a global service. The region parameter is accepted
    for session consistency but does not affect API behavior.
    """

    def __init__(self, region: str, session: boto3.Session | None = None) -> None:
        self._session = session or boto3.Session(region_name=region)
        self._iam = self._session.client("iam", config=_BOTO_CONFIG)

    def get_role_state(self, role_name: str) -> ActualRoleState | None:
        """Get the actual state of an IAM role.

        Returns None if the role doesn't exist or cannot be accessed.
        Logs specific error details for debugging.
        """
        try:
            self._iam.get_role(RoleName=role_name)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchEntity":
                logger.warning("Role '%s' does not exist in IAM", role_name)
            elif error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied accessing role '%s'. "
                    "Ensure iam:GetRole permission is granted.",
                    role_name,
                )
            else:
                logger.error(
                    "Unexpected error fetching role '%s': %s", role_name, error_code
                )
            return None

        inline_names = self._list_inline_policies(role_name)
        inline_docs = self._get_inline_policy_documents(role_name, inline_names)
        managed_arns = self._list_attached_policies(role_name)

        return ActualRoleState(
            role_name=role_name,
            inline_policy_names=tuple(inline_names),
            inline_policy_documents=tuple(inline_docs),
            managed_policy_arns=tuple(managed_arns),
        )

    def _list_inline_policies(self, role_name: str) -> list[str]:
        """List all inline policy names on a role using pagination."""
        names: list[str] = []
        try:
            paginator = self._iam.get_paginator("list_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                names.extend(page.get("PolicyNames", []))
        except ClientError as e:
            logger.error(
                "Failed to list inline policies for role '%s': %s",
                role_name,
                e.response["Error"]["Code"],
            )
        return names

    def _get_inline_policy_documents(
        self, role_name: str, policy_names: list[str]
    ) -> list[tuple[str, dict[str, Any]]]:
        """Fetch the policy document for each inline policy."""
        docs: list[tuple[str, dict[str, Any]]] = []
        for name in policy_names:
            try:
                response = self._iam.get_role_policy(
                    RoleName=role_name, PolicyName=name
                )
                doc_raw = response.get("PolicyDocument", {})
                # boto3 may return the document as a dict (already parsed)
                # or as a URL-encoded/JSON string depending on context
                if isinstance(doc_raw, dict):
                    doc = doc_raw
                elif isinstance(doc_raw, str):
                    try:
                        doc = json.loads(doc_raw)
                    except json.JSONDecodeError:
                        # Some environments return Python repr format
                        import ast
                        try:
                            doc = ast.literal_eval(doc_raw)
                        except (ValueError, SyntaxError):
                            logger.debug(
                                "Could not parse policy document '%s' for role '%s'",
                                name, role_name,
                            )
                            continue
                else:
                    doc = {}
                docs.append((name, doc))
            except ClientError as e:
                logger.error(
                    "Failed to get policy document '%s' for role '%s': %s",
                    name,
                    role_name,
                    e.response["Error"]["Code"],
                )
        return docs

    def _list_attached_policies(self, role_name: str) -> list[str]:
        """List all attached managed policy ARNs on a role using pagination."""
        arns: list[str] = []
        try:
            paginator = self._iam.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for policy in page.get("AttachedPolicies", []):
                    arns.append(policy["PolicyArn"])
        except ClientError as e:
            logger.error(
                "Failed to list attached policies for role '%s': %s",
                role_name,
                e.response["Error"]["Code"],
            )
        return arns
