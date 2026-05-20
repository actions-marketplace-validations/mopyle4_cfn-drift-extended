"""Custom exception hierarchy for cfn-drift-extended.

Provides structured error handling with clear error categories
for better debugging and programmatic error handling.
"""


class CfnDriftExtendedError(Exception):
    """Base exception for all cfn-drift-extended errors."""

    def __init__(self, message: str, *, details: str | None = None) -> None:
        self.details = details
        super().__init__(message)


class AWSPermissionError(CfnDriftExtendedError):
    """Raised when AWS API calls fail due to insufficient permissions.

    This tool requires read-only access to CloudFormation and IAM.
    See LEAST_PRIVILEGE_POLICY in the README for the minimal IAM policy.
    """


class AWSThrottlingError(CfnDriftExtendedError):
    """Raised when AWS API calls are throttled beyond retry capacity."""
