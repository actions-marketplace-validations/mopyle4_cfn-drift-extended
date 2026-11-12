"""cfn-drift-extended: Detect additive drift in CloudFormation-managed resources."""

from importlib.metadata import PackageNotFoundError, version

# Single source of truth is pyproject.toml; read it from the installed metadata
# so report tool_version and `--version` can never disagree.
try:
    __version__ = version("cfn-drift-extended")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+unknown"

from cfn_drift_extended.auditor import Auditor
from cfn_drift_extended.exceptions import (
    AWSPermissionError,
    AWSThrottlingError,
    CfnDriftExtendedError,
)
from cfn_drift_extended.models import AuditReport, DriftFinding, DriftType, ResourceAudit, Severity

__all__ = [
    "AWSPermissionError",
    "AWSThrottlingError",
    "AuditReport",
    "Auditor",
    "CfnDriftExtendedError",
    "DriftFinding",
    "DriftType",
    "ResourceAudit",
    "Severity",
]
