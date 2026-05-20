"""cfn-drift-extended: Detect additive drift in CloudFormation-managed resources."""

__version__ = "0.1.0"

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
