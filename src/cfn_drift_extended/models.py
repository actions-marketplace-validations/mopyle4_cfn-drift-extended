"""Domain models for drift findings.

Uses Pydantic for validation, serialization, and schema generation.
Frozen models ensure immutability after creation.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DriftType(StrEnum):
    """Type of additive drift detected."""

    INLINE_POLICY_ADDED = "inline_policy_added"
    MANAGED_POLICY_ATTACHED = "managed_policy_attached"
    INLINE_POLICY_MODIFIED = "inline_policy_modified"
    # Security Groups
    SECURITY_GROUP_INGRESS_ADDED = "security_group_ingress_added"
    SECURITY_GROUP_EGRESS_ADDED = "security_group_egress_added"
    # SNS/SQS
    SQS_POLICY_STATEMENT_ADDED = "sqs_policy_statement_added"
    SNS_POLICY_STATEMENT_ADDED = "sns_policy_statement_added"
    SNS_SUBSCRIPTION_ADDED = "sns_subscription_added"
    # EventBridge
    EVENTBRIDGE_RULE_ADDED = "eventbridge_rule_added"


class Severity(StrEnum):
    """Severity of the drift finding."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DriftFinding(BaseModel, frozen=True):
    """A single drift finding for a resource.

    Immutable after creation to prevent accidental mutation during reporting.
    """

    resource_type: str = Field(description="AWS resource type (e.g., AWS::IAM::Role)")
    resource_id: str = Field(description="Logical or physical resource identifier")
    stack_name: str = Field(description="CloudFormation stack the resource belongs to")
    drift_type: DriftType
    severity: Severity
    description: str = Field(description="Human-readable description of the drift")
    expected: Any = Field(default=None, description="What CFN declares")
    actual: Any = Field(default=None, description="What actually exists")
    extra: Any = Field(default=None, description="The additive element not in the template")


class ResourceAudit(BaseModel, frozen=True):
    """Audit result for a single resource. Immutable after creation."""

    resource_type: str
    resource_id: str
    stack_name: str
    in_sync: bool
    findings: tuple[DriftFinding, ...] = Field(default_factory=tuple)


class AuditReport(BaseModel):
    """Complete audit report across all scanned stacks."""

    # Metadata
    tool_version: str = ""
    account_id: str = ""
    region: str = ""
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    # Counts
    stacks_scanned: int = 0
    resources_scanned: int = 0
    resources_with_drift: int = 0

    # Results
    findings: list[DriftFinding] = Field(default_factory=list)
    audits: list[ResourceAudit] = Field(default_factory=list)
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal errors encountered during the audit",
    )

    @property
    def has_drift(self) -> bool:
        return self.resources_with_drift > 0

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0
