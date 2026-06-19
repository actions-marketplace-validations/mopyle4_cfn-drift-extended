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
    # S3
    S3_POLICY_STATEMENT_ADDED = "s3_policy_statement_added"
    S3_LIFECYCLE_RULE_ADDED = "s3_lifecycle_rule_added"
    S3_CORS_RULE_ADDED = "s3_cors_rule_added"
    # Lambda
    LAMBDA_ENV_VAR_ADDED = "lambda_env_var_added"
    LAMBDA_LAYER_ADDED = "lambda_layer_added"
    LAMBDA_PERMISSION_ADDED = "lambda_permission_added"
    # DynamoDB
    DYNAMODB_GSI_ADDED = "dynamodb_gsi_added"
    DYNAMODB_SCALING_TARGET_ADDED = "dynamodb_scaling_target_added"
    DYNAMODB_SCALING_POLICY_ADDED = "dynamodb_scaling_policy_added"


class OrphanType(StrEnum):
    """Type of orphaned resource detected."""

    IAM_ROLE_ORPHANED = "iam_role_orphaned"
    SECURITY_GROUP_ORPHANED = "security_group_orphaned"
    LAMBDA_FUNCTION_ORPHANED = "lambda_function_orphaned"
    SQS_QUEUE_ORPHANED = "sqs_queue_orphaned"
    SNS_TOPIC_ORPHANED = "sns_topic_orphaned"


class Provenance(StrEnum):
    """Origin classification of an orphaned resource."""

    CFN_ORPHAN_DELETED_STACK = "cfn_orphan_deleted_stack"
    NON_IAC = "non_iac"
    UNKNOWN = "unknown"


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


class OrphanFinding(BaseModel, frozen=True):
    """A single orphan finding for a resource not managed by CloudFormation.

    Immutable after creation. Use ``model_copy(update={...})`` to create
    a copy with updated fields (e.g., provenance classification).
    """

    resource_type: str = Field(description="AWS resource type (e.g., AWS::IAM::Role)")
    resource_id: str = Field(description="Physical resource identifier (ARN or name)")
    orphan_type: OrphanType
    severity: Severity
    description: str = Field(description="Human-readable description of the orphan")
    created_date: str | None = Field(
        default=None, description="ISO date when the resource was created"
    )
    last_used: str | None = Field(
        default=None, description="ISO date when the resource was last used"
    )
    region: str = Field(default="", description="AWS region of the resource")
    provenance: Provenance = Field(
        default=Provenance.UNKNOWN,
        description="Origin classification of the orphan",
    )
    originating_stack_name: str | None = Field(
        default=None,
        description="CFN stack that originally created this resource, if known",
    )


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


class OrphanReport(BaseModel):
    """Complete orphan detection report."""

    # Metadata
    tool_version: str = ""
    account_id: str = ""
    region: str = ""
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    # Counts
    resources_scanned: int = 0
    orphans_found: int = 0

    # Results
    findings: list[OrphanFinding] = Field(default_factory=list)
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal errors encountered during orphan detection",
    )
    filters_applied: list[str] = Field(
        default_factory=list,
        description="Descriptions of exclusion filters applied",
    )
