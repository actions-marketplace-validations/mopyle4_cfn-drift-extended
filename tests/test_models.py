"""Unit tests for Pydantic models."""


import pytest
from pydantic import ValidationError

from cfn_drift_extended.models import (
    AuditReport,
    DriftFinding,
    DriftType,
    ResourceAudit,
    Severity,
)


class TestDriftType:
    def test_values(self) -> None:
        assert DriftType.INLINE_POLICY_ADDED == "inline_policy_added"
        assert DriftType.MANAGED_POLICY_ATTACHED == "managed_policy_attached"
        assert DriftType.INLINE_POLICY_MODIFIED == "inline_policy_modified"


class TestDriftFinding:
    def test_frozen_immutability(self) -> None:
        finding = DriftFinding(
            resource_type="AWS::IAM::Role",
            resource_id="my-role",
            stack_name="my-stack",
            drift_type=DriftType.INLINE_POLICY_ADDED,
            severity=Severity.HIGH,
            description="Test",
        )
        with pytest.raises(ValidationError):
            finding.resource_id = "other"  # type: ignore[misc]


class TestResourceAudit:
    def test_frozen_immutability(self) -> None:
        audit = ResourceAudit(
            resource_type="AWS::IAM::Role",
            resource_id="role",
            stack_name="stack",
            in_sync=True,
        )
        with pytest.raises(ValidationError):
            audit.in_sync = False  # type: ignore[misc]


class TestAuditReport:
    def test_has_drift_false_when_empty(self) -> None:
        report = AuditReport()
        assert report.has_drift is False

    def test_has_drift_true_when_resources_drifted(self) -> None:
        report = AuditReport(resources_with_drift=1)
        assert report.has_drift is True

    def test_has_errors(self) -> None:
        report = AuditReport(errors=["oops"])
        assert report.has_errors is True

    def test_metadata_fields(self) -> None:
        report = AuditReport(
            tool_version="0.1.0",
            account_id="123456789012",
            region="us-east-1",
        )
        assert report.tool_version == "0.1.0"
        assert report.account_id == "123456789012"
        assert report.region == "us-east-1"
        assert report.timestamp != ""

    def test_serialization_roundtrip(self) -> None:
        finding = DriftFinding(
            resource_type="AWS::IAM::Role",
            resource_id="my-role",
            stack_name="my-stack",
            drift_type=DriftType.INLINE_POLICY_ADDED,
            severity=Severity.HIGH,
            description="Test finding",
            extra="extra-policy",
        )
        report = AuditReport(
            stacks_scanned=1,
            resources_scanned=1,
            resources_with_drift=1,
            findings=[finding],
            audits=[
                ResourceAudit(
                    resource_type="AWS::IAM::Role",
                    resource_id="my-role",
                    stack_name="my-stack",
                    in_sync=False,
                    findings=(finding,),
                )
            ],
        )
        json_str = report.model_dump_json()
        restored = AuditReport.model_validate_json(json_str)
        assert restored.stacks_scanned == 1
        assert restored.findings[0].extra == "extra-policy"
        assert restored.has_drift is True
