"""Compare expected IAM role state (from CFN) vs actual state (from IAM API).

Detects:
- Extra inline policies (added outside CFN)
- Extra managed policies (attached outside CFN)
- Modified inline policy documents (statements added to existing policies)

Uses set difference operations for O(n) comparison performance.
"""

import json
import logging
from typing import Any

from cfn_drift_extended.collectors.cfn_collector import ExpectedRoleState
from cfn_drift_extended.collectors.iam_collector import ActualRoleState
from cfn_drift_extended.models import DriftFinding, DriftType, ResourceAudit, Severity

logger = logging.getLogger(__name__)


class IamComparator:
    """Compares expected vs actual IAM role policies to find additive drift.

    Detects:
    - Additions: policies present in AWS but not in CFN template
    - Modifications: extra statements added to existing inline policies

    Removals are handled by native CloudFormation drift detection.
    """

    _RESOURCE_TYPE = "AWS::IAM::Role"

    def compare(self, expected: ExpectedRoleState, actual: ActualRoleState) -> ResourceAudit:
        """Compare a single role's expected state against its actual state.

        Uses set operations for efficient O(n) comparison.
        Returns a ResourceAudit with any additive drift findings.
        """
        findings: list[DriftFinding] = []

        findings.extend(self._find_extra_inline_policies(expected, actual))
        findings.extend(self._find_extra_managed_policies(expected, actual))
        findings.extend(self._find_modified_inline_policies(expected, actual))

        return ResourceAudit(
            resource_type=self._RESOURCE_TYPE,
            resource_id=expected.role_name,
            stack_name=expected.stack_name,
            in_sync=len(findings) == 0,
            findings=tuple(findings),
        )

    def _find_extra_inline_policies(
        self, expected: ExpectedRoleState, actual: ActualRoleState
    ) -> list[DriftFinding]:
        """Find inline policies that exist on the role but aren't in the CFN template."""
        extra = set(actual.inline_policy_names) - set(expected.inline_policy_names)
        return [
            DriftFinding(
                resource_type=self._RESOURCE_TYPE,
                resource_id=expected.role_name,
                stack_name=expected.stack_name,
                drift_type=DriftType.INLINE_POLICY_ADDED,
                severity=Severity.HIGH,
                description=(
                    f"Inline policy '{name}' exists on role "
                    f"'{expected.role_name}' but is not declared in the "
                    f"CloudFormation template for stack '{expected.stack_name}'"
                ),
                expected=list(expected.inline_policy_names),
                actual=list(actual.inline_policy_names),
                extra=name,
            )
            for name in sorted(extra)
        ]

    def _find_extra_managed_policies(
        self, expected: ExpectedRoleState, actual: ActualRoleState
    ) -> list[DriftFinding]:
        """Find managed policies attached to the role but not in the CFN template."""
        extra = set(actual.managed_policy_arns) - set(expected.managed_policy_arns)
        return [
            DriftFinding(
                resource_type=self._RESOURCE_TYPE,
                resource_id=expected.role_name,
                stack_name=expected.stack_name,
                drift_type=DriftType.MANAGED_POLICY_ATTACHED,
                severity=Severity.HIGH,
                description=(
                    f"Managed policy '{arn}' is attached to role "
                    f"'{expected.role_name}' but is not declared in the "
                    f"CloudFormation template for stack '{expected.stack_name}'"
                ),
                expected=list(expected.managed_policy_arns),
                actual=list(actual.managed_policy_arns),
                extra=arn,
            )
            for arn in sorted(extra)
        ]

    def _find_modified_inline_policies(
        self, expected: ExpectedRoleState, actual: ActualRoleState
    ) -> list[DriftFinding]:
        """Find inline policies whose documents have been modified with extra statements.

        Only checks policies that exist in both expected and actual (shared policies).
        Compares the policy document content to detect added statements.
        """
        if not expected.inline_policy_documents or not actual.inline_policy_documents:
            return []

        expected_docs = dict(expected.inline_policy_documents)
        actual_docs = dict(actual.inline_policy_documents)

        # Only compare policies that exist in both
        shared_names = set(expected_docs.keys()) & set(actual_docs.keys())
        findings: list[DriftFinding] = []

        for name in sorted(shared_names):
            expected_doc = expected_docs[name]
            actual_doc = actual_docs[name]

            if self._documents_differ(expected_doc, actual_doc):
                extra_statements = self._find_extra_statements(
                    expected_doc, actual_doc
                )
                findings.append(
                    DriftFinding(
                        resource_type=self._RESOURCE_TYPE,
                        resource_id=expected.role_name,
                        stack_name=expected.stack_name,
                        drift_type=DriftType.INLINE_POLICY_MODIFIED,
                        severity=Severity.HIGH,
                        description=(
                            f"Inline policy '{name}' on role "
                            f"'{expected.role_name}' has been modified. "
                            f"The policy document differs from what is declared "
                            f"in the CloudFormation template."
                        ),
                        expected=expected_doc,
                        actual=actual_doc,
                        extra=extra_statements if extra_statements else name,
                    ),
                )

        return findings

    def _documents_differ(
        self, expected: dict[str, Any], actual: dict[str, Any]
    ) -> bool:
        """Check if two policy documents differ (normalized comparison)."""
        return self._normalize_doc(expected) != self._normalize_doc(actual)

    def _normalize_doc(self, doc: dict[str, Any]) -> str:
        """Normalize a policy document for comparison (sorted keys, no whitespace)."""
        return json.dumps(doc, sort_keys=True, separators=(",", ":"))

    def _find_extra_statements(
        self, expected: dict[str, Any], actual: dict[str, Any]
    ) -> list[dict[str, Any]] | None:
        """Find statements in actual that don't exist in expected."""
        expected_stmts = expected.get("Statement", [])
        actual_stmts = actual.get("Statement", [])

        if not isinstance(expected_stmts, list) or not isinstance(actual_stmts, list):
            return None

        expected_normalized = {
            json.dumps(s, sort_keys=True) for s in expected_stmts
        }
        extra = [
            s for s in actual_stmts
            if json.dumps(s, sort_keys=True) not in expected_normalized
        ]
        return extra if extra else None
