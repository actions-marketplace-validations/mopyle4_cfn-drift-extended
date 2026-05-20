"""Unit tests for the IAM comparator."""

from cfn_drift_extended.collectors.cfn_collector import ExpectedRoleState
from cfn_drift_extended.collectors.iam_collector import ActualRoleState
from cfn_drift_extended.comparators.iam_comparator import IamComparator
from cfn_drift_extended.models import DriftType, Severity


class TestIamComparator:
    """Tests for IamComparator.compare()."""

    def setup_method(self) -> None:
        self.comparator = IamComparator()

    def test_no_drift_when_in_sync(self) -> None:
        expected = ExpectedRoleState(
            role_name="my-role",
            logical_id="MyRole",
            stack_name="my-stack",
            inline_policy_names=("policy-a",),
            managed_policy_arns=("arn:aws:iam::123456789012:policy/managed-a",),
        )
        actual = ActualRoleState(
            role_name="my-role",
            inline_policy_names=("policy-a",),
            managed_policy_arns=("arn:aws:iam::123456789012:policy/managed-a",),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_detects_extra_inline_policy(self) -> None:
        expected = ExpectedRoleState(
            role_name="my-role",
            logical_id="MyRole",
            stack_name="my-stack",
            inline_policy_names=("policy-a",),
        )
        actual = ActualRoleState(
            role_name="my-role",
            inline_policy_names=("policy-a", "sneaky-manual-policy"),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        assert audit.findings[0].drift_type == DriftType.INLINE_POLICY_ADDED
        assert audit.findings[0].severity == Severity.HIGH
        assert audit.findings[0].extra == "sneaky-manual-policy"

    def test_detects_extra_managed_policy(self) -> None:
        expected = ExpectedRoleState(
            role_name="my-role",
            logical_id="MyRole",
            stack_name="my-stack",
            managed_policy_arns=("arn:aws:iam::123456789012:policy/declared",),
        )
        actual = ActualRoleState(
            role_name="my-role",
            managed_policy_arns=(
                "arn:aws:iam::123456789012:policy/declared",
                "arn:aws:iam::aws:policy/AdministratorAccess",
            ),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert audit.findings[0].drift_type == DriftType.MANAGED_POLICY_ATTACHED
        assert audit.findings[0].extra == "arn:aws:iam::aws:policy/AdministratorAccess"

    def test_detects_multiple_drift_findings(self) -> None:
        expected = ExpectedRoleState(
            role_name="my-role", logical_id="MyRole", stack_name="my-stack"
        )
        actual = ActualRoleState(
            role_name="my-role",
            inline_policy_names=("extra-inline-1", "extra-inline-2"),
            managed_policy_arns=("arn:aws:iam::aws:policy/ReadOnlyAccess",),
        )
        audit = self.comparator.compare(expected, actual)
        assert len(audit.findings) == 3

    def test_no_drift_when_actual_has_fewer_policies(self) -> None:
        expected = ExpectedRoleState(
            role_name="my-role",
            logical_id="MyRole",
            stack_name="my-stack",
            inline_policy_names=("policy-a", "policy-b"),
            managed_policy_arns=("arn:aws:iam::123456789012:policy/managed-a",),
        )
        actual = ActualRoleState(
            role_name="my-role",
            inline_policy_names=("policy-a",),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_findings_are_sorted(self) -> None:
        expected = ExpectedRoleState(
            role_name="my-role", logical_id="MyRole", stack_name="my-stack"
        )
        actual = ActualRoleState(
            role_name="my-role",
            inline_policy_names=("z-policy", "a-policy", "m-policy"),
        )
        audit = self.comparator.compare(expected, actual)
        extras = [f.extra for f in audit.findings]
        assert extras == ["a-policy", "m-policy", "z-policy"]

    def test_detects_modified_inline_policy(self) -> None:
        """Detect when an existing inline policy has extra statements added."""
        expected_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        }
        actual_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"},
            ],
        }
        expected = ExpectedRoleState(
            role_name="my-role",
            logical_id="MyRole",
            stack_name="my-stack",
            inline_policy_names=("my-policy",),
            inline_policy_documents=(("my-policy", expected_doc),),
        )
        actual = ActualRoleState(
            role_name="my-role",
            inline_policy_names=("my-policy",),
            inline_policy_documents=(("my-policy", actual_doc),),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        assert audit.findings[0].drift_type == DriftType.INLINE_POLICY_MODIFIED
        # Extra should contain the added statement
        assert audit.findings[0].extra is not None

    def test_no_modification_when_docs_match(self) -> None:
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        }
        expected = ExpectedRoleState(
            role_name="my-role",
            logical_id="MyRole",
            stack_name="my-stack",
            inline_policy_names=("my-policy",),
            inline_policy_documents=(("my-policy", doc),),
        )
        actual = ActualRoleState(
            role_name="my-role",
            inline_policy_names=("my-policy",),
            inline_policy_documents=(("my-policy", doc),),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_modification_only_checks_shared_policies(self) -> None:
        """Modified check only applies to policies in both expected and actual."""
        expected = ExpectedRoleState(
            role_name="my-role",
            logical_id="MyRole",
            stack_name="my-stack",
            inline_policy_names=("policy-a",),
            inline_policy_documents=(("policy-a", {"Statement": []}),),
        )
        actual = ActualRoleState(
            role_name="my-role",
            inline_policy_names=("policy-a", "policy-b"),
            inline_policy_documents=(
                ("policy-a", {"Statement": []}),
                ("policy-b", {"Statement": [{"Effect": "Allow"}]}),
            ),
        )
        audit = self.comparator.compare(expected, actual)
        # Should detect policy-b as added, but NOT as modified
        drift_types = [f.drift_type for f in audit.findings]
        assert DriftType.INLINE_POLICY_ADDED in drift_types
        assert DriftType.INLINE_POLICY_MODIFIED not in drift_types
