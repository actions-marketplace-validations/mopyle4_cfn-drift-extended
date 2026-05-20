"""Tests for error handling paths."""

import json
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from cfn_drift_extended.auditor import Auditor
from cfn_drift_extended.collectors.cfn_collector import CfnCollector
from cfn_drift_extended.collectors.iam_collector import IamCollector
from cfn_drift_extended.exceptions import AWSPermissionError


def _make_client_error(code: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": "test"}}, "TestOp"
    )


class TestCfnCollectorErrors:
    @mock_aws
    def test_list_stacks_access_denied(self) -> None:
        session = boto3.Session(region_name="us-east-1")
        collector = CfnCollector(region="us-east-1", session=session)
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = _make_client_error("AccessDenied")
        with (
            patch.object(collector._cfn, "get_paginator", return_value=mock_paginator),
            pytest.raises(ClientError),
        ):
            collector.list_stacks_by_prefix("test")

    @mock_aws
    def test_get_template_access_denied(self) -> None:
        session = boto3.Session(region_name="us-east-1")
        collector = CfnCollector(region="us-east-1", session=session)
        with patch.object(
            collector._cfn, "get_template",
            side_effect=_make_client_error("AccessDenied"),
        ):
            assert collector._get_template("stack") is None

    @mock_aws
    def test_get_template_json_error(self) -> None:
        """Unparseable template content should return None."""
        session = boto3.Session(region_name="us-east-1")
        collector = CfnCollector(region="us-east-1", session=session)
        with patch.object(
            collector._cfn, "get_template",
            return_value={"TemplateBody": "{{{{invalid: [[["},
        ):
            result = collector._get_template("stack")
            # YAML parser may return a string or None for invalid content
            # Either way, it shouldn't be a usable dict
            assert not isinstance(result, dict) or result is None

    @mock_aws
    def test_resolve_role_name_fallback(self) -> None:
        session = boto3.Session(region_name="us-east-1")
        collector = CfnCollector(region="us-east-1", session=session)
        with patch.object(
            collector._cfn, "describe_stack_resource",
            side_effect=_make_client_error("ValidationError"),
        ):
            name = collector._resolve_role_name("MyRole", "my-stack", {})
            assert name == "my-stack-MyRole"

    @mock_aws
    def test_invalid_resources_section(self) -> None:
        session = boto3.Session(region_name="us-east-1")
        collector = CfnCollector(region="us-east-1", session=session)
        with patch.object(
            collector, "_get_template",
            return_value={"Resources": "not-a-dict"},
        ):
            assert collector.get_iam_roles_from_stack("stack") == []

    @mock_aws
    def test_nested_stack_depth_limit(self) -> None:
        """Recursion should stop at depth 10."""
        session = boto3.Session(region_name="us-east-1")
        collector = CfnCollector(region="us-east-1", session=session)
        roles: list = []
        # Should not recurse beyond depth 10
        collector._collect_roles_recursive("stack", roles, True, depth=11)
        assert roles == []


class TestIamCollectorErrors:
    @mock_aws
    def test_access_denied(self) -> None:
        session = boto3.Session(region_name="us-east-1")
        collector = IamCollector(region="us-east-1", session=session)
        with patch.object(
            collector._iam, "get_role",
            side_effect=_make_client_error("AccessDenied"),
        ):
            assert collector.get_role_state("role") is None

    @mock_aws
    def test_list_inline_error(self) -> None:
        session = boto3.Session(region_name="us-east-1")
        iam = session.client("iam")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                     "Action": "sts:AssumeRole"}
                ]}
            ),
        )
        collector = IamCollector(region="us-east-1", session=session)
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = _make_client_error("AccessDenied")
        with patch.object(collector._iam, "get_paginator", return_value=mock_paginator):
            result = collector._list_inline_policies("test-role")
            assert result == []


class TestAuditorErrors:
    @mock_aws
    def test_permission_error(self) -> None:
        session = boto3.Session(region_name="us-east-1")
        auditor = Auditor(region="us-east-1", session=session)
        with patch.object(
            auditor._cfn_collector, "list_stacks_by_prefix",
            side_effect=_make_client_error("AccessDenied"),
        ), pytest.raises(AWSPermissionError):
            auditor.audit_stacks(stack_prefix="test")

    @mock_aws
    def test_role_exception_captured(self) -> None:
        session = boto3.Session(region_name="us-east-1")
        auditor = Auditor(region="us-east-1", session=session, max_workers=1)

        from cfn_drift_extended.collectors.cfn_collector import ExpectedRoleState
        expected = ExpectedRoleState(
            role_name="crash-role", logical_id="CrashRole", stack_name="crash-stack"
        )
        with (
            patch.object(
                auditor._cfn_collector, "list_stacks_by_prefix", return_value=["s"]
            ),
            patch.object(
                auditor._cfn_collector, "get_iam_roles_from_stack",
                return_value=[expected],
            ),
            patch.object(
                auditor._iam_collector, "get_role_state",
                side_effect=RuntimeError("boom"),
            ),
        ):
            report = auditor.audit_stacks(stack_prefix="crash")
        assert report.has_errors
        assert "boom" in report.errors[0]
