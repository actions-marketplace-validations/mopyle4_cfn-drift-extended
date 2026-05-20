"""Tests for the exception hierarchy."""

from cfn_drift_extended.exceptions import (
    AWSPermissionError,
    AWSThrottlingError,
    CfnDriftExtendedError,
)


class TestExceptionHierarchy:
    def test_base_exception(self) -> None:
        err = CfnDriftExtendedError("test message")
        assert str(err) == "test message"
        assert err.details is None

    def test_base_exception_with_details(self) -> None:
        err = CfnDriftExtendedError("msg", details="extra info")
        assert err.details == "extra info"

    def test_permission_error_is_base(self) -> None:
        err = AWSPermissionError("no access")
        assert isinstance(err, CfnDriftExtendedError)

    def test_throttling_error_is_base(self) -> None:
        err = AWSThrottlingError("too fast")
        assert isinstance(err, CfnDriftExtendedError)

    def test_exceptions_are_catchable_by_base(self) -> None:
        exceptions = [
            AWSPermissionError("test"),
            AWSThrottlingError("test"),
        ]
        for exc in exceptions:
            try:
                raise exc
            except CfnDriftExtendedError:
                pass
