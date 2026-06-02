"""Helpers shared by the drift auditor and the orphan auditor.

These are small enough that each auditor previously kept its own copy. As
they accumulated they drifted out of sync; centralizing them keeps session
construction, account-id resolution, and the boto retry policy identical.
"""

import logging

import boto3

from cfn_drift_extended.collectors._aws import BOTO_CONFIG

logger = logging.getLogger(__name__)


def build_session(
    region: str,
    profile: str | None = None,
    session: boto3.Session | None = None,
) -> boto3.Session:
    """Return a boto3 Session honoring an explicit session > profile > default.

    Auditors expose all three knobs so callers can either pass a fully
    pre-built session (most flexible) or a profile string (most common).
    """
    if session is not None:
        return session
    if profile:
        return boto3.Session(region_name=region, profile_name=profile)
    return boto3.Session(region_name=region)


def get_account_id(session: boto3.Session) -> str:
    """Return the AWS account ID for report metadata, or 'unknown' on failure.

    STS access is so commonly granted that we treat the call as best-effort —
    a missing account id should never block an audit.
    """
    try:
        sts = session.client("sts", config=BOTO_CONFIG)
        return str(sts.get_caller_identity()["Account"])
    except Exception:
        logger.debug("Could not determine account ID")
        return "unknown"
