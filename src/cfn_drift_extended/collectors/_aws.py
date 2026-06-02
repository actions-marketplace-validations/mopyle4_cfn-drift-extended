"""Shared AWS-client configuration for collectors.

A single ``Config`` instance keeps retry behavior consistent across every
collector and the auditor — adaptive mode with five attempts handles the
throttling we see when sweeping a large account in parallel.
"""

from botocore.config import Config

BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})
