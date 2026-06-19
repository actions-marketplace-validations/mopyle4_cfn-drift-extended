"""Collect actual Lambda function state from AWS.

Retrieves configuration, environment variables, layers, and resource-based
policy for a specific Lambda function. Used by the drift comparator to detect
additive changes not declared in the CloudFormation template.

Required IAM permissions (least privilege):
- lambda:GetFunction
- lambda:GetPolicy
"""

import json
import logging
from dataclasses import dataclass

import boto3
from botocore.exceptions import ClientError

from cfn_drift_extended.collectors._aws import BOTO_CONFIG

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ActualLambdaState:
    """Immutable snapshot of a Lambda function's actual state."""

    function_name: str
    environment_variables: dict[str, str]
    layer_arns: tuple[str, ...]
    resource_policy_statements: tuple[str, ...]


class LambdaCollector:
    """Collects actual Lambda function state from AWS.

    Args:
        region: AWS region to query.
        session: Optional boto3 session (uses default if not provided).
    """

    def __init__(self, region: str, session: boto3.Session | None = None) -> None:
        self._session = session or boto3.Session(region_name=region)
        self._region = region
        self._lambda = self._session.client("lambda", config=BOTO_CONFIG)

    def get_function_state(self, function_name: str) -> ActualLambdaState | None:
        """Get the actual state of a Lambda function.

        Args:
            function_name: Name or ARN of the Lambda function.

        Returns:
            ActualLambdaState if the function exists, None otherwise.
        """
        try:
            response = self._lambda.get_function(FunctionName=function_name)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ResourceNotFoundException":
                logger.warning("Lambda function '%s' does not exist", function_name)
            elif error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error("Permission denied accessing Lambda '%s'.", function_name)
            else:
                logger.error(
                    "Unexpected error for Lambda '%s': %s", function_name, error_code
                )
            return None

        config = response.get("Configuration", {})

        # Extract environment variables
        env_vars = config.get("Environment", {}).get("Variables", {})

        # Extract layer ARNs
        layers = config.get("Layers", [])
        layer_arns = tuple(layer.get("Arn", "") for layer in layers)

        # Extract resource-based policy statements
        policy_statements = self._get_resource_policy(function_name)

        return ActualLambdaState(
            function_name=config.get("FunctionName", function_name),
            environment_variables=dict(env_vars),
            layer_arns=layer_arns,
            resource_policy_statements=policy_statements,
        )

    def _get_resource_policy(self, function_name: str) -> tuple[str, ...]:
        """Retrieve the resource-based policy statements for a function.

        Returns an empty tuple if no policy exists or the call fails.
        """
        try:
            response = self._lambda.get_policy(FunctionName=function_name)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ResourceNotFoundException":
                # No resource policy — this is normal
                return ()
            logger.warning(
                "Failed to get policy for Lambda '%s': %s",
                function_name,
                error_code,
            )
            return ()

        policy_str = response.get("Policy", "{}")
        try:
            policy_doc = json.loads(policy_str)
        except (json.JSONDecodeError, TypeError):
            return ()

        statements = policy_doc.get("Statement", [])
        return tuple(json.dumps(stmt) for stmt in statements)
