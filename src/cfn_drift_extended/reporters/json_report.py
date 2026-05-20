"""JSON reporter for machine-readable output.

Produces deterministic JSON suitable for CI/CD pipelines and diff comparison.
"""

import logging
from pathlib import Path

from cfn_drift_extended.models import AuditReport

logger = logging.getLogger(__name__)


class JsonReporter:
    """Renders audit results as JSON for CI/CD integration."""

    def render(self, report: AuditReport, output_path: Path | None = None) -> str:
        """Serialize the report to JSON.

        Args:
            report: The audit report to serialize.
            output_path: Optional file path to write the JSON to.

        Returns:
            The JSON string representation of the report.

        Raises:
            OSError: If the output file cannot be written.
        """
        json_str = report.model_dump_json(indent=2)

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_str, encoding="utf-8")
            logger.info("JSON report written to %s", output_path)

        return json_str
