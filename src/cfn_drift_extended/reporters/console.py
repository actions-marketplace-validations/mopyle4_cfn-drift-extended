"""Console reporter for terminal output.

Provides color-coded, human-readable output for interactive use.
"""

import click

from cfn_drift_extended.models import AuditReport, DriftFinding, Severity

# Map severity to terminal color — defined once, used everywhere
_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}


class ConsoleReporter:
    """Renders audit results to the terminal with color-coded output."""

    def render(self, report: AuditReport) -> None:
        """Print the audit report to the console."""
        self._print_header(report)

        if not report.has_drift:
            click.secho("\n✓ No additive drift detected.", fg="green", bold=True)
            return

        click.secho(
            f"\n⚠ Found {len(report.findings)} drift finding(s) "
            f"across {report.resources_with_drift} resource(s):",
            fg="red",
            bold=True,
        )
        click.echo()

        for finding in report.findings:
            self._print_finding(finding)

    def _print_header(self, report: AuditReport) -> None:
        """Print the report header summary."""
        click.secho("═" * 60, fg="cyan")
        click.secho("  cfn-drift-extended — Additive Drift Report", fg="cyan", bold=True)
        click.secho("═" * 60, fg="cyan")
        click.echo(f"  Stacks scanned:    {report.stacks_scanned}")
        click.echo(f"  Resources scanned: {report.resources_scanned}")
        click.echo(f"  Resources drifted: {report.resources_with_drift}")

    def _print_finding(self, finding: DriftFinding) -> None:
        """Print a single drift finding."""
        color = _SEVERITY_COLORS.get(finding.severity, "white")
        severity_label = finding.severity.value.upper()

        click.secho(f"  [{severity_label}] ", fg=color, bold=True, nl=False)
        click.echo(f"{finding.resource_id} ({finding.stack_name})")
        click.echo(f"         {finding.description}")
        if finding.extra:
            click.secho(f"         + {finding.extra}", fg=color)
        click.echo()
