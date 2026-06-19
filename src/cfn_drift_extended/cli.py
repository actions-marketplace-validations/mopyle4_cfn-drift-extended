"""Click CLI entry point for cfn-drift-extended.

Handles user-facing concerns: argument parsing, output formatting,
exit codes, and error presentation. Delegates all business logic to Auditor.
"""

import logging
import sys
from pathlib import Path

import click

from cfn_drift_extended.auditor import ALL_SERVICES, Auditor
from cfn_drift_extended.exceptions import AWSPermissionError, CfnDriftExtendedError
from cfn_drift_extended.reporters.console import ConsoleReporter
from cfn_drift_extended.reporters.json_report import JsonReporter

# Valid AWS region format: 2-3 letter prefix, dash, direction, dash, number
_REGION_PREFIXES = (
    "us-", "eu-", "ap-", "sa-", "ca-", "me-", "af-", "il-", "cn-",
)


def _validate_stack_prefix(
    ctx: click.Context, param: click.Parameter, value: str | None
) -> str | None:
    """Validate stack prefix is non-empty and reasonable length."""
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        raise click.BadParameter("Stack prefix cannot be empty or whitespace.")
    if len(stripped) > 128:
        raise click.BadParameter("Stack prefix cannot exceed 128 characters.")
    return stripped


def _validate_region(ctx: click.Context, param: click.Parameter, value: str) -> str:
    """Basic validation that region looks like an AWS region."""
    if not any(value.startswith(p) for p in _REGION_PREFIXES):
        raise click.BadParameter(
            f"'{value}' does not look like a valid AWS region. "
            f"Expected format: us-east-1, eu-west-2, etc."
        )
    return value


@click.group()
@click.version_option(package_name="cfn-drift-extended")
def main() -> None:
    """cfn-drift-extended — Detect additive drift that CloudFormation misses."""


@main.command()
@click.option(
    "--stack-prefix",
    default=None,
    callback=_validate_stack_prefix,
    help="Only audit stacks whose names start with this prefix.",
)
@click.option(
    "--stack-name",
    multiple=True,
    help="Exact stack name(s) to audit. Can be specified multiple times.",
)
@click.option(
    "--tag",
    multiple=True,
    help="Filter stacks by tag (format: Key=Value). Can be specified multiple times.",
)
@click.option(
    "--region",
    default="us-east-1",
    show_default=True,
    callback=_validate_region,
    help="AWS region to scan.",
)
@click.option(
    "--profile",
    default=None,
    help="AWS profile name to use (from ~/.aws/config).",
)
@click.option(
    "--output-json",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write JSON report to this file path.",
)
@click.option(
    "--fail-on-drift/--no-fail-on-drift",
    default=True,
    show_default=True,
    help="Exit with non-zero code if drift is detected (useful for CI).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose logging.",
)
@click.option(
    "--max-workers",
    type=click.IntRange(min=1, max=50),
    default=10,
    show_default=True,
    help="Maximum concurrent API calls for role auditing.",
)
@click.option(
    "--services",
    default=None,
    help=(
        "Comma-separated list of services to audit. "
        "Options: iam,sg,sns,sqs,eventbridge. Default: all."
    ),
)
def audit(
    stack_prefix: str | None,
    stack_name: tuple[str, ...],
    tag: tuple[str, ...],
    region: str,
    profile: str | None,
    output_json: Path | None,
    fail_on_drift: bool,
    verbose: bool,
    max_workers: int,
    services: str | None,
) -> None:
    """Audit resources for additive drift against CloudFormation templates."""
    # Validate that at least one filter is provided
    if not stack_prefix and not stack_name:
        click.secho(
            "Error: Must provide either --stack-prefix or --stack-name.",
            fg="red",
            err=True,
        )
        sys.exit(2)

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # Parse tag filters
    tag_filter: dict[str, str] | None = None
    if tag:
        tag_filter = {}
        for t in tag:
            if "=" not in t:
                click.secho(
                    f"Error: Invalid tag format '{t}'. Expected Key=Value.",
                    fg="red",
                    err=True,
                )
                sys.exit(2)
            key, value = t.split("=", 1)
            tag_filter[key] = value

    try:
        # Parse services filter
        enabled_services: frozenset[str] | None = None
        if services:
            requested = frozenset(s.strip().lower() for s in services.split(","))
            invalid = requested - ALL_SERVICES
            if invalid:
                click.secho(
                    f"Error: Invalid service(s): {', '.join(sorted(invalid))}. "
                    f"Valid options: {', '.join(sorted(ALL_SERVICES))}",
                    fg="red",
                    err=True,
                )
                sys.exit(2)
            enabled_services = requested

        auditor = Auditor(
            region=region,
            max_workers=max_workers,
            profile=profile,
            services=enabled_services,
        )
        report = auditor.audit_stacks(
            stack_prefix=stack_prefix or "",
            stack_names=list(stack_name) if stack_name else None,
            tag_filter=tag_filter,
        )
    except AWSPermissionError as e:
        click.secho(f"\n✗ Permission error: {e}", fg="red", err=True)
        if e.details:
            click.secho(f"  Details: {e.details}", fg="red", err=True)
        sys.exit(2)
    except CfnDriftExtendedError as e:
        click.secho(f"\n✗ Error: {e}", fg="red", err=True)
        sys.exit(2)
    except Exception as e:
        click.secho(f"\n✗ Unexpected error: {e}", fg="red", err=True)
        logger = logging.getLogger(__name__)
        logger.debug("Full traceback:", exc_info=True)
        sys.exit(2)

    # Console output
    console = ConsoleReporter()
    console.render(report)

    # JSON output
    if output_json:
        json_reporter = JsonReporter()
        json_reporter.render(report, output_path=output_json)
        click.echo(f"\nJSON report written to: {output_json}")

    # Report non-fatal errors
    if report.has_errors:
        click.secho(
            f"\n⚠ {len(report.errors)} non-fatal error(s) occurred during audit.",
            fg="yellow",
            err=True,
        )

    # Exit code for CI/CD
    if fail_on_drift and report.has_drift:
        sys.exit(1)


@main.command()
@click.option(
    "--stack-prefix",
    default=None,
    callback=_validate_stack_prefix,
    help="Only include stacks whose names start with this prefix in the index.",
)
@click.option(
    "--region",
    default="us-east-1",
    show_default=True,
    callback=_validate_region,
    help="AWS region to scan.",
)
@click.option(
    "--profile",
    default=None,
    help="AWS profile name to use (from ~/.aws/config).",
)
@click.option(
    "--output-json",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write JSON report to this file path.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose logging.",
)
@click.option(
    "--max-workers",
    type=click.IntRange(min=1, max=50),
    default=10,
    show_default=True,
    help="Maximum concurrent API calls for orphan detection.",
)
@click.option(
    "--max-deleted-stacks",
    type=click.IntRange(min=1),
    default=200,
    show_default=True,
    help=(
        "Maximum number of deleted stacks to scan for provenance. "
        "Caps the scan for accounts with thousands of deleted stacks. "
        "Use 0 or omit to scan all within the 90-day window."
    ),
)
@click.option(
    "--max-cfn-workers",
    type=click.IntRange(min=1, max=20),
    default=5,
    show_default=True,
    help=(
        "Maximum concurrent CloudFormation API calls for provenance lookup. "
        "Separate from --max-workers to avoid CFN API throttling."
    ),
)
@click.option(
    "--services",
    default=None,
    help=(
        "Comma-separated list of services to scan for orphans. "
        "Options: iam,sg,lambda,sqs,sns. Default: all."
    ),
)
def orphans(
    stack_prefix: str | None,
    region: str,
    profile: str | None,
    output_json: Path | None,
    verbose: bool,
    max_workers: int,
    max_deleted_stacks: int,
    max_cfn_workers: int,
    services: str | None,
) -> None:
    """Detect orphaned resources not managed by any CloudFormation stack."""
    from cfn_drift_extended.orphan_auditor import ALL_ORPHAN_SERVICES, OrphanAuditor

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        # Parse services filter
        enabled_services: frozenset[str] | None = None
        if services:
            requested = frozenset(s.strip().lower() for s in services.split(","))
            invalid = requested - ALL_ORPHAN_SERVICES
            if invalid:
                click.secho(
                    f"Error: Invalid service(s): {', '.join(sorted(invalid))}. "
                    f"Valid options: {', '.join(sorted(ALL_ORPHAN_SERVICES))}",
                    fg="red",
                    err=True,
                )
                sys.exit(2)
            enabled_services = requested

        auditor = OrphanAuditor(
            region=region,
            profile=profile,
            services=enabled_services,
            max_workers=max_workers,
            max_deleted_stacks=max_deleted_stacks if max_deleted_stacks > 0 else None,
            max_cfn_workers=max_cfn_workers,
        )
        report = auditor.detect_orphans(
            stack_prefix=stack_prefix or "",
        )
    except AWSPermissionError as e:
        click.secho(f"\n✗ Permission error: {e}", fg="red", err=True)
        if e.details:
            click.secho(f"  Details: {e.details}", fg="red", err=True)
        sys.exit(2)
    except CfnDriftExtendedError as e:
        click.secho(f"\n✗ Error: {e}", fg="red", err=True)
        sys.exit(2)
    except Exception as e:
        click.secho(f"\n✗ Unexpected error: {e}", fg="red", err=True)
        logger = logging.getLogger(__name__)
        logger.debug("Full traceback:", exc_info=True)
        sys.exit(2)

    # Summary output
    click.echo(f"\n{'='*60}")
    click.echo(f"Orphan Detection Report — {region}")
    click.echo(f"{'='*60}")
    click.echo(f"Resources scanned: {report.resources_scanned}")
    click.echo(f"Orphans found: {report.orphans_found}")

    if report.findings:
        click.echo(f"\n{'─'*60}")
        for finding in report.findings:
            provenance_label = f" [{finding.provenance}]" if finding.provenance else ""
            origin = (
                f" (from stack: {finding.originating_stack_name})"
                if finding.originating_stack_name
                else ""
            )
            click.secho(
                f"  [{finding.severity.upper()}] {finding.resource_type}: "
                f"{finding.resource_id}{provenance_label}{origin}",
                fg="red" if finding.severity == "high" else "yellow",
            )
            click.echo(f"    {finding.description}")
        click.echo(f"{'─'*60}")

    # JSON output
    if output_json:
        import json

        output_json.write_text(
            json.dumps(report.model_dump(mode="json"), indent=2)
        )
        click.echo(f"\nJSON report written to: {output_json}")

    # Report non-fatal errors
    if report.errors:
        click.secho(
            f"\n⚠ {len(report.errors)} non-fatal error(s) occurred.",
            fg="yellow",
            err=True,
        )

    # Exit code: non-zero if orphans found
    if report.orphans_found > 0:
        sys.exit(1)
