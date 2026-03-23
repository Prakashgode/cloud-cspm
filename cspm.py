#!/usr/bin/env python3

import sys
from typing import Any

import boto3
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from reports.generator import ReportGenerator
from scanners import (
    EC2Scanner,
    IAMScanner,
    LambdaScanner,
    LoggingScanner,
    RDSScanner,
    S3Scanner,
    SecretsManagerScanner,
)
from scanners.base_scanner import Finding, Status

console = Console()

# scanner registry - add new scanners here
SCANNERS = {
    "iam": ("IAM Security", IAMScanner),
    "s3": ("S3 Bucket Security", S3Scanner),
    "ec2": ("EC2 & Network Security", EC2Scanner),
    "rds": ("RDS Database Security", RDSScanner),
    "logging": ("Logging & Monitoring", LoggingScanner),
    "lambda": ("Lambda Security", LambdaScanner),
    "secrets": ("Secrets Manager Security", SecretsManagerScanner),
}

SEVERITY_COLORS = {
    "CRITICAL": "red bold",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}

STATUS_ICONS = {
    "PASS": "[green]PASS[/green]",
    "FAIL": "[red]FAIL[/red]",
    "ERROR": "[yellow]ERROR[/yellow]",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def create_base_session(profile: str | None, region: str | None):
    session_kwargs: dict[str, str] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region
    return boto3.Session(**session_kwargs)


def get_identity(session) -> dict[str, Any]:
    sts = session.client("sts")
    return sts.get_caller_identity()


def assume_role_session(
    session,
    role_arn: str,
    session_name: str,
    external_id: str | None,
    region: str | None,
):
    sts = session.client("sts")
    assume_kwargs = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
    }
    if external_id:
        assume_kwargs["ExternalId"] = external_id

    response = sts.assume_role(**assume_kwargs)
    credentials = response["Credentials"]

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )


def build_scan_session(
    profile: str | None,
    region: str | None,
    role_arn: str | None,
    external_id: str | None,
    session_name: str,
):
    base_session = create_base_session(profile, region)
    base_identity = get_identity(base_session)

    if not role_arn:
        return base_session, base_identity, None

    assumed_session = assume_role_session(
        base_session,
        role_arn,
        session_name,
        external_id,
        region,
    )
    assumed_identity = get_identity(assumed_session)
    return assumed_session, assumed_identity, base_identity


@click.command()
@click.option("--profile", default=None, help="AWS CLI profile name")
@click.option("--region", default=None, help="AWS region (default: all regions)")
@click.option("--role-arn", default=None, help="Assume this IAM role before scanning")
@click.option("--external-id", default=None, help="External ID for STS AssumeRole if required")
@click.option(
    "--session-name",
    default="cloud-cspm",
    show_default=True,
    help="STS role session name when using --role-arn",
)
@click.option(
    "--scanner",
    multiple=True,
    type=click.Choice(list(SCANNERS.keys()) + ["all"]),
    default=["all"],
    help="Scanners to run",
)
@click.option("--output", default=None, help="Output file path (JSON, CSV, or SARIF)")
@click.option(
    "--severity",
    default=None,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    help="Minimum severity to display",
)
def main(profile, region, role_arn, external_id, session_name, scanner, output, severity):
    console.print(
        Panel(
            Text("Cloud CSPM", style="bold cyan", justify="center"),
            subtitle="AWS Security Posture Management",
            border_style="cyan",
        )
    )

    try:
        session, identity, source_identity = build_scan_session(
            profile,
            region,
            role_arn,
            external_id,
            session_name,
        )

        if source_identity:
            console.print(f"\n[green]Source identity:[/green] {source_identity['Arn']}")
            console.print(f"[green]Assumed role:[/green] {identity['Arn']}")
            console.print(f"[green]Target account:[/green] {identity['Account']}\n")
        else:
            console.print(f"\n[green]Authenticated as:[/green] {identity['Arn']}")
            console.print(f"[green]Account:[/green] {identity['Account']}\n")
    except Exception as e:
        console.print(f"[red]Authentication failed:[/red] {e}")
        console.print("Configure AWS credentials with aws configure or provide a valid role ARN")
        sys.exit(1)

    scanners_to_run = list(SCANNERS.keys()) if "all" in scanner else list(scanner)
    all_findings: list[Finding] = []

    for scanner_name in scanners_to_run:
        label, scanner_class = SCANNERS[scanner_name]
        console.print(f"[cyan]Scanning:[/cyan] {label}...")

        try:
            s = scanner_class(session)
            findings = s.scan()
            all_findings.extend(findings)

            passed = sum(1 for f in findings if f.status == Status.PASS)
            failed = sum(1 for f in findings if f.status == Status.FAIL)
            console.print(f"  [green]{passed} passed[/green] | [red]{failed} failed[/red]")
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

    if severity:
        min_index = SEVERITY_ORDER.index(severity)
        all_findings = [
            f for f in all_findings if SEVERITY_ORDER.index(f.severity.value) <= min_index
        ]

    console.print()
    table = Table(title="Security Findings", show_lines=True)
    table.add_column("ID", style="dim", width=12)
    table.add_column("Check", width=28)
    table.add_column("Status", width=8, justify="center")
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Resource", width=30)
    table.add_column("Description", width=50)

    for finding in sorted(
        all_findings,
        key=lambda item: (
            item.status.value != "FAIL",
            SEVERITY_ORDER.index(item.severity.value),
        ),
    ):
        severity_style = SEVERITY_COLORS.get(finding.severity.value, "")
        table.add_row(
            finding.check_id,
            finding.check_name,
            STATUS_ICONS.get(finding.status.value, finding.status.value),
            f"[{severity_style}]{finding.severity.value}[/{severity_style}]",
            finding.resource_id[:30],
            finding.description[:50],
        )

    console.print(table)

    report = ReportGenerator(all_findings)
    summary = report.summary()

    console.print(
        Panel(
            f"[bold]Total Checks:[/bold] {summary['total_checks']}\n"
            f"[green]Passed:[/green] {summary['passed']}\n"
            f"[red]Failed:[/red] {summary['failed']}\n"
            f"[yellow]Errors:[/yellow] {summary['errors']}\n"
            f"[bold]Security Score:[/bold] {summary['score']}%\n\n"
            f"[bold]Failures by Severity:[/bold]\n"
            + "\n".join(
                f"  [{SEVERITY_COLORS.get(key, '')}]{key}:[/{SEVERITY_COLORS.get(key, '')}] {value}"
                for key, value in summary["failures_by_severity"].items()
            ),
            title="Scan Summary",
            border_style="cyan",
        )
    )

    if output:
        normalized_output = output.lower()
        if normalized_output.endswith(".csv"):
            report.to_csv(output)
        elif normalized_output.endswith(".sarif") or normalized_output.endswith(".sarif.json"):
            report.to_sarif(output)
        else:
            report.to_json(output)
        console.print(f"\n[green]Report saved to:[/green] {output}")


if __name__ == "__main__":
    main()
