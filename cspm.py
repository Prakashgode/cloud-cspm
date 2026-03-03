#!/usr/bin/env python3

import sys
import click
import boto3
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from scanners import IAMScanner, S3Scanner, EC2Scanner, RDSScanner, LoggingScanner
from scanners.base_scanner import Status, Severity

console = Console()

# scanner registry - add new scanners here
SCANNERS = {
    "iam": ("IAM Security", IAMScanner),
    "s3": ("S3 Bucket Security", S3Scanner),
    "ec2": ("EC2 & Network Security", EC2Scanner),
    "rds": ("RDS Database Security", RDSScanner),
    "logging": ("Logging & Monitoring", LoggingScanner),
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


@click.command()
@click.option("--profile", default=None, help="AWS CLI profile name")
@click.option("--region", default=None, help="AWS region (default: all regions)")
def main(profile, region):
    console.print(
        Panel(
            Text("Cloud CSPM", style="bold cyan", justify="center"),
            subtitle="AWS Security Posture Management",
            border_style="cyan",
        )
    )

    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    try:
        session = boto3.Session(**session_kwargs)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        console.print(f"\n[green]Authenticated as:[/green] {identity['Arn']}")
        console.print(f"[green]Account:[/green] {identity['Account']}\n")
    except Exception as e:
        console.print(f"[red]Authentication failed:[/red] {e}")
        console.print("Configure AWS credentials: aws configure")
        sys.exit(1)

    all_findings = []

    for scanner_name in SCANNERS:
        label, scanner_class = SCANNERS[scanner_name]
        console.print(f"[cyan]Scanning:[/cyan] {label}...")

        try:
            s = scanner_class(session)
            findings = s.scan()
            all_findings.extend(findings)

            passed = sum(1 for f in findings if f.status == Status.PASS)
            failed = sum(1 for f in findings if f.status == Status.FAIL)
            console.print(
                f"  [green]{passed} passed[/green] | [red]{failed} failed[/red]"
            )
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

    # basic results table
    console.print()
    table = Table(title="Security Findings", show_lines=True)
    table.add_column("ID", style="dim", width=10)
    table.add_column("Check", width=25)
    table.add_column("Status", width=8, justify="center")
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Resource", width=30)
    table.add_column("Description", width=50)

    for f in all_findings:
        severity_style = SEVERITY_COLORS.get(f.severity.value, "")
        table.add_row(
            f.check_id,
            f.check_name,
            STATUS_ICONS.get(f.status.value, f.status.value),
            f"[{severity_style}]{f.severity.value}[/{severity_style}]",
            f.resource_id[:30],
            f.description[:50],
        )

    console.print(table)


if __name__ == "__main__":
    main()
