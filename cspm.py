#!/usr/bin/env python3

import sys
import click
import boto3
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from scanners.base_scanner import Status, Severity

console = Console()

# scanner registry - add new scanners here
SCANNERS = {}

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

    console.print("[yellow]No scanners configured yet[/yellow]")


if __name__ == "__main__":
    main()
