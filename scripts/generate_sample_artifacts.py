from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from reports.generator import ReportGenerator
from scanners.base_scanner import Finding, Severity, Status

ROOT_DIR = Path(__file__).resolve().parents[1]
ASSETS_DIR = ROOT_DIR / "assets"
SAMPLES_DIR = ROOT_DIR / "samples"
FIXED_TIME = "2026-03-22T15:30:00+00:00"

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


def sample_findings() -> list[Finding]:
    return [
        Finding(
            check_id="CIS-1.1",
            check_name="Avoid Root Account Without MFA",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            resource_id="root-account",
            resource_type="AWS::IAM::Account",
            region="global",
            description="Root account MFA is not enabled",
            remediation="Enable a hardware or virtual MFA device on the root account",
            timestamp=FIXED_TIME,
        ),
        Finding(
            check_id="CIS-3.2",
            check_name="S3 Encryption",
            status=Status.PASS,
            severity=Severity.HIGH,
            resource_id="demo-logs",
            resource_type="AWS::S3::Bucket",
            region="global",
            description="Bucket 'demo-logs' has encryption enabled (AES256)",
            remediation=(
                "aws s3api put-bucket-encryption --bucket demo-logs "
                "--server-side-encryption-configuration "
                "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
            ),
            timestamp=FIXED_TIME,
        ),
        Finding(
            check_id="LAMBDA-1",
            check_name="Lambda Public Access",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            resource_id="public-demo-fn",
            resource_type="AWS::Lambda::Function",
            region="us-east-1",
            description="Function URL or policy allows public invoke",
            remediation="Require AWS_IAM authentication and remove wildcard invoke permissions",
            timestamp=FIXED_TIME,
        ),
        Finding(
            check_id="SECRETS-1",
            check_name="Secrets Manager Rotation Enabled",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            resource_id="prod/db/password",
            resource_type="AWS::SecretsManager::Secret",
            region="us-east-1",
            description="Secret rotation is disabled",
            remediation="Enable automatic rotation for the secret and attach a rotation Lambda",
            timestamp=FIXED_TIME,
        ),
    ]


def render_demo_svg(findings: list[Finding]) -> None:
    console = Console(record=True, width=160)
    report = ReportGenerator(findings, timestamp=FIXED_TIME)
    summary = report.summary()

    console.print(
        "[bold cyan]$[/bold cyan] cloud-cspm --profile audit "
        "--role-arn arn:aws:iam::123456789012:role/SecurityAudit "
        "--output report.sarif"
    )
    console.print(
        Panel(
            Text("Cloud CSPM", style="bold cyan", justify="center"),
            subtitle="AWS Security Posture Management",
            border_style="cyan",
        )
    )
    console.print("\n[green]Authenticated as:[/green] arn:aws:sts::123456789012:assumed-role/SecurityAudit/cloud-cspm")
    console.print("[green]Account:[/green] 123456789012\n")

    table = Table(title="Security Findings", show_lines=True)
    table.add_column("ID", style="dim", width=12)
    table.add_column("Check", width=30)
    table.add_column("Status", width=8, justify="center")
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Resource", width=28)
    table.add_column("Description", width=56)

    for finding in sorted(
        findings,
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
            finding.resource_id[:28],
            finding.description[:56],
        )

    console.print(table)
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
    console.save_svg(str(ASSETS_DIR / "cloud-cspm-demo.svg"), title="Cloud CSPM Demo")


def main() -> None:
    ASSETS_DIR.mkdir(exist_ok=True)
    SAMPLES_DIR.mkdir(exist_ok=True)

    findings = sample_findings()
    report = ReportGenerator(findings, timestamp=FIXED_TIME)
    report.to_json(str(SAMPLES_DIR / "demo-report.json"))
    report.to_csv(str(SAMPLES_DIR / "demo-report.csv"))
    report.to_sarif(str(SAMPLES_DIR / "demo-report.sarif"))
    render_demo_svg(findings)


if __name__ == "__main__":
    main()
