"""Rich presentation for environment check results."""

from rich.console import Console
from rich.table import Table
from rich.text import Text

from repopilot.application.services import CheckStatus, DoctorReport


def render_doctor(report: DoctorReport) -> None:
    """Render statuses as text labels with optional color for terminal output."""
    styles = {
        CheckStatus.PASS: "green",
        CheckStatus.WARN: "yellow",
        CheckStatus.FAIL: "red",
    }
    table = Table(title="RepoPilot · doctor", box=None, safe_box=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Result")
    for check in report.checks:
        result = Text(f"[{check.status.value}] ", style=styles[check.status])
        result.append(check.detail)
        table.add_row(check.name, result)
    Console().print(table)
