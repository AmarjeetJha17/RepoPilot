"""Typer command registration for the RepoPilot command-line application."""

from importlib.metadata import version as package_version
from typing import Annotated

import typer

from repopilot.application.services import inspect_environment
from repopilot.ui.doctor import render_doctor

app = typer.Typer(add_completion=False, no_args_is_help=True)


def _version_callback(value: bool | None) -> None:
    if value:
        typer.echo(f"RepoPilot {package_version('repopilot')}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the installed version and exit.",
        ),
    ] = None,
) -> None:
    """Inspect the local environment for RepoPilot."""


@app.command()
def doctor() -> None:
    """Check Python, local tools, and whether this directory is a Git repository."""
    report = inspect_environment()
    render_doctor(report)
    if report.exit_code:
        raise typer.Exit(code=report.exit_code)


def main() -> None:
    """Run the shared Typer application from the console script or module entry."""
    app()
