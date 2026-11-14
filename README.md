# RepoPilot

RepoPilot is a local-first, terminal-based coding agent focused on producing
reviewable patches and measuring their quality with independent evaluation.

## Planned capabilities

- Inspect Python repositories and gather bounded code context.
- Propose changes through policy-checked tools and stage patches for review.
- Verify changes in an isolated environment and report evidence and failures.
- Run reproducible evaluations and retain redacted local run history.

These are project goals, not claims about implemented functionality. See
[PRD.md](PRD.md) and [ARCHITECTURE.md](ARCHITECTURE.md) for the project contracts.

## Install and run

Install [uv](https://docs.astral.sh/uv/) and Python 3.12 or newer. From the
repository root, sync the project and run the CLI:

```bash
uv sync
uv run repopilot --help
uv run repopilot --version
uv run repopilot doctor
uv run python -m repopilot --help
```

`doctor` checks the Python version, Git, uv, Docker CLI, and whether the current
directory is inside a Git repository. It does not contact the network or Docker
daemon, inspect credentials, or modify files. Missing tools and a non-Git
directory are warnings; it exits with status 1 only when Python is older than
3.12. Other warnings return status 0.

## Current status

The initial CLI and read-only environment check are implemented. Agent
orchestration, model integration, repository tools, sandboxing, persistence,
and evaluation execution are not implemented yet.

The project pins Python 3.12 in `.python-version`; `pyproject.toml` supports
Python 3.12 and newer.

## Continuous integration

GitHub Actions runs the quality checks on pushes to `main`, pull requests
targeting `main`, and manual `workflow_dispatch` runs. The workflow uses Ubuntu
and Python 3.12, installs dependencies from `uv.lock`, checks Ruff formatting
and lint, runs mypy and pytest, measures coverage, validates the pre-commit
configuration, and builds the package. When generated, `coverage.xml` is
uploaded as a workflow artifact; no third-party coverage service is used.

Run the same checks locally after `uv sync`:

```bash
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync mypy src/repopilot
uv run --no-sync pytest -q
uv run --no-sync pytest --cov=repopilot --cov-report=term-missing --cov-report=xml
uv run --no-sync pre-commit validate-config
uv build
```

The initial workflow is a single Ubuntu/Python 3.12 job. It does not yet run a
Windows matrix, Docker sandbox smoke tests, live-model evaluations, or enforce a
coverage threshold. Workflow behavior still needs confirmation on GitHub after
the repository is pushed.
