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

## OpenAI provider adapter

The offline `MockModelProvider` remains available for deterministic tests. Code
that needs the live Responses API can explicitly instantiate
`repopilot.providers.adapters.openai.OpenAIModelProvider`; the functional CLI
does not select a model provider yet. The SDK reads `OPENAI_API_KEY` from the
process environment. Keep the key outside the repository and never put it in
source files or command output.

The adapter sends the `ModelRequest` messages and function schemas to OpenAI.
Do not send private repository content unless you have chosen to do so. API
requests may incur charges. Normal tests, lint, type checking, and builds use
mocked responses and make no API calls.

For an explicit, minimal live check, configure `OPENAI_API_KEY` and run:

```bash
uv run python scripts/openai_smoke.py --model YOUR_MODEL_ID
```

This sends only a fixed “reply with OK” prompt, has a 15-second timeout, and
does not read repository files or execute tools. It reports success without
printing the model response. The adapter currently supports completed text
responses and function-call proposals. It rejects mixed text and function-call
outputs, reasoning items, refusals, incomplete responses, and other output
types because the provider-neutral response contract cannot preserve their
continuation data safely. It also rejects assistant history entries that
combine text and tool calls because their ordering is not represented.

## Current status

The initial CLI and read-only environment check, agent lifecycle contracts,
mock provider, and OpenAI Responses API adapter are implemented. Agent
orchestration, repository tools, sandboxing, persistence, and evaluation
execution are not implemented yet. The OpenAI adapter has not been tested
against a live API invocation.

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
