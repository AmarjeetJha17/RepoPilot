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
mock provider, OpenAI Responses API adapter, explicit typed tool registry,
security policy engine, bounded single-decision orchestrator, and Linux copy-based
repository workspace preparation are implemented. Phase 4.2 adds read-only,
bounded repository discovery, UTF-8 excerpts, literal search, Python AST symbol
indexing, and deterministic context selection over that staged copy. The
orchestrator validates and authorizes proposed calls but does not execute them;
repository intelligence is not registered as an executable model tool. Docker
sandbox execution, concrete repository tools, persistence, and evaluation
execution are not implemented yet.
Native Windows and macOS workspace preparation fails closed; use Linux or WSL2. Unsupported OpenAI
reasoning continuation remains rejected because the provider-neutral contract
cannot preserve its opaque state.
The OpenAI adapter has not been tested against a live API invocation.

Repository-intelligence defaults cap discovery at 20,000 entries, 2,000 files,
and depth 20; each input file at 1 MB; returned text at 64 KB and 400 lines;
search at 500 files, 4 MB, and 500 matches; Python indexing at 500 files, 8 MB,
and 50,000 AST nodes; and combined selected context at 64 KB. These operations
read only an active workspace owned by its `WorkspaceManager`. Secret filtering
is best-effort, and AST results are syntactic rather than semantic. Trusted
application configuration can change these defaults but must keep them bounded.

### Linux workspace checks from Windows

Run the project from an Ubuntu WSL distribution, preferably from its Linux filesystem (for example,
`~/src/RepoPilot`), then run `uv sync --frozen`, `uv run pytest -q`, and
`uv run pytest tests/security/test_repository_intelligence.py -q`. Workspace and repository
intelligence tests are Linux-only; native Windows skips do not verify those boundaries. Check that
WSL is available separately with `wsl --status` in PowerShell and confirm the shell reports Linux
with `uname -s`.
Docker sandbox checks are a later milestone; if needed, verify Docker Desktop integration and daemon
availability separately with `docker version`. RepoPilot does not install or configure WSL or Docker.

The project pins Python 3.12 in `.python-version`; `pyproject.toml` supports
Python 3.12 and newer.

## Offline agent demonstration

Run the five-scenario, deterministic demonstration with:

```bash
uv run python scripts/demo_offline_agent.py
```

It creates a synthetic repository in a temporary directory and demonstrates an
authorized read proposal, a denied host operation, a change requiring human
approval, a text response, and a provider failure. The output contains run
metadata and policy decisions only. It uses the mock provider, makes no network
requests, and never executes proposed tools or modifies a user repository.
The authorization outcomes are illustrative; no tool result or independent
verification is produced.

Example output:

```text
RepoPilot offline simulation (mock provider; proposed tools are never executed)

Scenario: allowed_proposal
  Status: PARTIAL
  Termination reason: authorized_proposal_not_executed
  Authorization: ALLOW (capability_allowed)
  Tools executed: no
  Independently verified: no
```

## Continuous integration

GitHub Actions runs the quality checks on pushes to `main`, pull requests
targeting `main`, and manual `workflow_dispatch` runs. The workflow uses Ubuntu
and Python 3.12, installs dependencies from `uv.lock`, checks Ruff formatting
and lint, runs mypy and pytest, measures coverage, validates the pre-commit
configuration, runs workspace and repository-intelligence integration/security
targets on Ubuntu, and builds the package. When generated, `coverage.xml` is
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
