# RepoPilot — Coding Standards and Contribution Rules

> Status: Proposed v1.0 · Target language: Python 3.12+

## 1. Engineering principles
- Write simple, small, typed units; prefer readable deterministic code over abstraction for its own sake.
- Explicitly separate side effects from decision-making.
- Security checks must live in trusted Python code, never solely in prompts.
- Tests and docs change together with behavior; no undocumented safety exceptions.
- External service integrations must be replaceable with fakes in unit tests.

## 2. Python conventions
- Follow PEP 8 with **Ruff** as canonical formatter/linter, line length **100**.
- Use Python 3.12 syntax and built-in generics (`list[str]`, `dict[str, int]`).
- Type annotate all public functions and methods, and all cross-module interfaces. Run mypy in strict mode for `src/repopilot` with explicit scoped exceptions only.
- Use `pathlib.Path`, `datetime.now(timezone.utc)`, and enums or `Literal` for known states.
- Use Pydantic v2 for external/untrusted input and settings; dataclasses for small internal value objects where appropriate.
- Prefer compositional services; one responsibility per module and clear interfaces.
- Do not use mutable default arguments, bare `except`, broad except that silently swallows errors, global mutable state, or magic string status values.
- Avoid clever metaprogramming, dynamic imports and hidden module-level side effects in execution-critical paths.
- Function target <=40 lines when reasonable; refactor by responsibility, not arbitrary line count.

## 3. Naming and structure
| Item | Convention | Example |
|---|---|---|
| Module | `snake_case.py` | `policy_engine.py` |
| Function/variable | `snake_case` | `resolve_repo_root` |
| Class | `PascalCase` | `SandboxRunner` |
| Constant | `UPPER_SNAKE_CASE` | `MAX_OUTPUT_BYTES` |
| Private helper | `_leading_underscore` | `_redact_result` |
| Async functions | normal snake_case, `async def` | `invoke_model` |
| Test | `test_<behavior>_<condition>` | `test_denies_symlink_escape` |
| Protocol | noun/service name | `ModelProvider` |

Use `src/` layout; import absolute `repopilot.*` from other modules, and relative imports only within tight local packages if useful.

## 4. Module dependency rules
Allowed high-level direction:
`cli → application → agent/domain interfaces → infrastructure adapters`.
- `agent` must not import Typer, Rich, SQLAlchemy or provider SDK directly.
- `security` must not depend on LLM output semantics beyond validated tool-call schemas.
- `tools` must not talk directly to SQLite or render terminal UI.
- `persistence` must not initiate model calls or execute shell commands.
- `evaluation` owns scoring; agent cannot read hidden expected outputs.

## 5. Error handling
Create typed domain exceptions (`RepositoryAccessError`, `PolicyDeniedError`, `SandboxTimeoutError`, `ModelProviderError`, `BudgetExceededError`). At application boundary, translate to a stable error code and actionable message. Preserve original error as exception cause while redacting displayed details. Retry only known transient provider failures with jitter and a hard retry budget. Never retry a denied security operation.

## 6. Tool contracts and subprocess rules
- Register tools via explicit registry; JSON Schema/Pydantic validate all arguments.
- Return typed `ToolResult` with `ok`, `error_code`, bounded output and `truncated` flag.
- A tool can only operate on injected authorized context (workspace, policy, budget).
- Pass subprocess arguments as a **list**, not interpolated shell text; `shell=False`.
- No model-generated commands executed on host. Any executable test command goes to sandbox with validation.
- Use `asyncio` only where concurrency matters; every async operation has cancellation and timeout support.

```python
from pathlib import Path
from pydantic import BaseModel, Field

class ReadFileArgs(BaseModel):
    path: str = Field(min_length=1, max_length=512)
    start_line: int = Field(default=1, ge=1)
    max_lines: int = Field(default=120, ge=1, le=300)

async def read_file(args: ReadFileArgs, workspace: Path) -> str:
    """Read a validated, bounded portion of an authorized repository file."""
    # Path authorization and I/O belong in a reviewed implementation.
    raise NotImplementedError
```

The snippet is an interface example, **not an implemented security guard**.

## 7. Formatting, linting, typechecking
Baseline `pyproject.toml` settings planned:
```toml
[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM", "ASYNC"]

[tool.mypy]
python_version = "3.12"
strict = true
mypy_path = "src"
```
Local commands (once scaffolding exists):
```bash
uv sync --dev
uv run ruff check .
uv run ruff format --check .
uv run mypy src/repopilot
uv run pytest tests/unit -q
```
Pin/verify actual plugin packages and configuration during bootstrap; commands are planned project contracts until tooling is installed.

## 8. Documentation and comments
- Public classes/functions have docstrings describing **why**, contract and failure behavior, not restating obvious code.
- Document sensitive invariants around path checking, approval hashing, sandbox and redaction with threat references.
- Update PRD/ARCHITECTURE/DATABASE/SECURITY/TESTING when behavior changes.
- Significant architectural changes get `docs/adr/NNN-short-title.md` with context, decision, tradeoffs and rollback.

## 9. Git and pull requests
- Conventional Commits: `feat(agent): add bounded tool loop`, `fix(security): reject symlink escape`, `test(eval): add regression fixture`.
- Feature branches; pull requests include purpose, security impact, test commands/results, sample trace and relevant docs changes.
- Never commit `.env`, token traces, runtime SQLite databases, benchmark private answers, external provider responses with sensitive code, or `.repopilot` artifacts.
- Dependencies updated intentionally with lockfile, changelog/reason and relevant tests; no automated dependency installation from agent instructions.
- Prefer small independently reviewable patches.

## 10. Review checklist
1. Is implementation aligned to [PRD.md](PRD.md) and [ARCHITECTURE.md](ARCHITECTURE.md)?
2. Is untrusted input validated before filesystem, shell, Git, DB or network use?
3. Are secret redaction and telemetry boundaries upheld?
4. Do unit, integration and applicable security tests pass?
5. Are failure, timeout, cancellation and refusal paths covered?
6. Are docs, sample commands and traces updated?

See [TESTING.md](TESTING.md) and [AGENTS.md](AGENTS.md).
