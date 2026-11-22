# RepoPilot — Testing, Evaluation, and Release Quality

> Status: Proposed v1.0 · Testing strategy: deterministic first; live-model evaluations separately

## 1. Quality philosophy
Code generation does not prove correctness. For every AI action, distinguish **tool executed**, **test passed**, **independent oracle passed**, and **user approved**. Maintain reproducible benchmarks, explicit failure reporting, and strict security gates.

## 2. Test pyramid
| Layer | Goal | Examples | Runs |
|---|---|---|---|
| Unit | Deterministic logic | budgets, state transitions, policy, schemas, redaction | Every commit |
| Contract | Provider/tools agree on I/O | tool arguments, adapter mocked responses | Every PR |
| Integration | Components collaborate | SQLite transactions, scanner, patch application | Every PR |
| Security | Enforce trust boundaries | traversal, symlink escape, dangerous commands, prompt injection | Every PR; release gate |
| Sandbox | Real restricted execution | pytest fixture inside disposable Docker container | Linux CI / release |
| E2E offline | Mock LLM completes staged fix | deterministic fixture, trace, approval, clean workspace | Every PR |
| E2E live | Real provider attempts tasks | held-out benchmark with budget | Scheduled/manual, not required on every PR |
| Regression | Preserve prior fixed defects | minimized fixtures keyed to bug IDs | Every PR |

## 3. Directory layout
```text
tests/
  unit/
  contract/
  integration/
  security/
  e2e/
  fixtures/
benchmarks/
  README.md
  suites/v1/manifest.yaml
  fixtures/<case-id>/
  private_oracles/    # local/CI-protected; NOT exposed to agent
```
Use temporary directories and synthetic repositories; never point tests at user workspaces. Every test that can run code must use a constrained sandbox fixture.

Workspace-manager unit, integration, and security tests use synthetic temporary trees only. The
Linux CI job runs `tests/security/test_workspace_security.py` explicitly so source-symlink rejection
and the no-network/no-subprocess boundary execute on Ubuntu; the full suite also runs cleanup and
integrity tests. Native Windows and macOS workspace preparation is expected to fail closed until
secure no-follow, no-atime descriptor implementations are available.

Repository-intelligence parsing/value tests are portable and live in `tests/unit/`. Its integration
and filesystem-boundary tests use synthetic staged repositories and run only on Linux; CI invokes
`tests/integration/test_repository_intelligence.py` and
`tests/security/test_repository_intelligence.py` explicitly on Ubuntu so Linux security checks are
not silently treated as verified by Windows skips. Tests must assert that source fixtures stay
unchanged, malformed/binary inputs return safe results, and diagnostics disclose neither host
paths nor file contents.

The fixed read-only dispatcher has portable argument/allowlist tests plus Linux-only integration and
security tests under the corresponding directories. CI explicitly runs its integration/security
targets on Ubuntu. Those tests must prove real staged reads on `ALLOW`, no handler invocation on
denial/approval/cancellation, exact workspace ownership, path-scoped policy, bounded result bytes,
and no provider/network/subprocess use. Native Windows skips do not verify workspace execution.

Phase 4.4 patch-staging tests use synthetic repositories. Proposal-model tests are portable under
`tests/unit/`; filesystem replacement integration and security tests live under their matching
directories and are Linux-only. Ubuntu CI runs both patch-staging files explicitly so native
Windows skips cannot count as verification. Tests assert source-tree immutability, exact staged
hashes, policy denial, stale-hash rejection, symlink containment, bounded diff previews, and safe
relative-path output. No replacement content is executed.

Phase 4.5 runner contract/security tests use a deterministic fake backend and synthetic
manager-owned staging workspaces. Ubuntu CI runs these files explicitly so Linux-only workspace
tests cannot silently skip. They verify fixed command construction, policy denial, exact workspace
ownership, output/runtime bounds, cancellation and owned-container cleanup without requiring
Docker. Real Docker isolation remains a separate manually provisioned verification: use a
digest-pinned image already containing Python and pytest and a local rootless Linux daemon, then
verify no network, source/host/credential mounts, resource limits, timeout termination,
and cleanup. A fake backend is not evidence that Docker or kernel isolation works.

## 4. Test conventions
- Use **pytest** fixtures, parametrization, and named assertions.
- Test behavior, errors, and state invariants—not implementation-specific prompt wording.
- Control time, random seeds, UUID, provider responses, cost tables and temp paths in unit tests.
- No external model API or network access in regular CI.
- Failing security tests must never be xfailed to release; exceptions require documented ADR and controls.
- Coverage target: >=85% line coverage for core logic; >=95% line coverage of policy and path-validation modules. Coverage alone is not proof of security.
- Keep benchmark gold patches and hidden test outputs out of tool-visible workspace.

## 5. Acceptance testing for requirements
| Requirement | Representative check |
|---|---|
| Repo inspect read-only | compare file hashes and `git status` before/after |
| Allowed path scope | traversal, symlink, case-sensitivity, UNC/device paths where applicable |
| Bounded agent loop | fake model emits infinite tool calls; budget stops |
| Single-decision orchestration | mock text/tool-call responses cover validation, policy outcomes, limits, cancellation and no dispatch |
| Runtime budget accounting | fake monotonic clocks and synthetic provider usage cover hard count/time limits, unknown usage, and bounded event drops |
| Patch staging | malformed/duplicate/oversized proposals, invalid hash, policy denial, and path escapes fail safely; replacements are atomic per file and the live/source repo remains unchanged |
| Repository workspace | bounded copy, secret/cache exclusion, immutable baseline, staged integrity, owned cleanup, no source mutation |
| Approval binding | changed patch hash invalidates approval |
| Sandbox tests | CPU/memory/PID timeout, no outbound network, no host secrets |
| Audit | every allow/deny/approval creates correlated event |
| Stop/cancel | process tree terminated and status saved |
| SQLite | transactions atomic, migrations up/down where supported, FK constraints |
| Provider adapter | errors, invalid tool args, rate limits, empty result and usage unavailable |
| CLI UX | `--json`, `NO_COLOR`, non-TTY denial of live writes |

## 6. Evaluation task schema
Example YAML **planned** format:
```yaml
suite: python-maintenance-v1
version: 1
cases:
  - id: parser-empty-input
    repo_fixture: benchmarks/fixtures/parser-empty-input
    base_revision: fixture-v1
    task: "Handle empty input without raising IndexError"
    allowed_paths: ["src/**", "tests/**"]
    timeout_seconds: 300
    scoring:
      type: pytest_hidden
      command: ["python", "-m", "pytest", "-q", "/oracle-tests"]
```
The evaluator mounts hidden oracle tests **after** the agent produces a patch and keeps them inaccessible to agent/model. Never run untrusted manifest-provided commands on the host; parse through strict allowlist and sandbox.

## 7. Benchmark design and baselines
- Begin with 10 curated open-source or synthetic Python maintenance cases; expand to at least 30 held-out cases before portfolio release.
- Include easy, medium and hard categories: single-function bug, cross-file bug, regression test writing, configuration fix, type errors, dependency-independent refactor.
- Hold out cases and maintain immutable manifest hashes; exclude test-only tricks and duplicate tasks.
- Compare **no-agent baseline**, an initial agent build, and later improvements under equal model/budget conditions.
- Run representative stochastic configurations >=3 times per case when budget permits; report per-case and aggregate rates with variance/intervals when sample allows.
- Keep human review of semantic correctness; avoid reporting tests alone as complete proof of correctness.

## 8. Required metrics
| Metric | Formula / meaning |
|---|---|
| Task success rate | independently passing cases / valid attempted cases |
| Verification rate | cases with required checks passing / attempted cases |
| Patch application rate | successfully applied reviewable patches / patches proposed |
| Regression rate | cases breaking previously passing independent tests / valid cases |
| Median completion time | median wall-clock duration across attempts |
| Median tokens | median provider-reported input + output tokens where available |
| Cost per successful task | total estimated provider spend / successful tasks |
| Tool error rate | failed/denied tool calls / all tool calls (report separately by reason) |
| User intervention rate | user approvals/corrections per run |
| Sandbox violations | policy breaches or escapes detected; desired zero |

Report evaluation population, missing usage data, provider/model version, concurrency, seeds, fixture digests, sandbox image digest, scorer version and any API failures. Avoid cherry-picking only successful runs.

## 9. CI pipeline (planned)
```text
Checkout → uv sync --frozen → Ruff lint/format → mypy →
unit + contract + integration tests → security tests →
Linux restricted-sandbox smoke test → coverage summary → build
```
Use Linux CI for Docker sandbox tests where supported; run lightweight unit/type checks on Windows as a separate matrix job. Avoid relying on privileged Docker-in-Docker on untrusted PRs. Keep live-model benchmarks manually triggered with protected credentials and cost cap.

### Local validation commands (after project setup)
```bash
uv sync --dev
uv run ruff check .
uv run ruff format --check .
uv run mypy src/repopilot
uv run pytest tests/unit tests/contract tests/integration tests/security -q
uv run pytest --cov=repopilot --cov-report=term-missing
uv run pytest tests/security -q
```

## 10. Release gates
A milestone is releasable only when:
1. Requirements acceptance cases for shipped features pass.
2. Critical/high security findings and sandbox escape failures are resolved or capability disabled.
3. Local working tree remains unchanged during dry-run and on refusal/cancellation.
4. Core CI gates pass; benchmark results include failures as well as successes.
5. Documentation, CLI help and sample traces match actual behavior.
6. All claims in README/resume reference measured results, methodology and date.

## 11. Evidence to publish in portfolio
- Architecture diagram and ADRs.
- Short recording: issue → inspect → patch → test → explanation → review.
- Results table with dataset size, success rate, failures, model and cost.
- Redacted example execution trace and sample patch.
- Reproduction instructions and honest limitations.

See [PRD.md](PRD.md), [SECURITY.md](SECURITY.md), and [DATABASE.md](DATABASE.md).
