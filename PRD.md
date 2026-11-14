# RepoPilot — Product Requirements Document

> Status: Draft v1.0 · Date: 2026-11-13 · Owner: Project maintainer · Product: Local-first Python coding agent

## 1. Product definition
RepoPilot is an open-source, terminal-first, evaluation-driven autonomous software-engineering agent. It accepts a clearly scoped task against a local Python repository; inspects relevant files; proposes a plan; uses guarded tools to edit code; executes tests in a restricted environment; and reports evidence, diffs, failures, and costs. It is **not** a general-purpose clone of Codex or Claude Code.

### One-sentence value proposition
Turn a Python repository maintenance task into a **reviewable, tested patch with a transparent execution trace**.

### Primary goal
Demonstrate production-minded AI engineering for a developer's resume, GitHub, and job applications through measurable task completion, clear architecture, responsible safety controls, and reproducible evaluation.

### Target users
- Primary: maintainer/developer working locally on a Python project.
- Secondary: evaluator who wants to reproduce benchmark runs and inspect tool traces.
- Initial deployment: one local user, one repository workspace, one active task at a time.

## 2. Success criteria and non-goals
### Success metrics (targets, not achieved claims)
| Metric | Initial target | Measurement |
|---|---|---|
| Functional CLI | `repopilot --help`, `inspect`, `run`, `history`, `eval` work | CLI integration tests |
| Tool safety | 100% of mutating tool calls go through policy gate | Policy tests + trace review |
| Basic task coverage | >=10 curated Python maintenance tasks | Deterministic regression checks |
| Evaluation set | >=30 held-out isolated tasks before portfolio release | Versioned task manifests |
| Repeatability | A benchmark run can reproduce its inputs/config | Snapshot hashes + run metadata |
| Reliability | No writes outside authorized workspace in security tests | Traversal/symlink/adversarial tests |
| Transparency | Every run records status, steps, patch, tool outcome, model and usage where available | SQLite records and exported report |

No success-rate target is promised until a credible baseline has been collected. Report failures and variance, not just best-case demos.

### Non-goals for v1
- Full IDE extension or web SaaS; account registration; team collaboration.
- Arbitrary language support; remote shell access; self-hosted distributed execution.
- Autonomous merge, push, deploy, package installation, or cloud-resource mutation.
- Unrestricted computer access; secrets discovery; bypassing a user's confirmation.
- Multiple specialist agents, training a foundation model, or unrestricted internet browsing.
- Guaranteeing security, correctness, or bug-free changes.

## 3. User stories and acceptance criteria
| ID | User story | Acceptance |
|---|---|---|
| US-01 | As a developer, I can inspect repository structure | `inspect` shows eligible files, language, tests and Git state without mutation |
| US-02 | I can describe a bounded bug fix | `run` accepts task, repository path, model, budgets and `--dry-run` |
| US-03 | I can preview modifications | Agent emits unified diff and requires approval before editing live workspace |
| US-04 | I can allow safe tests | Tests run inside a restricted disposable workspace; timeouts and limits enforced |
| US-05 | I can understand failure and retry | Bounded retry cap with recorded reason; no infinite loops |
| US-06 | I can review results | Final result contains summary, changed files, checks, failures, risks, token/cost estimate |
| US-07 | I can inspect prior runs | `history` and `show RUN_ID` expose redacted traces and diff references |
| US-08 | I can benchmark | `eval` runs versioned tasks and emits success/latency/cost reports |
| US-09 | I can stop a task | Ctrl-C cancels cleanly, kills sandbox job, stores interrupted status |

## 4. Functional requirements
**FR-01 — Repository validation.** Resolve canonical repository root, reject nonexistent/untrusted roots, capture initial Git commit/status, and exclude ignored, binary, generated, oversized, and sensitive paths by default.

**FR-02 — Context gathering.** Expose bounded tools (`list_files`, `read_file`, `search_text`, `find_symbols`, `git_diff`) with truncation and pagination. Retrieval must respect path policies and token budgets.

**FR-03 — Agent loop.** Implement `plan → propose tool call → policy validate → execute → observe → decide next step`, with typed tool arguments and bounded steps. Untrusted repository text is data, not an instruction source.

**FR-04 — Safe mutations.** Apply exact, reviewable patches to a staging workspace first. Refuse out-of-root changes, symlinks escaping the root, binary modifications, and conflicting file hashes. Live workspace application requires explicit approval.

**FR-05 — Verification.** Detect or accept explicit pytest command, execute only approved allowlisted checks in isolated sandbox, collect exit code, stdout/stderr (redacted and capped), and run duration. An agent-generated assertion is not sufficient evidence by itself; independent hidden tests determine benchmark success.

**FR-06 — Recovery.** Up to three corrective attempts per task by default, bounded by step, wall-clock and spending limits.

**FR-07 — Reporting.** Human-readable Rich output plus machine-readable JSON report; distinguish `completed`, `verified`, `partial`, `blocked`, `failed`, `cancelled`.

**FR-08 — Persistence.** Store runs, steps, approvals, tool results (redacted), artifact metadata, evaluations, model and usage data in local SQLite. Never persist API secrets.

**FR-09 — Git support.** Read status, diff, commit hash; generate optional branch/patch artifacts. No automatic `push`, `merge`, or force operations in v1.

**FR-10 — Provider abstraction.** One initial provider adapter with a mock provider for offline tests; second provider supported by interface without rewriting runtime.

## 5. Non-functional requirements
- **Safety:** explicit allowlist, default deny for risky actions, protected path rules, non-root/no-network sandbox for default tests, resource limits, no Docker socket mount.
- **Performance:** repository discovery and text search operate incrementally; token-aware context, output size caps and cancellation.
- **Observability:** correlation IDs through calls and traces; redact credentials, file contents by default in telemetry.
- **Maintainability:** modular package boundaries, strict types for public APIs, migrations, test fixtures, clear documentation.
- **Portability:** Windows development supported via WSL2/Docker Desktop; Linux is the reference sandbox platform. macOS best-effort.
- **Privacy:** local data by default; any source snippets sent to an external model provider require user configuration and disclosure.
- **Reproducibility:** pin dependencies in `uv.lock`, version benchmark fixtures and execution images.

## 6. User journeys
1. `repopilot inspect --repo ./sample-project` → validated repository map.
2. `repopilot run --repo ./sample-project --task "Fix invalid token parsing" --dry-run` → planned tool trace, proposed diff, no workspace mutation.
3. User reviews diff, explicitly applies patch, and allows sandbox tests.
4. Agent reports checked outcomes and known limitations; `repopilot show <run-id>` retrieves its evidence.
5. Maintainer runs `repopilot eval --suite benchmarks/v1` to compare configuration against baseline.

Commands are *planned interface contracts*, not claims that they already exist.

## 7. Milestones and release gates
| Milestone | Scope | Exit condition |
|---|---|---|
| M0 | Docs, repo skeleton, CI, mocked CLI | Docs reviewed; tests and lint pass |
| M1 | Read-only repo inspection | Handles representative Python repos without escape |
| M2 | Agent loop, provider, dry-run patches | Mocked deterministic tasks pass |
| M3 | Sandbox verification and controlled apply | Adversarial safety suite passes |
| M4 | Tracing, history, benchmark harness | Reproducible evaluation reports |
| M5 | GitHub-ready release | Demo, public docs, test reports, release tag |

## 8. Risks and mitigations
| Risk | Mitigation |
|---|---|
| Prompt injection from repository files | Separate trusted instructions from retrieved content; policy gates remain code-enforced |
| Agent destroys host files | Staging workspace, canonical path checks, explicit approval and sandbox restrictions |
| Benchmark gaming/overfitting | Hold-out tasks, hidden tests, repeated runs and baseline comparisons |
| Excessive API costs | Token/step/time/cost budgets, model switch, preflight price estimate |
| Large-repo context overflow | Structured search, truncation, symbol index, retrieval ranking |
| Scope creep | Ship single-agent Python-first workflow before adding UI/multi-agent features |

## 9. Open decisions (tracked; not blockers)
- Which hosted model/provider is initially used, based on API access and budget?
- Benchmark corpus licensing and exact eligibility of tasks?
- Whether we add a web trace viewer after M4?

## 10. Related documents
Read [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [TESTING.md](TESTING.md), and [AGENTS.md](AGENTS.md).
