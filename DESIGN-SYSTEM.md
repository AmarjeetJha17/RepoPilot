# RepoPilot — Terminal Design System

> Status: Proposed v1.0 · v1 surface: terminal CLI (Typer + Rich), not a web frontend

## 1. Design principles
- **Readable over decorative:** task outcomes and risky actions must be clear in plain text.
- **Accessible by default:** status never conveyed by color alone; honor `NO_COLOR`, non-TTY output, and reduced motion.
- **Consistent:** shared status names, formatting, prompt wording, and spacing tokens.
- **Reviewable:** always display repository, affected files, and action scope before live write approval.
- **Automation-friendly:** human terminal rendering separate from stable `--json` machine output.

## 2. Color tokens
| Token | Hex (dark-terminal defaults) | Meaning |
|---|---|---|
| `brand.primary` | `#38BDF8` | Header, highlights |
| `brand.secondary` | `#A78BFA` | Agent/model metadata |
| `status.success` | `#22C55E` | Passed, verified |
| `status.warning` | `#F59E0B` | Requires attention, partial |
| `status.error` | `#EF4444` | Failed, denied |
| `status.info` | `#60A5FA` | Neutral progress/info |
| `text.primary` | `#F8FAFC` | Main text in true-color terminals |
| `text.muted` | `#94A3B8` | Supplemental details |
| `surface.panel` | `#0F172A` | Panel fill if background supported |
| `border.subtle` | `#334155` | Dividers |

Colors are optional enhancements; include `[PASS]`, `[FAIL]`, `[WARN]`, `[DENIED]`, `[NEEDS APPROVAL]` text indicators. Never rely exclusively on red/green.

## 3. Typography
Terminal font is **user-controlled**; do not download or bundle fonts. Assume monospace. Suggested developer font: JetBrains Mono or system monospace; never require it. Use Rich styles `bold`, `dim`, `italic` sparingly; uppercase only for terse status labels. Prefer ordinary ASCII characters for no-Unicode environments.

## 4. Spacing and layout tokens
| Token | Meaning | Default |
|---|---|---|
| `space.xs` | label-to-value | 1 space |
| `space.sm` | adjacent fields | 2 spaces |
| `space.md` | block padding | 1 row / 2 columns |
| `space.lg` | sections | 1 blank row |
| `panel.width` | render limit | terminal width, max ~100 cols for narratives |
| `table.max_rows` | preview | 20 before pagination |
| `output.preview_lines` | tool output preview | 40 lines default |

Line-wrap long paths rather than truncate the portion identifying the target; allow `--no-color` and `--plain`. Rich layout must remain usable at 80 columns.

## 5. Components
### Header
`RepoPilot · <command> · <short-run-id>` followed by repo and model ID.

### Progress
Use one live spinner only for foreground interactive commands. Show phase text (`Inspecting`, `Planning`, `Editing`, `Verifying`). For CI/non-TTY emit one event per line; no animated UI.

### Status
Text + optional icon: `[PASS] Verified`, `[WARN] Partial`, `[FAIL] Failed`, `[DENIED] Blocked`, `[INFO] Running`. Do not label a run `Verified` merely because the agent says it completed.

### Diff preview
Show Git-compatible diff formatting, list file count, inserted/deleted lines, and mark path restrictions. Apply approval must explicitly include root, exact patch digest and affected files.

### Confirmation prompt / buttons
A CLI has **prompts rather than buttons**. Prompt format: `Apply this patch to <repo>? [y/N]`. Defaults to **No**, no approval in non-interactive mode unless specific explicit flag with constrained scope. There is no catch-all `--yes` for dangerous operations in v1.

### Error panel
Show short actionable error, code, remediation hint, and redacted run ID. Use optional `--verbose` for safe diagnostic details, never secret values.

### Summary report
Display result, verification evidence, modified files, tests performed, costs as *estimates*, time, and artifact location. Include warnings if checks were skipped or provider usage unavailable.

## 6. Example terminal composition
```text
RepoPilot · run · 8f21a4c0
Repository  ./sample-project
Task        Fix parser exception on empty input
Model       configured-provider/model

[PASS] Repository inspected       42 eligible files
[INFO] Patch staged               2 files changed
[PASS] Unit tests                  18 passed, 0 failed
[WARN] Integration tests           not run

Review patch: .repopilot/runs/8f21a4c0/change.patch
Apply this patch to ./sample-project? [y/N]
```

## 7. Future web UI guidance (not in scope)
If a benchmark dashboard is later introduced, use a separate design decision record and implement accessible keyboard navigation, visible focus, semantic HTML, responsive spacing, contrast testing and explicit loading/error states. Do not add React/Tailwind/shadcn dependencies to the v1 CLI solely for future plans.

## 8. Testable UI acceptance
- `NO_COLOR=1 repopilot --help` is readable.
- Plain and JSON modes contain identical factual status information.
- No ANSI escape codes appear in redirected machine output.
- Non-interactive mode cannot silently approve live writes.
- 80-column terminal accommodates status and confirmation content.

See [CODE-STYLE.md](CODE-STYLE.md) and [SECURITY.md](SECURITY.md).
