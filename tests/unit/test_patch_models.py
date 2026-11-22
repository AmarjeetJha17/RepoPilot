"""Unit contracts for bounded, provider-neutral patch proposal types."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from repopilot.sandbox.patches import FileReplacement, PatchLimits, PatchProposal

pytestmark = pytest.mark.unit


def _replacement(**overrides: object) -> FileReplacement:
    values: dict[str, object] = {
        "path": "src/example.py",
        "operation": "replace_text",
        "expected_sha256": "a" * 64,
        "content": "VALUE = 2\n",
    }
    values.update(overrides)
    return FileReplacement.model_validate(values, strict=True)


def test_patch_proposal_has_explicit_version_and_immutable_replacements() -> None:
    replacement = _replacement()
    proposal = PatchProposal(replacements=(replacement,))

    assert proposal.schema_version == 1
    assert proposal.replacements == (replacement,)
    with pytest.raises(ValidationError):
        replacement.content = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "overrides",
    [
        {"operation": "delete"},
        {"expected_sha256": "not-a-digest"},
        {"content": b"not-text"},
        {"extra": "not allowed"},
    ],
)
def test_file_replacement_rejects_invalid_or_unknown_fields(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _replacement(**overrides)


def test_patch_proposal_rejects_empty_or_excessive_file_batches() -> None:
    with pytest.raises(ValidationError):
        PatchProposal(replacements=())
    with pytest.raises(ValidationError):
        PatchProposal(replacements=tuple(_replacement() for _ in range(21)))


def test_trusted_patch_limits_reject_non_positive_and_non_integer_values() -> None:
    with pytest.raises(ValueError):
        PatchLimits(max_files=0)
    with pytest.raises(ValueError):
        PatchLimits(max_file_bytes=True)  # type: ignore[arg-type]
