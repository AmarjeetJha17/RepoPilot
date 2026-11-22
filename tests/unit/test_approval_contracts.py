"""Exact-action approval and one-time receipt contracts."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from repopilot.security.approval import (
    ApprovalConsumptionState,
    ApprovalLedger,
    ApprovalReasonCode,
    PatchManifestEntry,
    ReviewedPatchManifest,
)

_HASH_A = "a" * 64
_HASH_B = "b" * 64
_HASH_C = "c" * 64


def _manifest(now: datetime | None = None) -> ReviewedPatchManifest:
    created = now or datetime(2026, 1, 1, tzinfo=UTC)
    return ReviewedPatchManifest(
        run_id="run-contract",
        operation_id="operation-contract",
        repository_identity=f"sha256:{_HASH_A}",
        staging_workspace_identity="workspace:contract",
        entries=(PatchManifestEntry("src/module.py", _HASH_B, _HASH_C),),
        diff_digest=f"sha256:{_HASH_A}",
        limits=(20, 1_000_000, 4_000_000, 20_000, 1_000_000, 20_000),
        created_at=created,
        expires_at=created + timedelta(minutes=2),
    )


def test_manifest_digest_is_canonical_and_binds_the_exact_action() -> None:
    manifest = _manifest()
    same_action = _manifest()
    changed_diff = replace(manifest, diff_digest=f"sha256:{_HASH_B}")

    assert manifest.canonical_json() == same_action.canonical_json()
    assert manifest.digest == same_action.digest
    assert manifest.digest != changed_diff.digest
    assert manifest.digest.startswith("sha256:")


@pytest.mark.parametrize("path", ["../secret", "/absolute/path", "C:/host/path", "a//b"])
def test_manifest_rejects_unsafe_or_non_normalized_paths(path: str) -> None:
    with pytest.raises(ValueError):
        PatchManifestEntry(path, _HASH_B, _HASH_C)


def test_receipt_is_one_time_and_rejects_a_changed_manifest() -> None:
    manifest = _manifest()
    ledger = ApprovalLedger()
    receipt = ledger._issue(manifest, manifest.created_at)

    consumed = ledger.consume(receipt, manifest, manifest.created_at)
    replay = ledger.consume(receipt, manifest, manifest.created_at)

    assert consumed.valid
    assert consumed.state is ApprovalConsumptionState.CONSUMED
    assert not replay.valid
    assert replay.reason is ApprovalReasonCode.REPLAYED

    second_receipt = ledger._issue(manifest, manifest.created_at)
    changed = replace(manifest, diff_digest=f"sha256:{_HASH_B}")
    stale = ledger.consume(second_receipt, changed, manifest.created_at)
    assert not stale.valid
    assert stale.reason is ApprovalReasonCode.MANIFEST_CHANGED


def test_expired_and_forged_receipts_fail_closed() -> None:
    manifest = _manifest()
    ledger = ApprovalLedger()
    receipt = ledger._issue(manifest, manifest.created_at)
    expired = ledger.consume(receipt, manifest, manifest.expires_at)

    forged = replace(receipt)
    foreign = ledger.consume(forged, manifest, manifest.created_at)

    assert expired.state is ApprovalConsumptionState.EXPIRED
    assert expired.reason is ApprovalReasonCode.EXPIRED
    assert not foreign.valid
    assert foreign.reason is ApprovalReasonCode.INVALID_RECEIPT
    assert "SECRET" not in repr(ledger.audit_records)


def test_concurrent_consumption_allows_exactly_one_apply_attempt() -> None:
    manifest = _manifest()
    ledger = ApprovalLedger()
    receipt = ledger._issue(manifest, manifest.created_at)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = tuple(
            pool.map(lambda _: ledger.consume(receipt, manifest, manifest.created_at), range(8))
        )

    assert sum(result.valid for result in results) == 1
    assert sum(result.reason is ApprovalReasonCode.REPLAYED for result in results) == 7
