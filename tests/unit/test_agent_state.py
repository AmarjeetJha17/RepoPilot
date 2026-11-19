"""Deterministic tests for the agent run lifecycle contract."""

from dataclasses import asdict
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest

from repopilot.agent.state import (
    IndependentVerificationEvidence,
    InvalidRunStatusError,
    InvalidTransitionError,
    InvalidVerificationEvidenceError,
    RunState,
    RunStatus,
    can_transition,
    create_run,
    get_transition_history,
    is_terminal,
    mark_verified,
    transition_run,
)

pytestmark = pytest.mark.unit

RUN_ID = UUID("a7f0ec51-3e88-4682-8a88-6f4104ea21e8")
START = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
EVIDENCE = IndependentVerificationEvidence(
    check_id="pytest-suite",
    result_digest="a" * 64,
)


def _run_at(status: RunStatus) -> RunState:
    paths = {
        RunStatus.CREATED: (),
        RunStatus.INSPECTING: (RunStatus.INSPECTING,),
        RunStatus.PLANNING: (RunStatus.INSPECTING, RunStatus.PLANNING),
        RunStatus.EXECUTING: (
            RunStatus.INSPECTING,
            RunStatus.PLANNING,
            RunStatus.EXECUTING,
        ),
        RunStatus.VERIFYING: (
            RunStatus.INSPECTING,
            RunStatus.PLANNING,
            RunStatus.EXECUTING,
            RunStatus.VERIFYING,
        ),
        RunStatus.AWAITING_APPROVAL: (
            RunStatus.INSPECTING,
            RunStatus.PLANNING,
            RunStatus.EXECUTING,
            RunStatus.VERIFYING,
            RunStatus.AWAITING_APPROVAL,
        ),
        RunStatus.COMPLETED: (
            RunStatus.INSPECTING,
            RunStatus.PLANNING,
            RunStatus.EXECUTING,
            RunStatus.VERIFYING,
            RunStatus.AWAITING_APPROVAL,
            RunStatus.COMPLETED,
        ),
        RunStatus.PARTIAL: (
            RunStatus.INSPECTING,
            RunStatus.PLANNING,
            RunStatus.EXECUTING,
            RunStatus.VERIFYING,
            RunStatus.PARTIAL,
        ),
        RunStatus.BLOCKED: (
            RunStatus.INSPECTING,
            RunStatus.PLANNING,
            RunStatus.EXECUTING,
            RunStatus.VERIFYING,
            RunStatus.AWAITING_APPROVAL,
            RunStatus.BLOCKED,
        ),
        RunStatus.FAILED: (RunStatus.INSPECTING, RunStatus.FAILED),
        RunStatus.CANCELLED: (RunStatus.CANCELLED,),
    }
    run = create_run(run_id=RUN_ID, at=START)
    for next_status in paths[status]:
        run, _ = transition_run(run, next_status, at=START)
    return run


def test_new_run_starts_created_with_utc_timestamps_and_no_verification() -> None:
    run = create_run(run_id=RUN_ID, at=START)

    assert run.run_id == RUN_ID
    assert run.status is RunStatus.CREATED
    assert run.created_at == run.updated_at == START
    assert run.sequence == 0
    assert run.transition_history == ()
    assert run.verified is False


@pytest.mark.parametrize(
    ("source", "targets"),
    [
        (RunStatus.CREATED, {RunStatus.INSPECTING, RunStatus.CANCELLED}),
        (
            RunStatus.INSPECTING,
            {RunStatus.PLANNING, RunStatus.FAILED, RunStatus.CANCELLED},
        ),
        (
            RunStatus.PLANNING,
            {RunStatus.EXECUTING, RunStatus.FAILED, RunStatus.CANCELLED},
        ),
        (
            RunStatus.EXECUTING,
            {RunStatus.VERIFYING, RunStatus.FAILED, RunStatus.CANCELLED},
        ),
        (
            RunStatus.VERIFYING,
            {
                RunStatus.EXECUTING,
                RunStatus.AWAITING_APPROVAL,
                RunStatus.PARTIAL,
                RunStatus.FAILED,
                RunStatus.CANCELLED,
            },
        ),
        (
            RunStatus.AWAITING_APPROVAL,
            {
                RunStatus.COMPLETED,
                RunStatus.BLOCKED,
                RunStatus.FAILED,
                RunStatus.CANCELLED,
            },
        ),
        (RunStatus.COMPLETED, set()),
        (RunStatus.PARTIAL, set()),
        (RunStatus.BLOCKED, set()),
        (RunStatus.FAILED, set()),
        (RunStatus.CANCELLED, set()),
    ],
)
def test_transition_table_matches_lifecycle_contract(
    source: RunStatus,
    targets: set[RunStatus],
) -> None:
    assert {target for target in RunStatus if can_transition(source, target)} == targets
    run = _run_at(source)
    for target in targets:
        updated, event = transition_run(run, target, at=START)
        assert updated.status is target
        assert event.sequence == run.sequence + 1


def test_documented_lifecycle_transitions_succeed_in_order() -> None:
    run = create_run(run_id=RUN_ID, at=START)
    states = [
        RunStatus.INSPECTING,
        RunStatus.PLANNING,
        RunStatus.EXECUTING,
        RunStatus.VERIFYING,
        RunStatus.AWAITING_APPROVAL,
        RunStatus.COMPLETED,
    ]

    for sequence, status in enumerate(states, start=1):
        run, event = transition_run(run, status, at=START + timedelta(seconds=sequence))
        assert event.sequence == sequence
        assert event.new_status is status

    history = get_transition_history(run)
    assert len(history) == run.sequence == 6
    assert [event.previous_status for event in history] == [
        RunStatus.CREATED,
        RunStatus.INSPECTING,
        RunStatus.PLANNING,
        RunStatus.EXECUTING,
        RunStatus.VERIFYING,
        RunStatus.AWAITING_APPROVAL,
    ]
    assert run.updated_at == START + timedelta(seconds=6)


def test_verifying_to_executing_records_repair_transition() -> None:
    run = create_run(run_id=RUN_ID, at=START)
    for status in (RunStatus.INSPECTING, RunStatus.PLANNING, RunStatus.EXECUTING):
        run, _ = transition_run(run, status, at=START)
    run, _ = transition_run(run, RunStatus.VERIFYING, at=START)

    retried, event = transition_run(
        run,
        RunStatus.EXECUTING,
        at=START + timedelta(seconds=1),
        reason_code="verification_retry",
    )

    assert retried.status is RunStatus.EXECUTING
    assert event.previous_status is RunStatus.VERIFYING
    assert event.sequence == 5
    assert event.reason_code == "verification_retry"


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (RunStatus.CREATED, RunStatus.PLANNING),
        (RunStatus.INSPECTING, RunStatus.EXECUTING),
        (RunStatus.EXECUTING, RunStatus.COMPLETED),
        (RunStatus.COMPLETED, RunStatus.INSPECTING),
    ],
)
def test_invalid_transitions_are_typed_and_do_not_mutate_run(
    source: RunStatus,
    target: RunStatus,
) -> None:
    run = _run_at(source)
    original = run

    with pytest.raises(InvalidTransitionError):
        transition_run(run, target, at=START + timedelta(seconds=1))

    assert run.status is source
    assert run is original


def test_repeated_transition_is_rejected() -> None:
    run = create_run(run_id=RUN_ID, at=START)
    inspecting, _ = transition_run(run, RunStatus.INSPECTING, at=START)

    with pytest.raises(InvalidTransitionError):
        transition_run(inspecting, RunStatus.INSPECTING, at=START)


def test_untrusted_reason_codes_are_rejected_without_run_mutation() -> None:
    run = create_run(run_id=RUN_ID, at=START)

    with pytest.raises(ValueError, match="bounded lowercase reason code"):
        transition_run(run, RunStatus.INSPECTING, at=START, reason_code="password=private")

    assert run.sequence == 0
    assert run.transition_history == ()


@pytest.mark.parametrize(
    "status",
    [
        RunStatus.COMPLETED,
        RunStatus.PARTIAL,
        RunStatus.BLOCKED,
        RunStatus.FAILED,
        RunStatus.CANCELLED,
    ],
)
def test_all_terminal_statuses_reject_transitions(status: RunStatus) -> None:
    run = _run_at(status)

    assert is_terminal(run.status)
    with pytest.raises(InvalidTransitionError) as error:
        transition_run(run, RunStatus.CANCELLED, at=START)

    assert error.value.reason_code == "terminal_state"
    assert run.status is status


@pytest.mark.parametrize(
    "status",
    [
        RunStatus.CREATED,
        RunStatus.INSPECTING,
        RunStatus.PLANNING,
        RunStatus.EXECUTING,
        RunStatus.VERIFYING,
        RunStatus.AWAITING_APPROVAL,
    ],
)
def test_cancellation_is_allowed_from_every_nonterminal_status(status: RunStatus) -> None:
    run = _run_at(status)

    cancelled, event = transition_run(run, RunStatus.CANCELLED, at=START)

    assert cancelled.status is RunStatus.CANCELLED
    assert event.previous_status is status


def test_unknown_external_status_is_rejected_without_echoing_input() -> None:
    run = create_run(run_id=RUN_ID, at=START)

    with pytest.raises(InvalidTransitionError) as error:
        transition_run(run, "credential-value-that-must-not-be-echoed", at=START)  # type: ignore[arg-type]

    assert error.value.target_status is None
    assert "credential-value" not in str(error.value)
    assert run.sequence == 0


def test_run_state_rejects_unknown_status_values() -> None:
    with pytest.raises(InvalidRunStatusError):
        RunState(RUN_ID, "CREATED", START, START)  # type: ignore[arg-type]


def test_timestamps_are_normalized_to_utc_and_naive_values_are_rejected() -> None:
    local_time = datetime(2026, 11, 19, 17, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    run = create_run(run_id=RUN_ID, at=local_time)

    assert run.created_at == START
    assert run.created_at.tzinfo is UTC
    _, event = transition_run(run, RunStatus.INSPECTING, at=local_time)
    assert event.occurred_at == START
    assert event.occurred_at.tzinfo is UTC
    with pytest.raises(ValueError, match="timezone-aware"):
        create_run(run_id=RUN_ID, at=datetime(2026, 11, 19, 12, 0))


def test_transition_history_rejects_backdated_events_without_mutating_run() -> None:
    run = create_run(run_id=RUN_ID, at=START)
    run, _ = transition_run(run, RunStatus.INSPECTING, at=START + timedelta(seconds=2))

    with pytest.raises(ValueError, match="chronological"):
        transition_run(run, RunStatus.PLANNING, at=START + timedelta(seconds=1))

    assert run.status is RunStatus.INSPECTING
    assert run.sequence == 1


def test_invalid_transition_does_not_append_an_event() -> None:
    run = create_run(run_id=RUN_ID, at=START)
    inspecting, _ = transition_run(run, RunStatus.INSPECTING, at=START)

    with pytest.raises(InvalidTransitionError):
        transition_run(inspecting, RunStatus.COMPLETED, at=START)

    assert len(get_transition_history(inspecting)) == 1
    assert inspecting.sequence == 1


def test_completed_run_is_not_verified_without_explicit_evidence() -> None:
    run = create_run(run_id=RUN_ID, at=START)
    for status in (
        RunStatus.INSPECTING,
        RunStatus.PLANNING,
        RunStatus.EXECUTING,
        RunStatus.VERIFYING,
        RunStatus.AWAITING_APPROVAL,
        RunStatus.COMPLETED,
    ):
        run, _ = transition_run(run, status, at=START)

    assert run.verified is False
    verified = mark_verified(run, EVIDENCE, at=START + timedelta(seconds=1))
    assert verified.verified is True
    assert verified.verification_evidence == EVIDENCE
    with pytest.raises(ValueError, match="updated_at"):
        mark_verified(run, EVIDENCE, at=START - timedelta(seconds=1))


def test_verification_requires_completed_run_and_valid_evidence() -> None:
    run = create_run(run_id=RUN_ID, at=START)

    with pytest.raises(InvalidVerificationEvidenceError):
        mark_verified(run, EVIDENCE, at=START)

    completed = _run_at(RunStatus.COMPLETED)
    with pytest.raises(InvalidVerificationEvidenceError):
        mark_verified(completed, object(), at=START)  # type: ignore[arg-type]


def test_run_state_rejects_status_inconsistent_with_transition_history() -> None:
    with pytest.raises(ValueError, match="match its transition history"):
        RunState(RUN_ID, RunStatus.COMPLETED, START, START)


def test_transition_event_has_serializable_audit_fields() -> None:
    run = create_run(run_id=RUN_ID, at=START)
    _, event = transition_run(run, RunStatus.INSPECTING, at=START, reason_code="start_inspection")

    fields = asdict(event)
    assert fields == {
        "run_id": RUN_ID,
        "previous_status": RunStatus.CREATED,
        "new_status": RunStatus.INSPECTING,
        "occurred_at": START,
        "sequence": 1,
        "reason_code": "start_inspection",
    }
