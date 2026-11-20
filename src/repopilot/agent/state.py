"""Deterministic run lifecycle states, transitions, and audit events."""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from re import compile as compile_pattern
from types import MappingProxyType
from uuid import UUID, uuid4


class RunStatus(StrEnum):
    """Lifecycle statuses from creation through a terminal outcome."""

    CREATED = "CREATED"
    INSPECTING = "INSPECTING"
    PLANNING = "PLANNING"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class InvalidRunStatusError(ValueError):
    """An external value is not a recognized lifecycle status."""

    def __init__(self) -> None:
        super().__init__("Run status must be a RunStatus value.")


class InvalidTransitionError(ValueError):
    """A requested lifecycle edge is not allowed."""

    def __init__(
        self,
        current_status: RunStatus,
        target_status: RunStatus | None,
        reason_code: str,
    ) -> None:
        self.current_status = current_status
        self.target_status = target_status
        self.reason_code = reason_code
        target = target_status.value if target_status is not None else "unknown"
        super().__init__(
            f"Cannot transition run from {current_status.value} to {target} ({reason_code})."
        )


class InvalidVerificationEvidenceError(ValueError):
    """Verification evidence is missing, invalid, or not applicable to the run."""


_REASON_CODE = compile_pattern(r"[a-z][a-z0-9_.-]{0,63}\Z")
_CHECK_ID = compile_pattern(r"[a-z][a-z0-9_.-]{0,63}\Z")
_SHA256 = compile_pattern(r"[0-9a-f]{64}\Z")

_TERMINAL_STATUSES = frozenset(
    {
        RunStatus.COMPLETED,
        RunStatus.PARTIAL,
        RunStatus.BLOCKED,
        RunStatus.FAILED,
        RunStatus.CANCELLED,
    }
)

_ALLOWED_TRANSITIONS: Mapping[RunStatus, frozenset[RunStatus]] = MappingProxyType(
    {
        RunStatus.CREATED: frozenset({RunStatus.INSPECTING, RunStatus.CANCELLED}),
        RunStatus.INSPECTING: frozenset(
            {RunStatus.PLANNING, RunStatus.FAILED, RunStatus.CANCELLED}
        ),
        RunStatus.PLANNING: frozenset(
            {
                RunStatus.EXECUTING,
                RunStatus.AWAITING_APPROVAL,
                RunStatus.PARTIAL,
                RunStatus.BLOCKED,
                RunStatus.FAILED,
                RunStatus.CANCELLED,
            }
        ),
        RunStatus.EXECUTING: frozenset(
            {RunStatus.VERIFYING, RunStatus.FAILED, RunStatus.CANCELLED}
        ),
        RunStatus.VERIFYING: frozenset(
            {
                RunStatus.EXECUTING,
                RunStatus.AWAITING_APPROVAL,
                RunStatus.PARTIAL,
                RunStatus.FAILED,
                RunStatus.CANCELLED,
            }
        ),
        RunStatus.AWAITING_APPROVAL: frozenset(
            {
                RunStatus.COMPLETED,
                RunStatus.BLOCKED,
                RunStatus.FAILED,
                RunStatus.CANCELLED,
            }
        ),
        RunStatus.COMPLETED: frozenset(),
        RunStatus.PARTIAL: frozenset(),
        RunStatus.BLOCKED: frozenset(),
        RunStatus.FAILED: frozenset(),
        RunStatus.CANCELLED: frozenset(),
    }
)


def _utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Lifecycle timestamps must be timezone-aware.")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class IndependentVerificationEvidence:
    """Safe reference to a successful independent check produced by trusted code."""

    check_id: str
    result_digest: str

    def __post_init__(self) -> None:
        if not _CHECK_ID.fullmatch(self.check_id) or not _SHA256.fullmatch(self.result_digest):
            raise ValueError("Verification evidence needs a safe check ID and SHA-256 digest.")


@dataclass(frozen=True, slots=True)
class TransitionEvent:
    """Immutable, content-minimized record of one successful lifecycle transition."""

    run_id: UUID
    previous_status: RunStatus
    new_status: RunStatus
    occurred_at: datetime
    sequence: int
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, UUID):
            raise TypeError("Transition event run_id must be a UUID.")
        if not isinstance(self.previous_status, RunStatus) or not isinstance(
            self.new_status, RunStatus
        ):
            raise InvalidRunStatusError()
        if self.sequence < 1:
            raise ValueError("Transition event sequence must be positive.")
        object.__setattr__(self, "occurred_at", _utc_timestamp(self.occurred_at))
        if self.reason_code is not None and not _REASON_CODE.fullmatch(self.reason_code):
            raise ValueError("Transition reason must be a bounded lowercase reason code.")


@dataclass(frozen=True, slots=True)
class RunState:
    """Immutable current run state with ordered lifecycle history."""

    run_id: UUID
    status: RunStatus
    created_at: datetime
    updated_at: datetime
    sequence: int = 0
    verified: bool = False
    transition_history: tuple[TransitionEvent, ...] = ()
    verification_evidence: IndependentVerificationEvidence | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, UUID):
            raise TypeError("Run ID must be a UUID.")
        if not isinstance(self.status, RunStatus):
            raise InvalidRunStatusError()
        if self.sequence < 0 or self.sequence != len(self.transition_history):
            raise ValueError("Run sequence must match its transition history length.")
        if not isinstance(self.transition_history, tuple):
            raise TypeError("Transition history must be immutable.")

        created_at = _utc_timestamp(self.created_at)
        updated_at = _utc_timestamp(self.updated_at)
        if updated_at < created_at:
            raise ValueError("Run updated_at cannot precede created_at.")
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "updated_at", updated_at)

        expected_status = RunStatus.CREATED
        expected_timestamp = created_at
        for sequence, event in enumerate(self.transition_history, start=1):
            if not isinstance(event, TransitionEvent):
                raise TypeError("Transition history entries must be TransitionEvent values.")
            if event.run_id != self.run_id or event.sequence != sequence:
                raise ValueError("Transition history must belong to the run and be sequential.")
            if event.previous_status is not expected_status or not can_transition(
                event.previous_status, event.new_status
            ):
                raise ValueError("Transition history must follow the lifecycle transition table.")
            if event.occurred_at < expected_timestamp:
                raise ValueError("Transition timestamps must be chronological.")
            expected_status = event.new_status
            expected_timestamp = event.occurred_at
        if self.status is not expected_status:
            raise ValueError("Run status must match its transition history.")
        if updated_at < expected_timestamp:
            raise ValueError("Run updated_at cannot precede its transition history.")
        if self.verification_evidence is not None and not isinstance(
            self.verification_evidence, IndependentVerificationEvidence
        ):
            raise TypeError(
                "Verification evidence must be an IndependentVerificationEvidence value."
            )
        if self.verified != (self.verification_evidence is not None):
            raise ValueError("Verified state requires explicit verification evidence.")
        if self.verified and self.status is not RunStatus.COMPLETED:
            raise ValueError("Only a completed run can be marked verified.")


def create_run(*, run_id: UUID | None = None, at: datetime | None = None) -> RunState:
    """Create a run in CREATED with deterministic injection points for tests."""
    created_at = _utc_timestamp(at if at is not None else datetime.now(UTC))
    identifier = run_id if run_id is not None else uuid4()
    return RunState(identifier, RunStatus.CREATED, created_at, created_at)


def is_terminal(status: RunStatus) -> bool:
    """Return whether a status has no outgoing transitions."""
    return isinstance(status, RunStatus) and status in _TERMINAL_STATUSES


def can_transition(current_status: RunStatus, target_status: RunStatus) -> bool:
    """Check the explicit transition table without changing a run."""
    if not isinstance(current_status, RunStatus) or not isinstance(target_status, RunStatus):
        return False
    return target_status in _ALLOWED_TRANSITIONS[current_status]


def transition_run(
    run: RunState,
    target_status: RunStatus,
    *,
    at: datetime | None = None,
    reason_code: str | None = None,
) -> tuple[RunState, TransitionEvent]:
    """Return a new state and event, rejecting illegal edges without mutation."""
    if not isinstance(target_status, RunStatus):
        raise InvalidTransitionError(run.status, None, "invalid_status")
    if not can_transition(run.status, target_status):
        reason = "terminal_state" if is_terminal(run.status) else "transition_not_allowed"
        raise InvalidTransitionError(run.status, target_status, reason)

    occurred_at = _utc_timestamp(at if at is not None else datetime.now(UTC))
    event = TransitionEvent(
        run_id=run.run_id,
        previous_status=run.status,
        new_status=target_status,
        occurred_at=occurred_at,
        sequence=run.sequence + 1,
        reason_code=reason_code,
    )
    updated_run = replace(
        run,
        status=target_status,
        updated_at=occurred_at,
        sequence=event.sequence,
        transition_history=(*run.transition_history, event),
    )
    return updated_run, event


def get_transition_history(run: RunState) -> tuple[TransitionEvent, ...]:
    """Return the immutable transition history for a run."""
    return run.transition_history


def mark_verified(
    run: RunState,
    evidence: IndependentVerificationEvidence,
    *,
    at: datetime | None = None,
) -> RunState:
    """Record trusted independent-check evidence after successful completion."""
    if not isinstance(evidence, IndependentVerificationEvidence):
        raise InvalidVerificationEvidenceError(
            "Explicit independent verification evidence is required."
        )
    if run.status is not RunStatus.COMPLETED:
        raise InvalidVerificationEvidenceError("Only a completed run can be verified.")
    if run.verified:
        raise InvalidVerificationEvidenceError("Verification evidence has already been recorded.")

    updated_at = _utc_timestamp(at if at is not None else datetime.now(UTC))
    return replace(
        run,
        updated_at=updated_at,
        verified=True,
        verification_evidence=evidence,
    )
