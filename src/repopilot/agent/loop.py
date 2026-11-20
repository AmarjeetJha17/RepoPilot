"""One bounded model-decision cycle; proposed calls are never dispatched here."""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID

from repopilot.agent.state import (
    RunState,
    RunStatus,
    create_run,
    transition_run,
)
from repopilot.providers.base import (
    FinishReason,
    ModelIdentifier,
    ModelMessage,
    ModelProvider,
    ModelProviderError,
    ModelRequest,
    ModelRole,
    ProviderErrorCode,
    TextResponse,
    ToolCallResponse,
)
from repopilot.security.policy import (
    AuthorizationContext,
    PolicyDecision,
    PolicyDecisionResult,
    PolicyEngine,
    PolicyReasonCode,
)
from repopilot.tools import ToolRegistry, ToolRegistryError, ToolRegistryErrorCode

MAX_TASK_CHARS = 32_768
MAX_MODEL_REQUESTS = 1
MAX_TOOL_CALLS_PER_RESPONSE = 32
MAX_PROVIDER_TIMEOUT_SECONDS = 60.0
MAX_RUN_TIMEOUT_SECONDS = 900.0


class OrchestrationOutcome(StrEnum):
    """What this single-decision cycle actually established."""

    TEXT_RESPONSE = "text_response"
    INCOMPLETE_RESPONSE = "incomplete_response"
    AWAITING_EXECUTION = "awaiting_execution"
    APPROVAL_REQUIRED = "approval_required"
    DENIED = "denied"
    LIMIT_EXCEEDED = "limit_exceeded"
    PROVIDER_ERROR = "provider_error"
    CANCELLED = "cancelled"


class ProposalOutcome(StrEnum):
    """A proposed call's validation and policy disposition; never execution."""

    AUTHORIZED_NOT_EXECUTED = "authorized_not_executed"
    APPROVAL_REQUIRED = "approval_required"
    DENIED = "denied"
    INVALID = "invalid"


class OrchestrationErrorCode(StrEnum):
    """Stable error categories; no raw provider or model text is retained."""

    MODEL_REQUEST_LIMIT = "model_request_limit"
    RUN_DEADLINE_EXCEEDED = "run_deadline_exceeded"
    TOO_MANY_TOOL_CALLS = "too_many_tool_calls"
    PROVIDER_TIMEOUT = "provider_timeout"
    PROVIDER_AUTHENTICATION = "provider_authentication"
    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_FAILURE = "provider_failure"
    INVALID_PROVIDER_RESPONSE = "invalid_provider_response"
    INTERNAL_ERROR = "internal_error"


class AgentEventType(StrEnum):
    """Bounded in-memory event categories containing no task or response text."""

    RUN_STARTED = "run_started"
    STATE_CHANGED = "state_changed"
    MODEL_REQUESTED = "model_requested"
    MODEL_RESPONDED = "model_responded"
    PROPOSAL_DECIDED = "proposal_decided"
    RUN_TERMINATED = "run_terminated"


@dataclass(frozen=True, slots=True)
class AgentLoopConfig:
    """Immutable run input and hard limits for a single model decision."""

    task: str
    model: ModelIdentifier
    run_id: UUID
    authorization: AuthorizationContext
    workspace: Path
    max_model_requests: int = 1
    max_tool_calls_per_response: int = 8
    request_timeout_seconds: float = MAX_PROVIDER_TIMEOUT_SECONDS
    run_timeout_seconds: float = MAX_RUN_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if (
            not isinstance(self.task, str)
            or not self.task.strip()
            or len(self.task) > MAX_TASK_CHARS
        ):
            raise ValueError("Task must be non-empty and within the configured input bound.")
        if not isinstance(self.model, ModelIdentifier) or not isinstance(self.run_id, UUID):
            raise TypeError("Model and run ID must use their typed contracts.")
        if not isinstance(self.authorization, AuthorizationContext):
            raise TypeError("Authorization context must come from trusted application code.")
        if self.authorization.run_id != str(self.run_id):
            raise ValueError("Authorization context must match the orchestration run ID.")
        if not isinstance(self.workspace, Path):
            raise TypeError("Workspace must be a pathlib Path.")
        if (
            not isinstance(self.max_model_requests, int)
            or isinstance(self.max_model_requests, bool)
            or not 0 <= self.max_model_requests <= MAX_MODEL_REQUESTS
        ):
            raise ValueError("This single-decision cycle supports zero or one model request.")
        if (
            not isinstance(self.max_tool_calls_per_response, int)
            or isinstance(self.max_tool_calls_per_response, bool)
            or not 1 <= self.max_tool_calls_per_response <= MAX_TOOL_CALLS_PER_RESPONSE
        ):
            raise ValueError("Tool-call limit must be between 1 and 32.")
        _validate_timeout(self.request_timeout_seconds, MAX_PROVIDER_TIMEOUT_SECONDS)
        _validate_timeout(self.run_timeout_seconds, MAX_RUN_TIMEOUT_SECONDS)


@dataclass(frozen=True, slots=True)
class ProposalDecision:
    """Safe per-call outcome without retaining arguments or fabricated tool results."""

    call_id: str | None
    tool_name: str | None
    outcome: ProposalOutcome
    validation_error: ToolRegistryErrorCode | None = None
    policy_decision: PolicyDecisionResult | None = None


@dataclass(frozen=True, slots=True)
class AgentEvent:
    """Content-minimized event ordered within one run and safe for in-memory inspection."""

    run_id: UUID
    sequence: int
    occurred_at: datetime
    event_type: AgentEventType
    status: RunStatus
    model: ModelIdentifier | None = None
    tool_name: str | None = None
    call_id: str | None = None
    validation_error: ToolRegistryErrorCode | None = None
    policy_decision: PolicyDecision | None = None
    policy_reason_code: PolicyReasonCode | None = None
    error_code: OrchestrationErrorCode | None = None


@dataclass(frozen=True, slots=True)
class AgentRunResult:
    """Observable run state; text, arguments, and ToolResult values are omitted."""

    run: RunState
    outcome: OrchestrationOutcome
    events: tuple[AgentEvent, ...]
    proposal_decisions: tuple[ProposalDecision, ...] = ()
    response_summary: str | None = None
    error_code: OrchestrationErrorCode | None = None
    model_requests: int = 0


class AgentRunCancelled(asyncio.CancelledError):
    """Propagate asyncio cancellation while exposing the safe terminal run snapshot."""

    def __init__(self, result: AgentRunResult) -> None:
        self.result = result
        super().__init__("RepoPilot run cancelled.")


class AgentOrchestrator:
    """Coordinate provider, registry, and policy once without tool execution."""

    def __init__(
        self,
        *,
        provider: ModelProvider,
        registry: ToolRegistry,
        policy_engine: PolicyEngine,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self._provider = provider
        self._registry = registry
        self._policy = policy_engine
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic or time.monotonic

    async def run(self, config: AgentLoopConfig) -> AgentRunResult:
        """Run one bounded decision cycle and terminate without dispatching proposals."""
        started_at = _utc(self._clock())
        deadline = self._monotonic() + config.run_timeout_seconds
        run = create_run(run_id=config.run_id, at=started_at)
        events: list[AgentEvent] = []
        proposals: tuple[ProposalDecision, ...] = ()
        response_summary: str | None = None
        model_requests = 0
        event_limit = config.max_tool_calls_per_response * 2 + 8

        def add_event(
            event_type: AgentEventType,
            *,
            model: ModelIdentifier | None = None,
            tool_name: str | None = None,
            call_id: str | None = None,
            validation_error: ToolRegistryErrorCode | None = None,
            policy_decision: PolicyDecision | None = None,
            policy_reason_code: PolicyReasonCode | None = None,
            error_code: OrchestrationErrorCode | None = None,
        ) -> None:
            if len(events) >= event_limit:
                return
            events.append(
                AgentEvent(
                    run_id=run.run_id,
                    sequence=len(events) + 1,
                    occurred_at=_utc(self._clock()),
                    event_type=event_type,
                    status=run.status,
                    model=model,
                    tool_name=tool_name,
                    call_id=call_id,
                    validation_error=validation_error,
                    policy_decision=policy_decision,
                    policy_reason_code=policy_reason_code,
                    error_code=error_code,
                )
            )

        def move(target: RunStatus, reason: str) -> None:
            nonlocal run
            at = max(_utc(self._clock()), run.updated_at)
            run, _ = transition_run(run, target, at=at, reason_code=reason)
            add_event(AgentEventType.STATE_CHANGED)

        def finish(
            outcome: OrchestrationOutcome,
            status: RunStatus,
            reason: str,
            *,
            error_code: OrchestrationErrorCode | None = None,
        ) -> AgentRunResult:
            move(status, reason)
            add_event(AgentEventType.RUN_TERMINATED, error_code=error_code)
            return AgentRunResult(
                run=run,
                outcome=outcome,
                events=tuple(events),
                proposal_decisions=proposals,
                response_summary=response_summary,
                error_code=error_code,
                model_requests=model_requests,
            )

        add_event(AgentEventType.RUN_STARTED, model=config.model)
        move(RunStatus.INSPECTING, "request_preparation")
        move(RunStatus.PLANNING, "single_decision_cycle")
        if config.max_model_requests == 0:
            return finish(
                OrchestrationOutcome.LIMIT_EXCEEDED,
                RunStatus.PARTIAL,
                "model_request_limit",
                error_code=OrchestrationErrorCode.MODEL_REQUEST_LIMIT,
            )

        remaining = deadline - self._monotonic()
        if remaining <= 0:
            return finish(
                OrchestrationOutcome.LIMIT_EXCEEDED,
                RunStatus.PARTIAL,
                "run_deadline_exceeded",
                error_code=OrchestrationErrorCode.RUN_DEADLINE_EXCEEDED,
            )

        timeout = min(config.request_timeout_seconds, remaining)
        try:
            request = ModelRequest(
                model=config.model,
                messages=(ModelMessage(ModelRole.USER, config.task),),
                tools=tuple(self._registry.export_schemas()),
                timeout_seconds=timeout,
            )
        except Exception:
            return finish(
                OrchestrationOutcome.PROVIDER_ERROR,
                RunStatus.FAILED,
                "internal_error",
                error_code=OrchestrationErrorCode.INTERNAL_ERROR,
            )
        add_event(AgentEventType.MODEL_REQUESTED, model=config.model)
        model_requests = 1
        try:
            async with asyncio.timeout(timeout):
                response = await self._provider.next_action(request)
        except asyncio.CancelledError as error:
            result = finish(OrchestrationOutcome.CANCELLED, RunStatus.CANCELLED, "cancelled")
            raise AgentRunCancelled(result) from error
        except TimeoutError:
            if remaining <= config.request_timeout_seconds:
                return finish(
                    OrchestrationOutcome.LIMIT_EXCEEDED,
                    RunStatus.PARTIAL,
                    "run_deadline_exceeded",
                    error_code=OrchestrationErrorCode.RUN_DEADLINE_EXCEEDED,
                )
            return finish(
                OrchestrationOutcome.PROVIDER_ERROR,
                RunStatus.FAILED,
                "provider_timeout",
                error_code=OrchestrationErrorCode.PROVIDER_TIMEOUT,
            )
        except ModelProviderError as error:
            error_code = _provider_error_code(error.code)
            return finish(
                OrchestrationOutcome.PROVIDER_ERROR,
                RunStatus.FAILED,
                error_code.value,
                error_code=error_code,
            )
        except Exception:
            return finish(
                OrchestrationOutcome.PROVIDER_ERROR,
                RunStatus.FAILED,
                "internal_error",
                error_code=OrchestrationErrorCode.INTERNAL_ERROR,
            )

        if self._monotonic() >= deadline:
            return finish(
                OrchestrationOutcome.LIMIT_EXCEEDED,
                RunStatus.PARTIAL,
                "run_deadline_exceeded",
                error_code=OrchestrationErrorCode.RUN_DEADLINE_EXCEEDED,
            )
        if (
            not isinstance(response, TextResponse | ToolCallResponse)
            or response.model != config.model
        ):
            return finish(
                OrchestrationOutcome.PROVIDER_ERROR,
                RunStatus.FAILED,
                "invalid_provider_response",
                error_code=OrchestrationErrorCode.INVALID_PROVIDER_RESPONSE,
            )
        add_event(AgentEventType.MODEL_RESPONDED, model=config.model)

        if isinstance(response, TextResponse):
            response_summary = (
                f"Text response received ({len(response.text)} chars; "
                f"{response.finish_reason.value})."
            )
            outcome = (
                OrchestrationOutcome.TEXT_RESPONSE
                if response.finish_reason is FinishReason.STOP
                else OrchestrationOutcome.INCOMPLETE_RESPONSE
            )
            return finish(outcome, RunStatus.PARTIAL, "no_execution_or_verification")

        if len(response.tool_calls) > config.max_tool_calls_per_response:
            return finish(
                OrchestrationOutcome.LIMIT_EXCEEDED,
                RunStatus.PARTIAL,
                "too_many_tool_calls",
                error_code=OrchestrationErrorCode.TOO_MANY_TOOL_CALLS,
            )
        try:
            proposals = self._decide_proposals(response, config, add_event)
        except Exception:
            return finish(
                OrchestrationOutcome.PROVIDER_ERROR,
                RunStatus.FAILED,
                "internal_error",
                error_code=OrchestrationErrorCode.INTERNAL_ERROR,
            )
        if any(
            item.outcome in {ProposalOutcome.DENIED, ProposalOutcome.INVALID} for item in proposals
        ):
            return finish(OrchestrationOutcome.DENIED, RunStatus.BLOCKED, "proposal_denied")
        if any(item.outcome is ProposalOutcome.APPROVAL_REQUIRED for item in proposals):
            return finish(
                OrchestrationOutcome.APPROVAL_REQUIRED,
                RunStatus.AWAITING_APPROVAL,
                "approval_required",
            )
        return finish(
            OrchestrationOutcome.AWAITING_EXECUTION,
            RunStatus.PARTIAL,
            "authorized_proposal_not_executed",
        )

    def _decide_proposals(
        self,
        response: ToolCallResponse,
        config: AgentLoopConfig,
        add_event: Callable[..., None],
    ) -> tuple[ProposalDecision, ...]:
        decisions: list[ProposalDecision] = []
        seen_ids: set[str] = set()
        for call in response.tool_calls:
            safe_id = _safe_identifier(call.id)
            try:
                definition = self._registry.get(call.name)
            except ToolRegistryError:
                definition = None
            if isinstance(call.id, str) and call.id in seen_ids:
                decision = ProposalDecision(
                    safe_id,
                    definition.name if definition is not None else None,
                    ProposalOutcome.INVALID,
                    ToolRegistryErrorCode.DUPLICATE_CALL_ID,
                )
                decisions.append(decision)
                add_event(
                    AgentEventType.PROPOSAL_DECIDED,
                    tool_name=decision.tool_name,
                    call_id=safe_id,
                    validation_error=decision.validation_error,
                )
                continue
            if isinstance(call.id, str):
                seen_ids.add(call.id)
            try:
                validated = self._registry.validate_call(call)
            except ToolRegistryError as error:
                decision = ProposalDecision(
                    safe_id,
                    definition.name if definition is not None else None,
                    ProposalOutcome.INVALID,
                    error.code,
                )
                decisions.append(decision)
                add_event(
                    AgentEventType.PROPOSAL_DECIDED,
                    tool_name=decision.tool_name,
                    call_id=safe_id,
                    validation_error=error.code,
                )
                continue
            policy_result = self._policy.authorize(
                validated, config.authorization, config.workspace
            )
            if policy_result.decision is PolicyDecision.ALLOW:
                proposal_outcome = ProposalOutcome.AUTHORIZED_NOT_EXECUTED
            elif policy_result.decision is PolicyDecision.REQUIRE_APPROVAL:
                proposal_outcome = ProposalOutcome.APPROVAL_REQUIRED
            else:
                proposal_outcome = ProposalOutcome.DENIED
            decision = ProposalDecision(
                validated.call_id,
                validated.name,
                proposal_outcome,
                policy_decision=policy_result,
            )
            decisions.append(decision)
            add_event(
                AgentEventType.PROPOSAL_DECIDED,
                tool_name=validated.name,
                call_id=_safe_identifier(validated.call_id),
                policy_decision=policy_result.decision,
                policy_reason_code=policy_result.reason_code,
            )
        return tuple(decisions)


def _validate_timeout(value: float, maximum: float) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or value <= 0
        or value > maximum
    ):
        raise ValueError("Timeout must be positive, finite, and within the hard maximum.")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Orchestration timestamps must be timezone-aware.")
    return value.astimezone(UTC)


def _safe_identifier(value: object) -> str | None:
    if isinstance(value, str) and value and len(value) <= 128 and value.isprintable():
        return value
    return None


def _provider_error_code(code: ProviderErrorCode) -> OrchestrationErrorCode:
    return {
        ProviderErrorCode.AUTHENTICATION: OrchestrationErrorCode.PROVIDER_AUTHENTICATION,
        ProviderErrorCode.RATE_LIMITED: OrchestrationErrorCode.PROVIDER_RATE_LIMITED,
        ProviderErrorCode.TIMEOUT: OrchestrationErrorCode.PROVIDER_TIMEOUT,
        ProviderErrorCode.UNAVAILABLE: OrchestrationErrorCode.PROVIDER_UNAVAILABLE,
        ProviderErrorCode.INVALID_RESPONSE: OrchestrationErrorCode.INVALID_PROVIDER_RESPONSE,
        ProviderErrorCode.PERMANENT: OrchestrationErrorCode.PROVIDER_FAILURE,
        ProviderErrorCode.MOCK_EXHAUSTED: OrchestrationErrorCode.PROVIDER_FAILURE,
    }[code]
