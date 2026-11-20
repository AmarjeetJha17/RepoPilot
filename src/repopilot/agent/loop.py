"""One bounded model-decision cycle; proposed calls are never dispatched here."""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID

from repopilot.agent.budget import (
    BudgetConfig,
    BudgetExceededError,
    BudgetReasonCode,
    BudgetSnapshot,
    RuntimeBudget,
)
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
    TOTAL_TOOL_CALL_LIMIT = "total_tool_call_limit"
    REPAIR_ATTEMPT_LIMIT = "repair_attempt_limit"
    REPORTED_INPUT_TOKEN_LIMIT = "reported_input_token_limit"
    REPORTED_OUTPUT_TOKEN_LIMIT = "reported_output_token_limit"
    INTERNAL_ERROR = "internal_error"


class AgentEventType(StrEnum):
    """Bounded in-memory event categories containing no task or response text."""

    RUN_STARTED = "run_started"
    STATE_CHANGED = "state_changed"
    MODEL_REQUESTED = "model_requested"
    MODEL_RESPONDED = "model_responded"
    USAGE_RECORDED = "usage_recorded"
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
    budget_limits: BudgetConfig | None = None
    max_events: int = 128
    max_event_bytes: int = 32_768

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
        if self.budget_limits is not None and not isinstance(self.budget_limits, BudgetConfig):
            raise TypeError("Budget limits must be a BudgetConfig value.")
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
        if not isinstance(self.max_events, int) or isinstance(self.max_events, bool):
            raise TypeError("Maximum event count must be an integer.")
        if not 1 <= self.max_events <= 1024:
            raise ValueError("Maximum event count must be between 1 and 1024.")
        if not isinstance(self.max_event_bytes, int) or isinstance(self.max_event_bytes, bool):
            raise TypeError("Maximum event output size must be an integer.")
        if not 0 <= self.max_event_bytes <= 1_048_576:
            raise ValueError("Maximum event output size must be between 0 and 1 MiB.")


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
    budget_reason_code: BudgetReasonCode | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    usage_reports: int | None = None


@dataclass(frozen=True, slots=True)
class AgentRunResult:
    """Observable run state; text, arguments, and ToolResult values are omitted."""

    run: RunState
    outcome: OrchestrationOutcome
    events: tuple[AgentEvent, ...]
    budget_snapshot: BudgetSnapshot
    proposal_decisions: tuple[ProposalDecision, ...] = ()
    response_summary: str | None = None
    error_code: OrchestrationErrorCode | None = None
    model_requests: int = 0
    budget_reason_code: BudgetReasonCode | None = None
    events_dropped: int = 0
    event_bytes: int = 0


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
        limits = config.budget_limits or BudgetConfig()
        limits = replace(
            limits,
            max_model_requests=min(limits.max_model_requests, config.max_model_requests, 1),
            max_run_seconds=min(limits.max_run_seconds, config.run_timeout_seconds),
            max_tool_calls_per_response=min(
                limits.max_tool_calls_per_response, config.max_tool_calls_per_response
            ),
        )
        budget = RuntimeBudget(limits, clock=self._monotonic)
        run = create_run(run_id=config.run_id, at=started_at)
        events: list[AgentEvent] = []
        proposals: tuple[ProposalDecision, ...] = ()
        response_summary: str | None = None
        event_bytes = 0
        events_dropped = 0
        event_attempts = 0

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
            budget_reason_code: BudgetReasonCode | None = None,
            input_tokens: int | None = None,
            output_tokens: int | None = None,
            usage_reports: int | None = None,
        ) -> None:
            nonlocal event_attempts, event_bytes, events_dropped
            event_attempts += 1
            event = AgentEvent(
                run_id=run.run_id,
                sequence=event_attempts,
                occurred_at=_utc(self._clock()),
                event_type=event_type,
                status=run.status,
                model=_safe_model(model),
                tool_name=tool_name,
                call_id=call_id,
                validation_error=validation_error,
                policy_decision=policy_decision,
                policy_reason_code=policy_reason_code,
                error_code=error_code,
                budget_reason_code=budget_reason_code,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                usage_reports=usage_reports,
            )
            encoded_size = _event_size(event)
            if (
                len(events) >= config.max_events
                or event_bytes + encoded_size > config.max_event_bytes
            ):
                events_dropped += 1
                return
            events.append(event)
            event_bytes += encoded_size

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
            budget_reason_code: BudgetReasonCode | None = None,
        ) -> AgentRunResult:
            move(status, reason)
            add_event(
                AgentEventType.RUN_TERMINATED,
                error_code=error_code,
                budget_reason_code=budget_reason_code,
            )
            return AgentRunResult(
                run=run,
                outcome=outcome,
                events=tuple(events),
                budget_snapshot=budget.snapshot(),
                proposal_decisions=proposals,
                response_summary=response_summary,
                error_code=error_code,
                model_requests=budget.model_requests,
                budget_reason_code=budget_reason_code,
                events_dropped=events_dropped,
                event_bytes=event_bytes,
            )

        def budget_failure(error: BudgetExceededError) -> AgentRunResult:
            error_code = _budget_error_code(error.reason_code)
            return finish(
                OrchestrationOutcome.LIMIT_EXCEEDED,
                RunStatus.PARTIAL,
                error.reason_code.value,
                error_code=error_code,
                budget_reason_code=error.reason_code,
            )

        def cancel(error: asyncio.CancelledError) -> None:
            result = finish(OrchestrationOutcome.CANCELLED, RunStatus.CANCELLED, "cancelled")
            raise AgentRunCancelled(result) from error

        add_event(AgentEventType.RUN_STARTED, model=config.model)
        move(RunStatus.INSPECTING, "request_preparation")
        move(RunStatus.PLANNING, "single_decision_cycle")
        try:
            await asyncio.sleep(0)
        except asyncio.CancelledError as error:
            cancel(error)
        try:
            timeout = budget.begin_model_request(config.request_timeout_seconds)
        except BudgetExceededError as error:
            return budget_failure(error)
        deadline_limited = (
            timeout < config.request_timeout_seconds or budget.remaining_seconds <= timeout
        )
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
        timeout_scope = asyncio.timeout(timeout)
        try:
            async with timeout_scope:
                response = await self._provider.next_action(request)
        except asyncio.CancelledError as error:
            cancel(error)
        except TimeoutError:
            if deadline_limited and timeout_scope.expired():
                return finish(
                    OrchestrationOutcome.LIMIT_EXCEEDED,
                    RunStatus.PARTIAL,
                    "run_deadline_exceeded",
                    error_code=OrchestrationErrorCode.RUN_DEADLINE_EXCEEDED,
                    budget_reason_code=BudgetReasonCode.RUN_DEADLINE_EXCEEDED,
                )
            return finish(
                OrchestrationOutcome.PROVIDER_ERROR,
                RunStatus.FAILED,
                "provider_timeout",
                error_code=OrchestrationErrorCode.PROVIDER_TIMEOUT,
            )
        except ModelProviderError as error:
            if (
                error.code is ProviderErrorCode.TIMEOUT
                and deadline_limited
                and timeout_scope.expired()
            ):
                return finish(
                    OrchestrationOutcome.LIMIT_EXCEEDED,
                    RunStatus.PARTIAL,
                    "run_deadline_exceeded",
                    error_code=OrchestrationErrorCode.RUN_DEADLINE_EXCEEDED,
                    budget_reason_code=BudgetReasonCode.RUN_DEADLINE_EXCEEDED,
                )
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

        try:
            budget.account_usage("model-request-1", response.usage)
        except BudgetExceededError as error:
            usage = budget.usage
            add_event(
                AgentEventType.USAGE_RECORDED,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                usage_reports=usage.reports,
                budget_reason_code=error.reason_code,
            )
            return budget_failure(error)
        except (TypeError, ValueError):
            return finish(
                OrchestrationOutcome.PROVIDER_ERROR,
                RunStatus.FAILED,
                "invalid_provider_response",
                error_code=OrchestrationErrorCode.INVALID_PROVIDER_RESPONSE,
            )
        usage = budget.usage
        add_event(
            AgentEventType.USAGE_RECORDED,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            usage_reports=usage.reports,
        )

        if budget.remaining_seconds <= 0:
            return finish(
                OrchestrationOutcome.LIMIT_EXCEEDED,
                RunStatus.PARTIAL,
                "run_deadline_exceeded",
                error_code=OrchestrationErrorCode.RUN_DEADLINE_EXCEEDED,
                budget_reason_code=BudgetReasonCode.RUN_DEADLINE_EXCEEDED,
            )

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

        try:
            budget.record_tool_call_proposals(len(response.tool_calls))
        except BudgetExceededError as error:
            return budget_failure(error)
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


def _safe_model(value: ModelIdentifier | None) -> ModelIdentifier | None:
    if value is None:
        return None
    if all(
        isinstance(part, str) and 0 < len(part) <= 128 and part.isprintable()
        for part in (value.provider_id, value.model_id)
    ):
        return value
    return None


def _event_size(event: AgentEvent) -> int:
    model = event.model
    data = {
        "run_id": str(event.run_id),
        "sequence": event.sequence,
        "occurred_at": event.occurred_at.isoformat(),
        "event_type": event.event_type.value,
        "status": event.status.value,
        "model": None if model is None else [model.provider_id, model.model_id],
        "tool_name": event.tool_name,
        "call_id": event.call_id,
        "validation_error": (
            None if event.validation_error is None else event.validation_error.value
        ),
        "policy_decision": None if event.policy_decision is None else event.policy_decision.value,
        "policy_reason_code": (
            None if event.policy_reason_code is None else event.policy_reason_code.value
        ),
        "error_code": None if event.error_code is None else event.error_code.value,
        "budget_reason_code": (
            None if event.budget_reason_code is None else event.budget_reason_code.value
        ),
        "input_tokens": event.input_tokens,
        "output_tokens": event.output_tokens,
        "usage_reports": event.usage_reports,
    }
    return len(json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))


def _budget_error_code(reason_code: BudgetReasonCode) -> OrchestrationErrorCode:
    return {
        BudgetReasonCode.MODEL_REQUEST_LIMIT: OrchestrationErrorCode.MODEL_REQUEST_LIMIT,
        BudgetReasonCode.RUN_DEADLINE_EXCEEDED: OrchestrationErrorCode.RUN_DEADLINE_EXCEEDED,
        BudgetReasonCode.TOOL_CALLS_PER_RESPONSE: OrchestrationErrorCode.TOO_MANY_TOOL_CALLS,
        BudgetReasonCode.TOTAL_TOOL_CALLS: OrchestrationErrorCode.TOTAL_TOOL_CALL_LIMIT,
        BudgetReasonCode.REPAIR_ATTEMPTS: OrchestrationErrorCode.REPAIR_ATTEMPT_LIMIT,
        BudgetReasonCode.REPORTED_INPUT_TOKENS: OrchestrationErrorCode.REPORTED_INPUT_TOKEN_LIMIT,
        BudgetReasonCode.REPORTED_OUTPUT_TOKENS: OrchestrationErrorCode.REPORTED_OUTPUT_TOKEN_LIMIT,
    }[reason_code]


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
