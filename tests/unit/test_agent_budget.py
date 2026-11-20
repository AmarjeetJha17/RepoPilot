"""Deterministic tests for reusable runtime budgets and provider usage accounting."""

from __future__ import annotations

import math

import pytest

from repopilot.agent.budget import (
    BudgetConfig,
    BudgetExceededError,
    BudgetReasonCode,
    RuntimeBudget,
)
from repopilot.providers.base import TokenUsage

pytestmark = pytest.mark.unit


def test_architecture_defaults_and_configured_limits_are_explicit() -> None:
    config = BudgetConfig()

    assert config.max_model_requests == 30
    assert config.max_run_seconds == 900
    assert config.max_repair_attempts == 3
    assert not hasattr(config, "estimated_cost_usd")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_model_requests": -1},
        {"max_run_seconds": 0},
        {"max_run_seconds": math.inf},
        {"max_run_seconds": math.nan},
        {"max_run_seconds": 10**1000},
        {"max_tool_calls_per_response": -1},
        {"max_total_tool_calls": -1},
        {"max_repair_attempts": -1},
        {"max_reported_input_tokens": -1},
        {"max_reported_output_tokens": -1},
    ],
)
def test_invalid_budget_limits_are_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        BudgetConfig(**kwargs)  # type: ignore[arg-type]


def test_request_limit_and_effective_timeout_use_monotonic_deadline() -> None:
    now = [10.0]
    budget = RuntimeBudget(
        BudgetConfig(max_model_requests=1, max_run_seconds=0.5), clock=lambda: now[0]
    )

    assert budget.begin_model_request(60) == 0.5
    with pytest.raises(BudgetExceededError) as exceeded:
        budget.begin_model_request(60)
    assert exceeded.value.reason_code is BudgetReasonCode.MODEL_REQUEST_LIMIT
    assert budget.snapshot().model_requests == 1


def test_expired_deadline_prevents_a_provider_request() -> None:
    now = [0.0]
    budget = RuntimeBudget(BudgetConfig(max_run_seconds=1), clock=lambda: now[0])
    now[0] = 1.0

    with pytest.raises(BudgetExceededError) as exceeded:
        budget.begin_model_request(0.5)

    assert exceeded.value.reason_code is BudgetReasonCode.RUN_DEADLINE_EXCEEDED
    assert budget.snapshot().model_requests == 0


def test_tool_proposal_and_repair_consumption_are_measured_before_rejection() -> None:
    budget = RuntimeBudget(
        BudgetConfig(max_tool_calls_per_response=2, max_total_tool_calls=2, max_repair_attempts=1),
        clock=lambda: 0.0,
    )

    budget.record_tool_call_proposals(2)
    with pytest.raises(BudgetExceededError) as proposals:
        budget.record_tool_call_proposals(1)
    assert proposals.value.reason_code is BudgetReasonCode.TOTAL_TOOL_CALLS
    assert budget.snapshot().tool_call_proposals == 3

    budget.record_repair_attempt()
    with pytest.raises(BudgetExceededError) as repairs:
        budget.record_repair_attempt()
    assert repairs.value.reason_code is BudgetReasonCode.REPAIR_ATTEMPTS
    assert budget.snapshot().repair_attempts == 2


def test_unknown_partial_and_zero_usage_remain_distinct() -> None:
    budget = RuntimeBudget(BudgetConfig(), clock=lambda: 0.0)

    assert budget.usage.input_tokens is None
    assert budget.account_usage("request-1", None)
    assert budget.usage.input_tokens is None
    assert budget.account_usage("request-2", TokenUsage(input_tokens=4, output_tokens=None))
    assert budget.usage.input_tokens is None
    assert budget.usage.output_tokens is None
    assert budget.account_usage("request-3", TokenUsage(input_tokens=0, output_tokens=0))
    assert budget.usage.input_tokens is None
    assert budget.usage.output_tokens is None
    assert budget.usage.reports == 3
    assert budget.usage.missing_reports == 1


def test_partial_usage_preserves_only_the_known_dimension() -> None:
    budget = RuntimeBudget(BudgetConfig(), clock=lambda: 0.0)

    budget.account_usage("request-1", TokenUsage(input_tokens=4, output_tokens=None))

    assert budget.usage.input_tokens == 4
    assert budget.usage.output_tokens is None


def test_known_zero_and_cumulative_usage_are_aggregated_deterministically() -> None:
    budget = RuntimeBudget(BudgetConfig(), clock=lambda: 0.0)

    assert budget.account_usage("request-1", TokenUsage(0, 0))
    assert budget.account_usage("request-2", TokenUsage(7, 3))

    assert budget.usage.input_tokens == 7
    assert budget.usage.output_tokens == 3
    assert budget.usage.reports == 2


def test_duplicate_usage_report_is_ignored_without_double_counting() -> None:
    budget = RuntimeBudget(BudgetConfig(), clock=lambda: 0.0)
    report = TokenUsage(8, 2)

    assert budget.account_usage("request-1", report)
    assert not budget.account_usage("request-1", report)
    assert budget.usage.input_tokens == 8
    assert budget.usage.output_tokens == 2
    assert budget.usage.reports == 1


def test_reported_token_limit_is_post_response_and_preserves_actual_usage() -> None:
    budget = RuntimeBudget(BudgetConfig(max_reported_output_tokens=2), clock=lambda: 0.0)

    with pytest.raises(BudgetExceededError) as exceeded:
        budget.account_usage("request-1", TokenUsage(5, 3))

    assert exceeded.value.reason_code is BudgetReasonCode.REPORTED_OUTPUT_TOKENS
    assert budget.usage.output_tokens == 3


def test_invalid_provider_usage_count_is_rejected() -> None:
    budget = RuntimeBudget(BudgetConfig(), clock=lambda: 0.0)

    with pytest.raises(ValueError, match="supported count range"):
        budget.account_usage("request-1", TokenUsage(1 << 64, 0))
