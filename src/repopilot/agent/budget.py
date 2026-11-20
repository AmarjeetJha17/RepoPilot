"""Reusable run limits and deterministic post-response usage accounting."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from repopilot.providers.base import TokenUsage

_REPORT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
MAX_REPORTED_TOKEN_COUNT = (1 << 63) - 1


class BudgetReasonCode(StrEnum):
    """Stable reasons for a configured runtime limit being reached."""

    MODEL_REQUEST_LIMIT = "model_request_limit"
    RUN_DEADLINE_EXCEEDED = "run_deadline_exceeded"
    TOOL_CALLS_PER_RESPONSE = "tool_calls_per_response_limit"
    TOTAL_TOOL_CALLS = "total_tool_call_limit"
    REPAIR_ATTEMPTS = "repair_attempt_limit"
    REPORTED_INPUT_TOKENS = "reported_input_token_limit"
    REPORTED_OUTPUT_TOKENS = "reported_output_token_limit"


class BudgetExceededError(RuntimeError):
    """A configured runtime budget prevented or stopped work."""

    def __init__(self, reason_code: BudgetReasonCode) -> None:
        self.reason_code = reason_code
        super().__init__(f"Runtime budget exceeded: {reason_code.value}.")


@dataclass(frozen=True, slots=True)
class BudgetConfig:
    """Configured ceilings; token ceilings apply only to provider-reported usage."""

    max_model_requests: int = 30
    max_run_seconds: float = 900.0
    max_tool_calls_per_response: int = 8
    max_total_tool_calls: int | None = None
    max_repair_attempts: int = 3
    max_reported_input_tokens: int | None = None
    max_reported_output_tokens: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "max_model_requests",
            "max_tool_calls_per_response",
            "max_repair_attempts",
        ):
            _validate_count(getattr(self, name), allow_zero=True)
        if self.max_total_tool_calls is not None:
            _validate_count(self.max_total_tool_calls, allow_zero=True)
        if self.max_reported_input_tokens is not None:
            _validate_count(self.max_reported_input_tokens, allow_zero=True)
        if self.max_reported_output_tokens is not None:
            _validate_count(self.max_reported_output_tokens, allow_zero=True)
        if (
            isinstance(self.max_run_seconds, bool)
            or not isinstance(self.max_run_seconds, int | float)
            or not _is_finite(self.max_run_seconds)
            or self.max_run_seconds <= 0
        ):
            raise ValueError("Run duration budget must be positive and finite.")


@dataclass(frozen=True, slots=True)
class UsageSnapshot:
    """Known cumulative provider usage; a missing dimension remains unknown."""

    input_tokens: int | None
    output_tokens: int | None
    reports: int
    missing_reports: int


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
    """Measured consumption paired with its configured limits."""

    limits: BudgetConfig
    model_requests: int
    tool_call_proposals: int
    repair_attempts: int
    elapsed_seconds: float
    usage: UsageSnapshot


class RuntimeBudget:
    """Track one run's counts, monotonic deadline, and provider-reported token usage."""

    def __init__(
        self,
        limits: BudgetConfig,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(limits, BudgetConfig):
            raise TypeError("Runtime budget limits must be a BudgetConfig.")
        self.limits = limits
        self._clock = clock
        self._started_at = self._read_clock()
        self._last_clock = self._started_at
        self.model_requests = 0
        self.tool_call_proposals = 0
        self.repair_attempts = 0
        self._usage_report_ids: set[str] = set()
        self._usage_reports = 0
        self._missing_usage_reports = 0
        self._input_tokens = 0
        self._output_tokens = 0
        self._input_known = True
        self._output_known = True

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.limits.max_run_seconds - (self._read_clock() - self._started_at))

    @property
    def usage(self) -> UsageSnapshot:
        return UsageSnapshot(
            input_tokens=self._input_tokens if self._usage_reports and self._input_known else None,
            output_tokens=(
                self._output_tokens if self._usage_reports and self._output_known else None
            ),
            reports=self._usage_reports,
            missing_reports=self._missing_usage_reports,
        )

    def begin_model_request(self, requested_timeout: float) -> float:
        """Consume one request slot and return a timeout bounded by remaining wall time."""
        if (
            isinstance(requested_timeout, bool)
            or not isinstance(requested_timeout, int | float)
            or not _is_finite(requested_timeout)
            or requested_timeout <= 0
        ):
            raise ValueError("Provider timeout must be positive and finite.")
        if self.model_requests >= self.limits.max_model_requests:
            raise BudgetExceededError(BudgetReasonCode.MODEL_REQUEST_LIMIT)
        remaining = self.remaining_seconds
        if remaining <= 0:
            raise BudgetExceededError(BudgetReasonCode.RUN_DEADLINE_EXCEEDED)
        self.model_requests += 1
        return min(float(requested_timeout), remaining)

    def record_tool_call_proposals(self, count: int) -> None:
        """Measure proposals, then reject a per-response or cumulative overage."""
        _validate_count(count, allow_zero=True)
        self.tool_call_proposals += count
        if count > self.limits.max_tool_calls_per_response:
            raise BudgetExceededError(BudgetReasonCode.TOOL_CALLS_PER_RESPONSE)
        if (
            self.limits.max_total_tool_calls is not None
            and self.tool_call_proposals > self.limits.max_total_tool_calls
        ):
            raise BudgetExceededError(BudgetReasonCode.TOTAL_TOOL_CALLS)

    def record_repair_attempt(self) -> None:
        """Measure a repair attempt and reject attempts above the configured ceiling."""
        self.repair_attempts += 1
        if self.repair_attempts > self.limits.max_repair_attempts:
            raise BudgetExceededError(BudgetReasonCode.REPAIR_ATTEMPTS)

    def account_usage(self, report_id: str, usage: TokenUsage | None) -> bool:
        """Account one unique provider report; return false for a duplicate report ID."""
        if not isinstance(report_id, str) or not _REPORT_ID.fullmatch(report_id):
            raise ValueError("Usage report ID must be a bounded safe identifier.")
        if usage is not None and not isinstance(usage, TokenUsage):
            raise TypeError("Provider usage must be TokenUsage or None.")
        if usage is not None and any(
            count is not None and count > MAX_REPORTED_TOKEN_COUNT
            for count in (usage.input_tokens, usage.output_tokens)
        ):
            raise ValueError("Provider token usage exceeds the supported count range.")
        if report_id in self._usage_report_ids:
            return False
        self._usage_report_ids.add(report_id)
        self._usage_reports += 1
        if usage is None:
            self._missing_usage_reports += 1
            self._input_known = self._output_known = False
        else:
            if usage.input_tokens is None:
                self._input_known = False
            elif self._input_known:
                self._input_tokens += usage.input_tokens
            if usage.output_tokens is None:
                self._output_known = False
            elif self._output_known:
                self._output_tokens += usage.output_tokens
        self._check_reported_token_limits()
        return True

    def snapshot(self) -> BudgetSnapshot:
        """Return configured ceilings and measured consumption at the current clock time."""
        elapsed = max(0.0, self._read_clock() - self._started_at)
        return BudgetSnapshot(
            limits=self.limits,
            model_requests=self.model_requests,
            tool_call_proposals=self.tool_call_proposals,
            repair_attempts=self.repair_attempts,
            elapsed_seconds=elapsed,
            usage=self.usage,
        )

    def _check_reported_token_limits(self) -> None:
        if (
            self.limits.max_reported_input_tokens is not None
            and self.usage.input_tokens is not None
            and self.usage.input_tokens > self.limits.max_reported_input_tokens
        ):
            raise BudgetExceededError(BudgetReasonCode.REPORTED_INPUT_TOKENS)
        if (
            self.limits.max_reported_output_tokens is not None
            and self.usage.output_tokens is not None
            and self.usage.output_tokens > self.limits.max_reported_output_tokens
        ):
            raise BudgetExceededError(BudgetReasonCode.REPORTED_OUTPUT_TOKENS)

    def _read_clock(self) -> float:
        value = self._clock()
        if not isinstance(value, int | float) or isinstance(value, bool) or not _is_finite(value):
            raise ValueError("Monotonic clock must return a finite number.")
        if hasattr(self, "_last_clock") and value < self._last_clock:
            raise ValueError("Monotonic clock moved backwards.")
        self._last_clock = float(value)
        return self._last_clock


def _validate_count(value: object, *, allow_zero: bool) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < (0 if allow_zero else 1):
        raise ValueError("Budget counts must be non-negative integers.")


def _is_finite(value: int | float) -> bool:
    try:
        return math.isfinite(value)
    except OverflowError:
        return False
