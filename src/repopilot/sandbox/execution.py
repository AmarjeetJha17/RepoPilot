"""Policy-gated, bounded execution of fixed verification commands."""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from repopilot.agent.contracts import ToolCall
from repopilot.sandbox.workspace import (
    IntegrityChangeKind,
    WorkspaceError,
    WorkspaceHandle,
    WorkspaceManager,
    workspace_identity_for_handle,
)
from repopilot.security.capabilities import Capability
from repopilot.security.policy import (
    AuthorizationContext,
    DefaultPolicyEngine,
    ExecutionWorkspace,
    PolicyDecision,
)
from repopilot.tools.definition import ToolDefinition
from repopilot.tools.registry import ToolRegistry

_IMAGE_DIGEST = re.compile(r"^[\w./:-]+@sha256:[a-fA-F0-9]{64}$")
_MAX_PATHS = 64
_MAX_OUTPUT_BYTES = 256 * 1024


class VerificationCommand(StrEnum):
    """The only command families accepted by this runner."""

    PYTHON_SYNTAX = "python-syntax"
    PYTEST = "pytest"


class ExecutionStatus(StrEnum):
    """Safe, stable execution outcomes."""

    PASSED = "passed"
    COMMAND_FAILED = "command_failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    RESOURCE_LIMIT = "resource_limit"
    DENIED = "denied"
    UNSUPPORTED = "unsupported"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    CLEANUP_FAILED = "cleanup_failed"


class CleanupStatus(StrEnum):
    NOT_CREATED = "not_created"
    REMOVED = "removed"
    FAILED = "failed"


class SandboxUnsupportedError(RuntimeError):
    """The host or Docker isolation mode cannot satisfy the runner contract."""


class SandboxCleanupError(RuntimeError):
    """A created or partially created container could not be safely removed."""


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    """Hard upper bounds; callers cannot raise limits above these defaults."""

    timeout_seconds: float = 120.0
    memory_bytes: int = 1_073_741_824
    cpu_count: float = 1.0
    pids: int = 128
    tmpfs_bytes: int = 67_108_864
    output_bytes: int = _MAX_OUTPUT_BYTES

    def __post_init__(self) -> None:
        if not 0 < self.timeout_seconds <= 600:
            raise ValueError("Execution timeout must be within 1..600 seconds.")
        if not 16_777_216 <= self.memory_bytes <= 4_294_967_296:
            raise ValueError("Memory limit is outside the supported range.")
        if not 0 < self.cpu_count <= 4:
            raise ValueError("CPU limit is outside the supported range.")
        if not 16 <= self.pids <= 512:
            raise ValueError("PID limit is outside the supported range.")
        if not 1_048_576 <= self.tmpfs_bytes <= 536_870_912:
            raise ValueError("Temporary filesystem limit is outside the supported range.")
        if not 1024 <= self.output_bytes <= _MAX_OUTPUT_BYTES:
            raise ValueError("Output limit is outside the supported range.")


@dataclass(frozen=True, slots=True)
class SandboxConfig:
    """Trusted operator configuration. No image is pulled implicitly."""

    image: str

    def __post_init__(self) -> None:
        if not isinstance(self.image, str) or not _IMAGE_DIGEST.fullmatch(self.image):
            raise ValueError("Sandbox image must use an immutable sha256 digest.")


@dataclass(frozen=True, slots=True)
class SandboxRequest:
    """Validated application request; paths are relative staging paths."""

    command: VerificationCommand
    paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.command, VerificationCommand):
            raise ValueError("Unsupported verification command.")
        if not isinstance(self.paths, tuple) or not 1 <= len(self.paths) <= _MAX_PATHS:
            raise ValueError("A bounded tuple of target paths is required.")
        if any(
            not isinstance(path, str)
            or not path
            or path.startswith(("/", "\\"))
            or "\\" in path
            or ":" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or "\x00" in path
            for path in self.paths
        ):
            raise ValueError("Target paths must be normalized workspace-relative paths.")
        if len(set(self.paths)) != len(self.paths):
            raise ValueError("Target paths must be unique.")


@dataclass(frozen=True, slots=True)
class ContainerSpec:
    """Complete trusted container configuration passed to a backend."""

    execution_id: str
    image: str
    staging_root: Path
    argv: tuple[str, ...]
    limits: SandboxLimits


@dataclass(frozen=True, slots=True)
class BackendExecution:
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool = False
    resource_limited: bool = False


class SandboxBackend(Protocol):
    """Narrow lifecycle interface; implementations must remove only owned IDs."""

    async def create(self, spec: ContainerSpec) -> str: ...

    async def execute(
        self, container_id: str, max_runtime: float, output_limit: int
    ) -> BackendExecution: ...

    async def cleanup(self, container_id: str, max_runtime: float) -> bool: ...


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    execution_id: str
    command: VerificationCommand
    status: ExecutionStatus
    exit_code: int | None
    duration_seconds: float
    stdout: str = ""
    stderr: str = ""
    output_truncated: bool = False
    cleanup: CleanupStatus = CleanupStatus.NOT_CREATED


class _SandboxPolicyArgs(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    paths: list[str] = Field(min_length=1, max_length=_MAX_PATHS)


class SandboxRunner:
    """Authorize and run fixed verification commands in an isolated container."""

    def __init__(
        self,
        manager: WorkspaceManager,
        handle: WorkspaceHandle,
        authorization: AuthorizationContext,
        config: SandboxConfig,
        backend: SandboxBackend,
        *,
        limits: SandboxLimits = SandboxLimits(),
        concurrency: int = 1,
        policy: DefaultPolicyEngine | None = None,
    ) -> None:
        if concurrency != 1:
            raise ValueError("This runner supports exactly one concurrent execution per instance.")
        if (
            authorization.workspace is not ExecutionWorkspace.SANDBOX
            or authorization.workspace_identity != workspace_identity_for_handle(handle)
            or not _same_path(authorization.workspace_root, handle.staging_root)
        ):
            raise ValueError("Sandbox authorization must match the exact staged workspace.")
        self._manager = manager
        self._handle = handle
        self._authorization = authorization
        self._config = config
        self._backend = backend
        self._limits = limits
        self._lock = asyncio.Lock()
        self._policy_registry = ToolRegistry(
            (
                ToolDefinition(
                    name="sandbox_verify",
                    description="Authorize fixed verification targets in the isolated sandbox.",
                    arguments_model=_SandboxPolicyArgs,
                    capabilities=frozenset({Capability.SANDBOXED_TEST_EXECUTION}),
                    resource_fields=("paths",),
                ),
            )
        )
        self._policy = policy or DefaultPolicyEngine(self._policy_registry)

    async def run(
        self,
        request: SandboxRequest,
        *,
        cancellation: asyncio.Event | None = None,
    ) -> ExecutionResult:
        """Run an authorized fixed command; always clean an owned container."""
        started = time.monotonic()
        execution_id = str(uuid4())
        status = ExecutionStatus.INFRASTRUCTURE_ERROR
        exit_code: int | None = None
        stdout = stderr = ""
        truncated = False
        container_id: str | None = None
        cleanup = CleanupStatus.NOT_CREATED
        async with self._lock:
            try:
                self._validate_request(request)
                if cancellation is not None and cancellation.is_set():
                    status = ExecutionStatus.CANCELLED
                    return self._result(execution_id, request.command, status, None, started)
                self._authorize(request)
                if not self._integrity_is_eligible():
                    status = ExecutionStatus.DENIED
                    return self._result(execution_id, request.command, status, None, started)
                argv = _command_argv(request)
                spec = ContainerSpec(
                    execution_id,
                    self._config.image,
                    self._handle.staging_root,
                    argv,
                    self._limits,
                )
                container_id = await asyncio.wait_for(
                    self._backend.create(spec), timeout=min(30.0, self._limits.timeout_seconds)
                )
                if not self._integrity_is_eligible():
                    status = ExecutionStatus.DENIED
                else:
                    operation = asyncio.create_task(
                        self._backend.execute(
                            container_id, self._limits.timeout_seconds, self._limits.output_bytes
                        )
                    )
                    if cancellation is None:
                        outcome = await asyncio.wait_for(operation, self._limits.timeout_seconds)
                    else:
                        cancelled = asyncio.create_task(cancellation.wait())
                        done, _ = await asyncio.wait(
                            {operation, cancelled},
                            timeout=self._limits.timeout_seconds,
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        if cancelled in done and cancelled.result():
                            operation.cancel()
                            await asyncio.gather(operation, return_exceptions=True)
                            cancelled.cancel()
                            status = ExecutionStatus.CANCELLED
                            outcome = None
                        elif operation not in done:
                            operation.cancel()
                            await asyncio.gather(operation, return_exceptions=True)
                            cancelled.cancel()
                            status = ExecutionStatus.TIMED_OUT
                            outcome = None
                        else:
                            cancelled.cancel()
                            outcome = operation.result()
                    if outcome is not None:
                        exit_code = outcome.exit_code
                        stdout, stderr, truncated = (
                            outcome.stdout,
                            outcome.stderr,
                            outcome.truncated,
                        )
                        status = (
                            ExecutionStatus.RESOURCE_LIMIT
                            if truncated or outcome.resource_limited
                            else ExecutionStatus.PASSED
                            if exit_code == 0
                            else ExecutionStatus.COMMAND_FAILED
                        )
            except TimeoutError:
                status = ExecutionStatus.TIMED_OUT
            except asyncio.CancelledError:
                raise
            except PermissionError:
                status = ExecutionStatus.DENIED
            except WorkspaceError:
                status = ExecutionStatus.DENIED
            except (ValueError, TypeError):
                status = ExecutionStatus.DENIED
            except SandboxUnsupportedError:
                status = ExecutionStatus.UNSUPPORTED
            except SandboxCleanupError:
                status = ExecutionStatus.CLEANUP_FAILED
                cleanup = CleanupStatus.FAILED
            except (OSError, RuntimeError):
                status = ExecutionStatus.INFRASTRUCTURE_ERROR
            finally:
                if container_id is not None:
                    try:
                        removed = await asyncio.wait_for(
                            self._backend.cleanup(container_id, 10), 12
                        )
                        cleanup = CleanupStatus.REMOVED if removed else CleanupStatus.FAILED
                    except (TimeoutError, OSError, RuntimeError):
                        cleanup = CleanupStatus.FAILED
        if cleanup is CleanupStatus.FAILED:
            status = ExecutionStatus.CLEANUP_FAILED
        return ExecutionResult(
            execution_id,
            request.command,
            status,
            exit_code,
            max(0.0, time.monotonic() - started),
            stdout,
            stderr,
            truncated,
            cleanup,
        )

    def _validate_request(self, request: SandboxRequest) -> None:
        if not isinstance(request, SandboxRequest):
            raise ValueError("Invalid sandbox request.")
        baseline = {item.path for item in self._handle.baseline.files}
        if any(path not in baseline for path in request.paths):
            raise ValueError("Targets must be baseline files in the staged workspace.")
        if request.command is VerificationCommand.PYTHON_SYNTAX and any(
            not path.endswith(".py") for path in request.paths
        ):
            raise ValueError("Syntax verification accepts Python files only.")

    def _integrity_is_eligible(self) -> bool:
        report = self._manager.check_integrity(self._handle)
        return all(change.kind is IntegrityChangeKind.MODIFIED for change in report.changes)

    def _authorize(self, request: SandboxRequest) -> None:
        proposal = ToolCall("sandbox-run", "sandbox_verify", {"paths": list(request.paths)})
        call = self._policy_registry.validate_call(proposal)
        decision = self._policy.authorize(call, self._authorization, self._handle.staging_root)
        if (
            decision.decision is not PolicyDecision.ALLOW
            or decision.call_id != proposal.id
            or decision.capabilities != (Capability.SANDBOXED_TEST_EXECUTION,)
        ):
            raise PermissionError("Sandbox execution denied.")

    def _result(
        self,
        execution_id: str,
        command: VerificationCommand,
        status: ExecutionStatus,
        exit_code: int | None,
        started: float,
    ) -> ExecutionResult:
        return ExecutionResult(
            execution_id,
            command,
            status,
            exit_code,
            max(0.0, time.monotonic() - started),
        )


def _command_argv(request: SandboxRequest) -> tuple[str, ...]:
    targets = tuple(f"/workspace/{path}" for path in request.paths)
    if request.command is VerificationCommand.PYTHON_SYNTAX:
        parser = (
            "import ast,pathlib,sys; "
            "[ast.parse(pathlib.Path(p).read_bytes(), filename=p) for p in sys.argv[1:]]"
        )
        return ("python", "-I", "-B", "-c", parser, *targets)
    return (
        "python",
        "-I",
        "-B",
        "-m",
        "pytest",
        "-c",
        "/dev/null",
        "-p",
        "no:cacheprovider",
        "--rootdir=/workspace",
        *targets,
    )


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve(strict=True) == right.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False
