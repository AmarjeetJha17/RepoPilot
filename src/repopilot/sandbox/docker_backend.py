"""Docker CLI backend with fixed flags, bounded streams, and owned cleanup."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path

from repopilot.sandbox.execution import (
    BackendExecution,
    ContainerSpec,
    SandboxCleanupError,
    SandboxUnsupportedError,
)

_CONTAINER_ID = re.compile(r"^[a-fA-F0-9]{12,64}$")
_OUTPUT_CHUNK = 4096


class DockerCliBackend:
    """Use only the local default Docker context and fixed runner arguments."""

    async def create(self, spec: ContainerSpec) -> str:
        self._validate_host_environment(spec.staging_root)
        await self._verify_daemon(spec.staging_root)
        argv = [
            "docker",
            "--context",
            "default",
            "create",
            "--pull=never",
            "--name",
            f"repopilot-{spec.execution_id}",
            "--label",
            f"org.repopilot.execution={spec.execution_id}",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit",
            str(spec.limits.pids),
            "--memory",
            str(spec.limits.memory_bytes),
            "--cpus",
            str(spec.limits.cpu_count),
            "--user",
            "0:0",
            "--mount",
            f"type=bind,source={spec.staging_root},target=/workspace,readonly,bind-recursive=readonly",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={spec.limits.tmpfs_bytes},mode=1777",
            "--workdir",
            "/workspace",
            "--env",
            "HOME=/tmp",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
            spec.image,
            *spec.argv,
        ]
        container_name = f"repopilot-{spec.execution_id}"
        try:
            stdout, _ = await _capture(argv, max_runtime=30)
        except (OSError, RuntimeError, TimeoutError, asyncio.CancelledError) as error:
            cleaned = await asyncio.shield(self._cleanup_partial(container_name, spec.execution_id))
            if not cleaned:
                raise SandboxCleanupError("Partial container cleanup failed.") from error
            raise
        try:
            container_id = stdout.decode("ascii", errors="strict").strip()
        except UnicodeError as error:
            if not await self._cleanup_partial(container_name, spec.execution_id):
                raise SandboxCleanupError("Partial container cleanup failed.") from error
            raise RuntimeError("Docker returned an invalid container identifier.") from error
        if not _CONTAINER_ID.fullmatch(container_id):
            if not await self._cleanup_partial(container_name, spec.execution_id):
                raise SandboxCleanupError("Partial container cleanup failed.")
            raise RuntimeError("Docker returned an invalid container identifier.")
        return container_id

    async def execute(
        self, container_id: str, max_runtime: float, output_limit: int
    ) -> BackendExecution:
        _validate_id(container_id)
        process = await asyncio.create_subprocess_exec(
            "docker",
            "--context",
            "default",
            "start",
            "--attach",
            container_id,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_docker_env(),
        )
        assert process.stdout is not None and process.stderr is not None
        stdout = bytearray()
        stderr = bytearray()
        truncated = False

        async def drain(stream: asyncio.StreamReader, target: bytearray) -> None:
            nonlocal truncated
            while chunk := await stream.read(_OUTPUT_CHUNK):
                remaining = output_limit - len(stdout) - len(stderr)
                if remaining > 0:
                    target.extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    truncated = True
                    if process.returncode is None:
                        process.kill()

        try:
            readers = (
                asyncio.create_task(drain(process.stdout, stdout)),
                asyncio.create_task(drain(process.stderr, stderr)),
            )
            await asyncio.wait_for(process.wait(), max_runtime)
            await asyncio.gather(*readers)
        except (TimeoutError, asyncio.CancelledError):
            process.kill()
            await process.wait()
            raise
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        exit_code = process.returncode
        if exit_code is None:
            raise RuntimeError("Docker client exited without an exit status.")
        resource_limited = await self._was_oom_killed(container_id) if exit_code else False
        return BackendExecution(
            exit_code,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            truncated,
            resource_limited,
        )

    async def cleanup(self, container_id: str, max_runtime: float) -> bool:
        _validate_id(container_id)
        try:
            await _capture(
                ["docker", "--context", "default", "rm", "--force", container_id],
                max_runtime=max_runtime,
            )
            return True
        except (OSError, RuntimeError, TimeoutError):
            return False

    def _validate_host_environment(self, staging_root: Path) -> None:
        if not sys.platform.startswith("linux"):
            raise SandboxUnsupportedError("Docker sandbox execution is supported only on Linux.")
        if any(
            key in os.environ
            for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")
        ):
            raise SandboxUnsupportedError("Remote or overridden Docker endpoint is not permitted.")
        if not staging_root.is_absolute() or "," in str(staging_root):
            raise RuntimeError(
                "Workspace path cannot be represented safely in Docker mount syntax."
            )

    async def _verify_daemon(self, staging_root: Path) -> None:
        endpoint, _ = await _capture(
            [
                "docker",
                "--context",
                "default",
                "context",
                "inspect",
                "default",
                "--format",
                "{{json .Endpoints.docker.Host}}",
            ],
            max_runtime=10,
        )
        host = json.loads(endpoint.decode("utf-8", errors="strict"))
        if not isinstance(host, str) or not host.startswith("unix://"):
            raise SandboxUnsupportedError("Only a local Unix-socket Docker endpoint is supported.")
        if not hasattr(os, "getuid") or os.getuid() == 0:
            raise SandboxUnsupportedError("Sandbox execution requires a non-root Linux host user.")
        try:
            staging_info, socket_info = await asyncio.gather(
                asyncio.to_thread(staging_root.stat),
                asyncio.to_thread(Path(host.removeprefix("unix://")).stat),
            )
            if staging_info.st_uid != os.getuid():
                raise SandboxUnsupportedError(
                    "Staging workspace is not owned by the current host user."
                )
            if socket_info.st_uid != os.getuid():
                raise SandboxUnsupportedError(
                    "Docker socket is not owned by the current host user."
                )
        except OSError as error:
            raise SandboxUnsupportedError("Local rootless Docker socket is unavailable.") from error
        options, _ = await _capture(
            ["docker", "--context", "default", "info", "--format", "{{json .SecurityOptions}}"],
            max_runtime=15,
        )
        security_options = json.loads(options.decode("utf-8", errors="strict"))
        text = " ".join(item.lower() for item in security_options if isinstance(item, str))
        if "rootless" not in text:
            raise SandboxUnsupportedError(
                "Docker daemon must be rootless; rootful user-namespace UID mapping is unsupported."
            )
        if "seccomp" not in text or "unconfined" in text:
            raise SandboxUnsupportedError(
                "Docker daemon does not report an active seccomp profile."
            )

    async def _cleanup_partial(self, container_name: str, execution_id: str) -> bool:
        """Remove only a uniquely named partial container with the exact owned label."""
        try:
            output, _ = await _capture(
                [
                    "docker",
                    "--context",
                    "default",
                    "ps",
                    "--all",
                    "--quiet",
                    "--filter",
                    f"name=^/{container_name}$",
                ],
                max_runtime=5,
            )
            container_id = output.decode("ascii", errors="strict").strip()
            if not container_id:
                return True
            _validate_id(container_id)
            label, _ = await _capture(
                [
                    "docker",
                    "--context",
                    "default",
                    "inspect",
                    "--format",
                    '{{ index .Config.Labels "org.repopilot.execution" }}',
                    container_id,
                ],
                max_runtime=5,
            )
            if label.decode("ascii", errors="strict").strip() == execution_id:
                await _capture(
                    ["docker", "--context", "default", "rm", "--force", container_id],
                    max_runtime=5,
                )
            return True
        except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
            return False

    async def _was_oom_killed(self, container_id: str) -> bool:
        try:
            state, _ = await _capture(
                [
                    "docker",
                    "--context",
                    "default",
                    "inspect",
                    "--format",
                    "{{.State.OOMKilled}}",
                    container_id,
                ],
                max_runtime=5,
            )
            return state.decode("ascii", errors="strict").strip().casefold() == "true"
        except (OSError, RuntimeError, TimeoutError, UnicodeError):
            return False


async def _capture(argv: list[str], *, max_runtime: float) -> tuple[bytes, bytes]:
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_docker_env(),
    )
    assert process.stdout is not None and process.stderr is not None
    output_limit = 4096
    stdout = bytearray()
    stderr = bytearray()
    oversized = False

    async def drain(stream: asyncio.StreamReader, target: bytearray) -> None:
        nonlocal oversized
        while chunk := await stream.read(_OUTPUT_CHUNK):
            remaining = output_limit - len(stdout) - len(stderr)
            if remaining > 0:
                target.extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                oversized = True
                if process.returncode is None:
                    process.kill()

    readers = (
        asyncio.create_task(drain(process.stdout, stdout)),
        asyncio.create_task(drain(process.stderr, stderr)),
    )
    try:
        await asyncio.wait_for(
            asyncio.gather(process.wait(), *readers),
            max_runtime,
        )
    except (TimeoutError, asyncio.CancelledError):
        process.kill()
        await process.wait()
        await asyncio.gather(*readers, return_exceptions=True)
        raise
    if process.returncode:
        raise RuntimeError("Docker command failed.")
    if oversized:
        raise RuntimeError("Docker command returned excessive diagnostic output.")
    return bytes(stdout), bytes(stderr)


def _docker_env() -> dict[str, str]:
    path = os.environ.get("PATH", "/usr/bin:/bin")
    return {"PATH": path, "HOME": os.environ.get("HOME", "/"), "LANG": "C.UTF-8"}


def _validate_id(container_id: str) -> None:
    if not isinstance(container_id, str) or not _CONTAINER_ID.fullmatch(container_id):
        raise ValueError("Invalid owned container identifier.")
