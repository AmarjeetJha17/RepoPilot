"""Docker CLI backend with fixed flags, trusted local contexts, and owned cleanup."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import signal
import stat
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from repopilot.sandbox.execution import (
    BackendExecution,
    ContainerSpec,
    SandboxCleanupError,
    SandboxConfig,
    SandboxUnsupportedError,
)

_CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
_OUTPUT_CHUNK = 4096


class DockerContext(StrEnum):
    """Operator-selected context names supported by the local sandbox backend."""

    DEFAULT = "default"
    ROOTLESS = "rootless"


def _docker_command(context: DockerContext, *arguments: str) -> list[str]:
    """Build a Docker argv with a validated, explicit local context."""
    return ["docker", "--context", context.value, *arguments]


class DockerCliBackend:
    """Use a trusted local context and fixed runner arguments."""

    def __init__(self, docker_context: DockerContext | str = DockerContext.DEFAULT) -> None:
        try:
            self._docker_context = DockerContext(docker_context)
        except ValueError as error:
            raise ValueError("Unsupported Docker context.") from error
        self._owned: dict[str, ContainerSpec] = {}

    @property
    def docker_context(self) -> DockerContext:
        """Return the fixed context used for this backend's entire container lifecycle."""
        return self._docker_context

    async def create(self, spec: ContainerSpec) -> str:
        self._validate_host_environment(spec.staging_root)
        await self._verify_daemon(spec.staging_root)
        await self._verify_image(spec.image)
        argv = _docker_command(
            self.docker_context,
            "create",
            "--pull=never",
            "--name",
            f"repopilot-{spec.execution_id}",
            "--label",
            f"org.repopilot.execution={spec.execution_id}",
            "--network=none",
            "--read-only",
            "--no-healthcheck",
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
            "--entrypoint",
            "python",
            "--env",
            "HOME=/tmp",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
            spec.image,
            *spec.argv[1:],
        )
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
        self._owned[container_id] = spec
        try:
            await self.inspect_isolation(container_id)
        except (OSError, RuntimeError, ValueError, asyncio.CancelledError) as error:
            if not await asyncio.shield(self.cleanup(container_id, 10)):
                raise SandboxCleanupError("Container inspection cleanup failed.") from error
            raise
        return container_id

    async def execute(
        self, container_id: str, max_runtime: float, output_limit: int
    ) -> BackendExecution:
        _validate_id(container_id)
        if container_id not in self._owned:
            raise ValueError("Container is not owned by this backend.")
        await self.inspect_isolation(container_id)
        process = await asyncio.create_subprocess_exec(
            *_docker_command(
                self.docker_context,
                "start",
                "--attach",
                container_id,
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_docker_env(),
            start_new_session=sys.platform.startswith("linux"),
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

        readers = (
            asyncio.create_task(drain(process.stdout, stdout)),
            asyncio.create_task(drain(process.stderr, stderr)),
        )
        try:
            await asyncio.wait_for(asyncio.gather(process.wait(), *readers), max_runtime)
        except (TimeoutError, asyncio.CancelledError):
            await _stop_client(process)
            raise
        finally:
            if process.returncode is None:
                await _stop_client(process)
            for reader in readers:
                reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
        state = await self._inspect_state(container_id)
        if truncated:
            exit_code, resource_limited = 137, True
        else:
            exit_code, resource_limited = _exit_state(state)
        return BackendExecution(
            exit_code,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            truncated,
            resource_limited,
            real_container=True,
            isolation_inspected=True,
        )

    async def cleanup(self, container_id: str, max_runtime: float) -> bool:
        _validate_id(container_id)
        if container_id not in self._owned:
            return False
        try:
            await self._verify_label(container_id)
            await _capture(
                _docker_command(self.docker_context, "rm", "--force", container_id),
                max_runtime=max_runtime,
            )
            remaining, _ = await _capture(
                _docker_command(
                    self.docker_context,
                    "ps",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    "--filter",
                    f"id={container_id}",
                ),
                max_runtime=max_runtime,
            )
            if remaining.strip():
                return False
            self._owned.pop(container_id)
            return True
        except (OSError, RuntimeError, ValueError, TimeoutError):
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
        if not staging_root.is_dir() or staging_root.is_symlink():
            raise SandboxUnsupportedError("Invalid staging directory.")

    async def _verify_daemon(self, staging_root: Path) -> None:
        endpoint, _ = await _capture(
            _docker_command(
                self.docker_context,
                "context",
                "inspect",
                self.docker_context.value,
                "--format",
                "{{json .Endpoints.docker.Host}}",
            ),
            max_runtime=10,
        )
        host = json.loads(endpoint.decode("utf-8", errors="strict"))
        if (
            not isinstance(host, str)
            or not host.startswith("unix:///")
            or ".." in Path(host.removeprefix("unix://")).parts
        ):
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
            if staging_info.st_mode & 0o022:
                raise SandboxUnsupportedError("Staging directory permits other-user writes.")
            if socket_info.st_uid != os.getuid() or not stat.S_ISSOCK(socket_info.st_mode):
                raise SandboxUnsupportedError(
                    "Docker socket is not owned by the current host user."
                )
        except OSError as error:
            raise SandboxUnsupportedError("Local rootless Docker socket is unavailable.") from error
        options, _ = await _capture(
            _docker_command(self.docker_context, "info", "--format", "{{json .SecurityOptions}}"),
            max_runtime=15,
        )
        security_options = json.loads(options.decode("utf-8", errors="strict"))
        if not isinstance(security_options, list) or any(
            not isinstance(item, str) for item in security_options
        ):
            raise SandboxUnsupportedError("Invalid daemon security response.")
        text = " ".join(item.lower() for item in security_options)
        if "name=rootless" not in security_options:
            raise SandboxUnsupportedError(
                "Docker daemon must be rootless; rootful user-namespace UID mapping is unsupported."
            )
        if (
            not any(item.split(",", 1)[0] == "name=seccomp" for item in security_options)
            or "unconfined" in text
        ):
            raise SandboxUnsupportedError(
                "Docker daemon does not report an active seccomp profile."
            )
        cgroups, _ = await _capture(
            _docker_command(
                self.docker_context,
                "info",
                "--format",
                "{{json .CgroupVersion}} {{json .CgroupDriver}}",
            ),
            max_runtime=10,
        )
        if cgroups.strip() != b'"2" "systemd"':
            raise SandboxUnsupportedError("Rootless resource limits require cgroup v2/systemd.")
        features, _ = await _capture(
            _docker_command(
                self.docker_context,
                "info",
                "--format",
                "{{json .MemoryLimit}} {{json .CpuCfsQuota}} {{json .PidsLimit}}",
            ),
            max_runtime=10,
        )
        if features.strip() != b"true true true":
            raise SandboxUnsupportedError("Required cgroup resource controllers are unavailable.")

    async def _cleanup_partial(self, container_name: str, execution_id: str) -> bool:
        """Remove only a uniquely named partial container with the exact owned label."""
        try:
            output, _ = await _capture(
                _docker_command(
                    self.docker_context,
                    "ps",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    "--filter",
                    f"name=^/{container_name}$",
                ),
                max_runtime=5,
            )
            container_id = output.decode("ascii", errors="strict").strip()
            if not container_id:
                return True
            _validate_id(container_id)
            label, _ = await _capture(
                _docker_command(
                    self.docker_context,
                    "inspect",
                    "--format",
                    '{{ index .Config.Labels "org.repopilot.execution" }}',
                    container_id,
                ),
                max_runtime=5,
            )
            if label.decode("ascii", errors="strict").strip() == execution_id:
                await _capture(
                    _docker_command(self.docker_context, "rm", "--force", container_id),
                    max_runtime=5,
                )
            return True
        except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
            return False

    async def _verify_image(self, image: str) -> None:
        SandboxConfig(image)
        output, _ = await _capture(
            _docker_command(
                self.docker_context,
                "image",
                "inspect",
                "--format",
                "{{json .RepoDigests}}",
                image,
            ),
            max_runtime=10,
        )
        digests = json.loads(output)
        if not isinstance(digests, list) or image not in digests:
            raise SandboxUnsupportedError("Configured image digest is not available locally.")

    async def _verify_label(self, container_id: str) -> None:
        spec = self._owned[container_id]
        output, _ = await _capture(
            _docker_command(
                self.docker_context,
                "inspect",
                "--format",
                '{{ index .Config.Labels "org.repopilot.execution" }}',
                container_id,
            ),
            max_runtime=5,
        )
        if output.decode("ascii").strip() != spec.execution_id:
            raise RuntimeError("Container ownership label mismatch.")

    async def _inspect_state(self, container_id: str) -> object:
        await self._verify_label(container_id)
        output, _ = await _capture(
            _docker_command(
                self.docker_context,
                "inspect",
                "--format",
                "{{json .State}}",
                container_id,
            ),
            max_runtime=5,
        )
        return json.loads(output)

    async def inspect_isolation(self, container_id: str) -> None:
        """Verify actual fixed configuration before start; this is not runtime enforcement proof."""
        _validate_id(container_id)
        if container_id not in self._owned:
            raise ValueError("Container is not owned by this backend.")
        await self._verify_label(container_id)
        output, _ = await _capture(
            _docker_command(
                self.docker_context,
                "inspect",
                "--format",
                "{{json .HostConfig}}\n{{json .Mounts}}\n{{json .Config.Env}}",
                container_id,
            ),
            max_runtime=5,
        )
        lines = output.splitlines()
        if len(lines) != 3:
            raise RuntimeError("Malformed isolation response.")
        host, mounts, environment = (json.loads(line) for line in lines)
        _check_isolation(self._owned[container_id], host, mounts, environment)


async def _capture(argv: list[str], *, max_runtime: float) -> tuple[bytes, bytes]:
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_docker_env(),
        start_new_session=sys.platform.startswith("linux"),
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
        await _stop_client(process)
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


async def _stop_client(process: asyncio.subprocess.Process) -> None:
    """Stop only this client's new process group; container termination uses owned cleanup."""
    if process.returncode is None:
        try:
            if sys.platform.startswith("linux"):
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
    await asyncio.wait_for(process.wait(), 5)


def _validate_id(container_id: str) -> None:
    if not isinstance(container_id, str) or not _CONTAINER_ID.fullmatch(container_id):
        raise ValueError("Invalid owned container identifier.")


def _exit_state(value: object) -> tuple[int, bool]:
    if not isinstance(value, dict):
        raise RuntimeError("Invalid container state.")
    if (
        value.get("Status") != "exited"
        or value.get("Running") is not False
        or type(value.get("ExitCode")) is not int
        or not 0 <= value["ExitCode"] <= 255
        or type(value.get("OOMKilled")) is not bool
        or value.get("Error") != ""
        or not value.get("StartedAt")
        or str(value["StartedAt"]).startswith("0001-")
    ):
        raise RuntimeError("Container command exit was not observed.")
    try:
        started = datetime.fromisoformat(value["StartedAt"])
        if started.tzinfo is None:
            raise ValueError("Missing timezone")
    except (TypeError, ValueError) as error:
        raise RuntimeError("Invalid container start timestamp.") from error
    return value["ExitCode"], value["OOMKilled"]


def _check_isolation(spec: ContainerSpec, host: object, mounts: object, env: object) -> None:
    if not isinstance(host, dict) or not isinstance(mounts, list) or not isinstance(env, list):
        raise RuntimeError("Malformed isolation configuration.")
    if (
        host.get("NetworkMode") != "none"
        or host.get("ReadonlyRootfs") is not True
        or host.get("Privileged") is not False
        or host.get("CapDrop") != ["ALL"]
        or host.get("CapAdd") not in (None, [])
        or "no-new-privileges:true" not in host.get("SecurityOpt", [])
        or host.get("Memory") != spec.limits.memory_bytes
        or host.get("NanoCpus") != int(spec.limits.cpu_count * 1_000_000_000)
        or host.get("PidsLimit") != spec.limits.pids
        or host.get("Tmpfs")
        != {"/tmp": f"rw,noexec,nosuid,nodev,size={spec.limits.tmpfs_bytes},mode=1777"}
        or len(mounts) != 1
    ):
        raise RuntimeError("Container isolation configuration mismatch.")
    mount = mounts[0]
    if (
        not isinstance(mount, dict)
        or mount.get("Type") != "bind"
        or mount.get("Source") != str(spec.staging_root)
        or mount.get("Destination") != "/workspace"
        or mount.get("RW") is not False
    ):
        raise RuntimeError("Container workspace mount mismatch.")
    allowed = {
        "PATH",
        "LANG",
        "LC_ALL",
        "PYTHON_VERSION",
        "PYTHON_SHA256",
        "HOME",
        "PYTHONDONTWRITEBYTECODE",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    }
    if any(not isinstance(item, str) or item.split("=", 1)[0] not in allowed for item in env):
        raise RuntimeError("Image environment requires operator review.")


class ReadinessStatus(StrEnum):
    READY = "READY"
    NOT_READY = "NOT_READY"


class ReadinessReason(StrEnum):
    READY = "prerequisites_observed"
    PLATFORM = "platform_unsupported"
    ROOT_USER = "root_host_user"
    CLI = "docker_cli_missing"
    ENDPOINT = "endpoint_override_or_remote"
    SOCKET = "socket_unavailable_or_owner_mismatch"
    ROOTFUL = "rootless_required"
    SECCOMP = "seccomp_required"
    CGROUP = "cgroup_v2_systemd_required"
    STAGING = "staging_incompatible"
    DAEMON = "daemon_unavailable_or_malformed"
    IMAGE = "image_missing_or_digest_mismatch"


@dataclass(frozen=True, slots=True)
class DockerReadiness:
    """Content-minimized diagnostic; readiness is not container execution evidence."""

    status: ReadinessStatus
    reason: ReadinessReason
    image_digest: str | None = None


async def diagnose_docker(
    config: SandboxConfig,
    staging_root: Path,
    *,
    docker_context: DockerContext | str = DockerContext.DEFAULT,
) -> DockerReadiness:
    """Inspect only the configured local environment and image, without creating containers."""
    try:
        backend = DockerCliBackend(docker_context)
    except ValueError:
        return DockerReadiness(ReadinessStatus.NOT_READY, ReadinessReason.ENDPOINT)
    phase = ReadinessReason.STAGING
    try:
        if not sys.platform.startswith("linux"):
            return DockerReadiness(ReadinessStatus.NOT_READY, ReadinessReason.PLATFORM)
        if os.getuid() == 0:
            return DockerReadiness(ReadinessStatus.NOT_READY, ReadinessReason.ROOT_USER)
        if shutil.which("docker") is None:
            return DockerReadiness(ReadinessStatus.NOT_READY, ReadinessReason.CLI)
        backend._validate_host_environment(staging_root)
        phase = ReadinessReason.DAEMON
        await backend._verify_daemon(staging_root)
        phase = ReadinessReason.IMAGE
        await backend._verify_image(config.image)
    except (OSError, RuntimeError, ValueError, UnicodeError, TimeoutError) as error:
        # Only map our fixed internal diagnostics; never expose the raw exception.
        message = str(error)
        if "rootless" in message or "non-root" in message:
            phase = ReadinessReason.ROOTFUL
        elif "seccomp" in message:
            phase = ReadinessReason.SECCOMP
        elif "cgroup" in message:
            phase = ReadinessReason.CGROUP
        elif "socket" in message:
            phase = ReadinessReason.SOCKET
        elif "endpoint" in message:
            phase = ReadinessReason.ENDPOINT
        return DockerReadiness(ReadinessStatus.NOT_READY, phase)
    return DockerReadiness(ReadinessStatus.READY, ReadinessReason.READY, config.image.split("@")[1])
