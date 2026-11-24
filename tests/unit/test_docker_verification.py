"""Offline verification of Docker diagnostics and command exit semantics."""

import asyncio
import dataclasses
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts.verify_docker_sandbox import _scenario_passed

from repopilot.sandbox import docker_backend as docker
from repopilot.sandbox.execution import (
    CleanupStatus,
    ContainerSpec,
    ExecutionResult,
    ExecutionStatus,
    ExecutionTimeoutPhase,
    SandboxConfig,
    SandboxExecutionTimeout,
    SandboxLimits,
    SandboxUnsupportedError,
    VerificationCommand,
)

IMAGE = "example.invalid/reviewed@sha256:" + "a" * 64


def _exit_state(exit_code: int = 0, *, seconds: float = 0.1) -> dict[str, object]:
    finished = datetime.now(UTC)
    started = finished - timedelta(seconds=seconds)
    return {
        "Status": "exited",
        "Running": False,
        "ExitCode": exit_code,
        "OOMKilled": False,
        "Error": "",
        "StartedAt": started.isoformat(),
        "FinishedAt": finished.isoformat(),
    }


def immediate(coroutine):
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("Fake operations must not wait for external resources")


def test_smoke_timeout_requires_real_started_workload_and_successful_cleanup():
    result = ExecutionResult(
        "smoke-test",
        VerificationCommand.PYTEST,
        ExecutionStatus.TIMED_OUT,
        None,
        3.1,
        cleanup=CleanupStatus.REMOVED,
        real_container=True,
        isolation_inspected=True,
        container_created=True,
        execution_started=True,
        execution_duration_seconds=3.0,
        timeout_phase=ExecutionTimeoutPhase.WORKLOAD_EXECUTION,
    )
    assert _scenario_passed(result, ExecutionStatus.TIMED_OUT, unchanged=True, timeout=3.0)

    for invalid in (
        {"container_created": False},
        {"real_container": False},
        {"isolation_inspected": False},
        {"execution_started": False},
        {"cleanup": CleanupStatus.FAILED},
        {"timeout_phase": ExecutionTimeoutPhase.CONTAINER_STARTUP},
        {"execution_duration_seconds": 2.9},
    ):
        assert not _scenario_passed(
            dataclasses.replace(result, **invalid),
            ExecutionStatus.TIMED_OUT,
            unchanged=True,
            timeout=3.0,
        )


@pytest.mark.parametrize("code", [0, 1, 2, 137])
def test_container_state_preserves_real_exit_code(code):
    state = {
        "Status": "exited",
        "Running": False,
        "ExitCode": code,
        "OOMKilled": code == 137,
        "StartedAt": "2026-11-23T00:00:00Z",
        "FinishedAt": "2026-11-23T00:00:01Z",
        "Error": "",
    }
    assert docker._exit_state(state) == (code, code == 137)


@pytest.mark.parametrize(
    "update",
    [
        {"Status": "running"},
        {"Running": True},
        {"ExitCode": False},
        {"ExitCode": -1},
        {"OOMKilled": "false"},
        {"StartedAt": "0001-01-01T00:00:00Z"},
        {"Error": "failed"},
    ],
)
def test_invalid_or_unstarted_state_cannot_claim_command_success(update):
    state = {
        "Status": "exited",
        "Running": False,
        "ExitCode": 0,
        "OOMKilled": False,
        "StartedAt": "2026-11-23T00:00:00Z",
        "FinishedAt": "2026-11-23T00:00:01Z",
        "Error": "",
    }
    state.update(update)
    with pytest.raises(RuntimeError):
        docker._exit_state(state)


@pytest.mark.parametrize("digests", [[], [IMAGE.replace("a" * 64, "b" * 64)], None, "bad"])
def test_missing_or_mismatched_image_is_rejected(monkeypatch, digests):
    async def capture(argv, **kwargs):
        assert argv[4:6] == ["inspect", "--format"]
        return json.dumps(digests).encode(), b""

    monkeypatch.setattr(docker, "_capture", capture)
    with pytest.raises(SandboxUnsupportedError):
        immediate(docker.DockerCliBackend()._verify_image(IMAGE))


def test_cleanup_does_not_delete_unowned_container():
    assert immediate(docker.DockerCliBackend().cleanup("a" * 64, 1)) is False


def test_readiness_rejects_unapproved_context_without_docker_calls(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("Unapproved context must be rejected before Docker inspection.")

    monkeypatch.setattr(docker, "_capture", unexpected)
    result = immediate(
        docker.diagnose_docker(
            SandboxConfig(IMAGE), Path("private"), docker_context="remote-context"
        )
    )
    assert result.status is docker.ReadinessStatus.NOT_READY
    assert result.reason is docker.ReadinessReason.ENDPOINT


@pytest.mark.parametrize("phase", ["host", "daemon", "image", "ready"])
@pytest.mark.parametrize("docker_context", ["default", "rootless"])
def test_readiness_uses_selected_context_without_exposing_private_paths(
    monkeypatch, phase, docker_context
):
    monkeypatch.setattr(docker.sys, "platform", "linux")
    monkeypatch.setattr(docker.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(docker.shutil, "which", lambda _: "/synthetic/docker")

    def host(self, root):
        if phase == "host":
            raise SandboxUnsupportedError("private path")

    selected_contexts = []

    async def daemon(self, root):
        selected_contexts.append(self.docker_context.value)
        if phase == "daemon":
            raise SandboxUnsupportedError("private path")

    async def image(self, ref):
        selected_contexts.append(self.docker_context.value)
        if phase == "image":
            raise SandboxUnsupportedError("private path")

    monkeypatch.setattr(docker.DockerCliBackend, "_validate_host_environment", host)
    monkeypatch.setattr(docker.DockerCliBackend, "_verify_daemon", daemon)
    monkeypatch.setattr(docker.DockerCliBackend, "_verify_image", image)
    result = immediate(
        docker.diagnose_docker(SandboxConfig(IMAGE), Path("private"), docker_context=docker_context)
    )
    assert result.status is (
        docker.ReadinessStatus.READY if phase == "ready" else docker.ReadinessStatus.NOT_READY
    )
    assert "private" not in repr(result)
    assert all(context == docker_context for context in selected_contexts)


@pytest.mark.parametrize(
    ("endpoint", "owner", "options", "cgroups", "ready"),
    [
        (
            "unix:///tmp/rootless.sock",
            1000,
            ["name=rootless", "name=seccomp,profile=builtin"],
            b'"2" "systemd"',
            True,
        ),
        ("tcp://remote:2376", 1000, ["name=rootless", "name=seccomp"], b'"2" "systemd"', False),
        (
            "unix:///tmp/rootless.sock",
            0,
            ["name=rootless", "name=seccomp"],
            b'"2" "systemd"',
            False,
        ),
        ("unix:///tmp/rootless.sock", 1000, ["name=seccomp"], b'"2" "systemd"', False),
        ("unix:///tmp/rootless.sock", 1000, ["name=rootless"], b'"2" "systemd"', False),
        (
            "unix:///tmp/rootless.sock",
            1000,
            ["name=rootless", "seccomp=unconfined"],
            b'"2" "systemd"',
            False,
        ),
        ("unix:///tmp/rootless.sock", 1000, None, b'"2" "systemd"', False),
        (
            "unix:///tmp/rootless.sock",
            1000,
            ["name=rootless", "name=seccomp"],
            b'"1" "none"',
            False,
        ),
    ],
)
def test_daemon_prerequisites_fail_closed(
    monkeypatch, tmp_path, endpoint, owner, options, cgroups, ready
):
    monkeypatch.setattr(docker.os, "getuid", lambda: 1000, raising=False)

    async def fake_stat(fn):
        if fn.__self__ == tmp_path:
            return SimpleNamespace(st_uid=1000, st_mode=stat.S_IFDIR | 0o700)
        return SimpleNamespace(st_uid=owner, st_mode=stat.S_IFSOCK | 0o600)

    async def capture(argv, **kwargs):
        if "context" in argv[3:]:
            return json.dumps(endpoint).encode(), b""
        if "{{json .SecurityOptions}}" in argv:
            return json.dumps(options).encode(), b""
        if "{{json .MemoryLimit}} {{json .CPUCfsQuota}} {{json .PidsLimit}}" in argv:
            return b"true true true", b""
        return cgroups, b""

    monkeypatch.setattr(docker.asyncio, "to_thread", fake_stat)
    monkeypatch.setattr(docker, "_capture", capture)
    if ready:
        asyncio.run(docker.DockerCliBackend("rootless")._verify_daemon(tmp_path))
    else:
        with pytest.raises(SandboxUnsupportedError):
            asyncio.run(docker.DockerCliBackend("rootless")._verify_daemon(tmp_path))


def test_rootless_context_is_used_for_daemon_endpoint_and_info(monkeypatch, tmp_path):
    monkeypatch.setattr(docker.os, "getuid", lambda: 1000, raising=False)
    commands = []

    async def fake_stat(fn):
        if fn.__self__ == tmp_path:
            return SimpleNamespace(st_uid=1000, st_mode=stat.S_IFDIR | 0o700)
        return SimpleNamespace(st_uid=1000, st_mode=stat.S_IFSOCK | 0o600)

    async def capture(argv, **kwargs):
        commands.append(argv)
        if argv[3] == "context":
            assert argv[4:6] == ["inspect", "rootless"]
            return b'"unix:///run/user/1000/docker.sock"', b""
        if "{{json .SecurityOptions}}" in argv:
            return b'["name=rootless", "name=seccomp,profile=builtin"]', b""
        if "{{json .MemoryLimit}} {{json .CPUCfsQuota}} {{json .PidsLimit}}" in argv:
            return b"true true true", b""
        return b'"2" "systemd"', b""

    monkeypatch.setattr(docker.asyncio, "to_thread", fake_stat)
    monkeypatch.setattr(docker, "_capture", capture)
    asyncio.run(docker.DockerCliBackend("rootless")._verify_daemon(tmp_path))

    assert commands
    assert all(command[:3] == ["docker", "--context", "rootless"] for command in commands)


@pytest.mark.parametrize(
    "features",
    [
        b"false true true",
        b"true false true",
        b"true true false",
        b"true false false",
        b"true true",
        b"malformed",
    ],
)
def test_daemon_rejects_missing_or_malformed_resource_capabilities(monkeypatch, tmp_path, features):
    monkeypatch.setattr(docker.os, "getuid", lambda: 1000, raising=False)

    async def fake_stat(fn):
        if fn.__self__ == tmp_path:
            return SimpleNamespace(st_uid=1000, st_mode=stat.S_IFDIR | 0o700)
        return SimpleNamespace(st_uid=1000, st_mode=stat.S_IFSOCK | 0o600)

    async def capture(argv, **kwargs):
        if argv[3] == "context":
            return b'"unix:///run/user/1000/docker.sock"', b""
        if "{{json .SecurityOptions}}" in argv:
            return b'["name=rootless", "name=seccomp,profile=builtin"]', b""
        if "{{json .CgroupVersion}} {{json .CgroupDriver}}" in argv:
            return b'"2" "systemd"', b""
        if "{{json .MemoryLimit}} {{json .CPUCfsQuota}} {{json .PidsLimit}}" in argv:
            return features, b""
        raise AssertionError("Daemon probe must use the expected CLI fields.")

    monkeypatch.setattr(docker.asyncio, "to_thread", fake_stat)
    monkeypatch.setattr(docker, "_capture", capture)
    with pytest.raises(SandboxUnsupportedError):
        asyncio.run(docker.DockerCliBackend("rootless")._verify_daemon(tmp_path))


@pytest.mark.parametrize("exit_code", [0, 1, 2])
@pytest.mark.parametrize("context", ["default", "rootless"])
def test_execute_uses_selected_context_and_inspects_container_exit(
    monkeypatch, tmp_path, exit_code, context
):
    backend = docker.DockerCliBackend(context)
    identifier = "a" * 64
    backend._owned[identifier] = ContainerSpec("run", IMAGE, tmp_path, ("python",), SandboxLimits())
    executed_argv = []

    class Stream:
        async def read(self, size):
            return b""

    class Process:
        stdout = stderr = Stream()
        returncode = 0  # Client succeeded even when pytest did not.

        async def wait(self):
            return 0

    async def spawn(*args, **kwargs):
        executed_argv.extend(args)
        return Process()

    async def inspect(_id):
        return None

    async def state(_id):
        return _exit_state(exit_code)

    monkeypatch.setattr(docker.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(backend, "inspect_isolation", inspect)
    monkeypatch.setattr(backend, "_inspect_state", state)
    result = asyncio.run(backend.execute(identifier, 1, 1024))
    assert executed_argv[:3] == ["docker", "--context", context]
    assert result.exit_code == exit_code
    assert result.real_container and result.isolation_inspected


def test_actual_workload_timeout_requires_observed_start_and_reports_safe_evidence(
    monkeypatch, tmp_path
):
    backend = docker.DockerCliBackend()
    identifier = "a" * 64
    backend._owned[identifier] = ContainerSpec("run", IMAGE, tmp_path, ("python",), SandboxLimits())
    stopped = []

    class Stream:
        async def read(self, size):
            await asyncio.Event().wait()

    class Process:
        stdout = stderr = Stream()
        returncode = None

        async def wait(self):
            await asyncio.Event().wait()
            return -9

    async def spawn(*args, **kwargs):
        return Process()

    async def inspect(_id):
        return None

    async def state(_id):
        return {
            "Status": "running",
            "Running": True,
            "StartedAt": datetime.now(UTC).isoformat(),
        }

    async def stop(process):
        process.returncode = -9
        stopped.append(True)

    monkeypatch.setattr(docker.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(backend, "inspect_isolation", inspect)
    monkeypatch.setattr(backend, "_inspect_state", state)
    monkeypatch.setattr(docker, "_stop_client", stop)
    with pytest.raises(SandboxExecutionTimeout) as error:
        asyncio.run(backend.execute(identifier, 0.02, 1024))
    assert error.value.phase is ExecutionTimeoutPhase.WORKLOAD_EXECUTION
    assert error.value.execution_started
    assert error.value.real_container
    assert error.value.isolation_inspected
    assert error.value.execution_duration_seconds >= 0.02
    assert stopped == [True]


def test_slow_container_startup_does_not_consume_workload_timeout(monkeypatch, tmp_path):
    backend = docker.DockerCliBackend()
    identifier = "a" * 64
    backend._owned[identifier] = ContainerSpec("run", IMAGE, tmp_path, ("python",), SandboxLimits())

    class Stream:
        async def read(self, size):
            return b""

    class Process:
        stdout = stderr = Stream()
        returncode = None

        async def wait(self):
            self.returncode = 0
            return 0

    async def spawn(*args, **kwargs):
        return Process()

    async def inspect(_id):
        return None

    calls = 0

    async def state(_id):
        nonlocal calls
        calls += 1
        if calls == 1:
            await asyncio.sleep(0.07)
            return {"Status": "created", "Running": False, "StartedAt": "0001-01-01T00:00:00Z"}
        if calls == 2:
            return {
                "Status": "running",
                "Running": True,
                "StartedAt": datetime.now(UTC).isoformat(),
            }
        return _exit_state(seconds=0.01)

    monkeypatch.setattr(docker, "CONTAINER_STARTUP_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(docker.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(backend, "inspect_isolation", inspect)
    monkeypatch.setattr(backend, "_inspect_state", state)
    result = asyncio.run(backend.execute(identifier, 0.05, 1024))
    assert result.exit_code == 0
    assert result.execution_started
    assert result.execution_duration_seconds is not None
    assert result.execution_duration_seconds < 0.05


def test_startup_timeout_does_not_claim_workload_started(monkeypatch, tmp_path):
    backend = docker.DockerCliBackend()
    identifier = "a" * 64
    backend._owned[identifier] = ContainerSpec("run", IMAGE, tmp_path, ("python",), SandboxLimits())

    class Stream:
        async def read(self, size):
            await asyncio.Event().wait()

    class Process:
        stdout = stderr = Stream()
        returncode = None

        async def wait(self):
            await asyncio.Event().wait()
            return -9

    async def spawn(*args, **kwargs):
        return Process()

    async def inspect(_id):
        return None

    async def state(_id):
        return {"Status": "created", "Running": False, "StartedAt": "0001-01-01T00:00:00Z"}

    async def stop(process):
        process.returncode = -9

    monkeypatch.setattr(docker, "CONTAINER_STARTUP_TIMEOUT_SECONDS", 0.02)
    monkeypatch.setattr(docker.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(backend, "inspect_isolation", inspect)
    monkeypatch.setattr(backend, "_inspect_state", state)
    monkeypatch.setattr(docker, "_stop_client", stop)
    with pytest.raises(SandboxExecutionTimeout) as error:
        asyncio.run(backend.execute(identifier, 0.02, 1024))
    assert error.value.phase is ExecutionTimeoutPhase.CONTAINER_STARTUP
    assert not error.value.execution_started
    assert not error.value.real_container
    assert error.value.isolation_inspected


def test_cancellation_during_container_startup_stops_client_and_drains_tasks(monkeypatch, tmp_path):
    backend = docker.DockerCliBackend()
    identifier = "a" * 64
    backend._owned[identifier] = ContainerSpec("run", IMAGE, tmp_path, ("python",), SandboxLimits())
    inspecting = asyncio.Event()
    stopped = []

    class Stream:
        async def read(self, size):
            await asyncio.Event().wait()

    class Process:
        stdout = stderr = Stream()
        returncode = None

    async def spawn(*args, **kwargs):
        return Process()

    async def inspect(_id):
        return None

    async def state(_id):
        inspecting.set()
        await asyncio.Event().wait()

    async def stop(process):
        process.returncode = -9
        stopped.append(True)

    async def scenario():
        task = asyncio.create_task(backend.execute(identifier, 1, 1024))
        await inspecting.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not [
            pending for pending in asyncio.all_tasks() if pending is not asyncio.current_task()
        ]

    monkeypatch.setattr(docker.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(backend, "inspect_isolation", inspect)
    monkeypatch.setattr(backend, "_inspect_state", state)
    monkeypatch.setattr(docker, "_stop_client", stop)
    asyncio.run(scenario())
    assert stopped == [True]


def test_create_timeout_cleans_only_owned_partial_container(monkeypatch, tmp_path):
    backend = docker.DockerCliBackend()
    spec = ContainerSpec("timed-setup", IMAGE, tmp_path, ("python",), SandboxLimits())
    cleaned = []

    async def no_op(*args):
        return None

    async def capture(*args, **kwargs):
        raise TimeoutError("create timed out")

    async def cleanup(name, execution_id):
        cleaned.append((name, execution_id))
        return True

    monkeypatch.setattr(backend, "_validate_host_environment", lambda _: None)
    monkeypatch.setattr(backend, "_verify_daemon", no_op)
    monkeypatch.setattr(backend, "_verify_image", no_op)
    monkeypatch.setattr(backend, "_cleanup_partial", cleanup)
    monkeypatch.setattr(docker, "_capture", capture)
    with pytest.raises(TimeoutError):
        asyncio.run(backend.create(spec))
    assert cleaned == [("repopilot-timed-setup", "timed-setup")]


def test_cleanup_checks_label_and_observed_removal(monkeypatch, tmp_path):
    backend = docker.DockerCliBackend()
    identifier = "a" * 64
    backend._owned[identifier] = ContainerSpec("run", IMAGE, tmp_path, ("python",), SandboxLimits())
    calls = []

    async def capture(argv, **kwargs):
        calls.append(argv)
        return (b"run" if "inspect" in argv else b""), b""

    monkeypatch.setattr(docker, "_capture", capture)
    assert immediate(backend.cleanup(identifier, 1))
    assert len(calls) == 3
    assert "rm" in calls[1]
    assert "ps" in calls[2]
    assert immediate(backend.cleanup(identifier, 1)) is False


def test_cleanup_label_mismatch_never_removes_container(monkeypatch, tmp_path):
    backend = docker.DockerCliBackend()
    identifier = "a" * 64
    backend._owned[identifier] = ContainerSpec("run", IMAGE, tmp_path, ("python",), SandboxLimits())

    async def capture(argv, **kwargs):
        assert "rm" not in argv
        return b"foreign", b""

    monkeypatch.setattr(docker, "_capture", capture)
    assert immediate(backend.cleanup(identifier, 1)) is False


def test_image_state_isolation_and_cleanup_share_selected_context(monkeypatch, tmp_path):
    backend = docker.DockerCliBackend("rootless")
    identifier = "a" * 64
    backend._owned[identifier] = ContainerSpec("run", IMAGE, tmp_path, ("python",), SandboxLimits())
    commands = []

    async def capture(argv, **kwargs):
        commands.append(argv)
        if "image" in argv:
            return json.dumps([IMAGE]).encode(), b""
        if "ps" in argv:
            return b"", b""
        if "--format" in argv:
            fmt = argv[argv.index("--format") + 1]
            if "Config.Labels" in fmt:
                return b"run", b""
            if ".State" in fmt:
                return b'{"state":"inspected"}', b""
            if ".HostConfig" in fmt:
                return b"{}\n[]\n[]", b""
        return b"", b""

    monkeypatch.setattr(docker, "_capture", capture)
    monkeypatch.setattr(docker, "_check_isolation", lambda *args: None)
    immediate(backend._verify_image(IMAGE))
    assert immediate(backend._inspect_state(identifier)) == {"state": "inspected"}
    immediate(backend.inspect_isolation(identifier))
    assert immediate(backend.cleanup(identifier, 1))

    assert commands
    assert all(command[:3] == ["docker", "--context", "rootless"] for command in commands)


def test_partial_create_cancellation_attempts_owned_cleanup(monkeypatch, tmp_path):
    backend = docker.DockerCliBackend()
    spec = ContainerSpec("run", IMAGE, tmp_path, ("python",), SandboxLimits())
    cleaned = []

    async def verify(*args):
        return None

    async def capture(*args, **kwargs):
        raise asyncio.CancelledError

    async def cleanup(name, execution_id):
        cleaned.append((name, execution_id))
        return True

    monkeypatch.setattr(backend, "_validate_host_environment", lambda _: None)
    monkeypatch.setattr(backend, "_verify_daemon", verify)
    monkeypatch.setattr(backend, "_verify_image", verify)
    monkeypatch.setattr(backend, "_cleanup_partial", cleanup)
    monkeypatch.setattr(docker, "_capture", capture)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(backend.create(spec))
    assert cleaned == [("repopilot-run", "run")]


def test_concurrent_stream_output_is_bounded_and_truncated(monkeypatch, tmp_path):
    backend = docker.DockerCliBackend()
    identifier = "a" * 64
    backend._owned[identifier] = ContainerSpec("run", IMAGE, tmp_path, ("python",), SandboxLimits())

    class Stream:
        def __init__(self):
            self.remaining = True

        async def read(self, size):
            if self.remaining:
                self.remaining = False
                return b"x" * 4096
            return b""

    class Process:
        returncode = None

        def __init__(self):
            self.stdout, self.stderr = Stream(), Stream()

        def kill(self):
            self.returncode = -9

        async def wait(self):
            await asyncio.sleep(0)
            self.returncode = 0 if self.returncode is None else self.returncode
            return self.returncode

    async def spawn(*args, **kwargs):
        return Process()

    async def inspect(_id):
        return None

    async def state(_id):
        return {
            "Status": "running",
            "Running": True,
            "StartedAt": datetime.now(UTC).isoformat(),
            "FinishedAt": "0001-01-01T00:00:00Z",
        }

    monkeypatch.setattr(docker.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(backend, "inspect_isolation", inspect)
    monkeypatch.setattr(backend, "_inspect_state", state)
    result = asyncio.run(backend.execute(identifier, 1, 1024))
    assert result.truncated and result.resource_limited
    assert len(result.stdout.encode()) + len(result.stderr.encode()) == 1024


def test_cancellation_stops_client_and_drains_tasks(monkeypatch, tmp_path):
    backend = docker.DockerCliBackend()
    identifier = "a" * 64
    backend._owned[identifier] = ContainerSpec("run", IMAGE, tmp_path, ("python",), SandboxLimits())
    started, stopped = asyncio.Event(), []

    class Stream:
        async def read(self, size):
            await asyncio.Event().wait()

    class Process:
        stdout = stderr = Stream()
        returncode = None

        async def wait(self):
            started.set()
            await asyncio.Event().wait()

    async def spawn(*args, **kwargs):
        return Process()

    async def inspect(_id):
        return None

    async def stop(process):
        process.returncode = -9
        stopped.append(True)

    async def scenario():
        task = asyncio.create_task(backend.execute(identifier, 1, 1024))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]

    monkeypatch.setattr(docker.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(backend, "inspect_isolation", inspect)

    async def state(_id):
        return {
            "Status": "running",
            "Running": True,
            "StartedAt": datetime.now(UTC).isoformat(),
        }

    monkeypatch.setattr(backend, "_inspect_state", state)
    monkeypatch.setattr(docker, "_stop_client", stop)
    asyncio.run(scenario())
    assert stopped == [True]


@pytest.mark.parametrize(
    "violation",
    [
        None,
        "network",
        "rootfs",
        "capabilities",
        "memory",
        "cpu",
        "pids",
        "tmpfs",
        "mount",
        "mount_propagation",
        "missing_mount_propagation",
        "environment",
    ],
)
def test_inspected_isolation_must_match_every_critical_control(tmp_path, violation):
    limits = SandboxLimits()
    spec = ContainerSpec("run", IMAGE, tmp_path, ("python",), limits)
    host = {
        "NetworkMode": "none",
        "ReadonlyRootfs": True,
        "Privileged": False,
        "CapDrop": ["ALL"],
        "CapAdd": None,
        "SecurityOpt": ["no-new-privileges:true"],
        "Memory": limits.memory_bytes,
        "NanoCpus": 1_000_000_000,
        "PidsLimit": limits.pids,
        "Tmpfs": {"/tmp": f"rw,noexec,nosuid,nodev,size={limits.tmpfs_bytes},mode=1777"},
    }
    mounts = [
        {
            "Type": "bind",
            "Source": str(tmp_path),
            "Destination": "/workspace",
            "RW": False,
            "Propagation": "rprivate",
        }
    ]
    environment = ["PATH=/usr/local/bin:/usr/bin", "HOME=/tmp"]
    if violation == "network":
        host["NetworkMode"] = "host"
    elif violation == "rootfs":
        host["ReadonlyRootfs"] = False
    elif violation == "capabilities":
        host["CapDrop"] = []
    elif violation == "memory":
        host["Memory"] = 0
    elif violation == "cpu":
        host["NanoCpus"] = 0
    elif violation == "pids":
        host["PidsLimit"] = -1
    elif violation == "tmpfs":
        host["Tmpfs"] = {}
    elif violation == "mount":
        mounts[0]["RW"] = True
    elif violation == "mount_propagation":
        mounts[0]["Propagation"] = "rshared"
    elif violation == "missing_mount_propagation":
        mounts[0].pop("Propagation")
    elif violation == "environment":
        environment.append("PROVIDER_API_KEY=synthetic-not-a-secret")
    if violation is None:
        docker._check_isolation(spec, host, mounts, environment)
    else:
        with pytest.raises(RuntimeError):
            docker._check_isolation(spec, host, mounts, environment)
