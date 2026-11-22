"""Docker CLI command construction must preserve the fixed isolation profile."""

from __future__ import annotations

from pathlib import Path

from repopilot.sandbox import docker_backend
from repopilot.sandbox.docker_backend import DockerCliBackend
from repopilot.sandbox.execution import ContainerSpec, SandboxLimits


def test_create_uses_only_the_owned_staging_mount_and_restrictive_flags(
    monkeypatch, tmp_path: Path
) -> None:
    for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        monkeypatch.delenv(name, raising=False)
    captured: list[str] = []

    def validate_host(self, staging_root: Path) -> None:
        return None

    async def verify_daemon(self, staging_root: Path) -> None:
        return None

    async def capture(argv: list[str], *, max_runtime: float) -> tuple[bytes, bytes]:
        captured.extend(argv)
        return b"a" * 64, b""

    monkeypatch.setattr(DockerCliBackend, "_validate_host_environment", validate_host)
    monkeypatch.setattr(DockerCliBackend, "_verify_daemon", verify_daemon)
    monkeypatch.setattr(docker_backend, "_capture", capture)
    staging = tmp_path / "private-staging"
    staging.mkdir()
    spec = ContainerSpec(
        execution_id="12345678-1234-5678-1234-567812345678",
        image="example.invalid/repopilot@sha256:" + "d" * 64,
        staging_root=staging,
        argv=("python", "-I", "-B", "-c", "fixed code", "/workspace/module.py"),
        limits=SandboxLimits(),
    )

    container_id = _run_immediate(DockerCliBackend().create(spec))

    assert container_id == "a" * 64
    assert "--pull=never" in captured
    assert "--network=none" in captured
    assert "--read-only" in captured
    assert "--cap-drop=ALL" in captured
    assert "--security-opt=no-new-privileges:true" in captured
    mount = captured[captured.index("--mount") + 1]
    assert f"source={staging}" in mount
    assert "target=/workspace,readonly,bind-recursive=readonly" in mount
    assert captured[captured.index("--user") + 1] == "0:0"
    assert str(tmp_path) not in " ".join(captured).replace(str(staging), "")
    assert "--privileged" not in captured


def test_remote_docker_environment_fails_closed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(docker_backend.sys, "platform", "linux")
    monkeypatch.setenv("DOCKER_HOST", "tcp://example.invalid:2376")

    backend = DockerCliBackend()
    try:
        backend._validate_host_environment(tmp_path)
    except RuntimeError as error:
        assert "Remote or overridden" in str(error)
    else:
        raise AssertionError("A remote Docker endpoint must be rejected.")


def _run_immediate(coroutine):
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("Mocked Docker calls should complete without yielding.")
