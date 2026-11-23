"""Docker CLI command construction must preserve the fixed isolation profile."""

from __future__ import annotations

from pathlib import Path

import pytest

from repopilot.sandbox import docker_backend
from repopilot.sandbox.docker_backend import DockerCliBackend
from repopilot.sandbox.execution import ContainerSpec, SandboxLimits


@pytest.mark.parametrize("context", ["default", "rootless"])
def test_create_uses_selected_context_and_restrictive_flags(
    monkeypatch, tmp_path: Path, context: str
) -> None:
    for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        monkeypatch.delenv(name, raising=False)
    captured: list[str] = []

    def validate_host(self, staging_root: Path) -> None:
        return None

    async def verify_daemon(self, staging_root: Path) -> None:
        return None

    async def verify_image(self, image: str) -> None:
        return None

    async def inspect_isolation(self, container_id: str) -> None:
        return None

    async def capture(argv: list[str], *, max_runtime: float) -> tuple[bytes, bytes]:
        captured.extend(argv)
        return b"a" * 64, b""

    monkeypatch.setattr(DockerCliBackend, "_validate_host_environment", validate_host)
    monkeypatch.setattr(DockerCliBackend, "_verify_daemon", verify_daemon)
    monkeypatch.setattr(DockerCliBackend, "_verify_image", verify_image)
    monkeypatch.setattr(DockerCliBackend, "inspect_isolation", inspect_isolation)
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

    container_id = _run_immediate(DockerCliBackend(docker_context=context).create(spec))

    assert container_id == "a" * 64
    assert captured[:3] == ["docker", "--context", context]
    assert "--pull=never" in captured
    assert "--network=none" in captured
    assert "--read-only" in captured
    assert "--cap-drop=ALL" in captured
    assert "--security-opt=no-new-privileges:true" in captured
    mount = captured[captured.index("--mount") + 1]
    assert mount == (
        f"type=bind,source={staging},target=/workspace,readonly,"
        "bind-recursive=readonly,bind-propagation=rprivate"
    )
    assert captured[captured.index("--user") + 1] == "0:0"
    assert str(tmp_path) not in " ".join(captured).replace(str(staging), "")
    assert "--privileged" not in captured


@pytest.mark.parametrize(
    "name", ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"]
)
def test_docker_environment_overrides_fail_closed(monkeypatch, tmp_path: Path, name: str) -> None:
    monkeypatch.setattr(docker_backend.sys, "platform", "linux")
    monkeypatch.setenv(name, "untrusted-override")

    backend = DockerCliBackend(docker_context="rootless")
    try:
        backend._validate_host_environment(tmp_path)
    except RuntimeError as error:
        assert "Remote or overridden" in str(error)
    else:
        raise AssertionError("A remote Docker endpoint must be rejected.")


def test_backend_rejects_unknown_context_names() -> None:
    try:
        DockerCliBackend(docker_context="unreviewed")
    except ValueError as error:
        assert "Unsupported Docker context" in str(error)
    else:
        raise AssertionError("Unreviewed contexts must not be accepted.")


def test_selected_context_cannot_be_reassigned_after_backend_creation() -> None:
    backend = DockerCliBackend(docker_context="rootless")
    try:
        backend.docker_context = docker_backend.DockerContext.DEFAULT
    except AttributeError:
        pass
    else:
        raise AssertionError("A backend context must remain fixed for its lifecycle.")


def _run_immediate(coroutine):
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("Mocked Docker calls should complete without yielding.")
