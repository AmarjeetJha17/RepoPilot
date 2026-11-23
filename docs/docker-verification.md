# Controlled rootless Docker verification

Phase 5.1 provides an operator-only harness. Real-container verification has **not
been run in the Windows development session**. A green ordinary PR job establishes
offline contracts only. No approved verification-image digest is bundled.

## Prerequisites and image provisioning

Use a controlled Linux host as a non-root user with a separately provisioned,
patched rootless Docker Engine. The operator may select the existing `default`
context (the backward-compatible default) or explicitly select `rootless`. The
selected context must resolve to that user's local Unix socket; RepoPilot checks
the selected context's endpoint, socket ownership, rootless mode, seccomp, and
resource controllers. Other context names, remote endpoints, and Docker endpoint
environment overrides are rejected. The harness never changes contexts or Docker
configuration.

Require cgroup v2 with the systemd cgroup driver and delegated memory, CPU and PID
controllers. Otherwise Docker rootless limits can be ignored. Require active
seccomp and support for recursive read-only bind mounts (Linux kernel 5.12+).
There is no locally verified minimum Docker release: use a supported patched Engine
that accepts the flags and passes the actual configuration checks.

References: [rootless prerequisites](https://docs.docker.com/engine/security/rootless/),
[resource limits](https://docs.docker.com/engine/security/rootless/tips/),
[recursive mounts](https://docs.docker.com/engine/storage/bind-mounts/#recursive-mounts),
[container inspection](https://docs.docker.com/reference/cli/docker/container/inspect/).

The operator must review an image containing Python 3.12+ and pytest with all
dependencies preinstalled. Audit its provenance, layers, environment and metadata;
do not embed keys, proxy credentials, extra volumes or health checks. Provision it
separately from RepoPilot, then record its registry `RepoDigests` identity. Local
build-only images without a repository digest are refused. The runner never builds,
pulls or installs packages. Do not substitute a mutable tag for the digest.

Set `DOCKER_CONTEXT_NAME` in the Linux shell to `default` or `rootless`. For the
WSL2 layout where the default points to an unavailable socket, set it to
`rootless`. The context name is an operator argument; repository files and model
output cannot select it. Set `APPROVED_IMAGE` to the actual reviewed
`registry/repository@sha256:<64 hexadecimal digits>` reference. The examples below
use these operator-supplied values; no example digest is represented as approved.

For the WSL2 rootless setup, the explicit option is:

```bash
uv run python scripts/verify_docker_sandbox.py --image "$APPROVED_IMAGE" --docker-context rootless
uv run python scripts/verify_docker_sandbox.py --image "$APPROVED_IMAGE" --docker-context rootless --smoke
```

```bash
docker --context "$DOCKER_CONTEXT_NAME" version
docker --context "$DOCKER_CONTEXT_NAME" context inspect "$DOCKER_CONTEXT_NAME"
docker --context "$DOCKER_CONTEXT_NAME" info
docker --context "$DOCKER_CONTEXT_NAME" image inspect "$APPROVED_IMAGE"
uv sync --frozen
uv run python scripts/verify_docker_sandbox.py --image "$APPROVED_IMAGE" --docker-context "$DOCKER_CONTEXT_NAME"
uv run python scripts/verify_docker_sandbox.py --image "$APPROVED_IMAGE" --docker-context "$DOCKER_CONTEXT_NAME" --smoke
```

The first script invocation is read-only: no containers are created. It reports
typed READY/NOT_READY status and safe reason codes without socket paths, private
directories, environment values or Docker error bodies. READY checks daemon and
image metadata, not Python/pytest installation or kernel enforcement. Those are
exercised only by the opt-in smoke run. The backend verifies the exact configured
repository digest is locally available before every create.

## Expected smoke evidence

Six fixed synthetic scenarios cover syntax success/failure, pytest success/failure,
timeout, and read-only workspace/rootfs behavior. Each uses a new copied fixture,
WorkspaceManager, scoped test authorization, SandboxRunner and DockerCliBackend.
Results include expected/actual status, container exit code, cleanup, fixture hash
and image digest. Nonzero commands must report COMMAND_FAILED; timeout must report
TIMED_OUT and cleanup removed. The readonly scenario tests failed writes, seccomp,
no-new-privileges, zero effective capabilities and absence of a network route.
Other isolation properties are configuration inspection only, not enforcement tests.
The harness does not independently verify a coding-task patch.

Before start, bounded Docker inspection checks network none, read-only rootfs and
the sole recursively read-only workspace mount with `rprivate` propagation,
dropped capabilities, no-new-privileges,
memory/CPU/PID limits, bounded tmpfs and an environment-name allowlist. Image
entrypoints are overridden by the fixed Python entrypoint; health checks are disabled.
Host home and daemon sockets are not mounted. Command completion uses inspected
State.ExitCode/OOMKilled, not the attachment client's exit status.

The harness stops on the first unexpected status, integrity or cleanup failure.
Exit 1 and NOT_RUN on missing prerequisites are not successful real tests. Keep
the JSON output as operational evidence only after actually running it. No raw
container output is printed or sent to a provider. Repeat under the same reviewed
image after infrastructure changes.

## Cleanup and troubleshooting

Verify no smoke containers remain with:

```bash
docker --context "$DOCKER_CONTEXT_NAME" ps --all --filter label=org.repopilot.execution
```

If Docker becomes unreachable, cleanup cannot be guaranteed. Restore access and
review exact labels and IDs before manually removing a leftover owned container;
never use a prune or delete unrelated containers. A new backend instance refuses
cleanup of IDs it did not create. Partial creates are discovered by exact generated
name and checked against their execution label before removal.

NOT_READY reason codes identify unsupported platform, root host user, missing CLI,
endpoint, socket ownership, rootless/seccomp/cgroup prerequisites, staging or image.
Inspect daemon health privately; do not paste credential-bearing configuration.
Image Python/pytest availability is determined by actual fixed smoke commands.

UID 0 is inside the rootless namespace and maps to the unprivileged staging owner.
Docker resolves bind paths by name: same-user path substitution races remain a
limitation. A Docker client process group and its owned container are separate
cleanup targets. Repeated cancellation or daemon failure can interrupt cleanup;
container/runtime/kernel escapes and complete same-user race resistance are not
claimed. CPU/memory/PID exhaustion enforcement remains unverified until separately
observed; this harness checks their configured values and OOM state classification.

Ordinary PR CI keeps fake-backed tests and never provisions Docker or pulls images.
Use these controlled-host commands manually after reviewing the checked-out code;
do not run this harness against untrusted PR code with privileged runner credentials.
Windows runs offline tests; verify Linux/WSL and rootless Docker availability
separately. No system settings are changed by this project.
