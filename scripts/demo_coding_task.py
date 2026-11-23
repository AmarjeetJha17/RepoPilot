"""Run the explicitly invoked synthetic offline coding-task demonstration."""

from __future__ import annotations

import argparse
import asyncio

from repopilot.application.coding_task_demo import (
    render_coding_task_demo,
    run_coding_task_demo,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit stable JSON output.")
    parser.add_argument(
        "--run-sandbox",
        action="store_true",
        help="Opt in to the fixed pytest command through SandboxRunner.",
    )
    parser.add_argument(
        "--docker-image",
        help="Pre-provisioned image reference pinned by sha256 digest; never pulled.",
    )
    args = parser.parse_args()
    result = asyncio.run(
        run_coding_task_demo(
            run_sandbox_tests=args.run_sandbox,
            docker_image=args.docker_image,
        )
    )
    print(result.to_json() if args.json else render_coding_task_demo(result))
    return int(result.failure_code is not None or result.sandbox_tests == "FAIL")


if __name__ == "__main__":
    raise SystemExit(main())
