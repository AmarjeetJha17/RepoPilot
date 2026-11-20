"""Run RepoPilot's synthetic, offline agent demonstration."""

from pathlib import Path
from tempfile import TemporaryDirectory

from repopilot.application.offline_demo import render_offline_demo, run_offline_demo


def main() -> None:
    with TemporaryDirectory(prefix="repopilot-offline-demo-") as temporary_directory:
        workspace = Path(temporary_directory)
        (workspace / "demo.py").write_text("VALUE = 1\n", encoding="utf-8")
        print(render_offline_demo(run_offline_demo(workspace)))


if __name__ == "__main__":
    main()
