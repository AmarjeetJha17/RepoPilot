"""Synthetic repository fixture content shared by repository-intelligence tests."""

from __future__ import annotations

from pathlib import Path


def create_repository(root: Path) -> tuple[Path, dict[str, bytes]]:
    """Create a small multi-package tree with text, binary, and sensitive entries."""
    source = root / "source"
    files: dict[str, bytes] = {
        "pkg/__init__.py": (
            b"# class CommentDecoy:\n"
            b"class Alpha:\n"
            b"    def method(self):\n"
            b"        def nested():\n"
            b"            return 'needle'\n"
            b"        return nested\n"
            b"async def async_task():\n"
            b"    return None\n"
        ),
        "pkg/first.py": b"def duplicate():\n    return 'needle one'\n",
        "other/second.py": b"def duplicate():\n    return 'needle two'\n",
        "notes/readme.txt": b"alpha needle\nsecond needle\nthird line\n",
        "notes/invalid.txt": b"valid prefix\xffinvalid utf-8\n",
        "notes/large.txt": b"L" * 256,
        "notes/syntax.py": b"def broken(:\n",
        "notes/decoy.py": b"# def comment_decoy(): pass\ntext = 'class StringDecoy:'\n",
        ".env": b"synthetic-secret=not-for-staging\n",
        "local_credentials.txt": b"synthetic-secret=not-for-staging\n",
        "media/image.bin": b"\x00binary payload",
    }
    for relative, content in files.items():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return source, files
