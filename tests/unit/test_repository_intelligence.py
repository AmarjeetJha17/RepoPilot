"""Portable tests for repository-intelligence parsing and value contracts."""

from __future__ import annotations

import pytest

from repopilot.context.models import IntelligenceError, IntelligenceErrorCode, IntelligenceLimits
from repopilot.context.reader import decode_text
from repopilot.context.symbols import extract_symbols

pytestmark = pytest.mark.unit


def test_extracts_nested_symbols_with_decorator_lines_and_duplicate_names() -> None:
    source = '''"""class Decoy: def ignored(): pass"""
@decorator
def outer():
    async def inner():
        return None
    class Nested:
        def method(self):
            def local():
                return None
            return local
class First:
    def same(self):
        return None
class Second:
    def same(self):
        return None
'''

    symbols = extract_symbols("pkg/module.py", source, max_nodes=100)

    actual = {(item.qualified_name, item.kind, item.start_line, item.end_line) for item in symbols}
    assert actual == {
        ("outer", "function", 2, 10),
        ("outer.inner", "async_function", 4, 5),
        ("outer.Nested", "class", 6, 10),
        ("outer.Nested.method", "method", 7, 10),
        ("outer.Nested.method.local", "function", 8, 9),
        ("First", "class", 11, 13),
        ("First.same", "method", 12, 13),
        ("Second", "class", 14, 16),
        ("Second.same", "method", 15, 16),
    }


def test_symbol_extraction_does_not_execute_module_code(tmp_path) -> None:
    marker = tmp_path / "executed"
    source = f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\ndef f(): pass\n"

    assert [item.name for item in extract_symbols("safe.py", source, max_nodes=100)] == ["f"]
    assert not marker.exists()


def test_syntax_errors_and_ast_node_limits_are_safe_domain_errors() -> None:
    with pytest.raises(IntelligenceError) as syntax_error:
        extract_symbols("bad.py", "def broken(:\n", max_nodes=100)
    assert syntax_error.value.code is IntelligenceErrorCode.SYNTAX_ERROR

    with pytest.raises(IntelligenceError) as node_error:
        extract_symbols("large.py", "value = [1, 2, 3]\n", max_nodes=2)
    assert node_error.value.code is IntelligenceErrorCode.AST_LIMIT_EXCEEDED
    assert "large.py" not in str(node_error.value)


def test_partial_utf8_tolerates_only_a_truncated_terminal_codepoint() -> None:
    assert decode_text("file.txt", b"valid\xe2\x82", partial=True) == "valid"

    with pytest.raises(IntelligenceError) as malformed:
        decode_text("file.txt", b"valid\xff", partial=True)

    assert malformed.value.code is IntelligenceErrorCode.INVALID_ENCODING


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_entries": 0},
        {"max_files": -1},
        {"max_depth": -1},
        {"max_file_bytes": True},
        {"max_search_bytes": 0},
    ],
)
def test_intelligence_limits_reject_invalid_values(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        IntelligenceLimits(**kwargs)  # type: ignore[arg-type]
