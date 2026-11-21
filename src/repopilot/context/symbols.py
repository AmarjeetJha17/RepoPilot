"""Bounded syntactic Python symbol extraction using the standard-library AST."""

from __future__ import annotations

import ast

from repopilot.context.models import (
    IntelligenceError,
    IntelligenceErrorCode,
    PythonSymbol,
    SymbolKind,
)


def extract_symbols(path: str, source: str, *, max_nodes: int) -> tuple[PythonSymbol, ...]:
    """Extract definitions without importing, executing, or resolving the module."""
    if type(max_nodes) is not int or max_nodes <= 0:
        raise ValueError("AST node limit must be a positive integer.")
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise IntelligenceError(IntelligenceErrorCode.SYNTAX_ERROR) from error
    except (MemoryError, RecursionError, ValueError) as error:
        raise IntelligenceError(IntelligenceErrorCode.AST_LIMIT_EXCEEDED) from error

    pending: list[ast.AST] = [tree]
    node_count = 0
    while pending:
        node = pending.pop()
        node_count += 1
        if node_count > max_nodes:
            raise IntelligenceError(IntelligenceErrorCode.AST_LIMIT_EXCEEDED)
        pending.extend(ast.iter_child_nodes(node))

    found: list[PythonSymbol] = []

    def visit(node: ast.AST, scopes: tuple[str, ...], class_scope: bool) -> None:
        if isinstance(node, ast.ClassDef):
            _append_symbol(found, path, node, scopes, SymbolKind.CLASS)
            for statement in node.body:
                visit(statement, (*scopes, node.name), True)
            return
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            if isinstance(node, ast.AsyncFunctionDef):
                kind = SymbolKind.ASYNC_METHOD if class_scope else SymbolKind.ASYNC_FUNCTION
            else:
                kind = SymbolKind.METHOD if class_scope else SymbolKind.FUNCTION
            _append_symbol(found, path, node, scopes, kind)
            for statement in node.body:
                visit(statement, (*scopes, node.name), False)
            return
        for descendant in ast.iter_child_nodes(node):
            visit(descendant, scopes, class_scope)

    try:
        for statement in tree.body:
            visit(statement, (), False)
    except RecursionError as error:
        raise IntelligenceError(IntelligenceErrorCode.AST_LIMIT_EXCEEDED) from error
    return tuple(sorted(found, key=lambda item: (item.start_line, item.qualified_name)))


def _append_symbol(
    result: list[PythonSymbol],
    path: str,
    node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
    scopes: tuple[str, ...],
    kind: SymbolKind,
) -> None:
    decorator_lines = [decorator.lineno for decorator in node.decorator_list]
    start_line = min(decorator_lines, default=node.lineno)
    qualified_name = ".".join((*scopes, node.name))
    result.append(PythonSymbol(path, node.name, qualified_name, kind, start_line, node.end_lineno))
