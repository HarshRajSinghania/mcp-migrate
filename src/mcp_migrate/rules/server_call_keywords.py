"""Find SDK Server()/MCPServer() keyword arguments across line wraps.

Matches server_call_keywords from #314. Vendored so this branch can use it
without rewriting history onto main.
"""
from __future__ import annotations

import ast

SDK_SERVER_CLASSES = frozenset({"Server", "MCPServer"})


def server_call_keywords(project, names, fallback_pattern):
    """Where a Server(...) or MCPServer(...) call is passed one of names.

    A file that does not parse keeps the one-line fallback_pattern, so this
    never finds less than the regex it replaced.
    """
    wanted = frozenset(names)
    out = []
    for f in project.files:
        if f.language != "python":
            continue
        tree = f.tree
        if tree is None:
            try:
                tree = ast.parse(f.text)
            except (SyntaxError, ValueError):
                out.extend(type(project)(root=project.root, files=[f]).search_code(fallback_pattern))
                continue
        lines = f.lines
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            called = (
                func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute)
                else None
            )
            if called not in SDK_SERVER_CLASSES:
                continue
            for keyword in node.keywords:
                if keyword.arg in wanted:
                    out.append((f, keyword.lineno, lines[keyword.lineno - 1].strip()))
    return sorted(out, key=lambda hit: (str(hit[0].path), hit[1]))
