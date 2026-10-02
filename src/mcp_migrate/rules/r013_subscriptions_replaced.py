import re

from .base import Finding, Project, Rule

# `SubscribeRequest`/`UnsubscribeRequest` are the MCP SDK's own model names
# -- distinctive, no false-positive risk.
SUBSCRIBE_CODE_RX = re.compile(r"\bSubscribeRequest\b|\bUnsubscribeRequest\b")

# The SDK also registers these without the request class name:
#   @app.subscribe_resource()                         -- mcp 1.x Server
#   Server("demo", on_subscribe_resource=subscribe)   -- mcp 2.x constructor
# Distinctive enough that they do not need the generic-name gate `.tool(` does.
# search_code (not raw search) so a docstring naming them stays silent.
SDK_DECORATOR_RX = re.compile(
    r"@[\w.]*\.(?:subscribe_resource|unsubscribe_resource)\s*\("
)
SDK_CONSTRUCTOR_START_RX = re.compile(r"\b(?:Server|MCPServer)\s*\(")
SDK_CONSTRUCTOR_KW_RX = re.compile(
    r"\bon_(?:subscribe_resource|unsubscribe_resource)\s*="
)

# The TypeScript SDK exports Zod schemas for request handling, and that's
# the name a server actually references -- `server.setRequestHandler(
# SubscribeRequestSchema, ...)`. Bounded to the exact SDK export names
# (optionally suffixed `Params`/`Schema`) rather than an unbounded `\w*`
# suffix, which would also match unrelated identifiers like
# `SubscribeRequester` -- see #87.
TS_SUBSCRIBE_CODE_RX = re.compile(
    r"\b(?:Subscribe|Unsubscribe)Request(?:Params|Schema)?\b"
)

WIRE_RX = r"resources/subscribe|resources/unsubscribe"
MESSAGE_CODE = "References the removed SubscribeRequest/UnsubscribeRequest handler."
MESSAGE_SDK = (
    "Registers the removed subscribe_resource/unsubscribe_resource handler "
    "through the SDK."
)
MESSAGE_WIRE = (
    "References the removed resources/subscribe or resources/unsubscribe "
    "JSON-RPC method."
)


class ResourceSubscriptionsReplaced(Rule):
    id = "R013"
    title = "Uses resources/subscribe or resources/unsubscribe, replaced by subscriptions/listen"
    severity = "breaking"
    spec_ref = "SEP-2575 https://modelcontextprotocol.io/specification/2026-07-28/changelog"
    fix = (
        "resources/subscribe and resources/unsubscribe are gone. Move subscription "
        "management to the new subscriptions/listen call."
    )
    languages = ("python", "typescript")

    def check(self, project: Project) -> list[Finding]:
        if project.language == "typescript":
            return self._check_ts(project)
        return self._check_python(project)

    def _check_python(self, project: Project) -> list[Finding]:
        out: list[Finding] = []
        for f, line, text in project.search_code(SUBSCRIBE_CODE_RX.pattern):
            out.append(self.finding(MESSAGE_CODE, f, line, text))
        for f, line, text in project.search_code(SDK_DECORATOR_RX.pattern):
            out.append(self.finding(MESSAGE_SDK, f, line, text))
        out.extend(_constructor_kw_findings(self, project))
        # resources/subscribe and resources/unsubscribe are JSON-RPC method
        # strings, not valid bare identifiers -- they can only appear
        # inside a STRING token, so search_code would never find them (see
        # the notifications/initialized note in r009). Scan raw text.
        for f, line, text in project.search_wire(WIRE_RX):
            out.append(self.finding(MESSAGE_WIRE, f, line, text))
        return out

    def _check_ts(self, project: Project) -> list[Finding]:
        seen: set[tuple[str, int]] = set()
        out: list[Finding] = []
        for pattern, message, search in (
            (TS_SUBSCRIBE_CODE_RX.pattern, MESSAGE_CODE, project.search_code),
            (WIRE_RX, MESSAGE_WIRE, project.search_wire),
        ):
            for f, line, text in search(pattern):
                # A dispatcher line can carry both signals at once, e.g.
                # `case "resources/subscribe": return this.subscribe(SubscribeRequestSchema);`
                # -- that's one removed-method usage, not two.
                if (str(f.path), line) in seen:
                    continue
                seen.add((str(f.path), line))
                out.append(self.finding(message, f, line, text))
        return sorted(out, key=lambda x: (str(x.path or ""), x.line or 0))


def _constructor_kw_findings(rule: Rule, project: Project) -> list[Finding]:
    """Flag on_subscribe_resource=/on_unsubscribe_resource= inside a Server() call.

    The kwarg is often on the next line (`Server("demo", on_subscribe_resource=fn,`
    then `on_unsubscribe_resource=fn)`). A single-line `[^)]*` pattern misses that.
    Only kwargs that search_code would keep are reported, so a docstring mention
    of the name does not fire.
    """
    code_lines = {
        (str(f.path), line)
        for f, line, _text in project.search_code(
            r"subscribe_resource|unsubscribe_resource"
        )
    }
    out: list[Finding] = []
    for f in project.files:
        lines = f.lines
        i = 0
        while i < len(lines):
            if (str(f.path), i + 1) not in code_lines or not SDK_CONSTRUCTOR_START_RX.search(lines[i]):
                i += 1
                continue
            depth = 0
            end = i
            started = False
            while end < len(lines) and end - i < 25:
                depth += lines[end].count("(") - lines[end].count(")")
                started = True
                if started and depth <= 0:
                    break
                end += 1
            end = min(end, len(lines) - 1)
            for j in range(i, end + 1):
                if (str(f.path), j + 1) not in code_lines:
                    continue
                if SDK_CONSTRUCTOR_KW_RX.search(lines[j]):
                    out.append(rule.finding(MESSAGE_SDK, f, j + 1, lines[j].strip()))
            i = end + 1
    return out
