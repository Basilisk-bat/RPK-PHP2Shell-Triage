"""Small legacy MCP stdio adapter for the read-only triage library.

Protocol revision 2025-11-25. Modern clients may fall back to this revision.
No dependency install, network listener, file access, or background process.
"""

from __future__ import annotations

import json
import sys
from io import BufferedReader
from typing import Any

from .core import assess_case, fixed_release_catalog


PROTOCOL = "2025-11-25"
TOOLS = [
    {
        "name": "rpk_php2shell_catalog",
        "description": "Return the reviewed upstream fixed-release snapshot for CVE-2026-109618 and CVE-2026-109619. It does not fetch current vendor status.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "rpk_php2shell_assess",
        "description": "Classify caller-supplied PHP serving-process, package and image evidence locally. No target inspection, network request or remediation occurs.",
        "inputSchema": {
            "type": "object",
            "properties": {"case": {"type": "object", "description": "Case packet described in README.md"}},
            "required": ["case"],
            "additionalProperties": False,
        },
    },
]


def _result(value: Any) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(value)}],
        "structuredContent": value,
        "isError": False,
    }


def dispatch(message: dict[str, Any]) -> dict[str, Any] | None:
    """Return a JSON-RPC response for requests; notifications produce no reply."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": message.get("id") if isinstance(message, dict) else None,
                "error": {"code": -32600, "message": "Invalid Request"}}
    request_id = message.get("id")
    if request_id is None:
        return None
    method = message.get("method")
    params = message.get("params") or {}
    if not isinstance(params, dict):
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32602, "message": "Invalid params"}}
    try:
        if method == "initialize":
            result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                      "serverInfo": {"name": "rpk-php2shell-triage", "version": "0.1.0"},
                      "instructions": "Local evidence triage only; supplying a version does not prove a deployed fix."}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise ValueError("arguments must be an object")
            if name == "rpk_php2shell_catalog":
                result = _result(fixed_release_catalog())
            elif name == "rpk_php2shell_assess":
                result = _result(assess_case(arguments.get("case")))
            else:
                raise ValueError("Unknown tool")
        else:
            return {"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": -32601, "message": "Method not found"}}
    except ValueError as exc:
        result = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def bounded_line(stream: BufferedReader, limit: int = 262144) -> tuple[bytes, bool] | None:
    """Read a protocol line with a fixed memory bound and drain excess bytes."""
    line = stream.readline(limit + 1)
    if not line:
        return None
    if len(line) <= limit:
        return line, False
    if not line.endswith(b"\n"):
        while True:
            remainder = stream.readline(8192)
            if not remainder or remainder.endswith(b"\n"):
                break
    return b"", True


def main() -> int:
    # MCP stdio uses one UTF-8 JSON-RPC message per line. Never print logs to stdout.
    while True:
        read = bounded_line(sys.stdin.buffer)
        if read is None:
            break
        line, oversized = read
        if oversized:
            response = {"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32600, "message": "Input line exceeds 256 KiB"}}
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
            continue
        try:
            request = json.loads(line.decode("utf-8"))
            response = dispatch(request)
            if response is not None:
                sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except (UnicodeError, json.JSONDecodeError):
            print("MCP input parse error", file=sys.stderr)
            response = {"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": "Parse error"}}
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
