"""Bounded, offline candidate-indicator review of explicitly supplied error logs.

The patterns identify fault lines worth investigating. They are not exploit
signatures and cannot establish compromise, a CVE, or a successful patch.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Sequence


MAX_SOURCES = 8
MAX_BYTES_PER_SOURCE = 8 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_LINE_NUMBERS = 64

PHP_ERROR = "php_error"
APACHE_ERROR = "apache_error"
SOURCE_TYPES = (PHP_ERROR, APACHE_ERROR)


class IOCInputError(Exception):
    """A fixed-code error that never contains a path or log content."""

    def __init__(self, code: str, source_index: int | None = None) -> None:
        self.code = code
        self.source_index = source_index
        super().__init__(code)

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"code": self.code}
        if self.source_index is not None:
            result["source_index"] = self.source_index
        return result


_LOG_PREFIX = rb"^(?:\[[^\]\r\n]{1,128}\][ \t]*){0,5}"
_PHP_FATAL_PREFIXES = (
    re.compile(_LOG_PREFIX + rb"PHP Fatal error:[ \t]*", re.IGNORECASE),
    re.compile(
        _LOG_PREFIX + rb"PHP message:[ \t]+PHP Fatal error:[ \t]*", re.IGNORECASE,
    ),
    re.compile(
        _LOG_PREFIX + rb"(?:NOTICE|WARNING|ERROR|ALERT):[ \t]+"
        rb"PHP message:[ \t]+PHP Fatal error:[ \t]*", re.IGNORECASE,
    ),
    re.compile(
        _LOG_PREFIX + rb"AH01071:[ \t]*Got error ['\"]"
        rb"(?:PHP message:[ \t]*)?PHP Fatal error:[ \t]*", re.IGNORECASE,
    ),
)
_PHP_OOM = rb"(?:Allowed memory size of [0-9]+ bytes exhausted|Out of memory\b)"
_UNKNOWN_LINE_OOM = re.compile(
    _PHP_OOM + rb"[^\r\n]*\bin Unknown on line 0(?:\b|\r?$)", re.IGNORECASE
)
_GENERIC_PHP_OOM = re.compile(_PHP_OOM, re.IGNORECASE)
_ZEND_HEAP_CORRUPTION = (
    re.compile(
        _LOG_PREFIX + rb"(?:PHP (?:Fatal error|Warning):[ \t]*)?"
        rb"zend_mm_heap corrupted[ \t]*\r?\n?$", re.IGNORECASE,
    ),
    re.compile(
        _LOG_PREFIX + rb"PHP message:[ \t]+"
        rb"(?:PHP (?:Fatal error|Warning):[ \t]*)?"
        rb"zend_mm_heap corrupted[ \t]*\r?\n?$", re.IGNORECASE,
    ),
    re.compile(
        _LOG_PREFIX + rb"(?:NOTICE|WARNING|ERROR|ALERT):[ \t]+"
        rb"PHP message:[ \t]+(?:PHP (?:Fatal error|Warning):[ \t]*)?"
        rb"zend_mm_heap corrupted[ \t]*\r?\n?$", re.IGNORECASE,
    ),
    re.compile(
        _LOG_PREFIX + rb"AH01071:[ \t]*Got error ['\"]"
        rb"(?:PHP message:[ \t]*)?(?:PHP (?:Fatal error|Warning):[ \t]*)?"
        rb"zend_mm_heap corrupted['\"](?:[ \t]*,[^\r\n]*)?\r?\n?$", re.IGNORECASE,
    ),
)
_APACHE_CHILD_SIGNAL = re.compile(
    _LOG_PREFIX + rb"(?:AH[0-9]{5}:[ \t]*)?child pid [0-9]+ exit signal "
    rb"(?:Segmentation fault|Aborted|Bus error|Illegal instruction)"
    rb"(?:[ \t]*\([0-9]+\))?\b",
    re.IGNORECASE,
)
_FPM_CHILD_SIGNAL = re.compile(
    _LOG_PREFIX + rb"(?:WARNING|NOTICE|ERROR|ALERT):[ \t]+"
    rb"\[pool [A-Za-z0-9_.-]{1,64}\][ \t]+child [0-9]+ exited on signal "
    rb"(?:11 \(SIGSEGV\)|6 \(SIGABRT\)|4 \(SIGILL\)|7 \(SIGBUS\))"
    rb"(?![A-Za-z0-9_])", re.IGNORECASE,
)

_PHP_RULES = (
    ("PHP_UNKNOWN_LINE_OOM", "runtime_memory_failure_candidate"),
    ("PHP_ZEND_HEAP_CORRUPTION", "memory_integrity_candidate"),
    ("PHP_OOM_CONTEXT", "memory_pressure_context"),
)
_RULES = {
    PHP_ERROR: _PHP_RULES + (
        ("PHP_FPM_CHILD_EXIT_SIGNAL", "worker_crash_context"),
    ),
    APACHE_ERROR: _PHP_RULES + (
        ("APACHE_CHILD_EXIT_SIGNAL", "worker_crash_context"),
    ),
}


def _has_reparse_attribute(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _is_local_absolute_path(path: Path) -> bool:
    spelling = str(path)
    if not path.is_absolute() or spelling.startswith(("\\\\", "//")):
        return False
    if os.name == "nt":
        drive = path.drive
        if not drive or drive.startswith("\\"):
            return False
        # A mapped network drive remains remote even though its spelling is C:-like.
        root = drive + "\\"
        return ctypes.windll.kernel32.GetDriveTypeW(root) in (2, 3, 5, 6)
    return True


def _checked_source(path_value: str | os.PathLike[str], index: int,
                    max_bytes: int = MAX_BYTES_PER_SOURCE) -> tuple[Path, os.stat_result]:
    try:
        path = Path(path_value)
        if not _is_local_absolute_path(path):
            raise IOCInputError("local_absolute_file_required", index)
        # Reject links and junctions in the entire supplied path, including parents.
        for component in (path, *path.parents):
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or _has_reparse_attribute(info):
                raise IOCInputError("linked_path_rejected", index)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise IOCInputError("regular_file_required", index)
        if info.st_size > max_bytes:
            raise IOCInputError("source_too_large", index)
        return path, info
    except IOCInputError:
        raise
    except (OSError, ValueError, TypeError):
        raise IOCInputError("source_unavailable", index) from None


def _matching_rule_ids(source_type: str, line: bytes) -> tuple[str, ...]:
    found: list[str] = []
    fatal_message = next(
        (line[match.end():] for pattern in _PHP_FATAL_PREFIXES
         if (match := pattern.match(line)) is not None), None
    )
    unknown_oom = bool(fatal_message and _UNKNOWN_LINE_OOM.match(fatal_message))
    if unknown_oom:
        found.append("PHP_UNKNOWN_LINE_OOM")
    if any(pattern.match(line) for pattern in _ZEND_HEAP_CORRUPTION):
        found.append("PHP_ZEND_HEAP_CORRUPTION")
    if not unknown_oom and fatal_message and _GENERIC_PHP_OOM.match(fatal_message):
        found.append("PHP_OOM_CONTEXT")
    if source_type == PHP_ERROR and _FPM_CHILD_SIGNAL.match(line):
        found.append("PHP_FPM_CHILD_EXIT_SIGNAL")
    if source_type == APACHE_ERROR and _APACHE_CHILD_SIGNAL.match(line):
        found.append("APACHE_CHILD_EXIT_SIGNAL")
    return tuple(found)


def _scan_source(path: Path, prior: os.stat_result, source_type: str,
                 index: int) -> dict[str, object]:
    counts = {rule_id: 0 for rule_id, _ in _RULES[source_type]}
    line_numbers: dict[str, list[int]] = {rule_id: [] for rule_id in counts}
    digest = hashlib.sha256()
    bytes_seen = 0
    lines_seen = 0
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            if (not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (prior.st_dev, prior.st_ino)
                    or opened.st_size > MAX_BYTES_PER_SOURCE):
                raise IOCInputError("source_changed", index)
            while True:
                line = source.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_LINE_BYTES:
                    raise IOCInputError("line_too_long", index)
                if b"\x00" in line:
                    raise IOCInputError("binary_content_rejected", index)
                bytes_seen += len(line)
                if bytes_seen > MAX_BYTES_PER_SOURCE:
                    raise IOCInputError("source_too_large", index)
                digest.update(line)
                lines_seen += 1
                for rule_id in _matching_rule_ids(source_type, line):
                    counts[rule_id] += 1
                    if len(line_numbers[rule_id]) < MAX_LINE_NUMBERS:
                        line_numbers[rule_id].append(lines_seen)
            completed = os.fstat(source.fileno())
            if (completed.st_size != bytes_seen
                    or completed.st_mtime_ns != opened.st_mtime_ns):
                raise IOCInputError("source_changed", index)
    except IOCInputError:
        raise
    except (OSError, ValueError):
        raise IOCInputError("source_unavailable", index) from None

    return {
        "index": index,
        "type": source_type,
        "sha256": digest.hexdigest(),
        "bytes": bytes_seen,
        "line_count": lines_seen,
        "rules": [
            {"id": rule_id, "category": category, "count": counts[rule_id],
             "line_numbers": line_numbers[rule_id],
             "line_numbers_truncated": counts[rule_id] > len(line_numbers[rule_id])}
            for rule_id, category in _RULES[source_type]
        ],
    }


def scan_saved_logs(
    sources: Sequence[tuple[str, str | os.PathLike[str]]],
) -> dict[str, object]:
    """Read explicit local saved files without returning their names or contents."""
    if not sources or len(sources) > MAX_SOURCES:
        raise IOCInputError("source_count_out_of_range")
    checked: list[tuple[str, Path, os.stat_result, int]] = []
    identities: set[tuple[int, int]] = set()
    for index, entry in enumerate(sources, 1):
        try:
            source_type, path_value = entry
        except (TypeError, ValueError):
            raise IOCInputError("invalid_source_specification", index) from None
        if source_type not in SOURCE_TYPES:
            raise IOCInputError("unsupported_source_type", index)
        path, info = _checked_source(path_value, index)
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise IOCInputError("duplicate_source", index)
        identities.add(identity)
        checked.append((source_type, path, info, index))
    return {
        "schema": "rpk.php2shell.saved_log_ioc.v1",
        "scope": "candidate_fault_lines_only",
        "sources": [
            _scan_source(path, info, source_type, index)
            for source_type, path, info, index in checked
        ],
        "limitations": [
            "Patterns are fault candidates, not PHP2Shell exploit signatures.",
            "No match does not exclude exploitation, compromise, or an unpatched worker.",
            "Log completeness, rotation, authenticity, and relation to a serving process are unverified.",
        ],
    }
