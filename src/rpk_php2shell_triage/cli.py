"""Command line entry point for local case files and saved-log review."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from .core import assess_case, fixed_release_catalog
from .ioc import APACHE_ERROR, PHP_ERROR, IOCInputError, MAX_SOURCES, _checked_source, scan_saved_logs


class _PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        """Keep invalid argument values out of stderr."""
        print(json.dumps({"error": {"code": "invalid_arguments"}}), file=sys.stderr)
        raise SystemExit(2)


def _main_ioc(arguments: list[str]) -> int:
    """Parse the sensitive-file command without echoing supplied arguments."""
    if arguments == ["--help"]:
        print("usage: rpk-php2shell-triage ioc "
              "[--php-error ABSOLUTE_LOCAL_FILE | --apache-error ABSOLUTE_LOCAL_FILE] ...")
        return 0
    sources: list[tuple[str, str]] = []
    options = {"--php-error": PHP_ERROR, "--apache-error": APACHE_ERROR}
    try:
        if not arguments or len(arguments) % 2 or len(arguments) // 2 > MAX_SOURCES:
            raise IOCInputError("invalid_arguments")
        for offset in range(0, len(arguments), 2):
            option, path = arguments[offset:offset + 2]
            if option not in options or not path or path.startswith("--"):
                raise IOCInputError("invalid_arguments")
            sources.append((options[option], path))
        result = scan_saved_logs(sources)
    except IOCInputError as exc:
        print(json.dumps({"error": exc.as_dict()}), file=sys.stderr)
        return 2
    except Exception:
        # An unexpected library or OS error must not echo a sensitive path or line.
        print(json.dumps({"error": {"code": "internal_error"}}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "ioc":
        return _main_ioc(argv[1:])
    parser = _PrivateArgumentParser(description="Offline PHP2Shell evidence triage")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("catalog", help="Print the reviewed fixed-release snapshot and separate advisory notice")
    sub.add_parser("ioc", help="Review explicit local saved error logs (see ioc --help)")
    assess = sub.add_parser("assess", help="Assess a caller-provided local JSON case")
    assess.add_argument("case_file", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "catalog":
            result = fixed_release_catalog()
        else:
            case_path, prior = _checked_source(args.case_file, 1, max_bytes=65536)
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(case_path, flags)
            with os.fdopen(descriptor, "rb") as source:
                opened = os.fstat(source.fileno())
                if (not stat.S_ISREG(opened.st_mode)
                        or (opened.st_dev, opened.st_ino) != (prior.st_dev, prior.st_ino)
                        or opened.st_size != prior.st_size):
                    raise IOCInputError("source_changed", 1)
                raw = source.read(65537)
                completed = os.fstat(source.fileno())
                if (len(raw) > 65536 or completed.st_size > 65536):
                    raise IOCInputError("source_too_large", 1)
                if (completed.st_size != len(raw)
                        or completed.st_mtime_ns != opened.st_mtime_ns):
                    raise IOCInputError("source_changed", 1)
            result = assess_case(json.loads(raw.decode("utf-8-sig")))
    except IOCInputError as exc:
        code = {
            "local_absolute_file_required": "case_file_local_required",
            "linked_path_rejected": "case_file_linked_path",
            "regular_file_required": "case_file_regular_required",
            "source_too_large": "case_file_too_large",
            "source_changed": "case_file_changed",
        }.get(exc.code, "case_file_io_error")
    except OSError:
        code = "case_file_io_error"
    except UnicodeError:
        code = "case_file_encoding_error"
    except json.JSONDecodeError:
        code = "case_file_json_error"
    except ValueError:
        code = "invalid_case"
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    print(json.dumps({"error": {"code": code}}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
