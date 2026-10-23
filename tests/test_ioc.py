import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rpk_php2shell_triage.ioc import (
    APACHE_ERROR, PHP_ERROR, IOCInputError, MAX_BYTES_PER_SOURCE,
    MAX_LINE_BYTES, MAX_LINE_NUMBERS, MAX_SOURCES, scan_saved_logs,
)


ROOT = Path(__file__).resolve().parents[1]


def rule(source, rule_id):
    return next(item for item in source["rules"] if item["id"] == rule_id)


class SavedLogIOCTests(unittest.TestCase):
    def test_php_candidates_and_benign_lines_are_separate(self):
        raw = (
            b"[22-Oct-2026 12:00:00 UTC] PHP Fatal error: Allowed memory size of "
            b"134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0\n"
            b"[22-Oct-2026 12:00:01 UTC] zend_mm_heap corrupted\n"
            b"[22-Oct-2026 12:00:02 UTC] PHP Fatal error: Allowed memory size of "
            b"134217728 bytes exhausted in /private/path.php on line 8\n"
            b"[22-Oct-2026 12:00:03 UTC] PHP Warning: request contained words "
            b"zend_mm_heap corrupted and Out of memory\n"
            b"[22-Oct-2026 12:00:04 UTC] PHP Fatal error: Out of memory "
            b"(allocated 2097152) in Unknown on line 0\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic-php.log"
            path.write_bytes(raw)
            result = scan_saved_logs([(PHP_ERROR, path)])
        self.assertEqual(result["schema"], "rpk.php2shell.saved_log_ioc.v1")
        source = result["sources"][0]
        self.assertEqual((source["index"], source["type"]), (1, PHP_ERROR))
        self.assertEqual(source["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual((source["bytes"], source["line_count"]), (len(raw), 5))
        self.assertEqual(rule(source, "PHP_UNKNOWN_LINE_OOM")["line_numbers"], [1, 5])
        self.assertEqual(rule(source, "PHP_ZEND_HEAP_CORRUPTION")["line_numbers"], [2])
        self.assertEqual(rule(source, "PHP_OOM_CONTEXT")["line_numbers"], [3])
        self.assertNotIn("/private/path.php", json.dumps(result))

    def test_apache_mixed_log_keeps_php_faults_and_worker_signals(self):
        raw = (
            b"[proxy_fcgi:error] [pid 90001] AH01071: Got error 'PHP message: "
            b"PHP Fatal error: Allowed memory size of 1024 bytes exhausted "
            b"in Unknown on line 0'\n"
            b"[proxy_fcgi:error] [pid 90001] AH01071: Got error 'zend_mm_heap corrupted'\n"
            b"[core:notice] [pid 90001] AH00051: child pid 90002 exit signal "
            b"Segmentation fault (11), possible coredump in /private\n"
            b"[core:notice] [pid 90001] child pid 90003 exit signal Aborted (6)\n"
            b"[core:notice] [pid 90001] child pid 90004 exit signal Illegal instruction (4)\n"
            b"[proxy_fcgi:error] PHP message: PHP Fatal error: Allowed memory size of "
            b"1024 bytes exhausted in /private/path.php on line 8\n"
            b"[core:notice] [pid 90001] client sent string zend_mm_heap corruption "
            b"and Segmentation fault\n"
            b"[core:notice] [pid 90001] client echoed child pid 90005 exit signal "
            b"Segmentation fault (11)\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic-apache.log"
            path.write_bytes(raw)
            source = scan_saved_logs([(APACHE_ERROR, path)])["sources"][0]
        self.assertEqual(rule(source, "PHP_UNKNOWN_LINE_OOM")["line_numbers"], [1])
        self.assertEqual(rule(source, "PHP_ZEND_HEAP_CORRUPTION")["line_numbers"], [2])
        self.assertEqual(rule(source, "PHP_OOM_CONTEXT")["line_numbers"], [6])
        self.assertEqual(rule(source, "APACHE_CHILD_EXIT_SIGNAL")["count"], 3)
        self.assertEqual(rule(source, "APACHE_CHILD_EXIT_SIGNAL")["line_numbers"], [3, 4, 5])
        self.assertNotIn("/private/path.php", json.dumps(source))

    def test_fpm_worker_exit_and_heap_notice_avoid_echoed_text(self):
        raw = (
            b"[22-Oct-2026 12:00:00] WARNING: [pool www] child 41 "
            b"exited on signal 11 (SIGSEGV) after 1.2 seconds from start\n"
            b"[22-Oct-2026 12:00:01] NOTICE: PHP message: zend_mm_heap corrupted\n"
            b"[22-Oct-2026 12:00:02] NOTICE: client echoed "
            b"[pool www] child 42 exited on signal 11 (SIGSEGV)\n"
            b"[22-Oct-2026 12:00:03] NOTICE: client echoed "
            b"PHP message: zend_mm_heap corrupted\n"
            b"[22-Oct-2026 12:00:04] NOTICE: client echoed "
            b"PHP Fatal error: Out of memory in Unknown on line 0\n"
            b"[22-Oct-2026 12:00:05] NOTICE: PHP message: "
            b"PHP Fatal error: Out of memory in Unknown on line 0\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic-fpm-error.log"
            path.write_bytes(raw)
            source = scan_saved_logs([(PHP_ERROR, path)])["sources"][0]
        self.assertEqual(rule(source, "PHP_FPM_CHILD_EXIT_SIGNAL")["line_numbers"], [1])
        self.assertEqual(rule(source, "PHP_ZEND_HEAP_CORRUPTION")["line_numbers"], [2])
        self.assertEqual(rule(source, "PHP_UNKNOWN_LINE_OOM")["line_numbers"], [6])

    def test_exception_text_containing_oom_is_not_a_fault_candidate(self):
        native_and_fpm = (
            b"PHP Fatal error: Uncaught Exception: Out of memory in Unknown on line 0\n"
            b"[22-Oct-2026 12:00:00] NOTICE: PHP message: PHP Fatal error: "
            b"Uncaught Exception: Allowed memory size of 1024 bytes exhausted "
            b"in Unknown on line 0\n"
        )
        apache = (
            b"[proxy_fcgi:error] [pid 90001] AH01071: Got error 'PHP message: "
            b"PHP Fatal error: Uncaught Exception: Out of memory "
            b"in Unknown on line 0'\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            php_path = root / "synthetic-php-exception.log"
            apache_path = root / "synthetic-apache-exception.log"
            php_path.write_bytes(native_and_fpm)
            apache_path.write_bytes(apache)
            sources = scan_saved_logs([(PHP_ERROR, php_path), (APACHE_ERROR, apache_path)])["sources"]
        for source in sources:
            with self.subTest(source_type=source["type"]):
                self.assertEqual(rule(source, "PHP_UNKNOWN_LINE_OOM")["count"], 0)
                self.assertEqual(rule(source, "PHP_OOM_CONTEXT")["count"], 0)

    def test_cli_keeps_content_paths_and_identifiers_out_of_output(self):
        secret = "private-token-8c1a985abf"
        raw = (
            b"[date] PHP Fatal error: Allowed memory size of 1024 bytes exhausted "
            b"in Unknown on line 0; token=topsecret-776655; IP=198.51.100.17; pid=981274\n"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / (secret + ".log")
            path.write_bytes(raw)
            child = subprocess.run(
                [sys.executable, "-m", "rpk_php2shell_triage.cli", "ioc",
                 "--php-error", str(path)],
                capture_output=True, text=True, env=env, timeout=10,
            )
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stderr, "")
        data = json.loads(child.stdout)
        self.assertEqual(data["sources"][0]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(rule(data["sources"][0], "PHP_UNKNOWN_LINE_OOM")["count"], 1)
        for forbidden in (secret, "topsecret", "198.51.100.17", "981274", "Unknown on line"):
            self.assertNotIn(forbidden, child.stdout + child.stderr)

    def test_invalid_arguments_and_file_errors_are_fixed_codes(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            secret = "private-token-8c1a985abf"
            oversized = root / (secret + ".log")
            oversized.write_bytes(b"x" * (MAX_BYTES_PER_SOURCE + 1))
            binary = root / "binary.log"
            binary.write_bytes(b"PHP Fatal error: Out of memory\x00 in Unknown on line 0\n")
            scenarios = (
                ["--php-error", str(oversized)],
                ["--php-error", str(binary)],
                ["--php-error", str(root)],
                ["--php-error", "https://example.invalid/token"],
                ["--php-error", "\\\\server\\share\\token.log"],
                ["--unrecognized", secret],
            )
            expected = (
                "source_too_large", "binary_content_rejected", "regular_file_required",
                "local_absolute_file_required", "local_absolute_file_required", "invalid_arguments",
            )
            for arguments, code in zip(scenarios, expected):
                with self.subTest(code=code):
                    child = subprocess.run(
                        [sys.executable, "-m", "rpk_php2shell_triage.cli", "ioc", *arguments],
                        capture_output=True, text=True, env=env, timeout=10,
                    )
                    self.assertEqual(child.returncode, 2)
                    self.assertEqual(child.stdout, "")
                    self.assertEqual(json.loads(child.stderr)["error"]["code"], code)
                    self.assertNotIn(secret, child.stderr)
                    self.assertNotIn(str(root), child.stderr)

    def test_symlink_and_parent_link_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "synthetic.log"
            target.write_bytes(b"benign\n")
            link = root / "link.log"
            parent = root / "linked-parent"
            try:
                link.symlink_to(target)
                parent.symlink_to(root, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable on this host")
            for path in (link, parent / target.name):
                with self.subTest(path=path.name):
                    with self.assertRaises(IOCInputError) as raised:
                        scan_saved_logs([(PHP_ERROR, path)])
                    self.assertEqual(raised.exception.code, "linked_path_rejected")

    def test_line_and_source_bounds_and_duplicate_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            long_line = root / "long.log"
            long_line.write_bytes(b"x" * (MAX_LINE_BYTES + 1) + b"\n")
            with self.assertRaises(IOCInputError) as raised:
                scan_saved_logs([(PHP_ERROR, long_line)])
            self.assertEqual(raised.exception.code, "line_too_long")
            short = root / "short.log"
            short.write_bytes(b"benign\n")
            with self.assertRaises(IOCInputError) as raised:
                scan_saved_logs([(PHP_ERROR, short), (APACHE_ERROR, short)])
            self.assertEqual(raised.exception.code, "duplicate_source")
            with self.assertRaises(IOCInputError) as raised:
                scan_saved_logs([(PHP_ERROR, short)] * (MAX_SOURCES + 1))
            self.assertEqual(raised.exception.code, "source_count_out_of_range")

    def test_line_number_cap_repeat_and_independent_new_input(self):
        match = b"PHP Fatal error: Out of memory in Unknown on line 0\n"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first = root / "first.log"
            first.write_bytes(match * (MAX_LINE_NUMBERS + 2))
            before = scan_saved_logs([(PHP_ERROR, first)])
            repeated = scan_saved_logs([(PHP_ERROR, first)])
            self.assertEqual(before, repeated)
            found = rule(before["sources"][0], "PHP_UNKNOWN_LINE_OOM")
            self.assertEqual(found["count"], MAX_LINE_NUMBERS + 2)
            self.assertEqual(len(found["line_numbers"]), MAX_LINE_NUMBERS)
            self.assertTrue(found["line_numbers_truncated"])
            second = root / "new-observation.log"
            second.write_bytes(b"benign line\n")
            after = scan_saved_logs([(PHP_ERROR, second)])
            self.assertNotEqual(before["sources"][0]["sha256"], after["sources"][0]["sha256"])
            self.assertEqual(rule(after["sources"][0], "PHP_UNKNOWN_LINE_OOM")["count"], 0)


if __name__ == "__main__":
    unittest.main()
