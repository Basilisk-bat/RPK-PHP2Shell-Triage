import json
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from rpk_php2shell_triage import assess_case, fixed_release_catalog
from rpk_php2shell_triage.cli import main as cli_main
from rpk_php2shell_triage.mcp_stdio import bounded_line


ROOT = Path(__file__).resolve().parents[1]


def case(version="8.5.12", kind="serving_process", channel="upstream"):
    runtime = {
        "version": version,
        "channel": channel,
        "evidence_kind": kind,
        "observed_at": "2026-10-22T00:00:00Z",
    }
    if kind == "serving_process":
        runtime.update(pid=4242, executable_path="C:\\lab\\php\\php-cgi.exe", sapi="cgi-fcgi")
    return {"case_id": "synthetic-example", "target": {"label": "Training worker"}, "runtime": runtime}


class TriageTests(unittest.TestCase):
    def test_fixed_floor_requires_serving_binding(self):
        self.assertEqual(assess_case(case(kind="http_header"))["verdict"], "unresolved")
        self.assertEqual(assess_case(case())["verdict"], "fixed_release_reported")

    def test_serving_claim_with_non_serving_or_unreviewed_sapi_stays_unresolved(self):
        for sapi in ("cli", "phpdbg", "embed", "custom-sapi"):
            with self.subTest(sapi=sapi):
                evidence = case()
                evidence["runtime"]["sapi"] = sapi
                result = assess_case(evidence)
                self.assertEqual(result["verdict"], "unresolved")
                self.assertFalse(result["serving_process_evidence_supplied"])
                self.assertIn("Confirm the serving SAPI", result["next_checks"][-1])

    def test_reviewed_serving_sapis_remain_eligible_for_conditional_verdict(self):
        for sapi in ("cgi-fcgi", "fpm-fcgi", "apache2handler", "cli-server", "litespeed"):
            with self.subTest(sapi=sapi):
                evidence = case()
                evidence["runtime"]["sapi"] = sapi
                result = assess_case(evidence)
                self.assertEqual(result["verdict"], "fixed_release_reported")
                self.assertTrue(result["serving_process_evidence_supplied"])

    def test_old_upstream_worker_needs_update(self):
        result = assess_case(case(version="8.5.11"))
        self.assertEqual(result["verdict"], "update_required")
        self.assertEqual(result["upstream_fixed_floor"], "8.5.12")

    def test_other_branch_needs_vendor_evidence(self):
        self.assertEqual(assess_case(case(version="8.1.35"))["verdict"], "unresolved")

    def test_vendor_backport_needs_both_cves_and_exact_revision(self):
        evidence = case(version="8.3.6", channel="vendor-backport")
        evidence["runtime"].update(
            executable_path="/usr/sbin/php-fpm8.3", sapi="fpm-fcgi",
            serving_package={"name": "synthetic-php-fpm", "installed_revision": "8.3.6-1+fix2"},
        )
        evidence["vendor_fix"] = {
            "package_name": "synthetic-php-fpm",
            "installed_revision": "8.3.6-1+fix2",
            "fixed_revision": "8.3.6-1+fix2",
            "advisory_url": "https://vendor.example.invalid/advisory",
            "covered_cves": ["CVE-2026-109618", "CVE-2026-109619"],
        }
        self.assertEqual(assess_case(evidence)["verdict"], "vendor_revision_match_reported")
        evidence["vendor_fix"]["covered_cves"] = ["CVE-2026-109618"]
        self.assertEqual(assess_case(evidence)["verdict"], "unresolved")
        evidence["vendor_fix"]["covered_cves"] = [{"bad": "shape"}]
        self.assertEqual(assess_case(evidence)["verdict"], "unresolved")

    def test_vendor_match_requires_worker_package_binding_and_real_fields(self):
        evidence = case(version="8.3.6", channel="vendor-backport")
        evidence["vendor_fix"] = {
            "package_name": "synthetic-php-fpm",
            "installed_revision": "8.3.6-1+fix2",
            "fixed_revision": "8.3.6-1+fix2",
            "advisory_url": "https://vendor.example.invalid/advisory",
            "covered_cves": ["CVE-2026-109618", "CVE-2026-109619"],
        }
        self.assertEqual(assess_case(evidence)["verdict"], "unresolved")
        evidence["runtime"]["serving_package"] = {
            "name": "synthetic-php-fpm", "installed_revision": "8.3.6-1+fix2",
        }
        self.assertEqual(assess_case(evidence)["verdict"], "vendor_revision_match_reported")
        for field, replacement in (
            ("package_name", "another-package"),
            ("installed_revision", "8.3.6-1+old"),
            ("fixed_revision", "unknown"),
            ("advisory_url", "https://"),
            ("advisory_url", "https://."),
            ("advisory_url", "https://vendor.example.invalid:bad/advisory"),
        ):
            with self.subTest(field=field):
                original = evidence["vendor_fix"][field]
                evidence["vendor_fix"][field] = replacement
                self.assertEqual(assess_case(evidence)["verdict"], "unresolved")
                evidence["vendor_fix"][field] = original
        evidence["runtime"]["serving_package"]["installed_revision"] = "unknown"
        self.assertEqual(assess_case(evidence)["verdict"], "unresolved")
        evidence["runtime"]["serving_package"]["installed_revision"] = "\x00"
        evidence["vendor_fix"]["installed_revision"] = "\x00"
        evidence["vendor_fix"]["fixed_revision"] = "\x00"
        self.assertEqual(assess_case(evidence)["verdict"], "unresolved")

    def test_digest_conflict_overrides_version(self):
        evidence = case()
        evidence["image"] = {
            "running_digest": "sha256:" + "a" * 64,
            "reviewed_fixed_digest": "sha256:" + "b" * 64,
        }
        self.assertEqual(assess_case(evidence)["verdict"], "provenance_conflict")

    def test_invalid_binding_rejected(self):
        evidence = case()
        evidence["runtime"].pop("executable_path")
        with self.assertRaisesRegex(ValueError, "executable_path"):
            assess_case(evidence)
        evidence["runtime"]["executable_path"] = "N/A"
        with self.assertRaisesRegex(ValueError, "absolute observed executable file path"):
            assess_case(evidence)
        for path in ("/", "/usr/bin/", "/usr/bin/..", "C:\\", "C:\\php\\"):
            with self.subTest(path=path):
                evidence["runtime"]["executable_path"] = path
                with self.assertRaisesRegex(ValueError, "executable file path"):
                    assess_case(evidence)

    def test_future_observation_rejected(self):
        evidence = case()
        evidence["runtime"]["observed_at"] = "2099-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "future"):
            assess_case(evidence)

    def test_past_observations_keep_historical_verdict_without_current_status(self):
        for version, expected in (("8.5.12", "fixed_release_reported"),
                                  ("8.5.11", "update_required")):
            with self.subTest(version=version):
                evidence = case(version=version)
                evidence["runtime"]["observed_at"] = "2026-10-21T23:00:00Z"
                result = assess_case(evidence)
                self.assertEqual(result["verdict"], expected)
                self.assertEqual(result["assessment_scope"], "supplied_observation_at_timestamp")
                self.assertEqual(result["present_deployment_status"], "unverified")
                self.assertIn("2026-10-21T23:00:00Z", result["summary"])

    def test_catalog_covers_both_cves(self):
        catalog = fixed_release_catalog()
        self.assertEqual(set(catalog["cves"]), {"CVE-2026-109618", "CVE-2026-109619"})
        self.assertEqual(catalog["upstream_fixed_releases"]["8.5"], "8.5.12")
        related = catalog["related_advisories"]
        self.assertEqual(related[0]["cve"], "CVE-2026-115560")
        self.assertNotIn("CVE-2026-115560", catalog["cves"])
        self.assertNotIn("fixed_releases", related[0])
        conditions = " ".join(related[0]["published_preconditions"])
        for required in ("session.upload_progress.enabled", "php_binary", "php_serialize", "ini_set()", "session_start()"):
            self.assertIn(required, conditions)

    def test_oversized_mcp_line_is_drained_before_next_message(self):
        stream = io.BufferedReader(io.BytesIO(b"a" * 300000 + b"\n" + b'{"jsonrpc":"2.0","id":4,"method":"ping"}\n'))
        self.assertEqual(bounded_line(stream), (b"", True))
        line, oversized = bounded_line(stream)
        self.assertFalse(oversized)
        self.assertEqual(json.loads(line)["id"], 4)

    def test_cli_rejects_oversized_case_file(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "large.json"
            path.write_bytes(b" " * 65537)
            child = subprocess.run([sys.executable, "-m", "rpk_php2shell_triage.cli", "assess", str(path)],
                                   capture_output=True, text=True, timeout=10, env=env)
        self.assertEqual(child.returncode, 2)
        self.assertEqual(json.loads(child.stderr)["error"]["code"], "case_file_too_large")

    def test_cli_case_file_errors_do_not_echo_private_path_or_bytes(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private-case-token.json"
            child = subprocess.run(
                [sys.executable, "-m", "rpk_php2shell_triage.cli", "assess", str(path)],
                capture_output=True, text=True, timeout=10, env=env,
            )
            self.assertEqual(child.returncode, 2)
            self.assertEqual(json.loads(child.stderr)["error"]["code"], "case_file_io_error")
            self.assertNotIn("private-case-token", child.stderr)
            path.write_bytes(b"\xffprivate-case-content")
            child = subprocess.run(
                [sys.executable, "-m", "rpk_php2shell_triage.cli", "assess", str(path)],
                capture_output=True, text=True, timeout=10, env=env,
            )
            self.assertEqual(child.returncode, 2)
            self.assertEqual(json.loads(child.stderr)["error"]["code"], "case_file_encoding_error")
            self.assertNotIn("private-case-content", child.stderr)

    def test_cli_invalid_arguments_do_not_echo_supplied_tokens(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        child = subprocess.run(
            [sys.executable, "-m", "rpk_php2shell_triage.cli", "assess", "--bad", "private-argument-token"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        self.assertEqual(child.returncode, 2)
        self.assertEqual(json.loads(child.stderr)["error"]["code"], "invalid_arguments")
        self.assertNotIn("private-argument-token", child.stderr)

    def test_cli_rejects_nonlocal_case_paths_before_open(self):
        for path in ("relative-private-case.json", r"\\remote.invalid\share\private-case.json"):
            with self.subTest(path=path):
                stderr = io.StringIO()
                with patch("rpk_php2shell_triage.cli.os.open",
                           side_effect=AssertionError("unexpected file open")):
                    with redirect_stderr(stderr):
                        result = cli_main(["assess", path])
                self.assertEqual(result, 2)
                self.assertEqual(json.loads(stderr.getvalue())["error"]["code"],
                                 "case_file_local_required")
                self.assertNotIn("private-case", stderr.getvalue())

    def test_cli_accepts_absolute_local_case_file(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic-case.json"
            path.write_text(json.dumps(case()), encoding="utf-8")
            child = subprocess.run(
                [sys.executable, "-m", "rpk_php2shell_triage.cli", "assess", str(path)],
                capture_output=True, text=True, timeout=10, env=env,
            )
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout)["verdict"], "fixed_release_reported")

    def test_stdio_parse_error_does_not_echo_private_input(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        child = subprocess.run(
            [sys.executable, "-m", "rpk_php2shell_triage.mcp_stdio"],
            input=b'{"jsonrpc":"2.0","secret":"private-wire-token\xff"}\n',
            capture_output=True, timeout=10, env=env,
        )
        self.assertEqual(child.returncode, 0)
        self.assertEqual(json.loads(child.stdout)["error"]["code"], -32700)
        self.assertNotIn(b"private-wire-token", child.stderr)

    def test_stdio_oversize_then_ping(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        wire = b"x" * 300000 + b'\n{"jsonrpc":"2.0","id":9,"method":"ping"}\n'
        child = subprocess.run([sys.executable, "-m", "rpk_php2shell_triage.mcp_stdio"],
                               input=wire, capture_output=True, timeout=10, env=env)
        self.assertEqual(child.returncode, 0, child.stderr)
        replies = [json.loads(line) for line in child.stdout.splitlines()]
        self.assertEqual(replies[0]["error"]["code"], -32600)
        self.assertEqual(replies[1]["id"], 9)
        self.assertEqual(replies[1]["result"], {})

    def test_stdio_handshake_and_tools(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "rpk-test", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "rpk_php2shell_assess", "arguments": {"case": case()}}},
        ]
        wire = "".join(json.dumps(x) + "\n" for x in requests)
        child = subprocess.run([sys.executable, "-m", "rpk_php2shell_triage.mcp_stdio"],
                               input=wire, text=True, capture_output=True, timeout=10, env=env)
        self.assertEqual(child.returncode, 0, child.stderr)
        replies = [json.loads(line) for line in child.stdout.splitlines()]
        self.assertEqual([x["id"] for x in replies], [1, 2, 3])
        self.assertEqual(replies[0]["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(len(replies[1]["result"]["tools"]), 2)
        self.assertEqual(replies[2]["result"]["structuredContent"]["verdict"], "fixed_release_reported")

    def test_stdio_rejects_unpaired_surrogate_and_keeps_request_id(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        bad = case()
        bad["target"]["label"] = "\ud800"
        requests = [
            {"jsonrpc": "2.0", "id": 41, "method": "tools/call", "params": {
                "name": "rpk_php2shell_assess", "arguments": {"case": bad}}},
            {"jsonrpc": "2.0", "id": 42, "method": "ping"},
        ]
        wire = "".join(json.dumps(x) + "\n" for x in requests)
        child = subprocess.run([sys.executable, "-m", "rpk_php2shell_triage.mcp_stdio"],
                               input=wire, text=True, capture_output=True, timeout=10, env=env)
        self.assertEqual(child.returncode, 0, child.stderr)
        replies = [json.loads(line) for line in child.stdout.splitlines()]
        self.assertEqual([x["id"] for x in replies], [41, 42])
        self.assertTrue(replies[0]["result"]["isError"])
        self.assertEqual(replies[1]["result"], {})


if __name__ == "__main__":
    unittest.main()
