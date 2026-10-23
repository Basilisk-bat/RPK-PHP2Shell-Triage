"""Assess supplied evidence; never inspect or change a target."""

from __future__ import annotations

import re
import ntpath
import posixpath
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit


CVES = ("CVE-2026-109618", "CVE-2026-109619")
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
SOURCES = (
    "https://www.php.net/archive/2026.php#2026-10-21-5",
    "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
    "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
)
_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# Reviewed PHP SAPI names that can serve requests. PHP's published list is not
# exhaustive, so an unfamiliar name needs review rather than a fixed verdict.
_SERVING_SAPIS = frozenset((
    "apache", "apache2handler", "cgi", "cgi-fcgi", "cli-server",
    "fpm-fcgi", "litespeed",
))
_PLACEHOLDERS = frozenset(("unknown", "n/a", "na", "none", "null", "-", "?"))


def fixed_release_catalog() -> dict[str, Any]:
    """Return the reviewed upstream release snapshot, not live vendor status."""
    return {
        "reviewed_at": "2026-10-21",
        "cves": list(CVES),
        "upstream_fixed_releases": {f"{a}.{b}": ".".join(map(str, v)) for (a, b), v in FIXED.items()},
        "sources": list(SOURCES),
        "scope": "Upstream PHP releases; vendor backports and running processes require separate evidence.",
    }


def _required_string(value: Any, field: str, limit: int = 500) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > limit
            or not value.isprintable()):
        raise ValueError(f"{field} must be a printable nonempty string of at most {limit} characters")
    return value.strip()


def _timestamp(value: Any, field: str) -> str:
    raw = _required_string(value, field, 64)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    if parsed > datetime.now(parsed.tzinfo) + timedelta(minutes=5):
        raise ValueError(f"{field} cannot be in the future beyond clock skew")
    return raw


def _version(value: Any) -> tuple[int, int, int]:
    raw = _required_string(value, "runtime.version", 32)
    match = _VERSION.fullmatch(raw)
    if not match:
        raise ValueError("runtime.version must be a numeric major.minor.patch release")
    return tuple(map(int, match.groups()))  # type: ignore[return-value]


def _evidence_identifier(value: Any) -> str | None:
    """Return a claimed package identifier only when it is not a placeholder."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return (value if (value and len(value) <= 200 and value.isprintable()
                      and any(ch.isalnum() for ch in value)
                      and value.casefold() not in _PLACEHOLDERS) else None)


def _https_advisory_url(value: Any) -> bool:
    if (not isinstance(value, str) or len(value) > 2048 or not value.isprintable()
            or any(ch.isspace() for ch in value)):
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        if (parsed.scheme != "https" or not hostname or parsed.username is not None
                or parsed.password is not None):
            return False
        # This is syntax checking, not a network lookup or proof of an advisory.
        labels = hostname.encode("idna").decode("ascii").split(".")
        if (len(labels) < 2 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                                   for label in labels)):
            return False
        port = parsed.port  # Reject malformed port syntax.
        if port is not None and port < 1:
            return False
        return True
    except (ValueError, UnicodeError):
        return False


def assess_case(case: dict[str, Any]) -> dict[str, Any]:
    """Classify a local evidence packet without fetching URLs or changing state.

    A verdict is conditional on the caller's supplied observations. It is not a
    vulnerability test, a patch action, or proof of exploit resistance.
    """
    if not isinstance(case, dict):
        raise ValueError("case must be a JSON object")
    case_id = _required_string(case.get("case_id"), "case_id", 128)
    if not _CASE_ID.fullmatch(case_id):
        raise ValueError("case_id permits letters, digits, dot, underscore and hyphen")
    target = case.get("target")
    if not isinstance(target, dict):
        raise ValueError("target must be an object")
    label = _required_string(target.get("label"), "target.label", 200)
    runtime = case.get("runtime")
    if not isinstance(runtime, dict):
        raise ValueError("runtime must be an object")
    version = _version(runtime.get("version"))
    version_text = ".".join(map(str, version))
    channel = _required_string(runtime.get("channel"), "runtime.channel", 32)
    if channel not in ("upstream", "vendor-backport", "unknown"):
        raise ValueError("runtime.channel must be upstream, vendor-backport, or unknown")
    evidence_kind = _required_string(runtime.get("evidence_kind"), "runtime.evidence_kind", 32)
    if evidence_kind not in ("serving_process", "cli", "http_header", "inventory"):
        raise ValueError("runtime.evidence_kind is unsupported")
    observed_at = _timestamp(runtime.get("observed_at"), "runtime.observed_at")

    serving_claim = evidence_kind == "serving_process"
    sapi: str | None = None
    if serving_claim:
        pid = runtime.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid < 1:
            raise ValueError("runtime.pid must be a positive integer for serving_process evidence")
        executable_path = _required_string(runtime.get("executable_path"), "runtime.executable_path", 1000)
        if (executable_path.casefold() in _PLACEHOLDERS
                or not executable_path.isprintable()
                or not (ntpath.isabs(executable_path) or posixpath.isabs(executable_path))
                or ntpath.basename(executable_path) in ("", ".", "..")):
            raise ValueError("runtime.executable_path must be an absolute observed executable file path")
        sapi = _required_string(runtime.get("sapi"), "runtime.sapi", 100)
    process_bound = serving_claim and sapi in _SERVING_SAPIS

    image = case.get("image")
    image_match: bool | None = None
    if image is not None:
        if not isinstance(image, dict):
            raise ValueError("image must be an object")
        running = _required_string(image.get("running_digest"), "image.running_digest", 71)
        reviewed = _required_string(image.get("reviewed_fixed_digest"), "image.reviewed_fixed_digest", 71)
        if not _DIGEST.fullmatch(running) or not _DIGEST.fullmatch(reviewed):
            raise ValueError("image digests must be lowercase sha256: followed by 64 hex characters")
        image_match = running == reviewed

    verdict = "unresolved"
    summary = "The supplied evidence does not identify a fixed serving PHP runtime."
    checks: list[str] = []
    floor = FIXED.get(version[:2])
    floor_text = ".".join(map(str, floor)) if floor else None

    if not process_bound:
        checks.append("Read the actual serving worker's executable, SAPI, process identity and loaded PHP version.")
        if serving_claim:
            summary = "The supplied SAPI does not establish that this process serves PHP requests."
            checks.append("Confirm the serving SAPI and bind the observed process to the intended application.")
        elif floor and version < floor:
            summary = "The supplied non-serving version is below the upstream fixed release; the serving worker is unknown."
    elif image_match is False:
        verdict = "provenance_conflict"
        summary = "The running image digest differs from the reviewed fixed image digest."
        checks.append("Resolve the running image identity before relying on image publication or version claims.")
    elif channel == "upstream" and floor is not None:
        if version < floor:
            verdict = "update_required"
            summary = "The supplied serving-process version is below the upstream fixed release."
            checks.append(f"Update the serving worker to upstream PHP {floor_text} or a verified vendor fix.")
        else:
            verdict = "fixed_release_reported"
            summary = "The supplied serving process reports an upstream release at or above the reviewed fixed floor."
            checks.append("Verify executable provenance, worker restart and a harmless application response on the intended target.")
    elif channel == "vendor-backport":
        vendor = case.get("vendor_fix")
        if isinstance(vendor, dict):
            package = runtime.get("serving_package")
            covered = vendor.get("covered_cves")
            if isinstance(package, dict):
                worker_name = _evidence_identifier(package.get("name"))
                worker_revision = _evidence_identifier(package.get("installed_revision"))
                vendor_name = _evidence_identifier(vendor.get("package_name"))
                vendor_installed = _evidence_identifier(vendor.get("installed_revision"))
                vendor_fixed = _evidence_identifier(vendor.get("fixed_revision"))
                if (worker_name and worker_revision and vendor_name and vendor_installed and vendor_fixed
                        and worker_name == vendor_name
                        and worker_revision == vendor_installed == vendor_fixed
                        and _https_advisory_url(vendor.get("advisory_url"))
                        and isinstance(covered, list)
                        and all(isinstance(cve, str) for cve in covered)
                        and set(covered) == set(CVES)):
                    verdict = "vendor_revision_match_reported"
                    summary = "The supplied serving-worker package revision matches the caller's vendor fixed-revision claim for both CVEs."
                    checks.append("Independently read the vendor advisory, verify package provenance, worker restart and a harmless application response.")
        if verdict == "unresolved":
            summary = "The supplied packet does not bind a serving-worker package to a valid vendor fixed-revision claim for both CVEs."
            checks.append("Identify the package owning the serving worker executable, then check its installed revision against the vendor advisory.")
    elif floor is None:
        summary = "This PHP branch is outside the reviewed upstream fixed-release table."
        checks.append("Find a maintained vendor fix or move the serving worker to a supported fixed upstream branch.")
    else:
        checks.append("Establish whether the serving binary is upstream PHP or a vendor-backported build.")

    if image_match is True:
        checks.append("Digest equality supports image provenance; verify the PHP binary loaded inside the running worker.")
    summary += f" This assessment applies to the supplied observation at {observed_at}."
    return {
        "case_id": case_id,
        "target": label,
        "observed_at": observed_at,
        "assessment_scope": "supplied_observation_at_timestamp",
        "present_deployment_status": "unverified",
        "verdict": verdict,
        "summary": summary,
        "reported_runtime_version": version_text,
        "upstream_fixed_floor": floor_text,
        "serving_process_evidence_supplied": process_bound,
        "reviewed_image_digest_matches_running": image_match,
        "cves": list(CVES),
        "next_checks": checks,
        "limits": [
            "Assessment uses supplied observations; it does not inspect a process or fetch an advisory.",
            "A fixed-release report is not proof of exploit resistance or full application behavior.",
            "Vendor fixes and other branches require current vendor evidence.",
            "Current deployment status requires a fresh serving-worker observation.",
        ],
        "catalog_reviewed_at": "2026-10-21",
        "sources": list(SOURCES),
    }
