# RPK PHP2Shell Triage

RPK-authored contributions use Apache License 2.0. Adapted Eric Mann indicator fragments retain his MIT notice. See [LICENSE-DECISION.md](LICENSE-DECISION.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and [PROVENANCE.md](PROVENANCE.md) for the scope of each license and the source history.

This local tool classifies evidence supplied for CVE-2026-109618 and CVE-2026-109619. It helps an operator decide what to inspect or update. Its code initiates no network client request, scans no target, and changes no service. Its first catalog snapshot uses the [PHP 21 October 2026 release](https://www.php.net/archive/2026.php#2026-10-21-5) and the linked PHP security advisories for [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w). Vendor status must be rechecked at decision time.

## Run locally

From this folder in PowerShell:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
python -m rpk_php2shell_triage.cli catalog
python -m rpk_php2shell_triage.cli assess (Join-Path (Get-Location) 'examples/fixed-upstream.json')
python -m rpk_php2shell_triage.cli ioc --php-error C:\absolute\path\saved-php-error.log
python -m unittest discover -s tests -v
```

The runtime-assessment library API is `from rpk_php2shell_triage import assess_case, fixed_release_catalog`. These commands need Python 3.10 or newer and no external Python package. The `assess` CLI requires an absolute local regular case-file path and reads at most 64 KiB. It rejects links, junctions/reparse paths, UNC paths, and recognized mapped network drives before opening the file. As with saved logs, path checks cannot detect every cloud-backed file or prevent every concurrent path change; opening one can trigger operating-system network access or hydration. The CLI never follows advisory URLs.
Its CLI errors use fixed codes instead of echoing file paths, input bytes, or case details. The `assess` result does include the caller's case ID, target label, and observation time, so keep both input and output private when they identify a real target. The MCP `assess` tool likewise returns caller-supplied target metadata in its structured and text results.

## Offline saved-log candidate review

`ioc` is a separate, explicit command for saved PHP, PHP-FPM, and Apache error logs. Repeat `--php-error ABSOLUTE_LOCAL_FILE` for PHP or PHP-FPM and `--apache-error ABSOLUTE_LOCAL_FILE` for Apache to supply the files to review. The library function is `rpk_php2shell_triage.ioc.scan_saved_logs([(type, absolute_path), ...])`, where `type` is `php_error` or `apache_error`. Nginx logs are not supported because this snapshot has no defensible Nginx-specific rule. The command performs no target discovery, live scan, or remediation and does not initiate a network client request. The caller must supply a suitable local saved copy whose collection and review are in scope. An absolute path alone does not prove that storage is local.

The command accepts at most 8 regular files, each at most 8 MiB, and rejects directories, symlinks, junctions/reparse paths, Windows mapped network drives, UNC paths, duplicate file identities, NUL-containing content, and lines above 64 KiB. Those path checks do not detect every remote mount or cloud-backed file; opening one can trigger operating-system network access or hydration. It streams each file through SHA-256 while counting physical lines. A file changed during reading is rejected when its size or modification time changes. Other concurrent in-place edits with unchanged metadata cannot be ruled out. The source files remain in place.

Output is JSON with schema `rpk.php2shell.saved_log_ioc.v1`. Each source has its input index, declared type, SHA-256, byte and line counts, and every applicable rule's ID, category, count, first 64 line numbers, and truncation flag. It never prints a source path or raw log line; errors contain fixed codes and optional source indexes. The CLI exits `0` when a scan completes regardless of candidate counts, and `2` on an error. Inspect the rule counts; exit `0` does not mean clean. The supplied file paths can still appear in shell history or local process inspection while the CLI runs. Protect those surfaces or call the library from an appropriately private local process. Treat even hashes and line numbers as case metadata and keep the result private. The command does not emit a `clean`, `compromised`, or CVE verdict.

The reviewed patterns are:

| Rule ID | Input type | Candidate signal |
| --- | --- | --- |
| `PHP_UNKNOWN_LINE_OOM` | PHP or Apache error | PHP fatal memory exhaustion reported in `Unknown on line 0` |
| `PHP_ZEND_HEAP_CORRUPTION` | PHP or Apache error | Exact `zend_mm_heap corrupted` phrase in an error line |
| `PHP_OOM_CONTEXT` | PHP or Apache error | Other PHP fatal memory exhaustion; excludes lines already counted by the more specific unknown-line rule |
| `PHP_FPM_CHILD_EXIT_SIGNAL` | PHP or PHP-FPM error | PHP-FPM pool child exit with mapped SIGSEGV, SIGABRT, SIGILL, or SIGBUS signal |
| `APACHE_CHILD_EXIT_SIGNAL` | Apache error | Apache child PID exit with Segmentation fault, Aborted, Bus error, or Illegal instruction |

These are line-oriented fault candidates, not PHP2Shell exploit signatures. Apache error logs may carry PHP fatal messages as well as child-exit notices, so PHP fatal and heap rules apply to both supported log types. PHP-FPM child-exit lines are assessed only for `php_error` sources. The matcher requires selected native PHP, FPM, or Apache error-log prefix shapes; echoed text can mimic those shapes, so review log provenance. Memory pressure, crashes, and heap faults have many possible causes. A match needs operator review with deployment timing and other evidence; no match cannot exclude exploitation or prove patch success. The tool does not establish whether the logs are complete, authentic, or from the serving worker under review. Preserve the original logs and collection provenance outside this tool.

## Case packet

`case_id` identifies this observation, `target.label` names the target locally, and `runtime` records the observation. `runtime.version` is numeric `major.minor.patch`. `runtime.channel` is `upstream`, `vendor-backport`, or `unknown`. `runtime.evidence_kind` is `serving_process`, `cli`, `http_header`, or `inventory`. `runtime.observed_at` needs an ISO 8601 UTC offset.

For `serving_process`, also supply the observed `pid`, absolute `executable_path`, and `sapi`. The observation timestamp cannot be far in the future. The tool recognizes the PHP SAPI names `apache`, `apache2handler`, `cgi`, `cgi-fcgi`, `cli-server`, `fpm-fcgi`, and `litespeed` as potentially serving; [PHP's published SAPI list](https://www.php.net/manual/en/function.php-sapi-name.php) is not exhaustive. A non-serving or unreviewed SAPI stays unresolved until its serving role is established. This is still a caller assertion; the tool cannot verify that the fields came from a real process or that it serves the named application. A CLI or HTTP header observation stays unresolved even if its version string meets a fixed floor.

For vendor backports, include `runtime.serving_package` with the name and installed revision of the package that owns the observed worker executable. Include `vendor_fix.package_name`, `installed_revision`, `fixed_revision`, a syntactically valid HTTPS `advisory_url`, and `covered_cves` with both CVEs. The tool accepts matching worker, installed, and fixed revisions as a **reported match** and asks the operator to read the advisory. Earlier packets without the worker package remain readable but return `unresolved`. The tool does not fetch the advisory, authenticate the package, or compare distro revision ordering. If an image is involved, `image.running_digest` and `image.reviewed_fixed_digest` can be supplied as lowercase SHA-256 digests. A mismatch takes precedence over a version claim; a match is supporting evidence only.

The verdicts are `unresolved`, `update_required`, `fixed_release_reported`, `vendor_revision_match_reported`, and `provenance_conflict`. A reported fixed release means only that the supplied process record meets the reviewed version threshold. It does not establish exploit resistance, worker restart, package authenticity, or application health. Preserve the input packet and output as separate local evidence. Do not upload host paths, process IDs, private names, or raw receipts to a public repository.
Each verdict applies to the supplied `runtime.observed_at` timestamp. Old observations remain useful for historical review; the output always sets `present_deployment_status` to `unverified` because the tool does not inspect the current worker. Read a fresh serving-worker observation before describing the present deployment, even if the saved packet reports a fixed release.

## MCP tool

The local stdio entry point is:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
python -m rpk_php2shell_triage.mcp_stdio
```

It implements the 2025-11-25 handshake-era stdio methods `initialize`, `ping`, `tools/list`, and `tools/call`. It exposes `rpk_php2shell_catalog` and `rpk_php2shell_assess`. The `assess` tool takes `{ "case": { ... } }`. It starts only when an MCP host launches it. The [MCP stdio specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) requires one newline-delimited JSON-RPC message per line and reserves stdout for protocol messages.

## Operator workflow

Identify an actual PHP-serving target and its owner. Read the serving worker's executable, process identity, SAPI, loaded version, and package or image provenance. For a vendor package, read the current vendor advisory. Run this tool on the saved observation. If it calls for an update, use the target's normal change procedure, recycle the worker, then make a fresh observation and check a harmless application response. Keep before and after case packets separate. An unchanged result does not authorize repeated updates or a probe against an external service.
