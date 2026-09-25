# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0]

First release of the community rule set. The 1.0.x preview releases were
withdrawn; 1.1.0 replaces them.

### Added

- PHP: reflected XSS where request input is concatenated or interpolated into
  an HTML string, and an `include`/`require` of a variable that is set in
  another file (reported as HIGH, to review).
- Python and Ruby rules: tainted module import, deprecated `ssl.wrap_socket`,
  response header CRLF injection, SSRF from a request-controlled host.
- A web repository that also holds an iOS app in a subdirectory (an Xcode
  project, workspace or `Package.swift` next to a server directory) is now
  scanned on both surfaces, and the report lists them. Sample, test and
  vendored projects are skipped.
- `--upload` prints a direct link to the scan in the dashboard.
- Outside a terminal (CI logs), a "still running" line every 30 seconds
  (`NARVY_PROGRESS_INTERVAL`, 0 = off).
- Anonymous usage telemetry, listed field by field in the README, with a
  notice on first run. Off with `narvy telemetry off`, `NARVY_TELEMETRY=0` or
  `DO_NOT_TRACK=1`.

### Changed

- Framework-specific rules and the C#/.NET code rules are no longer in the
  CLI; they run on Narvy paid plans. The CLI states in one line when a scanned
  project uses one of those frameworks. C#/.NET projects get secrets and NuGet
  dependency checks.
- Exit codes are distinct and listed in `--help`: 0 completed, 1 `--fail-on`
  threshold reached, 2 `--fail-on` could not certify the result (part of the
  scan did not run), 3 target or arguments not usable, 4 scan, login, upload
  or write failure. Exit 1 on `--fail-on` is unchanged.
- The structural analysis uses at most 4 workers and a memory ceiling, and
  trees above 20,000 files are scanned in directory batches. On the Linux
  kernel tree, peak memory went from 13 GB to 2.2 GB with the same findings
  (the scan takes longer). `NARVY_SEMGREP_JOBS`,
  `NARVY_SEMGREP_MAX_MEMORY_MB`, `NARVY_SEMGREP_BATCH_FILES` override.
- Help for `--upload` and `--fail-on` rewritten; the `.narvy-scope.yml` tip
  links to the public documentation.
- The FairPlay notice no longer says dynamic analysis always covers an
  encrypted app's own code: it does for most apps, and strongly protected apps
  can block it.

### Fixed

- PHP findings changed from one run to the next (49 to 52 on the same code):
  the PHP parser is not safe with parallel workers. PHP rules now run in a
  single worker.
- PHP command injection with a trailing concatenation
  (`shell_exec('ping ' . $target)`) was not detected, and escaping functions
  were not recognized as sanitizers. Values checked with `is_numeric()`,
  `ctype_digit()` or `filter_var()` are now treated as safe.
- Private-key detection no longer fires on a lone `BEGIN PRIVATE KEY`
  delimiter string; keys embedded as a single escaped string are still found.
  The high-entropy secret rule ignores public keys, constant names and path
  values. Rust: DDL statements built with `format!` are no longer reported as
  SQL injection.
- A web repository with an iOS app in a subdirectory was reported as web only,
  with a coverage note pointing to a directory that did not exist.
- SCA on an app with no identifiable dependency versions printed "0 known
  CVEs across 0 dependencies", which reads as clean. It now says the check
  was not applicable (`applicable: false` in JSON).
- Upgrade links returned by the server as relative paths are printed as full
  URLs.
- semgrep installed by pipx or in a non-activated virtualenv was not found,
  and the scan fell back to regex rules only.
- Cancelling a scan (SIGTERM/SIGHUP, CI cancel) left semgrep workers running,
  including workers that ignore SIGTERM.
- Without network access, each semgrep pass stalled for about 100 seconds on
  semgrep's own version check. The version check and semgrep metrics are now
  off.
- `web-scan --active` always timed out: its time budget assumed a third of the
  real template set.
- A corrupt or truncated APK/AAB/IPA exits 3 (unusable target) instead of 4.
  `host-audit` rejects an invalid host, user or port before connecting (exit 3).
- An output path that is a directory, or in a missing directory, is refused
  before the scan starts, for `web-scan`, `host-audit` and `cloud-scan` too.
- `narvy doctor` printed raw color codes from nuclei's version banner.
- C/C++ files are reported as not analyzed instead of being silently skipped.
- Plain APK results uploaded with `--upload` were filed as source scans.
