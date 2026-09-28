# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.2]

### Added

- `python -m narvy` (`py -m narvy` on Windows) runs the CLI. It works when
  pip put the `narvy` command in a directory that is not on PATH, the
  default for a user install on Windows and macOS. Run that way, Narvy
  prints once the command that adds the directory to PATH (PowerShell on
  Windows, your shell rc file elsewhere). It never changes PATH itself;
  `NARVY_NO_PATH_HINT=1` turns the hint off.
- README: install steps for Windows, macOS (Homebrew
  `externally-managed-environment`) and Linux, with pipx first.

### Fixed

- A user install run as `python -m narvy` (or by the launcher's full path)
  did not find semgrep in the same off-PATH directory, skipped the code pass
  and reported only dependency CVEs. semgrep is now looked up there and its
  directory is put on the PATH it runs with (it starts `pysemgrep` through
  PATH).
- macOS: when no Java 11+ was installed, the downloaded JRE was never found
  ("no bin/ dir found inside"), so APK scans failed on every such Mac. The
  macOS layout (`Contents/Home/bin`) is handled, Apple Silicon and ARM Linux
  get the native aarch64 JRE instead of x64, and a cached JRE that does not
  run is downloaded again.
- Windows: jadx failed to start when its path contained a space (a user name
  like `Jean Dupont`, or `C:\Program Files`), because `cmd /c` stripped the
  wrong quotes. The jadx command line now goes through `cmd /d /s /c` as one
  quoted string.
- Windows: tool output (semgrep, jadx, nuclei, ssh) is decoded as UTF-8
  instead of the console code page, semgrep runs in Python UTF-8 mode, and
  output redirected to a file or pipe replaces a character the code page
  cannot encode instead of stopping the scan with `UnicodeEncodeError`.
- A file still locked in a temporary directory (antivirus, a slow child
  process) no longer fails the scan at cleanup.
- SCA: only one version of each package was checked. A lockfile that holds
  `minimist 1.2.8` and a nested `minimist 0.0.8` now checks both. A version
  taken from a manifest range is still dropped when a lockfile resolves that
  package.
- yarn.lock (berry): the package comes from the `resolution:` line, so
  aliases (`string-width-cjs@npm:string-width@...`) and `patch:` entries
  name the real package, and `__metadata`, workspace, git and local entries
  are no longer sent to OSV as packages.
- semgrep with more than one worker drops taint-mode results at random with
  no error. Every rule pack that holds a taint rule now runs in its own
  single-worker semgrep process (packs still run side by side). Files where
  a rule hit the per-file timeout are named in the scan notes.

### Changed

- Community rule precision round (PHP, JavaScript, Go, Java, Python, Ruby):
  fewer findings on code that is not reachable by an attacker. Informational
  rules are lowered to LOW with the reason.

## [1.1.1]

### Added

- Flask cookie checks: `set_cookie()` without `httponly=True` or
  `secure=True`, the same checks Django already had.
- `scan` warns when files or folders could not be read (permissions) instead
  of skipping them silently; `-v` lists them and the JSON report has
  `summary.unreadable_paths`.
- `scan --format` is accepted as an alias of `--output`, like the other
  commands.

### Fixed

- A second `scan` of the same folder picked up the report written by the
  first one (`narvy.sarif`, the JSON report) and flagged the rule text quoted
  in it as secrets. Narvy reports are now recognized by their content, and
  the `--file` target is never scanned.
- `--upload` with only `NARVY_TOKEN` set printed "Uploading ... to  for
  server-side curation". The line now names the server (`narvy.io`, or
  `NARVY_URL`), and a failed upload or login says which server refused it.
- `web-scan http://localhost` said "internal/metadata addresses"; it now says
  the address is loopback and explains why local and private targets are
  refused.
- The web-scan, host-audit and cloud-scan JSON output carries a `tool` field.
- `narvy doctor` documents its exit codes (0 all required checks pass, 1 one
  failed).

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
