# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0]

### Added

- `narvy store-check <file>`: store readiness checks for an APK, AAB,
  split-APK set (`.apks`, `.xapk`, `.apkm`) or IPA against the Google Play
  and App Store upload requirements: target API level, 16 KB page size
  (ELF segment alignment and zip alignment of native libraries),
  `android:exported` on components with intent filters, debuggable builds,
  cleartext traffic, foreground service types, permissions that need a Play
  Console declaration, iOS SDK and minimum OS version, required-reason APIs
  against the privacy manifests, listed third-party SDKs without a privacy
  manifest, App Transport Security and purpose strings. Every finding cites
  the value read in the binary and the official page the rule comes from;
  a question the binary cannot settle is reported `not determined`, never
  guessed. Options: `--json` (both languages), `--lang fr`, `--as-of DATE`
  (store requirements are dated), `--fail-on warning`, `--verbose`. Exit
  codes: 0 no blocker, 1 blocker (or warning with `--fail-on warning`),
  3 file not analysable. The check runs offline, reads the archive in
  memory, writes nothing to disk and sends no telemetry. Python standard
  library only, no new dependency. It is not a security scan.

### Changed

- Secret findings are worded for what they are: "Potential secret: <kind>
  (format match, not tested)" or "(pattern match, not tested)". Narvy never
  tests a secret (no login, no API call, no revocation check). Findings
  carry `secret_confidence` (`likely` or `potential`) and `secret_tested:
  false` in JSON and SARIF. Public client keys shipped in app code (Firebase
  configuration, Google API keys restricted by design) are reported as
  Info.
- Secret values are masked in every output: console table, JSON, SARIF,
  the upload payload, raw tool output (`--verbose`) and log records. The
  wording and masking are the same as the Narvy dashboard, so dashboard
  fingerprints of uploaded findings do not change.

## [1.1.5]

### Changed

- The dependency check (SCA) now queries Narvy's EU-hosted vulnerability
  database, a mirror of OSV.dev, instead of api.osv.dev and api.github.com.
  It sends package names, ecosystems and versions only, never code, file
  paths or findings, and says so when it starts. `OSV_API_URL` points it
  at another OSV-compatible server; it accepts a base URL or, as before,
  the full `/query` URL. The batch URL now follows `OSV_API_URL` (it used
  to stay on api.osv.dev unless `OSV_BATCH_API_URL` was also set).
- iOS: the direct GitHub Advisory lookup is off by default. All 63 reviewed
  GitHub `swift` advisories are in OSV as `SwiftURL`, so the database above
  carries them. `NARVY_GITHUB_ADVISORIES=1` turns the direct lookup back on,
  and it now uses `GITHUB_TOKEN` when set (the rate-limit message already
  told users to set it, but it was not read).
- Batch pre-filter requests carry up to 1000 dependencies and stay under
  1 MB. A batch the server refuses as too large (HTTP 413) is split in
  halves and retried, down to a single dependency; one that is still
  refused is looked up on its own and counted unresolved if that fails.
- A scan now checks up to 20,000 unique dependencies (was 400, which left
  projects such as a Django app with a JavaScript front end reported as
  partial). Past that cap the check is still reported partial, with the
  number not queried. Requests to Narvy's database are paced to stay under
  its per-IP limits, so a very large project waits instead of being cut
  off by a rate limit; small scans are not slowed.

### Fixed

- A dependency check that got no usable answer is reported INCOMPLETE,
  never clean, in every case: server unreachable, 503 (database data older
  than 48 hours, or unavailable), 429 after one retry that honours
  `Retry-After` (at most 10 s), 400, 404 or an unreadable response. After
  the first such failure the rest of the run stops querying and counts the
  remaining dependencies as unresolved, with one log line for the outage
  instead of one per dependency. The end-of-scan message names the server
  and the reason.
- iOS libraries with no known source repository URL (most CocoaPods pods
  and embedded frameworks) were reported with 0 CVEs as if checked. They
  are now looked up by bare name (a few advisories are published that way)
  and counted as unverified in the SCA coverage note.
- Ecosystems the database does not carry are no longer sent (the server
  would reject the whole batch); those dependencies are counted as
  unverified.
- Results served from an expired local cache while the database was
  unavailable are now flagged in the coverage note.
- JSON output: `summary.sca_coverage` gains `dependencies_unverified`,
  `dependencies_from_stale_cache` and `vulnerability_db` (server host,
  database snapshot time and age when the server reports them, last error).
- Android: an APK scan is no longer refused for lack of memory. 1.1.2 to
  1.1.4 refused a 6,300-class app on a laptop with 1.1 GB free ("--max-mem
  4g asks JADX for 4.0 GB of Java heap ... run it anyway with --force"),
  and the `--max-mem 1g` it suggested was refused the same way. The jadx
  heap is now sized for each app: the smallest of `--max-mem` (new default
  `auto`), what fits in the memory free right now, and twice the app's
  estimate. The JVM's own memory is counted as about 250 MB plus 5% of the
  heap (measured on real apps), not a fixed 1 GB reserve plus 30%. When the
  app's estimate does not fit, the scan runs with the largest heap that
  does and says so before jadx starts. If jadx runs out of Java heap it is
  retried once with a bigger heap when memory allows; when the operating
  system refuses memory (commit limit, OOM killer) it is retried once with
  a smaller heap and one thread; then the scan fails with the numbers and
  what to do. `--force` now means: exactly `--max-mem`, no sizing, no retry.
- A generous `--max-mem` no longer inflates memory use: `-Xmx4g` on a
  6.5k-class app peaked at 1.56 GB of RAM against 0.99 GB with the 1 GB
  heap now chosen, for the same decompiled output.
- Linux and macOS: jadx no longer runs under an address-space limit
  (RLIMIT_AS). With a small heap it stopped the JVM from starting its
  threads, and jadx then exited 0 without writing any source, which would
  have been scanned as an empty app. A jadx run that exits 0 without
  writing sources, or that printed an OutOfMemoryError, is now a failure,
  never a clean scan.
- Linux: free memory honours a container or cgroup memory limit (Docker
  `--memory`, CI runners, systemd `MemoryMax`); `/proc/meminfo` shows the
  whole host there, so a 2 GB container used to size jadx for the host.
- Windows: free memory is `ullAvailPhys` (Task Manager's "Available",
  standby cache included), now also bounded by the commit charge left.
- Split bundles (.apkm/.xapk/.apks): the heap estimate counts the feature
  modules jadx decompiles together with the base APK.
- The line printed after decompiling gives the heap used and how many
  methods jadx could not fully decompile (kept as low-level code, so
  findings inside them can be missed); a tight heap raises that number.
- JSON and SARIF output say whether the structural (Semgrep) pass
  completed: `summary.structural_coverage` and
  `runs[0].properties.structuralCoverage` (`complete`, `incomplete` with
  the reason, or `not_run`). A timed-out pass was only visible on the
  console.
- Messages no longer send users to `--upload` for something it cannot do:
  it sends findings only, so it neither decompiles a large app nor finishes
  a timed-out structural pass. The memory messages point to an upload from
  the Narvy dashboard, the structural-pass note to `--upload-binary`.
- The SCA result line no longer reads "checked N ..., found 0 known
  CVE(s)" when the lookups failed; it says their CVE status is unknown.
- A jadx failure message is printed as text: brackets in jadx output were
  read as console markup.

## [1.1.4]

### Fixed

- APK scans: the structural (Semgrep) pass could match none of the app's
  own files and report "Deep analysis INCOMPLETE" (seen on Windows with
  Python 3.10). Two ways to get there were reproduced: a scan folder
  reached through a symlink (a Windows 8.3 short name such as `RUNNER~1`
  or a junction gives the folder a second spelling in the same way), and a
  `.git`/`.hg`/`.svn` folder in any parent of the scan folder, which moves
  semgrep's project root above it so the `sources/...` path filter no
  longer matched. The scan folder is now resolved to one long-name,
  physical path for every tool and every relative path, the path filters
  match at any depth, and if they still match nothing the app's own
  package folders are scanned as explicit roots.
- Secret findings that fired only on a variable NAME (key, secret,
  password, token, credential) were CRITICAL whatever the value was.
  The value is now checked: a known provider credential format (AWS,
  Google, Stripe, GitHub, Slack, ...) or key material of a real key length
  keeps the rule's severity; a plain non-secret (URL, path, dotted or
  snake_case identifier, UPPER_CASE constant, label repeating the word
  "password", format string, regex, sentence, placeholder) is dropped;
  anything else is capped at MEDIUM with LOW confidence and says why.
  Applies to Android (APK and source), iOS Objective-C and Swift source,
  and iOS binary strings. Provider-format rules are unchanged. JSON output
  carries `original_severity` and `value_evidence` for re-graded findings.

### Changed

- End-of-scan message: "Scanned ... with N local rules" counted only the
  pattern rules (APK) or mixed in one entry per dependency advisory found
  (source). It now gives the number of rules actually executed, by engine
  (pattern, taint, structural, native-library, config), and separately how
  many of them produced findings and how many dependency advisories
  matched. A structural pass that did not complete is not counted. JSON
  output: `summary.rules_executed`, `rules_executed_by_engine`,
  `rules_matched`, `sca_advisories_matched`.
- Console summary table: hits of the same rule in the same file are one
  row with a hit count and the lines involved. `--no-group` restores one
  row per hit. SARIF and JSON output still list every hit.
- Platform CI harness prints `narvy doctor` output.

## [1.1.3]

### Fixed

- APK scans were refused before decompiling on machines with less free
  memory than `--max-mem` needs (about 1.3x the heap plus 1 GB), even for
  small apps. On an 8 GB laptop at the default `--max-mem 4g` that was
  nearly every app, and on macOS the free-memory reading was low by
  several GB. `--max-mem` is a ceiling: when it does not fit but a smaller
  heap still covers the app's estimated need by 1.5x, jadx now runs with
  that smaller heap and the scan says so. A machine that cannot hold even
  that is still refused, with the same advice as before.
- macOS: available memory comes from the kernel's own figure
  (`kern.memorystatus_level`, what `memory_pressure` reports), which counts
  memory the compressor can reclaim. The `vm_stat` page count is the
  fallback and now includes speculative pages.
- APK scans: a structural (Semgrep) pass that failed was reported as
  complete with 0 findings when semgrep exited with an error but still
  printed JSON. It is now reported as incomplete with the error, after one
  retry with a single worker. A run whose path filters matched none of the
  app's own source files is reported the same way instead of as a clean
  pass. Rule ids no longer depend on where the package is installed.

### Changed

- Platform CI: the check removes the user Scripts/bin directory from PATH
  before running scans (hosted runners ship with it on PATH, a new user's
  shell does not), and prints the APK scan output on success so the
  structural-pass status is in the log.

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
