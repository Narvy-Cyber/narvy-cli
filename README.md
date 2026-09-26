# Narvy CLI

[![PyPI version](https://badge.fury.io/py/narvy-cli.svg)](https://badge.fury.io/py/narvy-cli)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A free, local static application security testing (SAST) scanner. It runs
entirely on your machine, needs no account, and finds real, high-signal
vulnerabilities - hardcoded secrets, insecure configuration, weak
cryptography, SSRF, injection, and more - in:

- **Android**: `.apk` / `.aab`, split-APK bundles (`.apkm` / `.xapk` /
  `.apks`), or a raw Gradle/Kotlin source checkout
- **iOS**: an unencrypted `.ipa`, or a raw Xcode/Swift source checkout
- **Web/backend source**: JavaScript/TypeScript, Python, PHP, Go, Ruby,
  Rust, Java/Kotlin, and C#/.NET (secrets and dependencies)

It also ships three standalone scanners that need nothing but network
access or your own existing credentials:

- `web-scan` - Nuclei-based scan of a live URL (passive by default, `--active` opt-in)
- `host-audit` - agentless host audit over your own SSH access (Narvy's own
  host checks plus Lynis (GPL-3.0) as the hardening baseline)
- `cloud-scan` - AWS account posture check using your own ambient AWS
  credentials

Your code, binaries and findings are never uploaded unless you explicitly
pass `--upload`. The CLI does send anonymous usage statistics, described
exactly in [Telemetry](#telemetry), which you can turn off.

## Install

```bash
pip install narvy-cli
```

Requires a Java 11+ JRE on your `PATH` for Android scanning (jadx itself is
auto-downloaded on first scan into `~/.narvy/tools`). Everything else
is pure Python plus a couple of optional extras:

```bash
pip install 'narvy-cli[ios-full]'  # full Obj-C introspection for iOS binary scans
pip install 'narvy-cli[cloud]'     # boto3, needed for cloud-scan
```

## Usage

```bash
# Android APK/AAB, split bundle, or a Gradle/Kotlin source checkout
narvy scan app-release.apk
narvy scan app.apkm
narvy scan ./my-android-app/

# iOS: unencrypted IPA, or a Swift/Xcode source checkout
narvy scan MyApp.ipa
narvy scan ./my-ios-app/

# Web/backend source (Node, Python, PHP, Go, Ruby, Rust, Java/Kotlin, C#/.NET)
narvy scan ./my-api-repo/

# SARIF output, for CI or GitHub/GitLab code scanning
narvy scan app-release.apk --output sarif --file results.sarif

# Passive web scan of a live URL - no active injection payloads, ever
narvy web-scan https://example.com

# Agentless host hardening audit over your own SSH access
narvy host-audit example.com --user deploy

# AWS account posture check using your own aws configure / env vars / IAM role
narvy cloud-scan

# List recent scans on your Narvy account (requires `narvy login`)
narvy scans

# Scan + upload every .apk/.aab/.apkm/.xapk/.ipa found in a folder, in one command
narvy upload-all ./my-apps-folder/
```

Run `narvy doctor` before your first scan to check your Java/jadx/iOS
tooling setup, and `narvy <command> --help` for the full flag list of
any subcommand.

### Very large Android apps

Decompiling is memory-hungry, and file size is a poor predictor of how much
you need. Before decompiling, the CLI reads the DEX headers to estimate the
Java heap the app needs and checks it against `--max-mem` and your
machine's free memory, so an app that won't fit fails in about a second
instead of after several minutes of doomed work. The estimate is a
heuristic, not a hard limit - `--force` runs the decompile regardless.

### Sending results to your Narvy dashboard

`narvy login` links the CLI to a Narvy account. Add `--upload` to a scan to
send its results (the findings, never your code or binary) to your account,
where they are de-duplicated, false-positive filtered and kept in the
dashboard history; the CLI prints a direct link to the scan. This needs a
paid plan (Starter and up) and is never on by default. `narvy upload-all
<directory>` does the same for every binary target found in a folder in one
command. `narvy scans` lists recent scans on your account from the terminal.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed (and nothing reached the `--fail-on` threshold) |
| 1 | `--fail-on`: at least one finding at or above the threshold |
| 2 | `--fail-on`: nothing reached the threshold, but part of the scan did not run (timed-out pass, unreachable CVE database), so it cannot be certified clean |
| 3 | The target or arguments are not usable (path not found, unsupported file type or project, refused URL, invalid option) |
| 4 | The scan, login, upload or report write failed |
| 130 | Interrupted (Ctrl-C, SIGTERM) |

`narvy doctor` exits 0 when every required check passes and 1 when one fails.
Missing optional tools are shown as INFO and do not change its exit code.

### Resource limits

The structural analysis pass runs with at most 4 parallel workers and a
3 GB memory ceiling per analyzed file, so a very large repository does not
exhaust the machine. `NARVY_SEMGREP_JOBS` and `NARVY_SEMGREP_MAX_MEMORY_MB`
(0 = no ceiling) override them; files skipped because of the ceiling are
listed in the scan notes. Outside a terminal (CI logs), a progress line is
printed every 30 seconds; `NARVY_PROGRESS_INTERVAL` changes that (0 = off).

## Telemetry

The CLI sends one small anonymous event per command, so we can see which
scan types are used and where they fail. It is sent in the background with
a 1 second timeout, is never retried or stored for later, and never fails a
scan. At most it adds 1 second at exit. A notice is printed the first time it runs.

Exactly these fields are sent:

| Field | Example |
|-------|---------|
| `schema` | `1`, the event format version |
| `install_id` | a random UUID created on first run and stored in `~/.narvy/config.json` (not derived from your machine, user or account) |
| `cli_version`, `python_version`, `os` | `1.1.1`, `3.11`, `linux` / `darwin` / `windows` / `other` |
| `ci` | `true` when a CI environment variable is set |
| `command` | `scan`, `web-scan`, `host-audit`, ... |
| `surface` | `android`, `ios`, `source`, `web`, `host`, `cloud` or `none` |
| `duration_bucket` | `<10s`, `10s-1m`, `1-5m`, `5-15m`, `15-60m`, `>60m` |
| `findings` | per severity, a bucket: `0`, `1-5`, `6-20`, `21-100`, `101-500`, `>500` |
| `exit_code` | the process exit code |
| `error_class` | on a crash, the exception class name only (e.g. `ValueError`), never its message |

Never sent: code, file, project, package or repository names, paths, URLs,
hosts or IPs you scan, finding details, your account id or email.

Turn it off with any of:

```bash
narvy telemetry off        # saved in ~/.narvy/config.json; `narvy telemetry on` to re-enable
export NARVY_TELEMETRY=0
export DO_NOT_TRACK=1
```

`narvy telemetry status` shows the current state.

## Free rules and premium rules

The CLI ships the community rule set under Apache 2.0: the language-level
rules for every supported language (injection, weak cryptography, dangerous
configuration, storage, WebView, transport), every hardcoded-secret rule, and
the Android and iOS rules. It is the same engine and the same community rules
that Narvy runs on its servers.

Framework-specific rules (Django, Flask, FastAPI, Express, Laravel, Symfony,
Ruby on Rails, Spring and the Java persistence/serialization stack, Gin) and
the C#/.NET code rules are premium: they run when a project is scanned on a
Narvy paid plan, not in the CLI. When a scanned project uses one of those
frameworks, the CLI says so in one line at the end of the scan, with the
number of checks it did not run. It never hides a finding it did compute.

## Known limitations

- Encrypted iOS binaries (the normal App Store distribution state) are
  detected but not decrypted; only the local, static checks that don't need
  the decrypted binary run.
- Web-source coverage depth isn't uniform across all eight languages - Rust
  and C#/.NET have a smaller rule set than the others, and the CLI says so
  in its own output when it applies.
- Only one architecture's native libraries are checked in a multi-ABI
  APK/split bundle.

See [SETUP.md](SETUP.md) for detailed install/troubleshooting steps and the
exact commands this README's examples were run against.

## License

Apache License 2.0 - see [LICENSE](LICENSE).

Rule packs under `narvy/rules/` are authored by Narvy
(Apache 2.0, same as the rest of this package) and contain no third-party
rule text.
`host-audit` runs Narvy's own host checks (secrets exposed on disk,
unauthenticated data services, cloud metadata exposure, container/daemon
posture, exposed VCS/artifacts in web roots) and, as the hardening baseline,
shells out to [Lynis](https://cisofy.com/lynis/) (GPL-3.0), auto-fetched at
run time over your SSH access, run arm's-length, never bundled. Lynis is
attributed as the engine in the audit output; its controls are not presented
as Narvy's own.

## Contributing

Issues and pull requests welcome, especially new or improved detection
rules. All rule packs are Narvy's own, under `narvy/rules/`: Android/iOS
(`rules/android`, `rules/ios`) and web/backend (`rules/web`). The
web/backend packs run on the Semgrep OSS engine, which Narvy invokes as a
dependency; the rules themselves are authored by Narvy (Apache-2.0).
