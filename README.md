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

and one check that is not a security scan:

- `store-check` - Google Play and App Store upload requirements for an
  APK, AAB, split-APK set or IPA, offline (see [Store check](#store-check))

Your code, binaries and findings are never uploaded unless you explicitly
pass `--upload`. The CLI does send anonymous usage statistics, described
exactly in [Telemetry](#telemetry), which you can turn off.

The dependency check sends package names and versions (never code, file paths or findings) to Narvy's EU-hosted vulnerability database. Set OSV_API_URL to use another OSV-compatible server.

## Install

```bash
pipx install narvy-cli      # recommended, puts `narvy` on PATH (run `pipx ensurepath` once)
pip install narvy-cli       # or plain pip
```

If your shell says `narvy: command not found` / `The term 'narvy' is not
recognized`, pip installed the command into a directory that is not on your
PATH. `python -m narvy` always works (`py -m narvy` on Windows), and prints
once the command that adds that directory to PATH. Narvy never edits PATH
itself.

### Windows

Recommended, with [pipx](https://pipx.pypa.io):

```powershell
py -m pip install --user pipx
py -m pipx ensurepath          # then close and reopen the terminal
pipx install narvy-cli
narvy scan app.apk
```

Without pipx:

```powershell
py -m pip install narvy-cli
py -m narvy scan app.apk
```

To use the short `narvy` command after a plain `pip install`, add pip's
Scripts directory to PATH. For the current PowerShell window only
(Python 3.14 from python.org; change `Python314` to your version):

```powershell
$env:Path += ";$env:APPDATA\Python\Python314\Scripts"
```

To make it permanent for your user account, then open a new terminal:

```powershell
[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:APPDATA\Python\Python314\Scripts", "User")
```

The exact directory is in pip's `WARNING: The script narvy.exe is installed
in ... which is not on PATH` line, and in the hint `py -m narvy` prints. The
Microsoft Store Python uses a different one (under
`%LOCALAPPDATA%\Packages\PythonSoftwareFoundation.Python.3.x_...\LocalCache\local-packages`).
Windows on ARM: semgrep has no Windows ARM64 build, use x64 Python.

### macOS

Homebrew's Python refuses `pip install` outside a virtualenv
(`error: externally-managed-environment`). Use pipx:

```bash
brew install pipx && pipx ensurepath   # then open a new terminal
pipx install narvy-cli
```

or a virtualenv (`python3 -m venv ~/.venvs/narvy && ~/.venvs/narvy/bin/pip install narvy-cli`).
A `pip install --user` puts `narvy` in `~/Library/Python/3.x/bin`, which is
not on PATH: add it with
`echo 'export PATH="$HOME/Library/Python/3.14/bin:$PATH"' >> ~/.zshrc`, or run
`python3 -m narvy`.

### Linux

pipx (`sudo apt install pipx` / `dnf install pipx`, then `pipx ensurepath`) is
the simplest. Debian 12+ and Ubuntu 23.04+ refuse a system-wide `pip install`
the same way Homebrew does. A `pip install --user` puts `narvy` in
`~/.local/bin`; if that is not on PATH, add
`export PATH="$HOME/.local/bin:$PATH"` to `~/.bashrc`, or run
`python3 -m narvy`.

### Requirements

Android scans need Java 11+. If none is found, a JRE (and jadx) is
downloaded into `~/.narvy/tools` on the first APK scan. Everything else
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

# Google Play / App Store upload requirements, offline (not a security scan)
narvy store-check app-release.aab
narvy store-check MyApp.ipa --lang fr --json
```

Run `narvy doctor` before your first scan to check your Java/jadx/iOS
tooling setup, and `narvy <command> --help` for the full flag list of
any subcommand.

The console summary table groups hits of the same rule in the same file
into one row, with a hit count and the lines involved. `--no-group` shows
one row per hit. SARIF and JSON output always list every hit.

### Very large Android apps

Decompiling is memory-hungry, and file size is a poor predictor of how much
you need. Before decompiling, the CLI reads the DEX headers to estimate the
Java heap the app needs and sizes the jadx heap from that estimate and the
memory free right now: a small app on a busy 8 GB laptop gets a small heap
instead of a refusal. `--max-mem` sets an upper limit (default `auto`). When
the estimate does not fit in free memory the scan still runs with the
largest heap that does, and says so. If jadx runs out of memory it is
retried once (a bigger heap when memory allows, otherwise one worker
thread), then the scan fails with the numbers. `--force` runs exactly
`--max-mem`, without sizing or retry.

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

## Store check

`narvy store-check` answers one question: will Google Play or the App Store
accept this build, and what will they ask about it? It reads the manifest,
resources, native libraries, Info.plist, Mach-O load commands, imported
symbols and privacy manifests of the file, and evaluates them against the
store requirements in force at a date (`--as-of`, default today).

```bash
narvy store-check app-release.aab
narvy store-check app.xapk --fail-on warning      # CI gate on warnings too
narvy store-check MyApp.ipa --json > store.json   # EN and FR messages in one report
narvy store-check MyApp.ipa --as-of 2027-02-01    # evaluate a future deadline
```

| Store | Checks |
|-------|--------|
| Google Play | `PLAY-TARGET-SDK`, `PLAY-16KB-ELF`, `PLAY-16KB-ZIPALIGN`, `PLAY-EXPORTED`, `PLAY-DEBUGGABLE`, `PLAY-CLEARTEXT`, `PLAY-FGS-TYPE`, `PLAY-FGS-PERMISSION`, `PLAY-FGS-DECLARATION`, `PLAY-PERMISSION-DECLARATION` |
| App Store | `APPSTORE-SDK-VERSION`, `APPSTORE-MIN-OS`, `APPSTORE-REQUIRED-REASON-API`, `APPSTORE-PRIVACY-MANIFEST`, `APPSTORE-THIRD-PARTY-SDK`, `APPSTORE-ATS`, `APPSTORE-PURPOSE-STRINGS` |

Each check reports `fail` (severity `blocker`, `warning` or `info`),
`pass`, `not_determined` (the binary does not settle the question) or
`not_applicable`, with the evidence read from the file and the official
page the rule comes from. In `--json`, `title` describes the result for its
status and cites the value read ("Target API 33 is below Google Play's
requirement (API 36)"), and `requirement` holds the rule itself ("Target API
level meets Google Play's current requirement"), both in English and French.
Store values and their sources live in `narvy/store_check/data/`.

It runs offline: no network call, no telemetry event, nothing written to
disk (the archive is read in memory). It does not check store listing
metadata, Data safety answers, whether a declared permission use is
acceptable under Play policy, or SDK signatures.

Exit codes: 0 no blocker (with `--fail-on warning`, no warning either),
1 at least one blocker (or warning), 3 the file cannot be analysed.

## Dependency check (SCA)

The dependency check sends package names and versions (never code, file paths or findings) to Narvy's EU-hosted vulnerability database. Set OSV_API_URL to use another OSV-compatible server.

What is sent, per dependency: the package name, its ecosystem (npm, PyPI,
Maven, ...) and the resolved version. Nothing else: no code, no file paths,
no project or repository name, no findings. The database is a mirror of
[OSV.dev](https://osv.dev) (data from OSV.dev and the sources it
aggregates, including the GitHub Advisory Database), refreshed from the
OSV.dev export and hosted in the EU by Narvy.

`OSV_API_URL` takes a base URL (`/query` and `/querybatch` are appended,
e.g. `OSV_API_URL=https://api.osv.dev/v1`) or, as in earlier releases, the
full query URL ending in `/query`. The batch URL follows it unless
`OSV_BATCH_API_URL` is set.

The check is reported INCOMPLETE, never clean, when the database cannot give
a usable answer: unreachable, rate-limited, or its data older than 48 hours.
Dependencies it cannot look up (an ecosystem the database does not carry, an
iOS library with no known source repository URL) are counted as unverified
in the scan's coverage note. Results are cached for 7 days in
`~/.narvy/osv_cache.db`.

## Telemetry

The CLI sends one small anonymous event per command (`store-check` sends
none), so we can see which scan types are used and where they fail. It is sent in the background with
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
- Windows: a decompiled file whose full path passes 260 characters is only
  read when Windows long-path support is enabled
  (`LongPathsEnabled`); a very deep package tree in `%TEMP%` can hit it.

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
