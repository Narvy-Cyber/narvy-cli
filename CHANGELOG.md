# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1]

### Fixed

- `--fail-on` no longer green-passes a build whose scan silently degraded. An
  SCA run that could not reach OSV.dev (outage / cold cache) is now reported as
  `degraded` and fails the gate (exit 2), not a clean 0. `cloud-scan`,
  `web-scan` and `host-audit` now feed their own coverage gaps (skipped AWS
  analyzers, SSRF-blocked redirect, partial non-root audit) into `--fail-on`.
- `cloud-scan`: one AccessDenied no longer aborts the remaining analyzers for a
  region; each runs in isolation and skipped checks are reported under
  `coverage` in the output.
- SARIF output on every surface (`scan`, `web-scan`, `host-audit`, `cloud-scan`)
  now carries a per-result `level` and a `security-severity` property, so
  GitHub/GitLab code scanning can rank findings.

### Changed

- `web-scan`, `host-audit` and `cloud-scan` now use `-o`/`--output` for the
  format and `-f`/`--file` for the destination, consistent with `scan`. The
  older `--format` / `--output-file` long options still work as aliases. A file
  path that is actually a format name (e.g. `-f json`) is now rejected loudly
  instead of writing a mis-named text file.

## [1.0.0]

First stable release, published to PyPI as `narvy-cli`.

### Changed

- Distribution name is `narvy-cli` on PyPI (`pip install narvy-cli`); the
  command and import package remain `narvy`.
- Web/backend rule packs are Narvy-authored and run on the Semgrep OSS engine,
  which is invoked as a dependency.

### Notes

- Runs entirely on your machine; nothing is uploaded unless you pass `--upload`.
- Honest coverage limits are surfaced in the tool's own output (for example,
  FairPlay-encrypted iOS binaries and partial multi-ABI native coverage).

## [0.9.0]

First public release. A free, local security scanner that runs entirely on your
machine and never uploads source code unless you explicitly ask it to.

### Added

- **Android SAST** - static analysis of APK/AAB binaries and Android source
  trees (Java/Kotlin), with third-party-code filtering to keep findings focused
  on first-party code.
- **iOS SAST** - static analysis of IPA/Mach-O binaries and iOS source trees
  (Swift/Objective-C), including symbol-table and Obj-C introspection.
- **Web and backend source SAST** - polyglot scanning of web/backend source
  directories (JavaScript/TypeScript, Python, PHP, Go, Ruby, Rust, Java,
  Kotlin) using Narvy-authored rule packs.
- **Software Composition Analysis (SCA)** - dependency scanning to surface known
  vulnerable components.
- **Passive web scanner** (`web-scan`) - Nuclei-based passive vulnerability
  scan of a URL with SSRF-guarded redirect resolution; no account required.
- **Host/infra audit** (`host-audit`) - agentless Lynis audit over your own SSH
  access; no credentials are sent anywhere.
- **Cloud posture scan** (`cloud-scan`) - cloud configuration checks using your
  own ambient credentials, with zero credential custody.
- **Semgrep detection engine** (pinned `semgrep==1.152.0`) driving
  independently-authored Narvy rule packs for mobile and web/backend
  source, shipped with the package.
- **`doctor`** - preflight environment check (Java, jadx, network, iOS tooling)
  before scanning.
- **`init-ci`** - drop-in CI templates for GitHub, GitLab, and Bitbucket.
- **`scan` / `upload-all` / `scans`** - scan a single artifact or a whole
  directory, optionally submitting results to a Narvy account, and list
  recent scans.
- **`login` / `logout`** - link a machine to a Narvy account using an API
  token stored locally.
- False-positive precision tuning across the Android, iOS, and web analyzers.

[0.9.0]: https://narvy.io
