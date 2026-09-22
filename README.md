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
  Rust, Java/Kotlin, C#/.NET

It also ships three standalone scanners that need nothing but network
access or your own existing credentials:

- `web-scan` - passive Nuclei-based scan of a live URL
- `host-audit` - agentless host audit over your own SSH access (Narvy's own
  host checks plus Lynis (GPL-3.0) as the hardening baseline)
- `cloud-scan` - AWS account posture check using your own ambient AWS
  credentials

Nothing is uploaded anywhere unless you explicitly pass `--upload`.

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

### Optional Narvy Cloud scan

`narvy login` links the CLI to a Narvy account. Add `--upload`
to a scan to also submit it for a deeper cloud pass (full taint
analysis, compliance mapping, dashboard history) - not required for local
scanning, and not on by default. `narvy upload-all <directory>` does
the same for every binary target found in a folder in one command.
`narvy scans` lists recent scans on your account from the terminal.

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
