# Narvy CLI - Setup & Test Guide

Real, tested commands only. If a command here doesn't work exactly as
written, that's a bug - not "you did something wrong."

**Working on the CLI's rules/detection engines yourself?** See
`tests/BENCHMARKING.md` for the precision/recall benchmark harness -
run it against the real-app corpus before AND after any rule change,
not just the one app you happen to be looking at.

---

## Recommended: pipx (one command, no venv/activate steps at all)

This is the real, standard way to install a Python CLI tool without
managing a venv yourself - the same approach tools like Poetry, Black, and
Ansible document as the primary path. It creates and manages its own
isolated venv somewhere outside your project folder, so OneDrive-sync
locks and stale-venv path issues (see below) don't apply to it either.

```bash
# One-time, if you don't have pipx yet:
python -m pip install --user pipx
python -m pipx ensurepath
# close and reopen your terminal after this (PATH change needs a fresh shell)

# Install the CLI - one command, that's it:
pipx install /path/to/narvy   # or a git URL once this is published

narvy doctor
narvy scan /path/to/some.apk
```

To upgrade after pulling a new version: `pipx uninstall narvy`
then `pipx install /path/to/narvy` again (pipx doesn't have a
one-shot "reinstall from local path" command).

---

## Alternative: manual venv (only if you specifically need editable/dev
## mode - e.g. you're modifying the CLI's own code)

### Universal rule (any OS, any project, not just this one)

**Every time you `rm -rf venv` or move a venv's folder, run `hash -r`
before calling `python`/`pip` again.**

Bash caches the resolved path of commands it's already run in that shell
("hashing" - standard POSIX bash behavior, not a bug). If you
delete or move a venv, bash keeps pointing at the old, now-missing path
until you clear that cache. Symptom: `type python` reports `python is
hashed (/old/path/that/no/longer/exists)`, or you get `No such file or
directory` errors that make no sense given what's actually on disk. A new
terminal window does NOT reliably clear this on Windows/Git Bash the way
you'd expect - `hash -r` does, every time, guaranteed.

```bash
hash -r   # run this any time paths stop making sense after moving/deleting things
```

### Windows (Git Bash / MINGW64)

**Known issue: `Permission denied` on `venv/Scripts/python.exe`.**
Almost always OneDrive syncing your `Downloads` folder and locking the file
mid-creation. Fix: delete the broken venv, then either move the project out
of a synced folder or just retry (OneDrive usually releases the lock after
a few seconds).

```bash
cd ~/dev/narvy   # NOT ~/Downloads if it's OneDrive-synced
rm -rf venv
hash -r
python -m venv venv
hash -r
source venv/Scripts/activate
which python   # sanity check - must point INSIDE this venv, not an old path
pip install -e .
narvy --help
```

### macOS / Linux

```bash
cd ~/dev/narvy   # or wherever you cloned it
rm -rf venv
python3 -m venv venv
source venv/bin/activate   # bin/, not Scripts/ (only Windows differs)
pip install -e .
narvy --help
```

---

## Prerequisites (all platforms)

- **Python 3.9+** (any recent Python 3 works)
- **Java: none required.** jadx needs a JRE 11+, but the CLI auto-detects
  your system Java and, if it's missing or too old (or JAVA_HOME is
  stale/broken), auto-downloads
  its own JRE 17 into `~/.narvy/tools`. You never need to install or
  manage Java yourself. Run `narvy doctor` to see what it resolved.

---

## First real test (all platforms, once installed)

```bash
# 1. Local-only scan, no account needed - this always works, free forever
narvy scan /path/to/some.apk

# First run auto-downloads jadx (~30MB) and, if needed, a JRE (~40-50MB) -
# one time each, into ~/.narvy/tools. Expected, not an error - the
# scan will just take longer on that first run.

# 2. Link to your account (paste your API token - get it from
#    narvy.io > Profile > API Credentials > Regenerate Key)
narvy login

# 3. Scan and send the results to your account's dashboard (paid plan)
narvy scan /path/to/some.apk --upload
```

**What "good" looks like:**
- Step 1 prints a progress bar ("Decompiling APK..." then "Analyzing
  files..." then "Deep structural analysis..." - the last one runs a real
  Semgrep-powered AST engine, can take several minutes on larger apps,
  that's normal, don't interrupt it), then either "No issues found" or a
  table of findings with Severity/Rule Name/File/Line columns.
- Step 2 prints "Logged in as your@email.com (your-plan plan)."
- Step 3 prints "Results uploaded. scan_id=..." followed by a direct
  "View this scan: https://narvy.io/analysis/s/..." link.

**If something doesn't match this exactly, run `narvy doctor` first
and report ITS output - it catches the whole class of environment issues
(Java, jadx, disk, network) in one shot.**

---

## Seeing your account's scan history, and bulk-uploading

```bash
# List recent scans on your account
narvy scans
narvy scans --limit 50 --status failed
narvy scans --format json

# Scan and upload every .apk/.aab/.apkm/.xapk/.ipa found under a directory,
# in one command, instead of running `scan --upload` once per file
narvy upload-all /path/to/a/folder/of/apps
narvy upload-all /path/to/a/folder/of/apps --no-recursive
```

Both require `narvy login` first.

`upload-all` walks the directory (recursively by default; `--no-recursive`
limits it to the top level), skipping the usual build/VCS/dependency noise
(`.git`, `node_modules`, `build`, `Pods`, etc.), and runs the exact same
`scan --upload` path on each target it finds - one failing app (corrupt
file, malware-triage refuse, out-of-memory decompile) does not stop the
rest of the batch. It ends with a succeeded/failed summary and exits 1 if
anything failed. `.apks` bundles (raw bundletool output) are found but not
uploaded - same restriction `scan --upload` already has on a single file -
and reported separately so they don't get silently dropped.

`scans` currently depends on a server endpoint (`GET /api/v1/scans`) that
is **not deployed yet** as of this writing - it will fail with a clear "not
available yet" message until the server ships it. It is real, tested CLI
code, ready to work the moment the server side lands; it is not fake or
half-built, it is genuinely blocked on separate server-side work. Track
your scans at narvy.io in the meantime.

---

## Don't have an APK to test with?

Any real APK works. If you don't have one handy:
- Any app installed on an Android device/emulator (`adb shell pm path
  <package>` then `adb pull` it)
- A downloaded APK from anywhere you'd normally get one

---

## iOS (binary IPA + Swift/ObjC source) - same install, same `scan` command

No separate install, no separate command. `narvy scan <path>` looks
at what you pointed it at and picks the right engine automatically:

| You pass... | Mode | What runs |
|---|---|---|
| `something.apk` | Android | unchanged, exactly as above |
| `something.ipa` | iOS binary | Mach-O analysis (LIEF) + Obj-C class-dump (icdump, see below) |
| a folder with `.xcodeproj`/`.xcworkspace`/`Package.swift`/`.swift`/`.m`/`.h` files | iOS source | Semgrep (Swift) + regex rules (Obj-C) + Info.plist/entitlements checks |

```bash
narvy scan /path/to/YourApp.ipa          # binary IPA
narvy scan /path/to/your/swift/repo/      # source checkout (point at the repo root)
```

**Scope, on purpose, not a limitation we're hiding:** binary mode is for
**your own build** - a dev/TestFlight export, an `.xcarchive` export, an
unencrypted IPA. It is *not* for scanning an app pulled from the App Store
link - those are FairPlay-encrypted, and no static tool (ours or anyone
else's) can read meaningful Obj-C/Swift structure out of ciphertext. If the
CLI detects `LC_ENCRYPTION_INFO cryptid=1` on the binary you gave it, it
tells you plainly instead of silently handing back an almost-empty report.

### Obj-C class-dump: `icdump` (optional, free, not required to run)

Real class/method/property/protocol extraction on a Mach-O binary needs
`icdump` (Apache 2.0, `pip install icdump`). Without it, binary mode still
works - it falls back to LIEF's symbol-table-only Obj-C detection (no
per-method names, but nothing crashes and nothing is silently skipped).

```bash
pip install narvy[ios-full]   # pulls in icdump on top of the base install
# or just: pip install icdump           # into the same venv/pipx env, any time
```

**Windows note:** `icdump` has no Windows wheel today (Linux + macOS only
- confirmed on PyPI, not a guess). On Windows, binary-mode iOS scans
automatically use the LIEF-only fallback - still functional, just without
full method-level class-dump. If you want the fuller path on Windows, run
it inside WSL. `narvy doctor` reports which path you're actually
getting.

### Don't have an IPA/repo to test with?

- Binary: export an `.xcarchive`/`.ipa` from Xcode for your own app (dev
  signing, not App Store distribution), or use one of the well-known public
  OWASP mobile training apps - all unencrypted, built for exactly this.
- Source: point it at any Swift/ObjC repo you have checked out locally.

---

## `.narvy-scope.yml` - tell the scanner "this is MY code" / "this is a vendor SDK", once

Both the Android and iOS binary scanners auto-detect first-party vs.
third-party code (Android: your app's own `applicationId` from the
manifest; iOS: bundle-id/framework-name matching against a curated vendor
list - see `narvy/third_party_filter.py` and
`narvy/ios/third_party_filter.py`). That detection is
best-effort and occasionally gets an unusual layout wrong - a white-label
namespace that never nests under your `applicationId`, or an iOS framework
whose CocoaPods bundle id (`org.cocoapods.<Name>`) can't be told
apart from a third-party pod's.

Instead of re-guessing (or, on iOS, tagging it `[Unconfirmed Origin]`) on
every single scan, declare it once. This is the same idea as GitHub
Linguist's own `.gitattributes`/`vendor.yml` override system, applied to
Narvy's first-party/third-party question.

**Where it goes:** a file named `.narvy-scope.yml`, either in the
directory you run `narvy scan` from (checked first) or in the same
directory as the `.apk`/`.ipa`/source-repo you're scanning (checked if the
first location has no file). Entirely optional - no file means today's
exact default behavior, unchanged.

**Format:**

```yaml
own:
  - qosiframework
  - qosiui
vendor:
  - some.unknown.sdk
  - name: legacy.vendored.copy
    reason: "vendored fork of libX, not maintained by us"   # optional
```

- `own` entries force full first-party severity (Android: scans that
  package; iOS: Tier 1, no `[Unconfirmed Origin]` tag) for anything
  matching, no matter what automatic detection or the curated vendor lists
  would otherwise say.
- `vendor` entries force the opposite - excluded from content scanning
  entirely, same as a confirmed third-party SDK today.
- Overrides win over everything: automatic package/bundle-id detection,
  the curated denylists, all of it. This file is your explicit final word.

**Matching:** each entry matches EXACTLY by default (case-insensitive).
Add a trailing `*` to opt into a prefix match (`qosi*`, `com.acme.*`).
This is deliberately *stricter* than the built-in curated lists' own
bare-prefix convention - an entry like `own: [auth]` will never
accidentally swallow an unrelated `OAuthKit`/`FirebaseAuth`/`AppAuth`
framework just because they contain the same letters; you'd have to write
`auth*` to opt into that. For dotted Android package paths and iOS bundle
ids, a plain entry (`com.google.android`, `com.facebook.sdk`) already
matches that exact namespace *and* everything nested beneath it - no `*`
needed there.

**Worked example.** An app embeds a licensed vendor framework that carries
no CocoaPods bundle id trace, so it lands as `[Unconfirmed Origin]`, plus
an internal framework of its own that shares the app's bundle-id root and
is therefore scanned as first-party by default. Both classifications can be
pinned explicitly:

```yaml
own:
  - MyInternalFramework
vendor:
  - SomeVendorFramework
```

Re-running the scan then shows `MyInternalFramework`'s findings with the
`[Unconfirmed Origin]` tag gone (full-confidence first-party), and every
`SomeVendorFramework` finding disappears from the report entirely.

**What if the file is broken?** Malformed YAML, or the wrong shape, prints
one warning to the console and the scan continues with zero overrides -
it never aborts a scan over a bad config file. An entry listed in both
`own` and `vendor` is also just a warning + that one entry falls back to
automatic classification (fail safe, not a crash).

**Scope:** wired into the Android
scan path and the iOS *binary* (`.ipa`) scan path - both are where a
single package/framework has to be labeled first- vs. third-party by name.
iOS *source-mode* scanning (a checked-out Swift/ObjC repo) excludes
vendored code by directory convention (`Pods/`, `Carthage/`, …) and
`Podfile.lock`/`Package.resolved` instead - a different mechanism, not
wired into this override file today.

**Trust model - this is a local, single-user CLI.** The person running
`narvy scan` and the person authoring `.narvy-scope.yml` are
assumed to be the same person on their own machine, the same trust model
`.gitignore` uses. If Narvy ever ports this to a multi-tenant
context where the file could ride in on someone else's repo content, that
port needs its own report-visibility and audit-log work first - see
`narvy/scope_config.py`'s module docstring for the full
trust-boundary writeup.

---

## SCA (third-party dependency CVE scanning) - automatic, part of `scan`

No separate command - every `narvy scan`
(Android APK, iOS IPA, iOS source directory) automatically also checks the
app's third-party libraries against known CVEs and merges the results into
the SAME report, tagged `SCA-<CVE id>` (e.g. `SCA-CVE-2021-0341`), right
alongside the SAST findings. Data sources:

- **[OSV.dev](https://osv.dev)** for the primary CVE lookup - free, no API
  key, no auth header, no documented rate limit for normal single-machine
  use. This is the only realistic choice for a free/local CLI with zero
  Narvy backend in the loop (same "zero credential custody" pattern
  as `cloud-scan`). Results are cached locally in
  `~/.narvy/osv_cache.db` (SQLite, 7-day TTL) so re-scanning the same
  app, or scanning several apps that share common libraries, doesn't
  re-query the network every time. A cheap batch pre-filter
  (`/v1/querybatch`) checks which of an app's (often 50-300) dependencies
  have ANY known vuln before spending a full detail query on each one.
- **GitHub Advisory Database** (iOS only, `ecosystem=swift`) as a
  supplementary source, because OSV's Swift-ecosystem coverage is real but
  thin. **Rate limit:** GitHub's REST API is
  rate-limited to 60 requests/hour *unauthenticated* - the CLI caches every
  response for 24h in `~/.narvy/github_advisory_cache/`, caps itself
  to at most 25 distinct package lookups per scan, and stops issuing new
  requests once the `X-RateLimit-Remaining` response header drops to 5 or
  below, so one large scan can't burn your whole hourly budget. If you hit
  the limit mid-scan, the console tells you plainly and the scan finishes
  anyway (OSV + the curated local DB below still ran normally).
- A **small curated local database** (a handful of verified, real,
  independently-checked CVEs - e.g. AFNetworking's CVE-2016-4817 SSL
  bypass) as an instant, zero-network baseline for a few historically
  significant iOS libraries.

### What's detected

| Scan mode | Detection source | Notes |
|---|---|---|
| Android (APK/AAB) | `META-INF/*.version` files, embedded `pom.properties`, Gradle module metadata, a couple of literal version strings (e.g. OkHttp embeds its own version in its default User-Agent header), and a low-confidence Maven-coordinate regex over raw DEX strings | Reliably catches AndroidX/Jetpack + anything that ships `pom.properties`. **Known gap:** many R8/proguard-shrunk release builds strip the metadata OkHttp/Retrofit/Gson/etc. would otherwise expose, so those libraries can go undetected even when present in the code, unless they happen to embed a literal version string the way OkHttp does. |
| iOS source (`Podfile.lock` / `Package.resolved`) | Exact locked versions - the most reliable source this tool has | `Package.resolved`'s own `location` field gives an exact GitHub repo URL for precise OSV lookups (OSV's Swift ecosystem, "SwiftURL", is keyed by the bare `github.com/<owner>/<repo>` path, NOT the library's short name - verified live against the real API, see `sca/osv_client.py`'s `ECOSYSTEMS` comment). Branch/commit-pinned SPM dependencies (no semver `version` field - common when a fork tracks a private branch) can't be version-compared and are skipped, not guessed at. |
| iOS binary (`.ipa`) | Embedded `Frameworks/*.framework/Info.plist`, scoped to a curated list of known third-party SDK names | **Known gap:** apps built with Xcode's newer consolidated/static SPM linking bundle every dependency's resources into namespaced sub-bundles inside ONE umbrella framework, each carrying a meaningless placeholder version ("1.0") instead of the real per-library version - those are correctly NOT reported (a wrong version would be worse than no finding), which means this mode under-covers on apps built that way. Classic CocoaPods/Carthage-style one-`.framework`-per-library apps are unaffected. |

### Ecosystem notes

OSV.dev has no "CocoaPods" ecosystem: the API rejects it outright
(`{"code":3,"message":"invalid ecosystem"}`), and its one Swift ecosystem
("SwiftURL") is keyed by GitHub repo URL, not by library name. See
`sca/osv_client.py`.

---

## Web scan, Host/Infra audit, Cloud posture - same install,
## same `narvy` command

No separate install and no separate venv: `web-scan`, `host-audit` and
`cloud-scan` are first-class `narvy` subcommands.

### `narvy web-scan` - Nuclei scan, passive by default

```bash
narvy web-scan https://example.com
narvy web-scan https://example.com --format json --output-file results.json
narvy web-scan https://example.com --fail-on high   # exit 1 if a high/critical finding exists (CI gate)
```

**Prerequisite: `nuclei`.** Prefers a `nuclei` already on PATH; if none is
found it auto-downloads a pinned release (~15MB) into
`~/.narvy/tools`, the same one-time pattern jadx uses - no manual
install step required, but do expect the first run to take a little longer.

**What "good" looks like:** a short header, then (after nuclei runs) either
"No issues found with the passive-only template set." or a list of
`[SEVERITY] Title - URL` lines, ending with a reminder that this was
passive-only.

**Safety posture:** by default only passive, GET-only templates run: no
injection payloads, no `-dast` pass. `--active` runs the full template set
(non-GET probes, input handling checks) but still excludes the `dos`,
`fuzzing`, `brute-force` and `intrusive` tags. Only use it on targets you own
or are authorized to test. The scanner refuses Narvy's own domains and a list
of major third-party platforms (`narvy/web/scan_blocklist.py`), and it
validates and pins the target's resolved IP before connecting
(`narvy/web/ssrf_guard.py`), so internal, private and loopback addresses are
refused, including through DNS rebinding or a redirect.

### `narvy host-audit` - agentless Lynis audit over your own SSH access

```bash
narvy host-audit some-server --user deploy
narvy host-audit 10.0.0.5 --user root --port 2222 --format json
```

**Prerequisite: your own working SSH access**, the same way `ssh
user@host` already works for you (`~/.ssh/config`, `ssh-agent`, default
identity files). Narvy's code never sees, stores, or transmits your
key/password - there is no code path in `narvy/host/ssh_exec.py`
that can, by construction (`use_ambient_identity=True`). If the target
doesn't already have `lynis` installed, this ships a checksum-pinned copy
over SSH, runs it from a throwaway `/tmp` dir, and removes it afterward -
it never touches the target's package manager.

**What "good" looks like:** a header naming the target, then (can take a
couple of minutes) a hardening index, a severity breakdown, and a list of
`[SEVERITY] Title` findings.

### `narvy cloud-scan` - AWS posture check, your own credentials

```bash
pip install narvy[cloud]   # pulls in boto3, opt-in (see below)
aws configure                        # if you haven't already
narvy cloud-scan --provider aws
narvy cloud-scan --provider aws --region eu-west-3 --format json
```

**Prerequisite: `pip install narvy[cloud]`** (boto3 is an opt-in
extra - most Android/iOS-only users never touch this command, so the base
install stays light; running `cloud-scan` without it prints a clear
one-line fix instead of a traceback) **and your own already-configured AWS
credentials** (`aws configure`, environment variables, or an assumed IAM
role) - the same pattern Prowler/ScoutSuite use. Zero credential custody:
nothing here stores, logs, or transmits your keys: with no explicit
credentials passed in, boto3's own ambient chain resolves them and
Narvy's code never sees them.

**What "good" looks like:** a provider/region header, then a severity
breakdown across ~30 checks (open security groups, public S3 buckets, IAM
users without MFA, unencrypted RDS, disabled GuardDuty, CIS 1.1-1.3
compliance, ...) and a list of `[SEVERITY] (category) Title` findings, or
"No issues found." on a clean account.

### All three: `--format {text,json,sarif}`, `--output-file`, `--fail-on {critical,high,medium,low,any}`

Same conventions as `narvy scan --output sarif`: `--fail-on` exits 1
when a finding at or above that severity exists (wire into CI), JSON/SARIF
go to stdout by default or to `--output-file` if given.

### Exit codes when you gate a build with `--fail-on`

`--fail-on` is available on `scan`, `web-scan`, `host-audit` and `cloud-scan`.

| code | meaning |
|------|---------|
| 0 | the scan ran with full coverage and found nothing at or above your threshold |
| 1 | the gate tripped: at least one finding is at or above your threshold (the reason is printed, with the count per severity) |
| 2 | the gate could not be evaluated (part of the scan didn't run), so it won't pass the build |

Exit 2 is the one worth reading twice. A gate is a claim about your code, not
about the scan, and there are cases where the scan finishes without ever having
read the target - in those, "0 findings" means UNKNOWN, not clean, and
returning 0 would be telling your pipeline something this tool cannot know.
The cases, all of them printed in full when they happen:

- the deep structural (Semgrep) pass did not run, or did not finish
  (semgrep missing from PATH, or it timed out on a large target - raise
  `NARVY_SEMGREP_TIMEOUT`). On web/backend source, Semgrep IS the code
  engine: without it only the dependency-CVE pass runs.
- the target is a FairPlay-encrypted `.ipa` (any App Store download). Most
  rules cannot see inside the encrypted `__TEXT`. Scan the build artifact from
  your own pipeline instead of a store download.
- `web-scan` reached a target that never answered, or that answered 429/503 to
  the verification probes. Nothing was scanned.

Without `--fail-on` none of this changes anything: the scan still prints
everything and still exits 0. The stricter behaviour only applies when you have
explicitly asked this tool to gate something.

One more thing a gate cannot rank: a finding carrying a severity outside
critical/high/medium/low/info. That also exits 1 rather than being quietly
treated as harmless. If you ever see it, it is a bug in this CLI - please send
us that output.
