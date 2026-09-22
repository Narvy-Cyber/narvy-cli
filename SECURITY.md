# Security Policy

Narvy (LIMITLESS KNOWLEDGE, SIREN 994 833 143) takes the security of the
Narvy CLI seriously. This document explains how to report a vulnerability
and what you can expect from us.

## Reporting a vulnerability

**Email: security@narvy.io**

Please include:

- the CLI version (`narvy --version`) and your OS/architecture,
- what the vulnerability is and where,
- steps to reproduce, ideally a minimal proof of concept,
- the impact you believe it has.

Do **not** open a public GitHub issue for a security vulnerability. Use the
email above (or GitHub's private "Report a vulnerability" advisory flow if
enabled on the repository).

If you need to send sensitive details encrypted, email us first with no
sensitive content and we will agree an encrypted channel. We do not currently
publish a PGP key and would rather say so than list one we do not use.

## Our commitments

- We **acknowledge** every good-faith report within **72 hours (3 business days)**.
- We give a first assessment (reproduced / severity) within **10 business days**.
- We keep you updated at least every **14 days** until resolution.
- We practise **coordinated disclosure**: we agree a public disclosure date with
  you, default **90 days**, sooner if a fix ships sooner. We will credit you if
  you want it, or keep you anonymous.
- Where warranted, we request a **CVE** so users can track the fix.

We do not run a paid bug-bounty programme today, and we will not imply one we
cannot fund. We intend to introduce one as we grow.

## Safe harbour

We will not pursue or support legal action against you for security research
conducted in good faith that respects this policy: stay in scope, avoid harm to
people, data and availability, only access data that is your own, and give us a
reasonable chance to fix before disclosing. Full terms, including the platform
scope, are on our disclosure page: https://narvy.io/security

## Supported versions

Security fixes are provided for the **latest released minor version** of the
CLI. Users on older versions should upgrade to receive fixes.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Previous minor | Best effort |
| Older | No, please upgrade |


## Regulated reporting (Cyber Resilience Act)

As the manufacturer of a product with digital elements placed on the EU market,
LIMITLESS KNOWLEDGE is subject to the reporting obligations of Article 14 of the
EU Cyber Resilience Act (Regulation (EU) 2024/2847), which apply from
**11 September 2026**. If a vulnerability in a shipped CLI release is found to be
**actively exploited**, we are required to notify ENISA and our national CSIRT
(CERT-FR / ANSSI, France) on a 24-hour early-warning, 72-hour notification, and
14-day final-report cadence. This runs in parallel with the coordinated
disclosure process above.

## Software Bill of Materials (SBOM)

Each CLI release ships with a **CycloneDX SBOM** of the CLI's own dependency
tree (`narvy-<version>.cyclonedx.json`), attached to the release. See
https://narvy.io/security for how to obtain it.

---

*This is our documented process and will be reviewed by counsel; it is not legal
advice.*
