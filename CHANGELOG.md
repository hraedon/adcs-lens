# Changelog

All notable changes to adcs-lens are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-07-14

First public release. Local-first, read-only AD CS / PKI posture analysis with a
deterministic, stdlib-only core (no AI in the truth path).

### Added
- **ESC detectors** for the statically-detectable family: ESC1, ESC2, ESC3, ESC4,
  ESC5, ESC6, ESC7, ESC8, ESC9, ESC10, ESC11, ESC13, ESC14, ESC15, ESC16
  (ESC12 has no established static-detectability boundary — see
  `docs/threat-model.md`).
- **Infrastructure lifecycle**: CA cert / CRL-signing cert expiry, CRL freshness
  with a proportional early-warning window, weak signing algorithm (SHA-1/MD5),
  weak CA/template RSA key size (ECDSA templates skipped).
- **Operational hygiene**: CA audit disabled / under-scoped (vs. the 127 baseline).
- **Plain-language consequences catalogue**: every finding carries a summary,
  risk, and remediation block in the text, JSON, SARIF, and HTML output.
- **Output formats**: stable JSON envelope, SARIF v2.1.0 (CI/GRC), self-contained
  deterministic HTML evidence report.
- **Drift detection** (`diff`): regressions / fixes / severity changes between two
  read-only exports, with `--exit-code` for scheduled-scan gating — no live access.
- **Collector** (`scripts/Export-AdcsEstate.ps1`, v0.6.0): read-only PowerShell
  export of CA config, templates (with DACLs + owner), PKI-object ACLs, IIS
  enrollment endpoints, issuance OIDs, and opt-in ESC10/ESC14 DC mapping passes.
- **Collector/core version-compat check**: warns at ingest when a collector
  predates the minimum (`0.6.0`) so a stale export cannot read as silently clean.
- **Threat-model ↔ detector traceability test**: AST-locks the design spine so no
  ESC class or hygiene row can drift undetected.

### Stability contracts (from 1.0.0)
- **Diff identity** is `(check, subject, source)`. `source` is load-bearing and
  **stable public API**: a cosmetic edit to a detector's `source` string is a
  breaking change that produces a false regression+resolved pair on the next
  `diff`. The `test_diff_identity_contract_is_check_subject_source` test pins it.
- **JSON envelope** `schema_version` is `2`. The catalogue of `check` identifiers
  is locked by `test_catalogue_matches_every_check_literal_in_detection`.

### Known limitations
- **No nested-group expansion.** ACL-gated detectors (ESC1–ESC5, ESC7, ESC9,
  ESC13, ESC15) match the ACE trustee SID directly; a Deny on a group containing
  the requester, or rights held via group membership, are not modeled. Surfaced
  as an estate-level coverage note (`ACL_GROUP_TOKEN_CAVEAT`) — a "no finding" is
  not proof of no path.
- **`ca_patch_state` is always `unknown`.** The collector cannot yet read the CA
  build/patch level for CVE-2024-49019, so ESC15 caps at **MEDIUM** (with a
  "confirm patch state" caveat) on every real estate rather than asserting HIGH.
- **ESC12 is out of scope.** No statically-detectable enabling configuration has
  been identified in canonical tooling or research; the number is preserved for
  catalogue continuity and tracked as `Out (unresolved)`.
- **Collector v0.6.0 CA `owner_sid` capture is not live-validated.** It is
  Pester-unit-tested and correct by inspection; the ESC7 owner-based finding
  should be treated as unconfirmed until the next live collector run.
- **ESC9 EKU / DC-enforcement gates deliberately omitted.** ESC9 gates on
  low-priv enrollability + no manager approval (the false-negative-safe subset);
  the client-auth-EKU and binding-enforcement questions are tracked, not silent.

### Read-only / defensive boundary
adcs-lens never authenticates to, enrolls against, writes to, or relays through
live AD CS. It detects the *enabling configuration* of a weakness statically and
never performs the attack to confirm it. ESC8/ESC11/ESC15 report the prerequisite
and state that exploitability is not confirmed.
