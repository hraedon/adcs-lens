# Plan 002 — Honest precision, the value layer, then public release

**Status:** Proposed 2026-06-30.
**Author:** Opus 4.8 (forward plan after the ESC1–15 + value-delivery cycle)
**Strategic role:** The statically-detectable ESC family (ESC1–11, 13–15) and
the value-delivery layer (consequences catalogue, SARIF, HTML report,
threat-model traceability guard) are built and green (297 tests, ruff +
mypy --strict). The next milestone is **not breadth — it is trust and reach.**
Trust: close the precision gaps that let the tool produce *false positives on a
healthy estate* (the trust contract's other edge) and finish the family-
completeness story honestly (ESC16). Reach: ship the narration layer that makes
findings legible to the no-PKI-specialist persona, and then publish. Public
release (WI-024) is **gated on the honesty work** so the "full ESC family" claim
never overclaims at the moment of widest exposure.

## Ground truth at time of writing

- `main` green; deterministic stdlib-only core intact; architecture guard +
  threat-model traceability test in place. ESC12 is honestly `Out (unresolved)`;
  ESC16 is honestly `Static (not yet implemented)`.
- Open work items in the regista store (`adcs_lens`), grouped:
  - **Precision / honesty (protect the trust contract both directions):**
    - **WI-027** — `detect_esc15` flags *every* schema-v1 enrollable template
      HIGH regardless of CA patch state for CVE-2024-49019; collector never
      captures CA build/patch level → false positives on a patched CA.
    - **WI-016** — template weak-key detector applies the 2048-bit RSA baseline
      to every template regardless of CSP/algorithm → ECDSA false positive.
    - **WI-036** — ESC16 detector (CA-wide security-extension disable via
      `disabled_extensions` containing `1.3.6.1.4.1.311.25.2`) missing; the
      catalogue marks it `Static (not yet implemented)`.
    - **WI-031** — ESC4/ESC5 completeness: owner-based control + property-scoped
      WriteProperty not modeled (gap documented at `detection.py:494`).
  - **Value delivery (reach the target persona):**
    - **WI-021** — narration layer: plain-English executive summary +
      prioritized remediation from `run_all`, grounded in the consequences
      catalogue, behind a strict architecture boundary.
    - **WI-022** — findings suppression / risk-acceptance for scheduled scans
      (pairs with the Stance-2 `diff --exit-code` workflow).
  - **Housekeeping / polish:** WI-019 (collector/core version-compat check at
    ingest), WI-025 (`Estate.validity` collected but read by no detector —
    dead data), WI-033 (group-token expansion caveat not surfaced in `doctor`
    output), WI-034 (deferred hygiene rows CDP/AIA + orphaned templates have no
    tracking WI), WI-032/WI-035 (SARIF artifactLocation, HTML TOC, diff
    SARIF/HTML, ESC8 EPA allow/none, esc7 sid-key normalization).
  - **Release:** **WI-024** — packaging & public release.

## Principles this plan must hold

- **No false all-clears, and no false alarms.** This milestone's spine is the
  trust contract from the *false-positive* side: a tool that cries ESC15/weak-
  key on a healthy estate trains operators to ignore it. Precision is honesty.
- **No AI in the truth path.** WI-021's narration imports the core and reads
  only computed findings + the consequences catalogue; the architecture guard
  must extend to forbid the reverse import. Narration never recomputes or
  re-judges a finding.
- **Flag, don't probe.** Unchanged. Every new field is read from a read-only
  export; no new collector pass authenticates, enrolls, or requests.
- **Threat-model is the spine.** Each detector change flips its catalogue verdict
  and stays inside the traceability + contiguity guards.

---

## Phase 1 — Detection honesty & precision

The highest-trust-value work. WI-027 and WI-016 kill false positives; WI-036
closes the family-completeness claim; WI-031 closes a documented detection gap.
WI-027 and WI-036 need a collector field; both are read-only.

### WI-036 — ESC16 detector (closes the "full family" claim)
- Collector: capture the CA's `disabled_extensions` (read-only `certutil -getreg`
  on the CA's policy module — already the collector's idiom). Model: a field on
  `CertAuthority`. Detector: `detect_esc16` flagging when `disabled_extensions`
  contains `1.3.6.1.4.1.311.25.2` (szOID_NTDS_CA_SECURITY_EXT) — a CA-wide
  weakening that mirrors ESC9 at the CA level. Flip the catalogue verdict from
  `Static (not yet implemented)` → `Static`; the traceability guard then
  requires the detector to exist.
- **AC:** synthetic fixture (CA with the OID disabled) → ESC16 finding; clean CA
  → none. Consequences-catalogue entry added. Live negative-validate on the lab
  CA; positive-validate on a synthetic estate (reverting any live mutation per
  the project's discipline — but prefer synthetic for a CA-wide reg change).

### WI-027 — ESC15 patch-state awareness (kills false positives)
- Collector: capture CA build / patch level (the registry/`certutil` signal that
  indicates the May-2024 CVE-2024-49019 fix). Model field. Detector: `detect_esc15`
  reports HIGH only when the CA is *not* known-patched; on a known-patched CA,
  downgrade to INFO/coverage-note (or suppress), since the requester-supplied
  application-policy injection is fixed. Where patch state is unknown, the
  honest output says so rather than asserting HIGH.
- **AC:** synthetic fixtures for patched / unpatched / unknown CA produce
  HIGH / suppressed-or-INFO / explicitly-unknown respectively; the existing
  ESC15 tests are updated; the threat-model row notes the patch-state dependency.

### WI-016 — Algorithm-aware template weak-key detector
- `detect_weak_key_size` template branch: read the template's CSP/algorithm and
  apply the algorithm-appropriate baseline (RSA 2048, ECDSA P-256 ≈ 256-bit),
  so an ECDSA-only template's legitimate `msPKI-Minimal-Key-Size` is not flagged
  against the RSA bar.
- **AC:** an ECDSA P-256 template no longer fires `WEAK_TEMPLATE_KEY_SIZE`; a
  genuine RSA-1024 template still does; an unknown-algorithm template degrades
  to an explicit coverage note, not a false HIGH.

### WI-031 — ESC4/ESC5 owner-based control + property-scoped WriteProperty
- Close the two gaps documented at `detection.py:494`: (a) a principal that
  *owns* a template or PKI object can rewrite its DACL → an ESC4/ESC5 path even
  with no control ACE; (b) WriteProperty scoped to the security-relevant
  property sets. Reuse the existing ACE/owner data the collector already emits.
- **AC:** synthetic fixtures for an owner-only-control template and a property-
  scoped WriteProperty ACE both fire; the `detection.py:494` comment is removed
  (gap closed, not just noted).

---

## Phase 2 — Value delivery for the no-specialist persona

The flagship differentiator: a regulated shop without a PKI expert gets a
plain-English answer, not a SARIF dump.

### WI-021 — Narration layer (optional AI, strict boundary)
- A `narration` extra (already stubbed in `pyproject.toml` per Plan 001) that
  imports the core, takes `run_all()` findings + the consequences catalogue, and
  produces an executive summary + prioritized remediation plan. Default models:
  the latest Claude family per the workspace standard. The narration **never**
  recomputes a finding — it only renders ones the deterministic core produced.
- Extend the architecture guard so `adcs_lens.narration` may import the core but
  nothing in the core may import `narration` (and the core stays import-clean of
  any LLM SDK).
- **AC:** with the extra installed and a key present, `doctor --narrate` (or
  similar) emits a grounded summary; with no key/extra, the core path is
  unaffected and tests pass with zero model calls. An architecture test fails if
  the core imports narration or an LLM SDK. The narration is verified to cite
  only findings present in the deterministic output (no invented findings).

### WI-022 — Findings suppression / risk-acceptance
- A `--suppress` file (or `suppressions.yaml` in the export dir) keyed by
  `(check, subject, reason, expiry)` so a risk-accepted finding stops tripping
  `diff --exit-code` while staying *visible* (reported as suppressed, never
  silently dropped). Pairs with the scheduled-scan / Stance-2 workflow.
- **AC:** a suppressed finding is excluded from the `--exit-code` gate but still
  printed as `suppressed (reason, expires …)`; an expired suppression re-arms;
  the suppression file format is documented and synthetic-tested.

---

## Phase 3 — Housekeeping & output polish

Low-severity drift and precision items; batch into one or two PRs.

- **WI-019** — version-compat check at ingest: compare the manifest's
  `collector_version` against a core-declared minimum and warn (not fail) on a
  stale collector that may omit fields. AC: a below-minimum manifest emits a
  visible warning; current version is silent.
- **WI-025** — `Estate.validity` (`model.py:211`): either give it a detector
  (CA cert-validity-vs-lifetime hygiene) or drop it from the model. AC: no
  collected-for-nothing field remains — decision recorded either way.
- **WI-033** — surface the group-token-expansion caveat in `doctor` output (a
  Deny on a group containing the requester is not modeled — today only a code
  comment). AC: the caveat appears as an output coverage note, not just in
  source.
- **WI-034** — file/track the deferred hygiene rows (CDP/AIA reachability,
  orphaned templates) so `HYGIENE_STATUS=None` entries map to a real WI. AC:
  both deferred rows reference a tracking WI; the traceability test asserts no
  silently-deferred row.
- **WI-032 / WI-035** — output polish bundle: SARIF `artifactLocation`/region
  for GitHub Code Scanning, HTML TOC, diff `--sarif`/`--html`, ESC8 EPA
  allow/none distinction, `detect_esc7` `by_trustee` keyed on the normalized SID
  (`detection.py:646`). AC: per-item, with synthetic coverage.

---

## Phase 4 — Public release (gated on Phase 1)

### WI-024 — Packaging & public release
- Pre-flight (the soft blockers): Phase 1 makes the "full ESC family" claim
  honest (ESC16 implemented, ESC12 documented-out, ESC15 patch-aware), so the
  README/threat-model claims no longer overclaim at the moment of widest
  exposure. Set the `ADCS_LENS_FORBIDDEN_IDENTIFIERS` repo secret so the
  leak-guard identifier scan is active before the repo is public; verify git
  history is clean of work-domain identifiers (the gpo-lens / acme history-scrub
  lesson: a pushed pull-ref survives force-push — recreate, don't just rewrite,
  if anything leaked); confirm the synthetic fixtures carry no real CA/template/
  OID/SID/domain. Then publish under the real name + MIT, matching the sibling
  repos.
- **AC:** identifier gate active and green; history verified clean (or
  recreated); README claims match implemented detectors; repo public.

---

## Sequencing & notes

- **Phase 1 first and in order of trust-value:** WI-027 (live false positives on
  patched CAs is the most active harm) → WI-036 (completeness claim) → WI-016 →
  WI-031. Each is a guarded, synthetic-testable change; WI-027/WI-036 add a
  collector field, so re-run the collector self-tests (Pester `-FunctionsOnly`).
- **Phase 2 is the reach lever** but carries the only AI in the project —
  guard the boundary hard before writing a line of narration.
- **Phase 4 is gated on Phase 1**, not on Phase 2/3: the tool can go public as a
  deterministic analyzer with narration following, but it must not go public
  while the family-completeness claim is dishonest.
- **DECIDED 2026-06-30 (user): publish after Phase 1**, as a deterministic
  analyzer, with narration (Phase 2) following in the open. Honesty is the only
  hard release gate; narration strengthens reach but isn't a blocker, and
  shipping earlier builds the engagement corpus sooner. So the effective order
  is Phase 1 → Phase 4 (release) → Phase 2 → Phase 3.
- Out of scope: any standing/live access or alerting (that boundary belongs to
  cert-watch); ESC12 detector (no static-detectability boundary exists — stays
  `Out (unresolved)` until canonical tooling defines one).
