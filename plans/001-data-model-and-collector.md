# Plan 001 — Data model & collector

**Status:** proposed 2026-06-13
**Author:** Opus 4.8 (charter + threat-model derivation)
**Strategic role:** adcs-lens is charter-stage — `README.md`, `AGENTS.md`, and
`docs/threat-model.md` exist; there is no code. This plan turns the threat
model's detectability table into the two things every later detector depends on:
a **faithful read-only collector** and a **normalized data model** validated
against a real CA export. The lesson from gpo-lens is explicit here — *model
first, validate against reality, then detect.* The detectors are easy once the
export is trustworthy; the export is the hard part.

## Ground truth at time of writing

- No `pyproject.toml`, no package, no git, no CI. The project exists as three
  Markdown files under `/projects/adcs-lens/`.
- `docs/threat-model.md` is the contract: it enumerates every check and, per
  check, what a read-only export can detect statically. **The collector must
  capture exactly what that table's "data source" column names — and nothing
  that requires enrolling, requesting, or relaying.**
- A real CA export does not yet exist. Phase 1's collector produces the first
  one; it goes in a gitignored `samples/` and is never committed (the gpo-lens
  work-domain leak is the cautionary tale — see WI-0.4 below).

## Principles this plan must hold

- **Read-only, flag-don't-probe.** The collector uses `certutil -getreg`, the
  AD CS PowerShell module, and LDAP reads of the Configuration NC. It never
  authenticates as an enrollee, never requests a cert, never touches an
  enrollment endpoint.
- **Deterministic, stdlib-only core.** `model`, `normalize`, `ingest`, `store`,
  `detection`, `display` import only the standard library. Narration/web are
  later, optional, and import the core — never the reverse.
- **Provenance in the export.** Every collection writes a manifest recording
  collector version, timestamp, host, domain, and *which gated passes were
  skipped*, so a finding can always be traced to what was (and wasn't) read.

---

## Phase 0 — Project infrastructure (before detectors)

Copy the *proven patterns* from cert-watch/gpo-lens, not their file trees
(stale breadcrumb dirs etc. are drift — see the project-initiation skill).

### WI-0.1 — Package skeleton + tooling
- `pyproject.toml`: stdlib-only core; extras `[dev]` (ruff, mypy, pytest),
  `[certs]` (cert/CRL parsing — see WI-2.2), `[narration]` (the LLM client,
  later), `[web]` (FastAPI, later). Console script
  `adcs-lens = adcs_lens.cli:main`.
- `src/adcs_lens/` with empty-but-typed `model.py`, `normalize.py`,
  `ingest.py`, `store.py`, `detection.py`, `display.py`, `cli/`.
- **AC:** `uv pip install -e ".[dev]"`, `ruff check .`, `mypy src` all clean on
  the skeleton.

### WI-0.2 — Git + remote + CI
- `git init`; **private** GitHub remote (public is gated on WI-0.4, learning
  from gpo-lens publishing before its sanitization review).
- CI: ruff + mypy --strict + pytest, pinned action SHAs, `permissions: contents:
  read` (cert-watch `ci.yml` is the template). Python 3.12 **and** 3.13 from day
  one (the cert-watch v0.6.5 local/CI version gap is on record).
- **AC:** CI green on first push; synthetic-fixture tests run without `samples/`.

### WI-0.3 — Synthetic fixtures + `samples/` discipline
- A `tests/fixtures/build_fixture.py` generator (gpo-lens learned hand-written
  XML is a time bomb — generate from declarative Python) emitting a fake export:
  one ESC6 CA, one ESC1-shaped template, one expiring CA cert, one over-broad
  template ACE. Emit at least one JSON file with a UTF-8 BOM (PowerShell 5.1).
- `samples/` gitignored; real exports never committed; sample-dependent tests
  carry a `samples` marker and skip when absent.
- **AC:** generated fixtures committed and checked by a regenerate-and-diff test;
  `.gitignore` survives a fresh clone.

### WI-0.4 — Sanitization rule (written, before any public flip)
- The export contains CA names, template names, OIDs, SIDs, domain. Decide in
  writing (`docs/publication-review.md`) what may appear in committed
  files (ranges/placeholders only) before the repo goes public. Add the rule to
  `AGENTS.md`.
- **AC:** decision note exists; no real CA/domain identifiers in any committed
  file.

---

## Phase 1 — The collector (`scripts/Export-AdcsEstate.ps1`)

Read-only PowerShell, run on the CA or a tier-0 admin box. Writes a directory of
JSON (+ raw certs/CRLs). One file per concern so ingest stays simple and a
partial collection is still useful.

| Output file | Contents | Threat-model rows |
|---|---|---|
| `collector-manifest.json` | version, timestamp, host, domain, collected/skipped passes | provenance |
| `ca-config.json` | `certutil -getreg` CA + policy hives: `EditFlags`, `InterfaceFlags`, `AuditFilter`, validity periods, CA identity | ESC6, ESC11, audit, lifecycle |
| `ca-security.json` | CA role permissions (ManageCA/ManageCertificates) as ACEs | ESC7 |
| `templates.json` | every `pKICertificateTemplate`: `msPKI-*` flags, EKUs, min key size, issuance policies, `nTSecurityDescriptor` | ESC1/2/3/4/9/13/15 |
| `enrollment-services.json` | `pKIEnrollmentService` objects: which CA publishes which templates | ESC1 enrollability, orphaned templates |
| `pki-acls.json` | `nTSecurityDescriptor` on Public Key Services containers, NTAuth, AIA, CDP | ESC5 |
| `oid-objects.json` | `msPKI-Enterprise-Oid` + `msDS-OIDToGroupLink` | ESC13 |
| `roles.json` | installed AD CS role services (Web Enrollment, CES/CEP) + IIS EPA state | ESC8 enabling-config |
| `certs/` | CA / sub-CA certs (DER) and current CRL(s) | lifecycle, weak alg/key |

- **Two-tier topology (the lab and the common SMB case).** The lab is an offline
  root (a separate box, kept offline) + an online issuing CA (`LABCA01`). The
  collector runs on the *issuing* CA and **cannot reach the offline root by
  design** — so it must
  capture the root cert and, critically, the **root CRL** from their *published*
  locations (the AIA/CDP URLs, the NTAuthCertificates / AIA containers in AD, and
  the issuing CA's own chain), not from the root host. The manifest records that
  the root was captured indirectly. This is what makes the catastrophic-but-
  invisible case detectable: a published root CRL that has expired invalidates
  the entire chain, and nobody is watching the box that signs it because it's
  powered off.
- **Gated passes** (widen the footprint; off by default, flagged in manifest
  when run): DC registry for ESC10 (`StrongCertificateBindingEnforcement`,
  `CertificateMappingMethods`) and principal `altSecurityIdentities` for ESC14.
- `-DryRun` lists what would be exported; `-OutputDir` required; least-privilege
  account documented (local admin on the CA for the registry hives; a domain
  read for the Config NC — no enroll right needed).
- **AC:** running against a real lab CA produces a complete directory; the
  manifest names every skipped gated pass; the script issues zero enrollment or
  cert-request operations (assert by review + a comment-level audit).

---

## Phase 2 — Normalized model + ingest

### WI-2.1 — Dataclasses (`model.py`) — the contract
```
CertAuthority(name, dns, config_string, kind, edit_flags: set[str],
              interface_flags: set[str], audit_filter, validity, roles: set[str],
              security: list[AceEntry], certs: list[CertLifecycle])
CertTemplate(name, display_name, schema_version, oid, ekus: list[str],
             name_flags: set[str], enrollment_flags: set[str], min_key_size,
             issuance_policy_oids: list[str], security: list[AceEntry],
             published_by: list[str])
AceEntry(trustee_sid, trustee_name, rights, ace_type)   # shared with gpo-lens concept
PkiObjectAcl(object_dn, kind, security: list[AceEntry])
IssuanceOid(oid, name, group_link_sid)
CertLifecycle(subject, kind, not_before, not_after, sig_alg, key_bits)
Crl(issuer, this_update, next_update)
Estate(cas, templates, acls, oids, crls, manifest)
```
- **AC:** dataclasses are frozen where possible; every field maps to a named
  collector output; mypy --strict clean.

### WI-2.2 — Ingest (`ingest.py`)
- Parse the collector directory → `Estate`. BOM-tolerant JSON (`utf-8-sig`).
- **Cert/CRL parsing lives behind the optional `[certs]` extra** (decided
  2026-06-13). The stdlib-only core never imports it; when the extra is absent,
  lifecycle fields are `None` and detectors degrade to "lifecycle not evaluated
  (install adcs-lens[certs])" and exit 0 — the same degrade-to-facts pattern as
  narration. This keeps the truth path pure and air-gappable.
- Canonical join keys: template by OID (fallback name), SIDs normalized.
- **AC:** the synthetic fixture round-trips to a fully-populated `Estate`;
  partial exports (missing a gated pass) ingest without error and mark the gap;
  with `[certs]` absent, ingest succeeds and lifecycle fields are `None`.

---

## Phase 3 — Two detectors to prove the model end-to-end

Not the full ESC suite — just enough to validate that the model + ingest carry
what detectors need, exercising both data paths (config and certs).

### WI-3.1 — ESC6 detector (config path)
- `EDITF_ATTRIBUTESUBJECTALTNAME2 in ca.edit_flags` → **critical** finding with
  the CA name and the exact registry source.
- **AC:** fixture ESC6 CA flagged critical; a clean CA produces nothing.

### WI-3.2 — Infrastructure cert-expiry detector (lifecycle path)
- CA, sub-CA, and CRL-signing certs within N days of `not_after` → severity by
  days remaining; expired → critical.
- **Offline-root cert and root CRL get explicit, top-severity treatment** (the
  two-tier case above): an expired or past-`next_update` **root CRL** → critical
  ("silent estate-wide auth failure"), and it is called out as root-tier because
  the signing box is offline and unmonitored. Issuing-CA CRL `next_update` in the
  past → critical likewise.
- **AC:** fixture expiring CA cert flagged; a fixture root CRL past `next_update`
  flagged critical and labelled root-tier; threshold flag works; absent `[certs]`
  extra degrades to a clear "lifecycle not evaluated" note, exit 0.

### WI-3.3 — `adcs-lens doctor` front door
- Compose 3.1 + 3.2 into a prioritized, severity-ordered report; `--json`
  everywhere (the future narration/report layers consume it).
- **AC:** `doctor` on the fixture prints both findings in severity order.

---

## Explicitly not in this plan

- **The full ESC1–ESC15 detector suite** — Plan 002, once the model is proven.
- **Per-host cert-store inventory** — deferred later module (charter scope).
- **Narration / web / report** — later, optional, import-bounded layers.
- **Any active validation of a finding** — permanently out (flag, don't probe).

## Sequencing

Phase 0 → 1 → 2 → 3 in order. The collector (Phase 1) is the critical path and
the highest-risk item: everything downstream is only as honest as the export.
Build the synthetic fixture (WI-0.3) *before* the real collector so ingest and
the two detectors can be developed and tested with zero access to a live CA, and
the real export (Phase 1 AC) becomes a calibration check rather than a blocker.

## Decisions

1. **Cert-parsing dependency** (WI-2.2) — **Resolved 2026-06-13:** core stays
   stdlib-only; cert/CRL parsing is an optional `[certs]` extra that degrades to
   "lifecycle not evaluated," exit 0.
2. **Lab CA** — **Resolved 2026-06-13:** `lab.example.com` lab has a two-tier
   PKI — a separate offline root (kept offline) + online issuing CA `LABCA01`
   (OCSP working; Web Enrollment `/certsrv/` not yet installed but installable).
   The Phase 1 collector targets `LABCA01`; the root cert + root CRL come from
   published locations (see the two-tier note in Phase 1). First real export and
   the root-CRL-expiry case both calibrate here. (`LABWAC01` was the CA earlier
   but the role moved to `LABCA01`; LABWAC01 now runs WAC.)
3. **Repo visibility** (still open) — recommend private now, public only after
   WI-0.4's sanitization review, mirroring the corrected gpo-lens posture.
