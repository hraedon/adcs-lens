# adcs-lens

Local-first, **read-only** Active Directory Certificate Services (AD CS) posture
analysis. Ingests *copies* of a CA + PKI configuration export (it never touches
or authenticates to live AD CS) and answers questions about its hygiene,
misconfiguration, and certificate lifecycle. The deterministic core has **no AI
in the truth path** — the LLM layer only narrates facts the core already
computed.

## Why this exists

Microsoft effectively froze AD CS over a decade ago. The misconfigurations are
correspondingly decade-deep, and nobody puts energy into a CA until an audit or
an incident forces it. The tooling that *does* exist for this surface —
Certipy, Certify — is built to **exploit** it: it authenticates, requests
certificates, and relays, and it produces output for an attacker, not an
auditor.

There is a real, open gap on the **defensive, read-only, evidence-producing**
side, and it is sharpest for the organizations least able to fill it: small,
regulated shops with a legacy on-prem CA, no PKI specialist, and a hard
constraint against shipping their CA configuration to a vendor cloud. That is
the org adcs-lens is for.

## The line vs. cert-watch

cert-watch and adcs-lens both touch certificates but answer different
questions. The dividing principle is **access, not subject**:

- **adcs-lens** — anything answerable from a **read-only export**, point-in-time
  or diffed over time: PKI posture (CA config, templates, enrollment
  permissions, ACLs) and the *point-in-time* state of infrastructure cert/CRL
  lifecycle. Air-gappable; holds no standing access; never alerts.
- **cert-watch** — anything needing **standing live access or push alerting**:
  continuous freshness/reachability of certs and CRLs, alerting before a
  deadline. For certs chaining to a **private trust**, reading the CRL and
  flagging misconfigurations is part of cert-watch's *default* scan workflow —
  the live half of this split.

So a CA / CRL-signing cert's *expiry as of an export* is an adcs-lens finding;
the *continuous watch that alerts you 7 days before* it expires is cert-watch's.
The two compose: adcs-lens discovers PKI structure (including CAs with no serving
leaf cert); cert-watch watches the live deadlines. adcs-lens does **not** acquire
live-touch to do drift — drift comes from diffing scheduled read-only exports (a
later plan), never from a standing connection.

## Scope

**In scope (v0.x core):**
- **CA configuration** — `EDITF_*` policy flags, `IF_*` interface flags, CA role
  permissions, audit configuration (ESC6 / ESC7 / ESC11 surface).
- **Certificate templates** — `msPKI-*` enrollment/name flags, EKUs,
  requester-supplied-SAN, security-extension settings, issuance-policy links
  (ESC1 / ESC2 / ESC3 / ESC9 / ESC13 / ESC15 surface).
- **PKI object ACLs** — `nTSecurityDescriptor` on templates and the Public Key
  Services containers, NTAuth, enrollment services (ESC4 / ESC5 surface).
- **Infrastructure cert lifecycle** — root/sub-CA cert expiry, CRL signing cert
  expiry, CRL freshness and CDP/AIA reachability *as declared in config*.

**Later module:**
- Per-host certificate-store inventory across the estate (a much larger
  read-only acquisition problem; deferred deliberately).

**Out of scope (non-goals):**
- **Any active probing or exploitation.** adcs-lens never authenticates,
  enrolls, requests a certificate, or relays. It reads exported configuration
  and flags the *condition that enables* a weakness — it never demonstrates the
  weakness. (See `docs/threat-model.md` for which ESC classes are statically
  detectable and which inherently require active testing we will not do.)
- **Endpoint TLS lifecycle** — cert-watch's job.
- **Live-touch / standing access / alerting.** adcs-lens never holds a live
  connection to AD CS and never alerts. Change detection comes from diffing
  *scheduled read-only exports* (Stance 2, a later plan), not from monitoring.
  Anything that genuinely needs standing access or push alerting — e.g.
  continuous private-trust CRL freshness — belongs to cert-watch.
- **Remediation execution.** adcs-lens describes and prioritizes; it does not
  change CA configuration.

## Design principles

- **Deterministic core.** No AI in the truth path. Parse, normalize, query — all
  pure and verifiable.
- **Read-only, never live.** Input is file copies of an export. No code
  authenticates to or writes to AD CS.
- **Flag, don't probe.** Detect enabling configuration statically; never perform
  the attack to confirm it. This is the defensive boundary that separates
  adcs-lens from offensive PKI tooling.
- **Zero runtime dependencies in the core.** Stdlib-only (`json`, `sqlite3`,
  `xml`/registry-export parsing, `argparse`) so the core is portable and
  air-gappable. Narration and any web UI are optional extras.
- **Evidence-producing.** The output is an artifact an auditor or manager can
  read — findings prioritized by severity, each traceable to a source fact.

## Intended workflow (not yet built — see `plans/`)

```powershell
# On the CA / a tier-0 admin box, export the PKI config (read-only):
scripts/Export-AdcsEstate.ps1 -OutputDir C:\AdcsExport
```

```bash
# Copy the export to your analysis machine, then:
adcs-lens ingest C:\AdcsExport
adcs-lens doctor C:\AdcsExport            # prioritized posture + lifecycle findings
adcs-lens doctor C:\AdcsExport --json     # stable JSON envelope
```

> Status: the deterministic core is built and tested (ingest → `doctor`) with
> **ESC1**, **ESC2**, **ESC3**, **ESC4**, **ESC5**, **ESC6**, **ESC7**, **ESC8**,
> **ESC9**, **ESC10**, **ESC11**, **ESC13**, **ESC14** and infrastructure
> cert/CRL-expiry detectors. Per-template ACL-gap detection
> (`TEMPLATE_ACL_UNREADABLE`) is also built.
> The read-only PowerShell **collector** (`scripts/Export-AdcsEstate.ps1`) is
> built and validated end-to-end against a live enterprise CA — including the
> PKI-object ACL pass (NTAuth / AIA / CDP / PKS containers + CA objects) that
> backs ESC5 and the IIS enrollment-endpoint pass (Web Enrollment / CES bindings,
> Windows-auth, Extended Protection) that backs ESC8. The synthetic fixture
> generator (`tests/fixtures/build_fixture.py`) exercises the full pipeline
> end-to-end. The **ESC10 / ESC14** detectors (DC certificate-mapping) are built
> and tested, but their collector passes (`esc10-dc-registry`,
> `esc14-altsecid`) are not wired yet — until then they degrade to a note rather
> than firing positively. ESC15 is still planned (see open work items).

## Status

Core built (Plan 001 Phases 0, 1, 2, 3) with ESC1/2/3/4/5/6/7/8/9/10/11/13/14
detectors and infrastructure cert/CRL-expiry checks. The collector is validated
against a live enterprise CA. Remaining: the ESC10/ESC14 collector passes (the
detectors exist; the DC-registry and altSecurityIdentities collection passes are
not wired yet) and ESC15 (EKUwu).
Foundational docs:
- [`docs/threat-model.md`](docs/threat-model.md) — the ESC + hygiene catalogue
  with the static-detectability boundary. **Start here.**
- [`AGENTS.md`](AGENTS.md) — conventions and hard rules.
- [`plans/001-data-model-and-collector.md`](plans/001-data-model-and-collector.md)
  — the plan this core implements.
