# AGENTS.md

Conventions and quick reference for agents (and humans) working on adcs-lens.

## What this is

Local-first, **read-only** AD CS / PKI posture analysis. The tool ingests
*copies* of a CA + PKI configuration export and answers questions about its
hygiene, misconfiguration (the ESC classes), and infrastructure certificate
lifecycle. It never authenticates to, enrolls against, or writes to live AD CS.
The deterministic core has **no AI in the truth path** — the LLM layer only
narrates facts the core computed. See `README.md` for the full charter.

## Orient

1. **Read the threat model.** `docs/threat-model.md` — the ESC + hygiene
   catalogue with the static-detectability boundary. This is the design spine:
   it dictates what the collector captures and what the tool is allowed to claim.
2. **Read the model** (once it exists). The normalized data model + the
   dataclasses will be the concrete contract, mapped against a real export.
3. **Validate against reality.** Tests encode measured numbers from a real,
   gitignored export; synthetic fixtures cover the structural cases for CI.

## Hard rules

- **Read-only, never live.** No code authenticates to, enrolls against, or
  writes to AD CS. Input is exported files only. **No standing connection and no
  alerting** — change detection comes from diffing scheduled read-only exports
  (Stance 2, the `diff` command), not monitoring. Live/continuous concerns are
  cert-watch's (see Boundary).
- **Flag, don't probe.** Detect the *enabling configuration* of a weakness
  statically; never perform the attack (enroll, relay, request) to confirm it.
  An ESC8/ESC11/ESC15 finding reports the prerequisite and says exploitability
  is not confirmed. This is the line between adcs-lens and offensive tooling.
- **No AI in the deterministic core.** Detection and lifecycle checks run with
  zero model calls. Narration is an optional layer that imports the core, never
  the reverse (enforce with an architecture test).
- **Defensive output only.** Findings are framed for remediation and evidence,
  not exploitation. No payloads, no relay tooling, no request crafting.
- **No work-domain identifiers in committed files.** Docs, reflections, and
  fixtures use placeholders (e.g. `WORK-DOMAIN.local`, `LABCA`). Real exports
  live in a gitignored `samples/` and must never be committed.
- **Fixture data is synthetic.** No real CA names, template names, OIDs, SIDs,
  or domain names in committed test files.
- **Stdlib-only core.** Keep the truth path dependency-free
  (`json`, `sqlite3`, `argparse`, stdlib parsing) so it stays portable and
  air-gappable. Narration / web are optional extras.

## Build / test / lint (intended — mirrors the sibling projects)

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q            # unit + fixture tests (sample tests skip if samples/ absent)
.venv/bin/pytest -q -m samples # calibration against a real export (needs samples/)
.venv/bin/ruff check .
.venv/bin/mypy src
```

## Collector

`scripts/Export-AdcsEstate.ps1` (to be built) produces the inputs: read-only
PowerShell run on the CA / a tier-0 admin box, using `certutil -getreg`, the AD
CS PowerShell module, and LDAP reads against the Configuration NC. See the
"Implications for the data model & collector" section of `docs/threat-model.md`
for exactly what it must capture — and what it must not (no enrollment, no
request).

## Boundary with cert-watch

The dividing principle is **access, not subject**: anything answerable from a
**read-only export** (point-in-time or diffed over time) is adcs-lens; anything
needing **standing live access or push alerting** is cert-watch. So
infrastructure cert/CRL *expiry as of an export* is an adcs-lens finding, but
*continuous* CRL freshness for private-trust certs is cert-watch's default scan
workflow (cert-watch WI-042). The two compose — adcs-lens discovers PKI
structure (incl. CAs with no serving leaf), cert-watch watches the live
deadlines. Drift detection in adcs-lens comes from diffing scheduled read-only
exports (WI-001), never from a standing connection.

## Status

The deterministic core is built and tested (ingest → `doctor` → `diff`, ESC1 + ESC2 +
ESC3 + ESC4 + ESC5 + ESC6 + ESC7 + ESC8 + ESC9 + ESC11 + ESC13 + infra lifecycle
detectors, architecture guard), plus a per-template unreadable-DACL signal
(`TEMPLATE_ACL_UNREADABLE`). The read-only PowerShell collector
(`scripts/Export-AdcsEstate.ps1`) captures CA config, templates (with their
DACLs → ACEs, and an `acl_obtained` marker), CA role security
(`CA\Security` → ESC7), PKI-object ACLs (NTAuth / AIA / CDP / PKS containers +
CA objects → ESC5), IIS enrollment endpoints (Web Enrollment / CES bindings +
Windows-auth + Extended Protection → ESC8), issuance OIDs, and the opt-in
ESC10/ESC14 DC certificate-mapping passes (`-CollectDcMapping`: `esc14-altsecid`
LDAP read of principal altSecurityIdentities + `esc10-dc-registry` per-DC KDC
StrongCertificateBindingEnforcement and Schannel CertificateMappingMethods via
WMI StdRegProv with explicit creds); validated end-to-end against a live
enterprise CA. ESC15 (EKUwu / CVE-2024-49019) flags schema v1 templates a low-priv
principal can enroll in (the requester injects application policies on an unpatched
CA) — reuses existing collector data (schema_version + enroll ACL), no new pass.
The full statically-detectable ESC family is now built. ESC5 is
negative-validated on the real CA with positive validation via the synthetic
fixture; ESC8/ESC10/ESC11/ESC13/ESC14 are **positive-validated on the real lab**
(ESC8 live `/certsrv` HTTP+NTLM+no-EPA → HIGH; ESC10 via a temporary Schannel UPN
bit + disabled binding on a DC; ESC11 via a temporarily-cleared
IF_ENFORCEENCRYPTICERTREQUEST; ESC13 via a temporary AMA OID→universal-security-group
link on a v1 template; ESC14 via a temporary weak altSecurityIdentities — all
reverted with cleanup discipline). The ESC13 validation caught a collector bug: it
read the OID→group link from the non-existent `msPKI-OIDToGroupLink` instead of
`msDS-OIDToGroupLink` (a group DN), so ESC13 was a permanent false negative.

The collector's OS-independent helpers (bit decoders, certutil parsers, IIS
classifiers) are unit-tested with Pester via `-FunctionsOnly` (CI `collector-helpers`
job on pwsh); the Windows-only collection paths stay out of scope (WI-009).
