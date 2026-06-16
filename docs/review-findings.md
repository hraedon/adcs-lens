# Open review findings / known gaps

Tracked items from the 2026-06-16 independent security-correctness review of the
detection path. Resolved items are dropped from this list.

## [HIGH] ESC4 misses blanket `WriteProperty` on templates

`_DANGEROUS_TEMPLATE_CONTROL` (detection.py) excludes `WriteProperty` to avoid
false positives from property-scoped ACEs. But a **blanket** WriteProperty (ACE
`ObjectType` = zero GUID = "all properties") lets a principal rewrite
`msPKI-Certificate-Name-Flag` to enable `ENROLLEE_SUPPLIES_SUBJECT` — a real ESC4
→ ESC1 path that currently goes unflagged.

**Fix needs all three layers + lab validation:** the collector (`_parseAces`)
must distinguish blanket vs property-scoped WriteProperty (it currently drops the
non-ExtendedRight `ObjectType`); the ACE model must carry that distinction; ESC4
then flags blanket WriteProperty/GenericWrite to low-priv. Validate by granting a
test template blanket WriteProperty to Domain Users (see
`reference-adcs-lens-collector-access` create-template procedure).

## [MEDIUM] No per-template signal when a template's DACL was unreadable

Estate-level degradation works (`template-security` in `skipped_passes` → ESC1
emits `TEMPLATE_ACL_NOT_EVALUATED`). But if the pass *ran* and a single template's
`nTSecurityDescriptor` came back empty/unreadable (LDAP denial, corrupt SD),
`template.security` is `()` and the template silently passes — indistinguishable
from a safe one. Needs a per-template "ACL requested but not obtained" marker in
the collector + model so detectors can note it.

## [LOW] ESC1/2/3 do not consider `published_by`

Detectors flag templates regardless of whether any CA actually offers them.
Deliberate for now — an unpublished-but-vulnerable template is a latent risk
(could be published; ESC4-style control could publish it), and the "flag, don't
probe" stance favors surfacing it. Consider *noting* publication status in the
finding detail to improve signal, rather than suppressing.

## [LOW] Deny-ACE precedence not evaluated

`_low_priv_allow_aces` counts an Allow/Enroll even if the same trustee has a
matching Deny/Enroll (Windows evaluates Deny first, so they cannot enroll). Rare
in practice; a theoretical false positive. Would need per-(trustee, right) Deny
cross-referencing.
