# Open review findings / known gaps

Tracked items from the 2026-06-16 independent security-correctness review of the
detection path. Resolved items are dropped from this list.

## [RESOLVED] ESC4 misses blanket `WriteProperty` on templates

Fixed in PR #9: `_DANGEROUS_TEMPLATE_CONTROL` now includes `writepropertyall`
(blanket WriteProperty). Collector emits `WritePropertyAll` for zero-GUID
ObjectType on WriteProperty ACEs.

## [RESOLVED] No per-template signal when a template's DACL was unreadable

Fixed in PR #10: `CertTemplate.acl_obtained` field + `detect_template_acl_gaps`
detector + collector `acl_obtained` marker. ESC1/2/3/4/13 skip templates where
`acl_obtained` is False; `TEMPLATE_ACL_UNREADABLE` notes the gap.

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
