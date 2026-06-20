# Publication review

**Status:** private repository; public flip gated on this review.

## Sanitization rule

No work-domain identifiers may appear in any committed file. All committed
examples, fixtures, tests, plans, and documentation must use synthetic
placeholders:

- Domain names: use `lab.example.com` or another reserved/example domain.
- CA names: use `LAB Root CA`, `LAB Issuing CA`, etc.
- Computer names: use `LABCA01` or similar.
- SIDs: use synthetically constructed values (e.g.
  `S-1-5-21-1111111111-2222222222-3333333333-513`).
- OIDs: use arcs under the Microsoft enterprise OID space or otherwise clearly
  synthetic sub-arcs.
- Real exports, if produced, live in the gitignored `samples/` directory and
  are never committed.

## Pre-publication checklist

- [x] No real CA names, domain names, SIDs, OIDs, or template names in committed
      source, tests, fixtures, plans, or docs — **HEAD only** (working tree).
      Sanitized 2026-06-20: the real issuing-CA common name leaked into two
      committed session reflections; replaced with the `ad-LABCA01` placeholder
      in the working tree. Re-verify before any flip by grepping all tracked
      files for the internal CA hostname / common-name / AD-domain tokens (do
      not hardcode them here) — only the intentional `hraedon` GitHub identity
      should remain.
- [ ] **Git history clean.** The 2026-06-16 `filter-repo` + repo-recreate scrub
      caught the CA *hostname* and AD *domain* but missed the CA *common name*,
      which two reflections committed *after* the scrub then re-introduced. The
      2026-06-20 fix above only cleans HEAD; the token still lives in history.
      **Blocks the public flip** — needs another `filter-repo` pass (and, since
      the repo was already pushed, the delete+recreate remedy) before going
      public. Tracked as a work item (WI-010).
- [x] `.gitignore` rejects `samples/` and local environment artifacts.
- [x] CI is green on Python 3.12 and 3.13.
- [x] Architecture guard (`tests/test_architecture.py`) passes.

> Note: the `hraedon` GitHub handle/author name in `pyproject.toml` and project
> URLs is the public repo identity and is intentionally retained — only internal
> infrastructure identifiers (CA hostnames, AD domain, topology) are scrubbed.
