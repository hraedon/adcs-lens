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

- [ ] No real CA names, domain names, SIDs, OIDs, or template names in committed
      source, tests, fixtures, plans, or docs.
- [ ] `.gitignore` rejects `samples/` and local environment artifacts.
- [ ] CI is green on Python 3.12 and 3.13.
- [ ] Architecture guard (`tests/test_architecture.py`) passes.
