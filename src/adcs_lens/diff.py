"""Drift detection over two read-only snapshots (Stance 2).

Pure, stdlib-only. Diffs the *findings* run_all produces for an older and a newer
export and reports what changed: regressions (new findings), fixes (resolved
findings), and severity changes on the same issue. This is the air-gap-preserving
"what got worse since the last scan" signal — no live access, just two exports.

A finding's drift identity is ``(check, subject)`` — the same check on the same CA
/ template / object. A severity change on that pair is a "changed" finding, not a
new-and-resolved pair. Content changes (different title, detail, or source) with
an unchanged severity are also reported as "changed" but do not count as
regressions.
"""

from __future__ import annotations

from dataclasses import dataclass

from adcs_lens.detection import Finding
from adcs_lens.model import SEVERITY_RANK


def _key(f: Finding) -> tuple[str, str]:
    return (f.check, f.subject)


def _worst_first(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.check, f.subject))


@dataclass(frozen=True)
class FindingDelta:
    """A finding that drifted between snapshots (same check + subject).

    The change can be a severity shift, a content shift (title/detail/source),
    or both. ``content_changed`` is true only when severity stayed the same but
    the explanatory fields changed.
    """

    old: Finding
    new: Finding

    @property
    def worsened(self) -> bool:
        # Lower rank == worse, so a smaller rank in `new` means it got worse.
        return SEVERITY_RANK[self.new.severity] < SEVERITY_RANK[self.old.severity]

    @property
    def content_changed(self) -> bool:
        """True when severity is unchanged but title, detail, or source differ."""
        if self.old.severity != self.new.severity:
            return False
        return (
            self.old.title,
            self.old.detail,
            self.old.source,
        ) != (
            self.new.title,
            self.new.detail,
            self.new.source,
        )


@dataclass(frozen=True)
class DriftReport:
    """The diff between an older and a newer posture snapshot."""

    new: tuple[Finding, ...]  # regressions: present now, absent before
    resolved: tuple[Finding, ...]  # fixes: present before, absent now
    changed: tuple[FindingDelta, ...]  # same (check, subject), different severity or content
    unchanged: int  # count of findings identical across both

    @property
    def regressions(self) -> bool:
        """True when posture got worse: a new finding or a worsened severity.

        Content-only changes (same severity, changed detail/title/source) are
        reported in ``changed`` but do not make this True.
        """
        return bool(self.new) or any(d.worsened for d in self.changed)


def diff_findings(old: list[Finding], new: list[Finding]) -> DriftReport:
    """Compute the drift between two finding sets, keyed by ``(check, subject)``."""
    old_by = {_key(f): f for f in old}
    new_by = {_key(f): f for f in new}

    added = [f for k, f in new_by.items() if k not in old_by]
    resolved = [f for k, f in old_by.items() if k not in new_by]
    changed: list[FindingDelta] = []
    unchanged = 0
    for k, nf in new_by.items():
        of = old_by.get(k)
        if of is None:
            continue
        delta = FindingDelta(old=of, new=nf)
        # Any severity difference (worse or better) is a change; otherwise a
        # content change (same severity, different title/detail/source) is.
        # content_changed is False when severity differs, so the disjunction is
        # exact and the tuple comparison lives in one place.
        if of.severity != nf.severity or delta.content_changed:
            changed.append(delta)
        else:
            unchanged += 1

    return DriftReport(
        new=tuple(_worst_first(added)),
        resolved=tuple(_worst_first(resolved)),
        changed=tuple(sorted(changed, key=lambda d: (SEVERITY_RANK[d.new.severity], d.new.check))),
        unchanged=unchanged,
    )
