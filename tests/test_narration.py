"""Tests for the optional narration layer (WI-016)."""

from __future__ import annotations

from adcs_lens.consequences import consequence_for
from adcs_lens.detection import Finding
from adcs_lens.model import Severity
from adcs_lens.narration import (
    generate_executive_summary,
    generate_narrated_summary,
    summarize_posture,
)


def _f(
    check: str,
    severity: Severity,
    *,
    subject: str = "subj",
    title: str = "title",
    detail: str = "detail",
    source: str = "source",
) -> Finding:
    return Finding(
        check=check,
        severity=severity,
        title=title,
        subject=subject,
        detail=detail,
        source=source,
    )


def _sample_findings() -> list[Finding]:
    return [
        _f("ESC6", Severity.CRITICAL, subject="LABCA", title="CA honors requester-supplied SAN"),
        _f("ESC1", Severity.CRITICAL, subject="VulnTemplate"),
        _f("ESC8", Severity.HIGH, subject="WEBENROLL"),
        _f("WEAK_TEMPLATE_KEY_SIZE", Severity.MEDIUM, subject="SmallKeyTemplate"),
        _f("TEMPLATE_ACL_NOT_EVALUATED", Severity.INFO, subject="(estate)"),
        _f("PKI_ACL_NOT_EVALUATED", Severity.INFO, subject="(estate)"),
    ]


# --- summarize_posture ------------------------------------------------------


def test_summarize_posture_counts_and_risks() -> None:
    posture = summarize_posture(_sample_findings())
    assert posture["total"] == 6
    assert posture["actionable"] == 4

    by_severity = posture["by_severity"]
    assert isinstance(by_severity, dict)
    assert by_severity["critical"] == 2
    assert by_severity["high"] == 1
    assert by_severity["medium"] == 1
    assert by_severity["info"] == 2
    assert by_severity["low"] == 0

    top_risks = posture["top_risks"]
    assert isinstance(top_risks, list)
    assert len(top_risks) == 4
    # Worst-first; the two criticals lead, ordered by check then subject.
    assert top_risks[0]["severity"] == "critical"
    assert top_risks[0]["check"] == "ESC1"
    assert top_risks[1]["check"] == "ESC6"
    assert top_risks[2]["severity"] == "high"
    assert top_risks[3]["severity"] == "medium"

    # Each top risk carries the catalogue summary.
    esc6_entry = consequence_for("ESC6")
    assert esc6_entry is not None
    assert top_risks[1]["summary"] == esc6_entry.summary

    # Coverage gaps are the two INFO degradation notes.
    gaps = posture["coverage_gaps"]
    assert isinstance(gaps, list)
    assert len(gaps) == 2
    assert {g["check"] for g in gaps} == {
        "TEMPLATE_ACL_NOT_EVALUATED",
        "PKI_ACL_NOT_EVALUATED",
    }


def test_summarize_posture_unknown_check_summary_is_none() -> None:
    posture = summarize_posture([_f("NO_SUCH_CHECK", Severity.HIGH)])
    top_risks = posture["top_risks"]
    assert isinstance(top_risks, list)
    assert top_risks[0]["summary"] is None


def test_summarize_posture_empty_findings() -> None:
    posture = summarize_posture([])
    assert posture["total"] == 0
    assert posture["actionable"] == 0
    assert posture["top_risks"] == []
    assert posture["coverage_gaps"] == []


# --- generate_executive_summary --------------------------------------------


def test_generate_executive_summary_has_key_info() -> None:
    text = generate_executive_summary(_sample_findings())
    assert isinstance(text, str)
    assert text.strip()
    assert "EXECUTIVE SUMMARY" in text
    assert "4 actionable finding(s)" in text
    assert "2 coverage gap(s)" in text
    # Worst-first: a critical risk is listed first.
    assert "CRITICAL" in text
    assert "ESC6" in text
    assert "LABCA" in text
    assert "WEAK_TEMPLATE_KEY_SIZE" in text
    # Coverage gaps are named.
    assert "TEMPLATE_ACL_NOT_EVALUATED" in text
    # Closes with a priority recommendation.
    assert "Priority:" in text


def test_generate_executive_summary_empty_findings() -> None:
    text = generate_executive_summary([])
    assert "EXECUTIVE SUMMARY" in text
    assert "0 actionable finding(s)" in text
    assert "0 coverage gap(s)" in text
    assert "Priority:" in text
    assert "No findings and no coverage gaps" in text


def test_generate_executive_summary_only_degradation_notes() -> None:
    findings = [
        _f("TEMPLATE_ACL_NOT_EVALUATED", Severity.INFO, subject="(estate)"),
        _f("PKI_ACL_NOT_EVALUATED", Severity.INFO, subject="(estate)"),
    ]
    text = generate_executive_summary(findings)
    assert "0 actionable finding(s)" in text
    assert "2 coverage gap(s)" in text
    assert "TEMPLATE_ACL_NOT_EVALUATED" in text
    assert "PKI_ACL_NOT_EVALUATED" in text
    assert "No posture findings were detected" in text


def test_generate_executive_summary_includes_consequence_text() -> None:
    text = generate_executive_summary([_f("ESC6", Severity.CRITICAL, subject="LABCA")])
    entry = consequence_for("ESC6")
    assert entry is not None
    assert entry.summary in text
    assert entry.consequence in text
    assert entry.remediation in text
    assert "In plain terms:" in text
    assert "Risk:" in text
    assert "How to fix:" in text


def test_generate_executive_summary_caps_top_risks_at_five() -> None:
    findings = [_f(f"ESC{i}", Severity.HIGH, subject=f"T{i}") for i in range(1, 8)]
    text = generate_executive_summary(findings)
    assert "1. [HIGH]" in text
    assert "5. [HIGH]" in text
    assert "6. [HIGH]" not in text
    assert "7. [HIGH]" not in text


def test_generate_executive_summary_is_deterministic() -> None:
    findings = _sample_findings()
    assert generate_executive_summary(findings) == generate_executive_summary(findings)


def test_generate_executive_summary_does_not_mutate_input() -> None:
    findings = _sample_findings()
    snapshot = list(findings)
    generate_executive_summary(findings)
    assert findings == snapshot


# --- generate_narrated_summary ----------------------------------------------


def test_narrated_summary_without_client_matches_deterministic() -> None:
    findings = _sample_findings()
    assert generate_narrated_summary(findings) == generate_executive_summary(findings)


def test_narrated_summary_uses_llm_when_client_succeeds() -> None:
    findings = _sample_findings()

    class _FakeClient:
        def __init__(self) -> None:
            self.called = False
            self.prompt: str | None = None

        def chat(self, prompt: str) -> str:
            self.called = True
            self.prompt = prompt
            return "LLM narration output."

    client = _FakeClient()
    result = generate_narrated_summary(findings, llm_client=client)
    assert client.called is True
    assert client.prompt is not None
    # The prompt carries the deterministic summary + findings JSON as context.
    assert "EXECUTIVE SUMMARY" in client.prompt
    assert "ESC6" in client.prompt
    assert "STRICT RULES" in client.prompt
    assert result == "LLM narration output."


def test_narrated_summary_falls_back_when_client_raises() -> None:
    findings = _sample_findings()

    class _BrokenClient:
        def chat(self, prompt: str) -> str:
            raise RuntimeError("LLM unavailable")

    result = generate_narrated_summary(findings, llm_client=_BrokenClient())
    assert result == generate_executive_summary(findings)


def test_narrated_summary_falls_back_when_client_returns_empty() -> None:
    findings = _sample_findings()

    class _EmptyClient:
        def chat(self, prompt: str) -> str:
            return "   "

    result = generate_narrated_summary(findings, llm_client=_EmptyClient())
    assert result == generate_executive_summary(findings)
