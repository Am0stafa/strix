"""Deterministic, browser-free source-to-sink regression over CSPT fixtures.

PR #789 proves CSPT detection with a Playwright capture test that skips in any
CI without Chromium. This instead pins the same source-to-sink intent with a
tiny matcher over hand-authored fixtures, so it runs everywhere. It is a
fixture/pattern regression — not a claim that Strix ships a static taint
tracker — kept honest by a convention: the attacker-controlled value that
reaches a sink is named ``userPath`` in every fixture.
"""

from __future__ import annotations

from pathlib import Path


_FIXTURES = Path(__file__).parent / "fixtures" / "cspt"

#: Browser-controlled input sources an attacker influences.
_SOURCES = (
    "location.search",
    "URLSearchParams",
    "location.hash",
    "document.referrer",
    "postMessage",
    "localStorage",
)
#: Request sinks whose path, if attacker-shaped, makes the flow a CSPT.
_SINKS = ("fetch(", "XMLHttpRequest", "axios", "EventSource", "WebSocket")
#: Markers of a guard that neutralises the flow (so it is a safe control).
_MITIGATIONS = ("/^", ".test(", "allowlist", "hardcoded")


def _taints_sink(text: str) -> bool:
    """True when the attacker value (``userPath``) appears on a sink-call line."""
    return any(
        any(sink in line for sink in _SINKS) and "userPath" in line
        for line in text.splitlines()
    )


def _classify(text: str) -> str:
    """Exploitable only when an unguarded attacker source reaches a sink path."""
    has_source = any(token in text for token in _SOURCES)
    has_sink = any(token in text for token in _SINKS)
    guarded = any(token in text for token in _MITIGATIONS)
    if has_source and has_sink and _taints_sink(text) and not guarded:
        return "positive"
    return "negative"


def test_cspt_fixtures_classify_by_their_label() -> None:
    fixtures = sorted(_FIXTURES.glob("*.html"))
    assert fixtures, "no CSPT fixtures found"

    positives = [f for f in fixtures if f.name.startswith("positive_")]
    negatives = [f for f in fixtures if f.name.startswith("negative_")]
    assert len(positives) >= 2, "need at least two positive CSPT fixtures"
    assert len(negatives) >= 2, "need at least two negative control fixtures"

    for fixture in fixtures:
        expected = "positive" if fixture.name.startswith("positive_") else "negative"
        actual = _classify(fixture.read_text(encoding="utf-8"))
        assert actual == expected, f"{fixture.name}: expected {expected}, matched {actual}"
