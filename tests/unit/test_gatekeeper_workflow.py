"""Tests for user-facing prose in the GitHub gatekeeper workflow."""

from __future__ import annotations

from pathlib import Path

_WORKFLOW = Path(__file__).parent.parent.parent / ".github" / "workflows" / "gatekeeper.yml"


def test_gatekeeper_status_comment_uses_readable_counts():
    workflow = _WORKFLOW.read_text()

    assert "error(s)" not in workflow
    assert "warning(s)" not in workflow
    assert "plugin(s)" not in workflow
    assert "format_count()" in workflow
    assert "${ERROR_TEXT}" in workflow
    assert "${WARNING_TEXT}" in workflow
