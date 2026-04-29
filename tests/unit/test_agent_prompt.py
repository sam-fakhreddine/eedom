"""Tests for agent system prompt module.
# tested-by: tests/unit/test_agent_prompt.py
"""

from __future__ import annotations

from eedom.agent.prompt import build_system_prompt
from tests.unit.prose_assertions import assert_review_prose_contract

_ALL_DIMENSIONS = [
    "NECESSITY",
    "MINIMALITY",
    "MAINTENANCE",
    "SECURITY",
    "EXPOSURE",
    "BLAST_RADIUS",
    "ALTERNATIVES",
    "BEHAVIORAL",
]


def test_system_prompt_contains_all_eight_dimensions():
    prompt = build_system_prompt(policy_version="1.0.0")
    for dim in _ALL_DIMENSIONS:
        assert dim in prompt, f"Missing dimension: {dim}"


def test_system_prompt_contains_gatekeeper_identity():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "GATEKEEPER" in prompt


def test_build_system_prompt_injects_policy_version():
    prompt = build_system_prompt(policy_version="2.5.1")
    assert "v2.5.1" in prompt


def test_build_system_prompt_injects_alternatives():
    prompt = build_system_prompt(
        policy_version="1.0.0",
        alternatives=["httpx", "urllib3"],
    )
    assert "httpx" in prompt
    assert "urllib3" in prompt


def test_build_system_prompt_no_alternatives_section_when_none():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "Approved alternative packages" not in prompt


def test_system_prompt_contains_semgrep_guidance():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "Semgrep" in prompt
    assert "Code Pattern" in prompt


def test_system_prompt_contains_comment_format():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "🟢" in prompt
    assert "🔴" in prompt
    assert "APPROVED" in prompt
    assert "REJECTED" in prompt


def test_system_prompt_contains_opa_gate_rule():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "OPA" in prompt
    assert "override" in prompt.lower()


def test_system_prompt_mentions_three_tools():
    prompt = build_system_prompt(policy_version="1.0.0")
    assert "evaluate_change" in prompt
    assert "check_package" in prompt
    assert "scan_code" in prompt


def test_system_prompt_requires_prescriptive_review_comments():
    prompt = build_system_prompt(policy_version="1.0.0")

    assert "**Required:**" in prompt
    assert "**Consider:**" in prompt
    assert "**FYI:**" in prompt
    assert "Why it matters:" in prompt
    assert "Fix:" in prompt
    assert "Done when:" in prompt
    assert "Verify:" in prompt
    assert "comment about the code" in prompt
    assert "not the developer" in prompt
    assert_review_prose_contract(prompt)
