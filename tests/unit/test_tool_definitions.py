"""Tests for src/tools/definitions.py — shared tool JSON schemas."""

from __future__ import annotations

from src.tools.definitions import TOOL_SCHEMAS

# All tool names the agent should expose
_EXPECTED_TOOLS = {
    "query_secure_score",
    "assess_defender_coverage",
    "check_purview_policies",
    "get_entra_config",
    "generate_remediation_plan",
    "create_adoption_scorecard",
    "get_green_playbook",
    "push_posture_snapshot",
}


def test_tool_schemas_contains_all_tools() -> None:
    """Every expected tool is present in TOOL_SCHEMAS."""
    names = {t["function"]["name"] for t in TOOL_SCHEMAS}
    assert names == _EXPECTED_TOOLS


def test_tool_schemas_are_valid_openai_format() -> None:
    """Each schema has the required OpenAI function-calling structure."""
    for schema in TOOL_SCHEMAS:
        assert schema["type"] == "function"
        func = schema["function"]
        assert "name" in func
        assert "description" in func
        assert "parameters" in func
        params = func["parameters"]
        assert params["type"] == "object"
        assert "properties" in params
        assert "required" in params
