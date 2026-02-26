"""Comprehensive tests for the get_entra_config tool.

Covers:
  - Parser helpers (_parse_conditional_access, _parse_role_assignments,
    _parse_risky_users, _parse_access_reviews)
  - Status computation (_compute_status)
  - Mock fallback path (no Graph credentials)
  - Graph API integration path (mocked SDK responses)
  - Partial endpoint failure resilience
  - Critical gap collection
  - Error handling and edge cases
  - Trace span creation via @trace_tool_call decorator
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ═══════════════════════════════════════════════════════════════════════
# Helpers — build fake Graph SDK objects
# ═══════════════════════════════════════════════════════════════════════

def _make_ca_policy(
    *,
    display_name: str = "Test Policy",
    state: str = "enabled",
    include_users: list | None = None,
    client_app_types: list | None = None,
    built_in_controls: list | None = None,
) -> SimpleNamespace:
    """Build a fake ConditionalAccessPolicy."""
    users = SimpleNamespace(
        include_users=include_users or [],
        exclude_groups=[],
    )
    conditions = SimpleNamespace(
        users=users,
        client_app_types=client_app_types or [],
    )
    grant_controls = SimpleNamespace(
        built_in_controls=built_in_controls or [],
    )
    return SimpleNamespace(
        display_name=display_name,
        state=state,
        id=f"policy-{display_name[:8]}",
        conditions=conditions,
        grant_controls=grant_controls,
    )


def _make_role_assignment(
    *,
    role_definition_id: str = "some-role-id",
    principal_id: str = "user-1",
    directory_scope_id: str = "/",
) -> SimpleNamespace:
    return SimpleNamespace(
        role_definition_id=role_definition_id,
        principal_id=principal_id,
        directory_scope_id=directory_scope_id,
    )


def _make_risky_user(*, id: str = "risky-1") -> SimpleNamespace:
    return SimpleNamespace(id=id, risk_level="high")


def _make_access_review(
    *,
    display_name: str = "Quarterly Review",
    status: str = "InProgress",
) -> SimpleNamespace:
    return SimpleNamespace(
        display_name=display_name,
        status=status,
        scope=None,
        reviewers=None,
        settings=None,
    )


def _graph_list_response(items: list) -> SimpleNamespace:
    """Build a fake Graph collection response."""
    return SimpleNamespace(value=items, odata_next_link=None)


GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"


# ═══════════════════════════════════════════════════════════════════════
# 1. _compute_status
# ═══════════════════════════════════════════════════════════════════════

class TestEntraComputeStatus:
    def test_green_at_70(self):
        from src.tools.entra_config import _compute_status
        assert _compute_status(70.0) == "green"

    def test_green_above(self):
        from src.tools.entra_config import _compute_status
        assert _compute_status(100.0) == "green"

    def test_yellow_at_40(self):
        from src.tools.entra_config import _compute_status
        assert _compute_status(40.0) == "yellow"

    def test_yellow_between(self):
        from src.tools.entra_config import _compute_status
        assert _compute_status(55.0) == "yellow"

    def test_red_below_40(self):
        from src.tools.entra_config import _compute_status
        assert _compute_status(39.9) == "red"

    def test_red_at_zero(self):
        from src.tools.entra_config import _compute_status
        assert _compute_status(0.0) == "red"


# ═══════════════════════════════════════════════════════════════════════
# 2. _parse_conditional_access
# ═══════════════════════════════════════════════════════════════════════

class TestParseConditionalAccess:
    def test_empty_policies(self):
        from src.tools.entra_config import _parse_conditional_access
        result = _parse_conditional_access([])
        assert result["status"] == "red"
        assert result["details"]["total_policies"] == 0
        assert len(result["gaps"]) > 0

    def test_none_policies(self):
        from src.tools.entra_config import _parse_conditional_access
        result = _parse_conditional_access(None)
        assert result["status"] == "red"

    def test_mfa_for_all_users(self):
        from src.tools.entra_config import _parse_conditional_access
        policy = _make_ca_policy(
            display_name="MFA All",
            state="enabled",
            include_users=["All"],
            built_in_controls=["mfa"],
        )
        result = _parse_conditional_access([policy])
        assert result["details"]["mfa_enforced_all_users"] is True

    def test_legacy_auth_blocked(self):
        from src.tools.entra_config import _parse_conditional_access
        policy = _make_ca_policy(
            display_name="Block Legacy",
            state="enabled",
            client_app_types=["exchangeActiveSync", "other"],
            built_in_controls=["block"],
        )
        result = _parse_conditional_access([policy])
        assert result["details"]["legacy_auth_blocked"] is True

    def test_report_only_counted(self):
        from src.tools.entra_config import _parse_conditional_access
        policy = _make_ca_policy(
            display_name="Report Only",
            state="enabledForReportingButNotEnforced",
        )
        result = _parse_conditional_access([policy])
        assert result["details"]["report_only_policies"] == 1
        assert result["details"]["active_policies"] == 0

    def test_multiple_policies(self):
        from src.tools.entra_config import _parse_conditional_access
        policies = [
            _make_ca_policy(display_name="P1", state="enabled"),
            _make_ca_policy(display_name="P2", state="enabled"),
            _make_ca_policy(display_name="P3", state="enabled"),
            _make_ca_policy(
                display_name="MFA",
                state="enabled",
                include_users=["All"],
                built_in_controls=["mfa"],
            ),
            _make_ca_policy(
                display_name="Block",
                state="enabled",
                client_app_types=["exchangeActiveSync"],
                built_in_controls=["block"],
            ),
        ]
        result = _parse_conditional_access(policies)
        assert result["details"]["active_policies"] == 5
        assert result["details"]["mfa_enforced_all_users"] is True
        assert result["details"]["legacy_auth_blocked"] is True
        assert result["status"] == "green"

    def test_no_mfa_no_legacy_block(self):
        from src.tools.entra_config import _parse_conditional_access
        policy = _make_ca_policy(display_name="Basic", state="enabled")
        result = _parse_conditional_access([policy])
        assert result["details"]["mfa_enforced_all_users"] is False
        assert result["details"]["legacy_auth_blocked"] is False
        assert any("MFA" in g for g in result["gaps"])
        assert any("Legacy" in g or "legacy" in g.lower() for g in result["gaps"])

    def test_mfa_not_all_users(self):
        from src.tools.entra_config import _parse_conditional_access
        policy = _make_ca_policy(
            display_name="MFA Admins",
            state="enabled",
            include_users=["admin-group-id"],
            built_in_controls=["mfa"],
        )
        result = _parse_conditional_access([policy])
        assert result["details"]["mfa_enforced_all_users"] is False


# ═══════════════════════════════════════════════════════════════════════
# 3. _parse_role_assignments
# ═══════════════════════════════════════════════════════════════════════

class TestParseRoleAssignments:
    def test_empty_assignments(self):
        from src.tools.entra_config import _parse_role_assignments
        result = _parse_role_assignments([])
        assert result["status"] == "red"
        assert result["details"]["total_assignments"] == 0

    def test_none_assignments(self):
        from src.tools.entra_config import _parse_role_assignments
        result = _parse_role_assignments(None)
        assert result["status"] == "red"

    def test_few_global_admins_green(self):
        from src.tools.entra_config import _parse_role_assignments
        assignments = [
            _make_role_assignment(role_definition_id=GLOBAL_ADMIN_ROLE_ID),
            _make_role_assignment(role_definition_id=GLOBAL_ADMIN_ROLE_ID, principal_id="u2"),
        ]
        result = _parse_role_assignments(assignments)
        assert result["details"]["permanent_global_admins"] == 2
        assert result["status"] == "green"

    def test_too_many_global_admins(self):
        from src.tools.entra_config import _parse_role_assignments
        assignments = [
            _make_role_assignment(role_definition_id=GLOBAL_ADMIN_ROLE_ID, principal_id=f"u{i}")
            for i in range(5)
        ]
        result = _parse_role_assignments(assignments)
        assert result["details"]["permanent_global_admins"] == 5
        assert len(result["gaps"]) > 0
        assert any("Global Admin" in g for g in result["gaps"])

    def test_many_assignments_warns(self):
        from src.tools.entra_config import _parse_role_assignments
        assignments = [
            _make_role_assignment(principal_id=f"u{i}") for i in range(15)
        ]
        result = _parse_role_assignments(assignments)
        assert result["details"]["total_assignments"] == 15
        assert any("eligible" in g.lower() or "jit" in g.lower() for g in result["gaps"])

    def test_non_global_admin_roles(self):
        from src.tools.entra_config import _parse_role_assignments
        assignments = [
            _make_role_assignment(role_definition_id="some-other-role"),
        ]
        result = _parse_role_assignments(assignments)
        assert result["details"]["permanent_global_admins"] == 0


# ═══════════════════════════════════════════════════════════════════════
# 4. _parse_risky_users
# ═══════════════════════════════════════════════════════════════════════

class TestParseRiskyUsers:
    def test_no_risky_users(self):
        from src.tools.entra_config import _parse_risky_users
        result = _parse_risky_users([])
        assert result["status"] == "green"
        assert result["details"]["risky_users_count"] == 0
        assert len(result["gaps"]) == 0

    def test_none_input(self):
        from src.tools.entra_config import _parse_risky_users
        result = _parse_risky_users(None)
        assert result["status"] == "green"
        assert result["details"]["risky_users_count"] == 0

    def test_few_risky_users_yellow(self):
        from src.tools.entra_config import _parse_risky_users
        users = [_make_risky_user(id=f"u{i}") for i in range(5)]
        result = _parse_risky_users(users)
        assert result["status"] == "yellow"
        assert result["details"]["risky_users_count"] == 5
        assert len(result["gaps"]) == 1

    def test_many_risky_users_red(self):
        from src.tools.entra_config import _parse_risky_users
        users = [_make_risky_user(id=f"u{i}") for i in range(15)]
        result = _parse_risky_users(users)
        assert result["status"] == "red"
        assert result["details"]["risky_users_count"] == 15


# ═══════════════════════════════════════════════════════════════════════
# 5. _parse_access_reviews
# ═══════════════════════════════════════════════════════════════════════

class TestParseAccessReviews:
    def test_no_reviews(self):
        from src.tools.entra_config import _parse_access_reviews
        result = _parse_access_reviews([])
        assert result["status"] == "red"
        assert result["details"]["reviews_configured"] == 0
        assert any("No access reviews" in g for g in result["gaps"])

    def test_none_input(self):
        from src.tools.entra_config import _parse_access_reviews
        result = _parse_access_reviews(None)
        assert result["status"] == "red"

    def test_one_review_yellow(self):
        from src.tools.entra_config import _parse_access_reviews
        result = _parse_access_reviews([_make_access_review()])
        assert result["status"] == "yellow"
        assert result["details"]["reviews_configured"] == 1

    def test_three_reviews_green(self):
        from src.tools.entra_config import _parse_access_reviews
        reviews = [_make_access_review(display_name=f"R{i}") for i in range(3)]
        result = _parse_access_reviews(reviews)
        assert result["status"] == "green"
        assert result["details"]["reviews_configured"] == 3
        assert len(result["gaps"]) == 0


# ═══════════════════════════════════════════════════════════════════════
# 6. Mock fallback — get_entra_config with no Graph client
# ═══════════════════════════════════════════════════════════════════════

class TestEntraMockFallback:
    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client", return_value=None)
    async def test_returns_mock_data_source(self, _mock):
        from src.tools.entra_config import get_entra_config
        result = await get_entra_config()
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client", return_value=None)
    async def test_mock_has_all_components(self, _mock):
        from src.tools.entra_config import get_entra_config, ALL_COMPONENTS
        result = await get_entra_config()
        assert set(result["components"].keys()) == set(ALL_COMPONENTS)

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client", return_value=None)
    async def test_mock_has_overall_coverage(self, _mock):
        from src.tools.entra_config import get_entra_config
        result = await get_entra_config()
        assert 0.0 <= result["overall_coverage_pct"] <= 100.0

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client", return_value=None)
    async def test_mock_has_total_gaps(self, _mock):
        from src.tools.entra_config import get_entra_config
        result = await get_entra_config()
        assert result["total_gaps"] > 0

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client", return_value=None)
    async def test_mock_has_critical_gaps(self, _mock):
        from src.tools.entra_config import get_entra_config
        result = await get_entra_config()
        assert isinstance(result["critical_gaps"], list)
        assert len(result["critical_gaps"]) > 0

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client", return_value=None)
    async def test_mock_has_assessed_at(self, _mock):
        from src.tools.entra_config import get_entra_config
        result = await get_entra_config()
        assert "assessed_at" in result

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client", return_value=None)
    async def test_mock_component_structure(self, _mock):
        from src.tools.entra_config import get_entra_config
        result = await get_entra_config()
        for component in result["components"].values():
            assert "status" in component
            assert "details" in component
            assert "gaps" in component


# ═══════════════════════════════════════════════════════════════════════
# 7. Graph API path — full integration
# ═══════════════════════════════════════════════════════════════════════

def _build_entra_mock_client(
    *,
    ca_policies: list | None = None,
    role_assignments: list | None = None,
    risky_users: list | None = None,
    access_reviews: list | None = None,
    ca_error: Exception | None = None,
    pim_error: Exception | None = None,
    idp_error: Exception | None = None,
    ar_error: Exception | None = None,
) -> MagicMock:
    """Build a mock GraphServiceClient with all 4 endpoints configured."""
    mock_client = MagicMock()

    # Conditional Access
    if ca_error:
        mock_client.identity.conditional_access.policies.get = AsyncMock(side_effect=ca_error)
    else:
        mock_client.identity.conditional_access.policies.get = AsyncMock(
            return_value=_graph_list_response(ca_policies or [])
        )

    # Role Assignments
    if pim_error:
        mock_client.role_management.directory.role_assignments.get = AsyncMock(side_effect=pim_error)
    else:
        mock_client.role_management.directory.role_assignments.get = AsyncMock(
            return_value=_graph_list_response(role_assignments or [])
        )

    # Risky Users
    if idp_error:
        mock_client.identity_protection.risky_users.get = AsyncMock(side_effect=idp_error)
    else:
        mock_client.identity_protection.risky_users.get = AsyncMock(
            return_value=_graph_list_response(risky_users or [])
        )

    # Access Reviews
    if ar_error:
        mock_client.identity_governance.access_reviews.definitions.get = AsyncMock(side_effect=ar_error)
    else:
        mock_client.identity_governance.access_reviews.definitions.get = AsyncMock(
            return_value=_graph_list_response(access_reviews or [])
        )

    return mock_client


class TestEntraGraphPath:
    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_basic_graph_response(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client(
            ca_policies=[
                _make_ca_policy(
                    display_name="MFA",
                    include_users=["All"],
                    built_in_controls=["mfa"],
                ),
            ],
            role_assignments=[_make_role_assignment()],
            risky_users=[],
            access_reviews=[_make_access_review()],
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert result["data_source"] == "graph_api"
        assert "overall_coverage_pct" in result
        assert set(result["components"].keys()) >= {
            "Conditional Access",
            "Privileged Identity Management",
            "Identity Protection",
            "Access Reviews",
            "SSO & App Registrations",
        }

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_all_green_scenario(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        ca_policies = [
            _make_ca_policy(display_name="P1", state="enabled"),
            _make_ca_policy(display_name="P2", state="enabled"),
            _make_ca_policy(
                display_name="MFA All",
                state="enabled",
                include_users=["All"],
                built_in_controls=["mfa"],
            ),
            _make_ca_policy(
                display_name="Block Legacy",
                state="enabled",
                client_app_types=["exchangeActiveSync"],
                built_in_controls=["block"],
            ),
        ]
        mock_client = _build_entra_mock_client(
            ca_policies=ca_policies,
            role_assignments=[
                _make_role_assignment(role_definition_id=GLOBAL_ADMIN_ROLE_ID),
            ],
            risky_users=[],
            access_reviews=[
                _make_access_review(display_name=f"R{i}") for i in range(3)
            ],
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert result["data_source"] == "graph_api"
        assert result["overall_coverage_pct"] > 50.0

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_all_red_scenario(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client(
            ca_policies=[],
            role_assignments=[],
            risky_users=[_make_risky_user(id=f"u{i}") for i in range(20)],
            access_reviews=[],
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert result["data_source"] == "graph_api"
        assert result["overall_coverage_pct"] < 30.0

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_all_endpoints_fail_returns_graph_api_with_unknowns(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = MagicMock()
        # Make all endpoints fail — each is caught individually
        mock_client.identity.conditional_access.policies.get = AsyncMock(
            side_effect=RuntimeError("total failure")
        )
        mock_client.role_management.directory.role_assignments.get = AsyncMock(
            side_effect=RuntimeError("total failure")
        )
        mock_client.identity_protection.risky_users.get = AsyncMock(
            side_effect=RuntimeError("total failure")
        )
        mock_client.identity_governance.access_reviews.definitions.get = AsyncMock(
            side_effect=RuntimeError("total failure")
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        # Per-endpoint try/except means client is still used → graph_api
        assert result["data_source"] == "graph_api"
        # All assessment components should be "unknown"
        for name in ("Conditional Access", "Privileged Identity Management",
                     "Identity Protection", "Access Reviews"):
            assert result["components"][name]["status"] == "unknown"

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_total_gaps_summed(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client(
            ca_policies=[_make_ca_policy()],
            role_assignments=[
                _make_role_assignment(role_definition_id=GLOBAL_ADMIN_ROLE_ID, principal_id=f"u{i}")
                for i in range(5)
            ],
            risky_users=[_make_risky_user()],
            access_reviews=[],
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert result["total_gaps"] > 0

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_critical_gaps_detected(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client(
            ca_policies=[_make_ca_policy()],
            role_assignments=[
                _make_role_assignment(role_definition_id=GLOBAL_ADMIN_ROLE_ID, principal_id=f"u{i}")
                for i in range(5)
            ],
            risky_users=[_make_risky_user()],
            access_reviews=[],
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert len(result["critical_gaps"]) > 0

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_assessed_at_present(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client()
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert "assessed_at" in result


# ═══════════════════════════════════════════════════════════════════════
# 8. Partial endpoint failures
# ═══════════════════════════════════════════════════════════════════════

class TestEntraPartialFailures:
    """Each endpoint has independent error handling, so partial failures
    produce 'unknown' status but don't block the rest."""

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_ca_error_recovers(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client(
            ca_error=Exception("403 Forbidden"),
            risky_users=[],
            access_reviews=[_make_access_review()],
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert result["data_source"] == "graph_api"
        assert result["components"]["Conditional Access"]["status"] == "unknown"
        assert result["components"]["Identity Protection"]["status"] == "green"

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_pim_error_recovers(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client(
            ca_policies=[_make_ca_policy()],
            pim_error=Exception("403 Forbidden"),
            risky_users=[],
            access_reviews=[],
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert result["data_source"] == "graph_api"
        assert result["components"]["Privileged Identity Management"]["status"] == "unknown"

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_identity_protection_error_recovers(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client(
            ca_policies=[_make_ca_policy()],
            idp_error=Exception("Insufficient privileges"),
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert result["data_source"] == "graph_api"
        assert result["components"]["Identity Protection"]["status"] == "unknown"

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_access_reviews_error_recovers(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client(
            ca_policies=[_make_ca_policy()],
            ar_error=Exception("403"),
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert result["data_source"] == "graph_api"
        assert result["components"]["Access Reviews"]["status"] == "unknown"

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_all_endpoints_fail_unknown(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client(
            ca_error=Exception("fail"),
            pim_error=Exception("fail"),
            idp_error=Exception("fail"),
            ar_error=Exception("fail"),
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert result["data_source"] == "graph_api"
        # All should be unknown except SSO (always yellow)
        for comp in ("Conditional Access", "Privileged Identity Management",
                      "Identity Protection", "Access Reviews"):
            assert result["components"][comp]["status"] == "unknown"

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_unknown_excluded_from_overall(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client(
            ca_error=Exception("fail"),
            pim_error=Exception("fail"),
            idp_error=Exception("fail"),
            ar_error=Exception("fail"),
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        # Only SSO is non-unknown (yellow), so overall should be based on SSO alone
        assert result["overall_coverage_pct"] > 0.0


# ═══════════════════════════════════════════════════════════════════════
# 9. SSO component
# ═══════════════════════════════════════════════════════════════════════

class TestEntraSSO:
    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_sso_always_yellow(self, mock_factory):
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client()
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        sso = result["components"]["SSO & App Registrations"]
        assert sso["status"] == "yellow"
        assert len(sso["gaps"]) >= 1


# ═══════════════════════════════════════════════════════════════════════
# 10. Tracing
# ═══════════════════════════════════════════════════════════════════════

class TestEntraTracing:
    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client", return_value=None)
    @patch("src.middleware.tracing.get_tracer")
    async def test_span_created(self, mock_tracer_fn, _mock_client):
        from src.tools.entra_config import get_entra_config

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_tracer_fn.return_value = mock_tracer

        await get_entra_config()
        mock_tracer.start_as_current_span.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client", return_value=None)
    @patch("src.middleware.tracing.get_tracer")
    async def test_span_name_contains_tool(self, mock_tracer_fn, _mock_client):
        from src.tools.entra_config import get_entra_config

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_tracer_fn.return_value = mock_tracer

        await get_entra_config()
        call_args = mock_tracer.start_as_current_span.call_args
        span_name = call_args[0][0] if call_args[0] else call_args[1].get("name", "")
        assert "get_entra_config" in span_name


# ═══════════════════════════════════════════════════════════════════════
# 11. Edge cases
# ═══════════════════════════════════════════════════════════════════════

class TestEntraEdgeCases:
    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_null_response_values(self, mock_factory):
        """Endpoints returning response with value=None."""
        from src.tools.entra_config import get_entra_config

        mock_client = MagicMock()
        null_resp = SimpleNamespace(value=None)
        mock_client.identity.conditional_access.policies.get = AsyncMock(return_value=null_resp)
        mock_client.role_management.directory.role_assignments.get = AsyncMock(return_value=null_resp)
        mock_client.identity_protection.risky_users.get = AsyncMock(return_value=null_resp)
        mock_client.identity_governance.access_reviews.definitions.get = AsyncMock(return_value=null_resp)
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert result["data_source"] == "graph_api"

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_none_responses(self, mock_factory):
        """Endpoints returning None instead of response object."""
        from src.tools.entra_config import get_entra_config

        mock_client = MagicMock()
        mock_client.identity.conditional_access.policies.get = AsyncMock(return_value=None)
        mock_client.role_management.directory.role_assignments.get = AsyncMock(return_value=None)
        mock_client.identity_protection.risky_users.get = AsyncMock(return_value=None)
        mock_client.identity_governance.access_reviews.definitions.get = AsyncMock(return_value=None)
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        assert result["data_source"] == "graph_api"

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client")
    async def test_legacy_auth_other_keyword(self, mock_factory):
        """Block policy with 'other' client type still detects legacy auth."""
        from src.tools.entra_config import get_entra_config

        mock_client = _build_entra_mock_client(
            ca_policies=[
                _make_ca_policy(
                    display_name="Block Other",
                    state="enabled",
                    client_app_types=["other"],
                    built_in_controls=["block"],
                ),
            ],
        )
        mock_factory.return_value = mock_client

        result = await get_entra_config()
        ca = result["components"]["Conditional Access"]
        assert ca["details"]["legacy_auth_blocked"] is True
