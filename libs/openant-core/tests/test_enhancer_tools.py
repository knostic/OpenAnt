"""Tests for the agentic enhancer tools, specifically the get_static_dependencies tool."""
import pytest

from utilities.agentic_enhancer.repository_index import RepositoryIndex
from utilities.agentic_enhancer.tools import ToolExecutor


def _make_index(functions: dict) -> RepositoryIndex:
    """Create a RepositoryIndex from a minimal functions dict."""
    return RepositoryIndex({"functions": functions})


SAMPLE_FUNCTIONS = {
    "src/user.controller.ts:UserController.getUser": {
        "name": "UserController.getUser",
        "code": "async getUser(id) { return this.userService.findById(id); }",
        "className": "UserController",
        "unitType": "class_method",
        "startLine": 10,
        "endLine": 12,
    },
    "src/user.service.ts:UserService.findById": {
        "name": "UserService.findById",
        "code": "async findById(id) { return this.repo.findOne(id); }",
        "className": "UserService",
        "unitType": "class_method",
        "startLine": 5,
        "endLine": 7,
    },
    "src/auth.guard.ts:AuthGuard.canActivate": {
        "name": "AuthGuard.canActivate",
        "code": "canActivate(context) { return this.validate(context); }",
        "className": "AuthGuard",
        "unitType": "class_method",
        "startLine": 3,
        "endLine": 5,
    },
}


class TestResolveDependencies:
    """Test RepositoryIndex.resolve_dependencies."""

    def test_resolves_by_function_id(self):
        index = _make_index(SAMPLE_FUNCTIONS)
        result = index.resolve_dependencies([
            "src/user.service.ts:UserService.findById"
        ])
        assert len(result) == 1
        assert result[0]["id"] == "src/user.service.ts:UserService.findById"
        assert result[0]["className"] == "UserService"

    def test_resolves_by_qualified_name(self):
        """Resolve using Class.method format when full ID is unknown."""
        index = _make_index(SAMPLE_FUNCTIONS)
        result = index.resolve_dependencies(["AuthGuard.canActivate"])
        assert len(result) == 1
        assert "AuthGuard.canActivate" in result[0]["id"]

    def test_returns_empty_for_unknown(self):
        index = _make_index(SAMPLE_FUNCTIONS)
        result = index.resolve_dependencies(["nonExistentFunction"])
        assert result == []

    def test_deduplicates_results(self):
        index = _make_index(SAMPLE_FUNCTIONS)
        result = index.resolve_dependencies([
            "src/user.service.ts:UserService.findById",
            "src/user.service.ts:UserService.findById",
        ])
        assert len(result) == 1


class TestGetStaticDependenciesTool:
    """Test the get_static_dependencies tool via ToolExecutor."""

    def test_returns_resolved_deps(self):
        index = _make_index(SAMPLE_FUNCTIONS)
        executor = ToolExecutor(index)
        executor.set_unit_context(
            static_deps=["src/user.service.ts:UserService.findById"],
            static_callers=[],
        )

        result = executor.execute("get_static_dependencies", {})
        assert result["dependencies"]["count"] == 1
        assert len(result["dependencies"]["resolved"]) == 1
        assert result["dependencies"]["resolved"][0]["className"] == "UserService"
        assert result["callers"]["count"] == 0

    def test_returns_resolved_callers(self):
        index = _make_index(SAMPLE_FUNCTIONS)
        executor = ToolExecutor(index)
        executor.set_unit_context(
            static_deps=[],
            static_callers=["src/user.controller.ts:UserController.getUser"],
        )

        result = executor.execute("get_static_dependencies", {})
        assert result["callers"]["count"] == 1
        assert result["callers"]["resolved"][0]["className"] == "UserController"

    def test_empty_context(self):
        index = _make_index(SAMPLE_FUNCTIONS)
        executor = ToolExecutor(index)
        executor.set_unit_context([], [])

        result = executor.execute("get_static_dependencies", {})
        assert result["dependencies"]["count"] == 0
        assert result["callers"]["count"] == 0

    def test_context_resets_between_units(self):
        index = _make_index(SAMPLE_FUNCTIONS)
        executor = ToolExecutor(index)

        # First unit
        executor.set_unit_context(
            static_deps=["src/user.service.ts:UserService.findById"],
            static_callers=[],
        )
        result1 = executor.execute("get_static_dependencies", {})
        assert result1["dependencies"]["count"] == 1

        # Second unit - different context
        executor.set_unit_context(static_deps=[], static_callers=[])
        result2 = executor.execute("get_static_dependencies", {})
        assert result2["dependencies"]["count"] == 0
