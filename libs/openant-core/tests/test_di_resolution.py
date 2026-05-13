"""Tests for dependency injection-aware call resolution.

Tests that the TypeScript analyzer extracts constructor parameter types
and the dependency resolver uses them to resolve DI-injected service calls.

Requires Node.js and npm dependencies installed:
  cd parsers/javascript && npm install
"""
import json
import subprocess
import shutil
from pathlib import Path

import pytest

PARSERS_JS_DIR = Path(__file__).parent.parent / "parsers" / "javascript"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def run_node(script_name, *args):
    """Run a Node.js script from the JS parsers directory."""
    cmd = ["node", str(PARSERS_JS_DIR / script_name)] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


# -- Fixture: NestJS-style DI codebase --

RESOLVER_TS = """\
import { Injectable } from '@nestjs/common';
import { CallService } from './call.service';
import { AuthService } from './auth.service';

@Injectable()
export class CallResolver {
    constructor(
        private callService: CallService,
        private authService: AuthService,
    ) {}

    async getCall(id: string) {
        return await this.callService.getById(id);
    }

    async deleteCall(id: string) {
        return await this.callService.remove(id);
    }
}
"""

SERVICE_TS = """\
import { Injectable } from '@nestjs/common';

@Injectable()
export class CallService {
    async getById(id: string) {
        const call = await this.repository.findOne(id);
        await this.authService.can('read', call);
        return call;
    }

    async remove(id: string) {
        return await this.repository.delete(id);
    }
}
"""

AUTH_SERVICE_TS = """\
import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
    async can(action: string, resource: any) {
        // authorization check
        return true;
    }
}
"""

# Versioned implementation (interface CallService, impl CallServiceV2)
VERSIONED_SERVICE_TS = """\
import { Injectable } from '@nestjs/common';

@Injectable()
export class CallServiceV2 {
    async getById(id: string) {
        return { id };
    }

    async remove(id: string) {
        return true;
    }
}
"""

# Interface + implementing class for nominal type tests
ICALL_SERVICE_TS = """\
export interface ICallService {
    getById(id: string): Promise<any>;
}
"""

IMPL_CALL_SERVICE_TS = """\
import { Injectable } from '@nestjs/common';
import { ICallService } from './icall.service';

@Injectable()
export class CallServiceImpl implements ICallService {
    async getById(id: string) {
        return { id };
    }
}
"""

NOMINAL_RESOLVER_TS = """\
import { Injectable } from '@nestjs/common';
import { ICallService } from './icall.service';

@Injectable()
export class CallResolver {
    constructor(private callService: ICallService) {}

    async getCall(id: string) {
        return this.callService.getById(id);
    }
}
"""


@pytest.fixture
def nestjs_repo(tmp_path):
    """Create a minimal NestJS-style repo with DI patterns."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "call.resolver.ts").write_text(RESOLVER_TS)
    (src / "call.service.ts").write_text(SERVICE_TS)
    (src / "auth.service.ts").write_text(AUTH_SERVICE_TS)
    return tmp_path


@pytest.fixture
def nestjs_repo_versioned(tmp_path):
    """Create a repo where the DI type doesn't exactly match the class name."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "call.resolver.ts").write_text(RESOLVER_TS)
    (src / "call.service.ts").write_text(VERSIONED_SERVICE_TS)
    return tmp_path


@pytest.fixture
def nestjs_repo_nominal(tmp_path):
    """Create a repo where injection is via interface and impl uses implements."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "icall.service.ts").write_text(ICALL_SERVICE_TS)
    (src / "call.service.impl.ts").write_text(IMPL_CALL_SERVICE_TS)
    (src / "call.resolver.ts").write_text(NOMINAL_RESOLVER_TS)
    return tmp_path


def find_class(classes, class_name):
    """Find a class entry in the file-qualified classes dict (key is "filePath:ClassName")."""
    for key, val in classes.items():
        if key.endswith(':' + class_name):
            return val
    return None


def analyze_and_resolve(repo_path, files):
    """Run analyzer + resolver on given files and return resolved data."""
    analyzer_out = repo_path / "analyzer_output.json"
    resolved_out = repo_path / "resolved.json"

    file_paths = [str(f) for f in files]
    result = run_node(
        "typescript_analyzer.js", str(repo_path),
        *file_paths,
        "--output", str(analyzer_out),
    )
    assert result.returncode == 0, f"Analyzer failed: {result.stderr}"

    result = run_node(
        "dependency_resolver.js", str(analyzer_out),
        "--output", str(resolved_out),
    )
    assert result.returncode == 0, f"Resolver failed: {result.stderr}"

    return json.loads(resolved_out.read_text())


class TestConstructorDepsExtraction:
    """Test that the analyzer extracts constructorDeps into the classes table."""

    def test_extracts_constructor_deps(self, nestjs_repo):
        analyzer_out = nestjs_repo / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(nestjs_repo),
            "src/call.resolver.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0

        data = json.loads(analyzer_out.read_text())
        classes = data["classes"]

        call_resolver = find_class(classes, "CallResolver")
        assert call_resolver is not None, "CallResolver not in classes table"
        deps = call_resolver.get("constructorDeps", {})
        assert deps.get("callService") == "CallService"
        assert deps.get("authService") == "AuthService"

        # Methods themselves should NOT carry constructorDeps (stored in classes table instead)
        for fid, func in data["functions"].items():
            if "CallResolver" in fid:
                assert "constructorDeps" not in func, f"{fid} should not have constructorDeps"

    def test_skips_primitive_types(self, tmp_path):
        """Constructor params with primitive types should not be included."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "example.ts").write_text("""\
export class Example {
    constructor(
        private name: string,
        private count: number,
        private service: MyService,
    ) {}

    doWork() {
        return this.service.run();
    }
}
""")
        analyzer_out = tmp_path / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(tmp_path),
            "src/example.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0

        data = json.loads(analyzer_out.read_text())
        deps = (find_class(data["classes"], "Example") or {}).get("constructorDeps", {})
        # Only MyService should be captured (PascalCase), not string/number
        assert "service" in deps
        assert deps["service"] == "MyService"
        assert "name" not in deps
        assert "count" not in deps


    def test_same_name_different_file_no_collision(self, tmp_path):
        """Two classes with the same name in different files must not collide.

        Pre-fix: this.classes["UserController"] is last-write-wins, so the first
        class's constructorDeps are silently overwritten and its DI calls miss.
        Post-fix: both entries are keyed by "filePath:ClassName".
        """
        (tmp_path / "admin").mkdir()
        (tmp_path / "v2").mkdir()
        (tmp_path / "admin" / "user_controller.ts").write_text("""\
export class UserController {
    constructor(private fooService: FooService) {}
    getFoo() { return this.fooService.get(); }
}
""")
        (tmp_path / "v2" / "user_controller.ts").write_text("""\
export class UserController {
    constructor(private barService: BarService) {}
    getBar() { return this.barService.get(); }
}
""")
        (tmp_path / "foo_service.ts").write_text("""\
export class FooService {
    get() { return 'foo'; }
}
""")
        (tmp_path / "bar_service.ts").write_text("""\
export class BarService {
    get() { return 'bar'; }
}
""")

        # 1. Analyzer: both class entries present (no last-write-wins collision)
        analyzer_out = tmp_path / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(tmp_path),
            "admin/user_controller.ts",
            "v2/user_controller.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0
        data = json.loads(analyzer_out.read_text())
        classes = data["classes"]

        admin_entry = next((v for k, v in classes.items() if "admin" in k and k.endswith(":UserController")), None)
        v2_entry = next((v for k, v in classes.items() if "v2" in k and k.endswith(":UserController")), None)
        assert admin_entry is not None, "admin/UserController missing from classes table"
        assert v2_entry is not None, "v2/UserController missing from classes table"
        assert admin_entry.get("constructorDeps", {}).get("fooService") == "FooService"
        assert v2_entry.get("constructorDeps", {}).get("barService") == "BarService"

        # 2. Resolver: each class resolves calls to the right service (not the other's)
        data = analyze_and_resolve(tmp_path, [
            "admin/user_controller.ts",
            "v2/user_controller.ts",
            "foo_service.ts",
            "bar_service.ts",
        ])
        call_graph = data["callGraph"]

        admin_calls = next((calls for fid, calls in call_graph.items() if "admin" in fid and "UserController.getFoo" in fid), None)
        v2_calls = next((calls for fid, calls in call_graph.items() if "v2" in fid and "UserController.getBar" in fid), None)

        assert admin_calls is not None, "admin/UserController.getFoo not in call graph"
        assert v2_calls is not None, "v2/UserController.getBar not in call graph"
        assert any("FooService.get" in c for c in admin_calls), \
            f"admin/UserController.getFoo should resolve to FooService.get, got: {admin_calls}"
        assert any("BarService.get" in c for c in v2_calls), \
            f"v2/UserController.getBar should resolve to BarService.get, got: {v2_calls}"


class TestBaseTypesExtraction:
    """Test that the analyzer extracts implements/extends into baseTypes."""

    def test_extracts_implements(self, nestjs_repo_nominal):
        analyzer_out = nestjs_repo_nominal / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(nestjs_repo_nominal),
            "src/call.service.impl.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0

        data = json.loads(analyzer_out.read_text())
        base_types = (find_class(data["classes"], "CallServiceImpl") or {}).get("baseTypes", [])
        assert "ICallService" in base_types

    def test_generic_implements_stripped(self, tmp_path):
        """implements Repository<User> should store as Repository."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "impl.ts").write_text("""\
export class UserRepo implements Repository<User> {
    findOne(id: string) { return null; }
}
""")
        analyzer_out = tmp_path / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(tmp_path),
            "src/impl.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0

        data = json.loads(analyzer_out.read_text())
        base_types = (find_class(data["classes"], "UserRepo") or {}).get("baseTypes", [])
        assert "Repository" in base_types
        assert not any("<" in t for t in base_types)

    def test_extracts_extends(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "impl.ts").write_text("""\
export class ConcreteService extends BaseService {
    run() { return true; }
}
""")
        analyzer_out = tmp_path / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(tmp_path),
            "src/impl.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0

        data = json.loads(analyzer_out.read_text())
        base_types = (find_class(data["classes"], "ConcreteService") or {}).get("baseTypes", [])
        assert "BaseService" in base_types


class TestNominalTypeResolution:
    """Test that implements/extends clauses are used for DI resolution."""

    def test_resolves_via_implements(self, nestjs_repo_nominal):
        """this.callService.getById() resolves to CallServiceImpl.getById via implements."""
        data = analyze_and_resolve(nestjs_repo_nominal, [
            "src/call.resolver.ts",
            "src/call.service.impl.ts",
        ])

        call_graph = data["callGraph"]
        resolver_calls = None
        for fid, calls in call_graph.items():
            if "CallResolver.getCall" in fid:
                resolver_calls = calls
                break

        assert resolver_calls is not None, "CallResolver.getCall not in call graph"
        assert any(
            "CallServiceImpl.getById" in c for c in resolver_calls
        ), f"Expected CallServiceImpl.getById via implements, got: {resolver_calls}"

    def test_nominal_ambiguity_skips_resolution(self, tmp_path):
        """Two classes implementing same interface → no resolution (ambiguous)."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "resolver.ts").write_text("""\
export class MyResolver {
    constructor(private svc: IMyService) {}
    work() { return this.svc.run(); }
}
""")
        (src / "impl_a.ts").write_text("""\
export class ImplA implements IMyService {
    run() { return 'a'; }
}
""")
        (src / "impl_b.ts").write_text("""\
export class ImplB implements IMyService {
    run() { return 'b'; }
}
""")
        data = analyze_and_resolve(tmp_path, [
            "src/resolver.ts",
            "src/impl_a.ts",
            "src/impl_b.ts",
        ])

        call_graph = data["callGraph"]
        resolver_calls = None
        for fid, calls in call_graph.items():
            if "MyResolver.work" in fid:
                resolver_calls = calls
                break

        assert resolver_calls is not None
        assert not any(
            "ImplA.run" in c or "ImplB.run" in c for c in resolver_calls
        ), f"Should not resolve ambiguous implements, got: {resolver_calls}"


class TestFieldDepsExtraction:
    """Test that @Inject* decorators and inject() function are captured as fieldDeps."""

    def test_extracts_inject_decorator(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "service.ts").write_text("""\
import { Injectable, Inject } from '@nestjs/common';

@Injectable()
export class MyService {
    @Inject('TOKEN')
    private depService: DepService;

    run() { return this.depService.execute(); }
}
""")
        analyzer_out = tmp_path / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(tmp_path),
            "src/service.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0
        data = json.loads(analyzer_out.read_text())
        field_deps = (find_class(data["classes"], "MyService") or {}).get("fieldDeps", {})
        assert field_deps.get("depService") == "DepService"

    def test_extracts_inject_repository_decorator(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "service.ts").write_text("""\
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class UserService {
    @InjectRepository(User)
    private userRepo: Repository<User>;

    findAll() { return this.userRepo.find(); }
}
""")
        analyzer_out = tmp_path / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(tmp_path),
            "src/service.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0
        data = json.loads(analyzer_out.read_text())
        field_deps = (find_class(data["classes"], "UserService") or {}).get("fieldDeps", {})
        assert field_deps.get("userRepo") == "Repository"

    def test_extracts_functional_inject(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "component.ts").write_text("""\
import { inject } from '@angular/core';

export class MyComponent {
    private authService = inject(AuthService);

    login() { return this.authService.signIn(); }
}
""")
        analyzer_out = tmp_path / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(tmp_path),
            "src/component.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0
        data = json.loads(analyzer_out.read_text())
        field_deps = (find_class(data["classes"], "MyComponent") or {}).get("fieldDeps", {})
        assert field_deps.get("authService") == "AuthService"

    def test_ignores_non_inject_decorator(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "service.ts").write_text("""\
export class MyService {
    @Column()
    private name: string;

    getName() { return this.name; }
}
""")
        analyzer_out = tmp_path / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(tmp_path),
            "src/service.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0
        data = json.loads(analyzer_out.read_text())
        field_deps = (find_class(data["classes"], "MyService") or {}).get("fieldDeps", {})
        assert "name" not in field_deps

    def test_resolves_field_injection_calls(self, tmp_path):
        """Calls via @Inject field deps resolve correctly through the full pipeline."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "service.ts").write_text("""\
import { Injectable, Inject } from '@nestjs/common';

@Injectable()
export class MyService {
    @Inject('TOKEN')
    private depService: DepService;

    run() { return this.depService.execute(); }
}
""")
        (src / "dep_service.ts").write_text("""\
export class DepService {
    execute() { return 'done'; }
}
""")
        data = analyze_and_resolve(tmp_path, [
            "src/service.ts",
            "src/dep_service.ts",
        ])
        call_graph = data["callGraph"]
        service_calls = next(
            (calls for fid, calls in call_graph.items() if "MyService.run" in fid), None
        )
        assert service_calls is not None, "MyService.run not in call graph"
        assert any("DepService.execute" in c for c in service_calls), \
            f"Expected DepService.execute via field injection, got: {service_calls}"


class TestDIAwareCallResolution:
    """Test that the dependency resolver uses constructorDeps for DI resolution."""

    def test_resolves_exact_type_match(self, nestjs_repo):
        """this.callService.getById() resolves to CallService.getById."""
        data = analyze_and_resolve(nestjs_repo, [
            "src/call.resolver.ts",
            "src/call.service.ts",
        ])

        call_graph = data["callGraph"]

        # Find CallResolver.getCall's call graph
        resolver_calls = None
        for fid, calls in call_graph.items():
            if "CallResolver.getCall" in fid:
                resolver_calls = calls
                break

        assert resolver_calls is not None, "CallResolver.getCall not in call graph"
        assert any(
            "CallService.getById" in c for c in resolver_calls
        ), f"Expected CallService.getById in calls, got: {resolver_calls}"

    def test_resolves_versioned_implementation(self, nestjs_repo_versioned):
        """this.callService.getById() resolves to CallServiceV2.getById via prefix match."""
        data = analyze_and_resolve(nestjs_repo_versioned, [
            "src/call.resolver.ts",
            "src/call.service.ts",
        ])

        call_graph = data["callGraph"]
        resolver_calls = None
        for fid, calls in call_graph.items():
            if "CallResolver.getCall" in fid:
                resolver_calls = calls
                break

        assert resolver_calls is not None
        assert any(
            "CallServiceV2.getById" in c for c in resolver_calls
        ), f"Expected CallServiceV2.getById in calls, got: {resolver_calls}"

    def test_resolves_multiple_di_methods(self, nestjs_repo):
        """Both getById and remove should resolve to CallService methods."""
        data = analyze_and_resolve(nestjs_repo, [
            "src/call.resolver.ts",
            "src/call.service.ts",
        ])

        call_graph = data["callGraph"]

        # deleteCall should resolve to CallService.remove
        delete_calls = None
        for fid, calls in call_graph.items():
            if "CallResolver.deleteCall" in fid:
                delete_calls = calls
                break

        assert delete_calls is not None
        assert any(
            "CallService.remove" in c for c in delete_calls
        ), f"Expected CallService.remove in calls, got: {delete_calls}"

    def test_ambiguous_prefix_skips_resolution(self, tmp_path):
        """When multiple classes share a type-name prefix, resolution is skipped."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "resolver.ts").write_text("""\
export class MyResolver {
    constructor(private callService: CallService) {}
    getCall(id: string) {
        return this.callService.getById(id);
    }
}
""")
        (src / "call_service.ts").write_text("""\
export class CallServiceV1 {
    getById(id: string) { return 'v1'; }
}
""")
        (src / "call_service_mock.ts").write_text("""\
export class CallServiceMock {
    getById(id: string) { return 'mock'; }
}
""")
        data = analyze_and_resolve(tmp_path, [
            "src/resolver.ts",
            "src/call_service.ts",
            "src/call_service_mock.ts",
        ])

        call_graph = data["callGraph"]
        resolver_calls = None
        for fid, calls in call_graph.items():
            if "MyResolver.getCall" in fid:
                resolver_calls = calls
                break

        # Two classes match the CallService prefix — should not resolve to either
        assert resolver_calls is not None
        assert not any(
            "CallServiceV1.getById" in c or "CallServiceMock.getById" in c
            for c in resolver_calls
        ), f"Should not resolve ambiguous prefix match, got: {resolver_calls}"

    def test_no_false_positives_without_di(self, tmp_path):
        """Methods without constructor deps should not spuriously resolve."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "plain.ts").write_text("""\
export class PlainService {
    doWork() {
        return this.unknownService.process();
    }
}
""")
        (src / "other.ts").write_text("""\
export class UnknownService {
    process() {
        return 42;
    }
}
""")
        data = analyze_and_resolve(tmp_path, [
            "src/plain.ts",
            "src/other.ts",
        ])

        call_graph = data["callGraph"]
        plain_calls = None
        for fid, calls in call_graph.items():
            if "PlainService.doWork" in fid:
                plain_calls = calls
                break

        # Without constructor deps, unknownService.process() should NOT resolve
        assert plain_calls is not None
        assert not any(
            "UnknownService.process" in c for c in plain_calls
        ), f"Should not resolve without DI metadata, got: {plain_calls}"
