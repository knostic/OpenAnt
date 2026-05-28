"""Tests for AST-shape inventory gaps in the JS analyzer.

Each test feeds an inline fixture with a particular function-defining AST
shape and asserts the function appears in the analyzer's `functions` map.

Skips when Node.js or the parser's npm dependencies aren't installed.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest


PARSERS_JS_DIR = Path(__file__).parent.parent.parent.parent / "parsers" / "javascript"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def _analyze(repo_path, file_path):
    cmd = ["node", str(PARSERS_JS_DIR / "typescript_analyzer.js"), str(repo_path), str(file_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (
        f"analyzer failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    return json.loads(result.stdout)


def _write(tmp_path, name, content, filename="file.js"):
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    fp = repo / filename
    fp.write_text(content)
    return repo, fp


# --- ClassExpression (module.exports = class {}) ------------------

def test_class_expression_methods_extracted(tmp_path):
    repo, fp = _write(
        tmp_path,
        "b073",
        "module.exports = class Service {\n  doWork() { return 1; }\n};\n",
    )
    out = _analyze(repo, fp)
    keys = list(out["functions"])
    assert any(k.endswith(":Service.doWork") for k in keys), (
        f"ClassExpression method `doWork` must be extracted; got {keys}"
    )


# --- anon export default fn, prototype assign, this.method, Object.assign ---

def test_anonymous_export_default_function(tmp_path):
    repo, fp = _write(
        tmp_path,
        "b088_default",
        "export default function(){ return secretHelper(); }\nfunction secretHelper(){ return 1; }\n",
    )
    out = _analyze(repo, fp)
    keys = list(out["functions"])
    assert any("default" in k for k in keys), (
        f"anonymous `export default function(){{}}` must be extracted; got {keys}"
    )


def test_prototype_method_assignment(tmp_path):
    repo, fp = _write(
        tmp_path,
        "b088_proto",
        "function Foo(){}\nFoo.prototype.bar = function(){ return 2; };\n",
    )
    out = _analyze(repo, fp)
    keys = list(out["functions"])
    assert any(k.endswith(":Foo.bar") for k in keys), (
        f"`Foo.prototype.bar = fn` must be extracted as Foo.bar; got {keys}"
    )


def test_object_assign_prototype(tmp_path):
    repo, fp = _write(
        tmp_path,
        "b088_assign",
        "function Foo(){}\nObject.assign(Foo.prototype, {\n  greet(){ return 'hi'; },\n  wave: function(){ return 'wave'; },\n});\n",
    )
    out = _analyze(repo, fp)
    keys = list(out["functions"])
    assert any(k.endswith(":Foo.greet") for k in keys), (
        f"`Object.assign(Foo.prototype, {{greet(){{}}}})` must extract greet; got {keys}"
    )
    assert any(k.endswith(":Foo.wave") for k in keys), (
        f"`Object.assign(Foo.prototype, {{wave: fn}})` must extract wave; got {keys}"
    )


# --- this.method = fn inside a constructor function ----------------

def test_this_method_in_constructor(tmp_path):
    repo, fp = _write(
        tmp_path,
        "b127",
        "function Ctor(){\n  this.handleLogin = function(){ return 3; };\n}\n",
    )
    out = _analyze(repo, fp)
    keys = list(out["functions"])
    assert any(k.endswith(":Ctor.handleLogin") for k in keys), (
        f"`this.handleLogin = fn` in a constructor must be extracted; got {keys}"
    )


# --- Object.defineProperty(X.prototype, "n", {value: fn}) ----------

def test_define_property_value_function(tmp_path):
    repo, fp = _write(
        tmp_path,
        "b092",
        'function X(){}\nObject.defineProperty(X.prototype, "n", { value: function(){ return 1; } });\n',
    )
    out = _analyze(repo, fp)
    keys = list(out["functions"])
    assert any(k.endswith(":X.n") for k in keys), (
        f"`Object.defineProperty(X.prototype, 'n', {{value: fn}})` must extract X.n; got {keys}"
    )


# --- top-level side-effect call -----------------------

def test_top_level_side_effect_call_yields_unit(tmp_path):
    repo, fp = _write(
        tmp_path,
        "m006",
        "contextBridge.exposeInMainWorld('api', { ping: () => 1 });\n",
    )
    out = _analyze(repo, fp)
    assert len(out["functions"]) >= 1, (
        f"a file with only a top-level side-effect call must emit >=1 unit; got {list(out['functions'])}"
    )


# --- HOC const initializer (memo/forwardRef/styled) ---

def test_hoc_const_initializer(tmp_path):
    repo, fp = _write(
        tmp_path,
        "m008",
        "const Card = memo(() => { return null; });\nconst Wrapped = forwardRef((props, ref) => { return null; });\n",
        filename="file.jsx",
    )
    out = _analyze(repo, fp)
    keys = list(out["functions"])
    assert any(k.endswith(":Card") for k in keys), (
        f"`const Card = memo(() => {{}})` must be extracted; got {keys}"
    )
    assert any(k.endswith(":Wrapped") for k in keys), (
        f"`const Wrapped = forwardRef(...)` must be extracted; got {keys}"
    )


# --- re-export barrel object literal -------------------------------

def test_reexport_barrel_property(tmp_path):
    repo, fp = _write(
        tmp_path,
        "b109",
        "module.exports = { foo: require('./x').foo };\n",
    )
    out = _analyze(repo, fp)
    keys = list(out["functions"])
    assert any(k.endswith(":exports.foo") or k.endswith(":foo") for k in keys), (
        f"re-export barrel `{{foo: require('./x').foo}}` must surface foo; got {keys}"
    )


# --- class accessors (getters/setters) dropped by getMethods() -----

def test_class_accessors_extracted_with_companion(tmp_path):
    """`get x(){}` / `set x(v){}` are excluded by ts-morph getMethods(), so they
    must be iterated via getGetAccessors()/getSetAccessors(). The accessor must
    appear in `functions` AND have a callGraph companion (Pattern-A)."""
    repo, fp = _write(
        tmp_path,
        "b126",
        "class Account {\n"
        "  get balance(){ return 1; }\n"
        "  set balance(v){ this._v = v; }\n"
        "  normalMethod(){ return 2; }\n"
        "}\n",
    )
    out = _analyze(repo, fp)
    funcs = list(out["functions"])
    graph = set(out["callGraph"])
    # The accessor `balance` must be emitted as a function.
    accessor_keys = [k for k in funcs if k.endswith(":Account.balance")]
    assert accessor_keys, (
        f"class accessor `get/set balance` must be extracted as Account.balance; got {funcs}"
    )
    # And it must have a callGraph companion (no Pattern-A asymmetry).
    for k in accessor_keys:
        assert k in graph, (
            f"accessor {k} present in functions but missing callGraph companion; graph={sorted(graph)}"
        )
    # Sanity: the plain method is still emitted.
    assert any(k.endswith(":Account.normalMethod") for k in funcs), (
        f"plain method normalMethod must still be extracted; got {funcs}"
    )
