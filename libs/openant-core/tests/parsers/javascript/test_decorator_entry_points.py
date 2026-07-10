"""A framework route handler identified only by a decorator (NestJS @Get /
@Controller, Angular, ...) must be captured as a decorator by the TS analyzer
and seeded as a reachability entry point.

The analyzer emitted function records with no `decorators` field at all, so the
detector's decorator check (@Get/@Post/@Controller in ENTRY_POINT_DECORATORS)
could never fire for JS/TS — a decorated handler with no other input signal
seeded zero entry points and its whole subtree (the sink it calls) was a
reachability false negative.
"""
import json
import shutil
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[3]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

_NODE_MODULES = CORE / "parsers" / "javascript" / "node_modules"
pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not _NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)

from core.parser_adapter import parse_repository  # noqa: E402
from utilities.agentic_enhancer.entry_point_detector import EntryPointDetector  # noqa: E402

NEST_TS = (
    "import { Controller, Get } from '@nestjs/common';\n"
    "@Controller('users')\n"
    "export class UsersController {\n"
    "  @Get()\n"
    "  findAll() {\n"
    "    return dangerousQuery();\n"
    "  }\n"
    "}\n"
    "function dangerousQuery() { return 1; }\n"
)


def _run(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "users.controller.ts").write_text(NEST_TS)
    out = tmp_path / "out"
    out.mkdir()
    parse_repository(
        str(repo), str(out), language="javascript",
        processing_level="all", skip_tests=True, name="t",
    )
    return json.loads((out / "call_graph.json").read_text())


def test_decorated_nest_handler_is_captured_and_seeded(tmp_path):
    cg = _run(tmp_path)
    funcs = cg["functions"]
    call_graph = cg.get("call_graph", {})
    hid = "src/users.controller.ts:UsersController.findAll"
    assert hid in funcs, list(funcs)

    # 1. The analyzer captured the decorators (@Get / @Controller).
    decs = funcs[hid].get("decorators") or []
    assert any("Get" in d or "Controller" in d for d in decs), (
        f"the @Get/@Controller decorators must be captured; got {decs!r}"
    )

    # 2. The handler is seeded as an entry point via the decorator check.
    detector = EntryPointDetector(funcs, call_graph)
    seeds = detector.detect_entry_points()
    assert hid in seeds, (
        f"a @Get-decorated handler must be seeded; reasons={detector.entry_point_details.get(hid)}"
    )

    # 3. Its callee (the sink it invokes) is therefore reachable.
    reach = set(seeds)
    stack = list(seeds)
    while stack:
        for callee in call_graph.get(stack.pop(), []):
            if callee not in reach:
                reach.add(callee)
                stack.append(callee)
    sink = "src/users.controller.ts:dangerousQuery"
    assert sink in reach, (
        f"the handler's callee must be reachable via the decorated entry point; reachable={reach}"
    )
