"""
Entry Point Detector

Identifies entry points where user input enters the application.
Entry points are functions that directly receive external input such as:
- HTTP route handlers (Flask, FastAPI, Django, Express)
- CLI argument handlers (argparse, click, sys.argv)
- WebSocket handlers
- File/stdin readers
- Streamlit input widgets

This is used for reachability analysis to determine if vulnerable code
can be reached from user-controlled input.

Usage:
    detector = EntryPointDetector(functions, call_graph)
    entry_points = detector.detect_entry_points()
    # entry_points is a set of func_ids that are entry points
"""

import re
from typing import Dict, List, Set


def _unit_type(func_data: Dict) -> str:
    """Read a unit's type tolerating both key casings.

    The per-parser reachable path normalizes function metadata under the
    camelCase key ``unitType`` (parsers/{c,php,ruby}/test_pipeline.py), while the
    central Python path and this detector historically used the snake_case
    ``unit_type``. Reading only one casing left Check-1 (and the module_level
    Check-4) dead on the camelCase path — a valid entry type was silently
    ignored. Prefer snake_case, fall back to camelCase.
    """
    return func_data.get('unit_type') or func_data.get('unitType') or ''


# Entry point patterns by unit_type (from function extractor classification)
ENTRY_POINT_TYPES = {
    'route_handler',      # Flask/FastAPI/Express routes
    'route_middleware',   # Express anonymous middleware callbacks (req, res, next)
    'view_function',      # Django views
    'websocket_handler',  # WebSocket endpoints
    'cli_handler',        # CLI commands
    # Native program entry points emitted by the systems-language parsers.
    # The C and Go extractors classify a top-level `main` as unit_type='main'
    # (parsers/c/function_extractor.py, go_parser/types.go UnitTypeMain); the
    # Zig extractor does too once its `main` classifier branch is fixed. Without
    # these the only seed for a compiled binary is absent, so reachability seeds
    # zero entry points and silently empties the dataset for every C/Go/Zig repo.
    'main',               # C/Go/Zig program entry
    # Go runs every package-level `func init()` automatically at startup, before
    # main (Go spec: Package initialization). The Go extractor classifies it as
    # unit_type='init' (go_parser/types.go UnitTypeInit). It is an execution root,
    # so its transitive callees (config loaders, registrations, side-effecting
    # startup code that can reach sinks) must be reachable; omitting it blacked
    # them out. Over-approximating an auto-run root is reachability-safe.
    'init',               # Go package init() — auto-run startup root
    'http_handler',       # Go net/http handlers (go_parser/types.go UnitTypeHTTPHandler)
    'middleware',         # Go HTTP middleware (go_parser/types.go UnitTypeMiddleware)
}

# Decorator patterns indicating entry points (case-insensitive matching)
ENTRY_POINT_DECORATORS = [
    # Python web frameworks
    r'@app\.route',
    r'@router\.(get|post|put|delete|patch|options|head|websocket)',
    # N3 fix: FastAPI / Flask 2.0 direct-app decorators (@app.get/@app.post/…),
    # the canonical modern idiom, previously unmatched by any pattern here. The
    # trailing \b keeps it from over-matching @app.getter / @app.headers.
    r'@app\.(get|post|put|delete|patch|options|head|websocket)\b',
    r'@blueprint\.',
    # F4 additive: custom APIRouter / router instances — `@api.get`, `@v1.post`,
    # `@router.api_route`, any method on an `api`/`v1`/`router` receiver. ADDED
    # alongside the `@router\.(get|...)` pattern above (which stays); this widens
    # to custom-named routers the fixed verb list misses. Over-seeding is safe.
    r'@(api|v1|router)\.\w',
    # F4 additive: aiohttp RouteTableDef — `@routes.get`/`@routes.post`/`@routes.view`/...
    r'@routes\.(get|post|put|delete|patch|options|head|view|route|static)\b',
    # F4 additive: Starlette websocket route decorator `@app.websocket_route`
    # (the `@app\.(...|websocket)\b` pattern below misses it — the `_route` suffix
    # defeats the word boundary after `websocket`).
    r'@app\.websocket_route',
    r'@(get|post|put|delete|patch)\b',
    r'@api_view',
    r'@action\b',
    # Django
    r'@require_(GET|POST|http_methods)',
    r'@csrf_exempt',
    # WebSockets
    r'@(websocket|socketio|sio)\.',
    r'@app\.on_event',
    # CLI
    r'@click\.(command|group)',
    r'@app\.command',
    # JavaScript/TypeScript (as comments or decorators)
    r'@(Get|Post|Put|Delete|Patch)\(',
    r'@Controller\(',
    r'@WebSocketGateway',
    # Swift: ObjC-exposed / Interface-Builder-invoked methods are externally
    # callable via the ObjC runtime / UI even when they are not `public`, so a
    # method carrying one is an entry-point root. The Swift extractor emits these
    # as `decorators` (base name, e.g. '@objc', '@IBAction'). Over-seeding an
    # externally-invokable method is reachability-safe.
    r'@objc\b',
    r'@IBAction\b',
    r'@IBSegueAction\b',
]

# PHP 8 routing attributes (Symfony / API-Platform): `#[Route(...)]`, `#[Get]`,
# `#[Post]`, ... A method carrying one of these IS a route handler regardless of
# the class name, so a handler on a class NOT named *Controller (which the PHP
# extractor's name/path-based classifier leaves as a plain `method`) is still
# seeded as an entry point.
ROUTE_ATTRIBUTE_PATTERNS = [
    # A PHP 8 routing attribute anywhere in the attribute list — not only right
    # after `#[`. Allows a namespace prefix (#[Routing\Route], #[\Symfony\...\Route]),
    # grouped attributes (#[Foo, Route(...)]), and (with IGNORECASE at compile)
    # case-insensitive class names, since PHP class names are case-insensitive.
    r'#\[[^\]]*\b(Route|Get|Post|Put|Delete|Patch|Options|Head)\b',
]

# Code patterns indicating direct user input sources
USER_INPUT_PATTERNS = [
    # Flask
    r'request\.(args|form|json|data|files|values|get_json)',
    r'request\.environ',
    # FastAPI
    r'request\.(query_params|body|json)',
    r'\b(Query|Body|Form|File|Header|Cookie)\s*\(',
    # Django
    r'request\.(GET|POST|data|FILES|body)',
    r'self\.request\.(GET|POST|data)',
    # Express.js
    r'req\.(body|query|params|cookies|headers)',
    r'req\.file[s]?',
    # CLI arguments
    r'sys\.argv',
    r'argparse\.',
    r'\bArgumentParser\s*\(',
    r'click\.(argument|option)',
    # Ruby CLI / stdin / env: a method that reads these IS a user-input entry
    # point, including the dominant `def run; ...ARGV...; end` behind an
    # `if __FILE__ == $0` guard (the sink lives in a `function` unit, so it must
    # be seeded by this check, not only the module_level check). Mirrors sys.argv.
    r'\bARGV\b',
    r'\bgets\b',
    r'\bSTDIN\b',
    r'\$stdin\b',
    r'\bENV\s*(\[|\.(fetch|values_at|dig|to_h|slice)\b)',
    # Standard input
    r'\binput\s*\(',
    r'sys\.stdin',
    r'fileinput\.',
    # Environment variables (often contain secrets/config)
    r'os\.environ\[',
    r'os\.getenv\s*\(',
    r'environ\.get\s*\(',
    # Streamlit (user input widgets)
    r'st\.(text_input|text_area|number_input|selectbox|multiselect)',
    r'st\.(slider|checkbox|radio|file_uploader|date_input|time_input)',
    r'st\.(color_picker|camera_input|data_editor)',
    # File reading (external data source)
    r'open\s*\([^)]*["\']r',
    r'Path\([^)]*\)\.read_',
    # WebSocket message handlers
    r'on_message|onmessage|message\.data',
    r'websocket\.receive',
    # PHP superglobals (request/server/file/cookie input)
    r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV|SESSION)\b',
    r'\$HTTP_RAW_POST_DATA\b',
    r'php://input',
    r'\bfile_get_contents\s*\(\s*["\']php://input',
    r'\bfilter_input\s*\(',
    # Symfony request reads, anchored to a $request / $req / $this->request
    # receiver so they read HTTP input, not an unrelated ->query->all() on an
    # ORM builder or a ->headers->get() on the app's own response object.
    #  - request bags:   $request->query->get(...) / ->request-> / ->cookies-> / ...
    #  - direct methods: $request->get(...) / ->getPayload() / ->getContent() /
    #                    ->toArray() / ->input(...) / ->all()
    r'(\$(request|req)\b|\$this\s*->\s*request\b)\s*->\s*(query|request|cookies|attributes|headers|files)\s*->\s*(get|all)\s*\(',
    r'(\$(request|req)\b|\$this\s*->\s*request\b)\s*->\s*(get|getPayload|getContent|toArray|input|all)\s*\(',
    # Swift daemon / CLI / stdin / XPC / network input surfaces. Apple's
    # security-pcc and similar frameworks expose their attack surface through
    # daemon request handling (XPC listeners, network listeners) and CLI/stdin —
    # not a web `main`. A method that reads one of these IS a user-input entry
    # point even when it is `internal` (so public-API seeding alone would miss it).
    r'CommandLine\.arguments',
    r'ProcessInfo\.processInfo\.(arguments|environment)',
    r'\breadLine\s*\(',
    r'FileHandle\.standardInput',
    r'\bNSXPCListener\b',
    r'\bshouldAcceptNewConnection\b',
    r'\bxpc_connection_',
    r'\bNWListener\b',
    # Rust CLI / stdin / env input surfaces: a function that reads these IS a
    # user-input entry point even when it carries no route/main marker of its
    # own (e.g. a helper called from `main` via `std::env::args()`).
    # #355: std::env::var — the ORDINARY env read — was missing (args was
    # listed; var was not), so a Rust config reader seeded through neither
    # route.
    r'std::env::args',
    r'\benv::args(?:_os)?\b',
    r'std::env::var',
    # wave r1 (fable): the trailing \b rejected env::var_os / env::vars —
    # after `use std::env;` (the idiomatic import) the short forms were
    # unseeded through BOTH routes while the fully-qualified form matched.
    r'\benv::var(?:s|_os)?\b',
    r'\bstd::io::stdin\b',
    r'\bio::stdin\b',
    r'\bstdin\(\)',
    # #355: JavaScript/TypeScript CLI / env / stdin — Node reads argv through
    # process.argv, configuration AND SECRETS through process.env, and stdin
    # through process.stdin; the argv-parse libraries and readline are the same
    # surface as Python's argparse/click block above. The JS parser assigns
    # these units unit_type=function (typescript_analyzer.js) with NO
    # cli_handler classifier, so without this block NEITHER check seeds them.
    r'process\.argv',
    r'process\.env',
    r'process\.stdin',
    r'\byargs\b',
    r'\bcommander\b',
    r'\bminimist\b',
    r'\breadline\b',
    # #355: Go env reads — os.Getenv / os.LookupEnv. argv needs no idiom (the
    # parser classifies os.Args code as cli_handler, extractor.go:344, so
    # Check 1 seeds it), but env had no route at all; flag. is the CLI-args
    # idiom for the flag package (flag.Parse/flag.String).
    r'\bos\.Getenv\s*\(',
    r'\bos\.LookupEnv\s*\(',
    r'\bflag\.',
    # #355: C CLI / env — getenv( and argc/argv: a non-`main` helper taking
    # argc/argv is seeded only under apps/ via the parser's cli_handler gate
    # (c/function_extractor.py:353-356), a property of the DIRECTORY, not of
    # the code; the idiom closes the gap for every directory. Over-seeding is
    # the safe direction (a false entry point costs analysis budget; a missing
    # one silently drops a unit and everything reachable only through it).
    # `\bgetenv\s*\(` also covers PHP's getenv() — the lists are not
    # language-scoped (the documented \bgets\b accident above).
    r'\bgetenv\s*\(',
    r'\bargv\b',
    r'\bargc\b',
    # #355: PHP CLI forms — the web-superglobal pattern covers
    # $_SERVER['argv'] and $_ENV by accident; the direct CLI forms matched
    # nothing.
    r'\$argv\b',
    # #355: Zig CLI / env — std.process args (one prefix covers args and
    # argsAlloc) and the env-var reader. The Zig parser assigns
    # unit_type=function with no cli route.
    r'std\.process\.args',
    r'getEnvVarOwned',
]

# Patterns that indicate module-level scripts with user input
MODULE_LEVEL_INPUT_PATTERNS = [
    r'if\s+__name__\s*==\s*["\']__main__["\']',
    r'sys\.argv',
    r'\binput\s*\(',
    r'argparse\.',
    # PHP file-scope scripts: superglobal reads and WordPress hook dispatch
    # (procedural plugins/themes register handlers at the top level).
    r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV|SESSION)\b',
    r'php://input',
    r'\badd_action\s*\(',
    r'\badd_filter\s*\(',
    r'\bdo_action\s*\(',
    r'\bapply_filters\s*\(',
    # Ruby file-scope scripts (bin/ executables, Rakefiles): CLI args, stdin and
    # env reads that run on load, so a module_level unit carrying them is a
    # user-input entry point.
    r'\bARGV\b',
    r'\bSTDIN\b',
    r'\$stdin\b',
    r'\bgets\b',
    r'\bENV\[',
]


class EntryPointDetector:
    """
    Detects entry points in a codebase where user input enters the application.

    Entry points are the starting points for reachability filtering. What the
    filter computes today is call-graph reachability: a unit with no recorded
    call path from any entry point is dropped — a claim about the parsed
    call graph, not a proof of unexploitability (an edge the parser did not
    record produces the same result as dead code). "Taint analysis" is the
    roadmap framing, not a description of the current filter.

    Attributes:
        functions: Dict of func_id -> func_data from extractor
        call_graph: Forward call graph (func_id -> [called_func_ids])
        entry_points: Set of func_ids identified as entry points
        entry_point_details: Dict with details about why each is an entry point
    """

    def __init__(self, functions: Dict, call_graph: Dict):
        """
        Initialize the detector.

        Args:
            functions: Dict mapping func_id to function metadata
            call_graph: Forward call graph from CallGraphBuilder
        """
        self.functions = functions
        self.call_graph = call_graph
        self.entry_points: Set[str] = set()
        self.entry_point_details: Dict[str, Dict] = {}

        # Compile regex patterns for efficiency
        self._decorator_patterns = [
            re.compile(p, re.IGNORECASE) for p in ENTRY_POINT_DECORATORS
        ]
        self._route_attribute_patterns = [
            re.compile(p, re.IGNORECASE) for p in ROUTE_ATTRIBUTE_PATTERNS
        ]
        self._input_patterns = [
            re.compile(p) for p in USER_INPUT_PATTERNS
        ]
        self._module_input_patterns = [
            re.compile(p) for p in MODULE_LEVEL_INPUT_PATTERNS
        ]

    def detect_entry_points(self) -> Set[str]:
        """
        Identify all entry points in the codebase.

        Returns:
            Set of func_ids that are entry points
        """
        for func_id, func_data in self.functions.items():
            reasons = self._get_entry_point_reasons(func_data)
            if reasons:
                self.entry_points.add(func_id)
                self.entry_point_details[func_id] = {
                    'reasons': reasons,
                    'unit_type': _unit_type(func_data),
                    'name': func_data.get('name'),
                    # A synthesized fuzz harness seeds the BFS (unit_type=main) but
                    # is NOT a real structural entry point; record the tag so the
                    # blackout advisory can exclude it from the structural count.
                    'synthetic_harness': bool(
                        func_data.get('synthetic_harness')
                        or func_data.get('syntheticHarness')),
                    # A build.rs / examples/ / benches/ `main` seeds the BFS
                    # (unit_type=main) but is NOT the crate's runtime entry point;
                    # tag it so the blackout advisory excludes it from the
                    # structural count (the seed is kept).
                    'non_runtime_main': _is_non_runtime_main(
                        func_data.get('file_path') or func_data.get('filePath') or ''),
                }

        return self.entry_points

    def _get_entry_point_reasons(self, func_data: Dict) -> List[str]:
        """
        Determine why a function is an entry point.

        Args:
            func_data: Function metadata from extractor

        Returns:
            List of reasons (empty if not an entry point)
        """
        reasons = []

        # Check 1: Unit type indicates entry point
        unit_type = _unit_type(func_data)
        if unit_type in ENTRY_POINT_TYPES:
            reasons.append(f'unit_type:{unit_type}')

        # Check 1b: A function named `main` is a program execution root by name,
        # even when the extractor classified its unit_type as something else
        # (defensive: covers language extractors that emit a generic unit_type
        # for main). A program's main is an entry point; over-approximating it
        # is reachability-safe.
        elif func_data.get('name') == 'main':
            reasons.append('name:main')

        # Check 1c: A PHP 8 routing attribute (#[Route]/#[Get]/#[Post]/...) marks
        # the method as a route handler INDEPENDENT of the class name. Symfony /
        # API-Platform endpoints live on classes not named *Controller, which the
        # PHP extractor's name/path-based classifier leaves as a plain `method`;
        # the attribute is the authoritative signal.
        decorators = func_data.get('decorators', [])
        decorators_str = ' '.join(decorators)
        for pattern in self._route_attribute_patterns:
            if pattern.search(decorators_str):
                reasons.append('unit_type:route_handler')
                break

        # Check 2: Decorators indicate entry point
        for pattern in self._decorator_patterns:
            if pattern.search(decorators_str):
                reasons.append(f'decorator:{pattern.pattern}')
                break  # One decorator match is enough

        # Check 3: Code contains user input patterns
        code = func_data.get('code', '')
        for pattern in self._input_patterns:
            match = pattern.search(code)
            if match:
                reasons.append(f'input_pattern:{match.group(0)[:30]}')
                break  # One input pattern is enough

        # Check 4: Module-level code with input patterns
        if unit_type == 'module_level':
            for pattern in self._module_input_patterns:
                if pattern.search(code):
                    reasons.append('module_level_with_input')
                    break

        return reasons

    def is_entry_point(self, func_id: str) -> bool:
        """Check if a function is an entry point."""
        if not self.entry_points:
            self.detect_entry_points()
        return func_id in self.entry_points

    def get_entry_point_reason(self, func_id: str) -> str:
        """Get human-readable reason why func_id is an entry point."""
        if func_id not in self.entry_point_details:
            return ""
        details = self.entry_point_details[func_id]
        return "; ".join(details.get('reasons', []))

    def get_statistics(self) -> Dict:
        """Get statistics about detected entry points."""
        if not self.entry_points:
            self.detect_entry_points()

        by_type = {}
        by_reason = {}

        for func_id, details in self.entry_point_details.items():
            unit_type = details.get('unit_type', 'unknown')
            by_type[unit_type] = by_type.get(unit_type, 0) + 1

            for reason in details.get('reasons', []):
                reason_category = reason.split(':')[0]
                by_reason[reason_category] = by_reason.get(reason_category, 0) + 1

        return {
            'total_entry_points': len(self.entry_points),
            'total_functions': len(self.functions),
            'entry_point_percentage': round(
                len(self.entry_points) / len(self.functions) * 100, 1
            ) if self.functions else 0,
            'by_unit_type': by_type,
            'by_reason_category': by_reason,
        }


def library_seed_ids(functions):
    """Public-API seed set for library-mode reachability.

    A pure library exposes no main/route/CLI entry point, so the structural
    detector finds nothing and the whole library is filtered out (0 reachable).
    In library-mode the *public surface* IS the entry surface: seed every
    exported/public function and let the forward BFS pull in its callees.

    Public = exported AND not name-private. Honours ``is_exported``/``isExported``
    when the parser provides it (C/Go/JS exclude static/unexported); for parsers
    without the field (python/ruby/php) it defaults True and the leading-underscore
    name heuristic decides. Both key casings are accepted because the subprocess
    pipelines normalize to camelCase while the on-disk call_graph is snake_case.
    The bias is intentionally toward over-seeding (more reachable = more analysed),
    never under-seeding.
    """
    seeds = set()
    for func_id, fd in functions.items():
        name = (fd.get("name") or func_id.rsplit(":", 1)[-1]).split(".")[-1]
        exported = fd.get("is_exported", fd.get("isExported", True))
        if exported and not name.startswith("_"):
            seeds.add(func_id)
    return seeds


def real_entry_point_ids(entry_points, functions):
    """Entry-point ids that are REAL structural seeds — excludes synthesized
    fuzz harnesses.

    A libFuzzer ``fuzz_target!`` harness is lifted as an entry point with
    ``unit_type=main`` (so it seeds the BFS) but it is NOT a program root: it is
    tagged ``synthetic_harness=True``. When the ONLY seeds are synthetic
    harnesses — a pure-library-plus-fuzz target whose real public API is often
    macro-hidden from the call graph — the keep-all blackout net must still fire
    instead of trusting the harness-only reachable set, which would silently drop
    the un-reached exported surface. Shared by ``core.parser_adapter`` and the
    rust pipeline so the two nets cannot drift. Both key casings are accepted
    (subprocess pipelines normalize to camelCase while the on-disk call_graph is
    snake_case), matching ``library_seed_ids``.
    """
    return {
        ep for ep in entry_points
        if not (functions.get(ep, {}).get("synthetic_harness")
                or functions.get(ep, {}).get("syntheticHarness"))
    }


# Reason categories that indicate a STRUCTURAL entry point — a real route, program
# main, CLI command, framework handler, or decorator-marked endpoint — as opposed
# to an INCIDENTAL match (code merely contains an input-reading pattern). A result
# seeded ONLY by incidental matches is the library-blackout signature: the public
# API was never a seed, so the BFS dropped the core.
_STRUCTURAL_REASON_CATEGORIES = {"unit_type", "decorator", "name"}


def _is_non_runtime_main(file_path: str) -> bool:
    """True when a `main` in this file runs at build/example/bench time rather
    than as the crate's deployed runtime entry point, so it must NOT count as a
    structural entry point for the blackout advisory. The main is still SEEDED
    (over-seeding is reachability-safe); only the advisory's structural count
    excludes it. Mirrors the ``synthetic_harness`` exclusion, path-based on Cargo
    conventions:

      * a crate-root ``build.rs`` (compile-time build script), and
      * ``examples/`` and ``benches/`` targets (auxiliary binaries that consume
        the public API rather than being it).

    A file UNDER ``src/`` is an ordinary module, never one of these targets, so
    it is left alone (a ``src/build.rs`` module or ``src/examples/`` submodule
    stays structural).

    Scope note: this is a purely path-based check applied to every language's
    functions (the detector is shared across all parsers), not gated to Rust.
    ``build.rs`` is Rust-specific, but ``examples/`` and ``benches/`` are a
    common cross-language layout for non-runtime auxiliary code, so treating a
    top-level ``examples/``/``benches/`` main as non-structural is intended for
    any language — a Go/Python ``examples/`` demo is a consumer of the API, not
    its structural entry point. The effect is confined to the advisory string
    (never seeding), so the worst case is the library-blackout advisory firing
    for a project whose only entry lives under ``examples/`` — which is itself a
    library-shaped project the advisory means to flag.

    Documented residual limits: a build script renamed via Cargo's
    ``build = "custom.rs"`` manifest key is not recognised; a non-crate-root file
    literally named ``build.rs`` (e.g. ``scripts/build.rs``) is over-tagged
    (advisory noise only); and — pre-existing, orthogonal to this change — the
    advisory itself is written only to ``metadata.reachability_filter.warning``
    and stderr, not the CLI JSON/exit envelope, so a correctly-fired warning is
    not yet surfaced to a CI consumer. This is a conservative check: an
    unknown/empty path returns False (counts structural, i.e. pre-fix
    behaviour), never dropping a real structural seed.
    """
    if not file_path:
        return False
    parts = file_path.replace("\\", "/").split("/")
    ancestors = parts[:-1]
    if "src" in ancestors:
        return False
    if parts[-1] == "build.rs":
        return True
    return "examples" in ancestors or "benches" in ancestors


def blackout_warning(entry_point_details, original_count, reachable_count,
                     library_mode=False, reduction_threshold=0.90):
    """Advisory string when a reachability result looks like a silent library
    blackout, else None. This is ADVISORY ONLY — it never changes which units
    are kept.

    Two triggers (both off when ``library_mode`` is set, since then the public
    API was deliberately seeded and a high reduction is the intended result):
      * total blackout — 0 of N units kept (no seedable frontier); or
      * partial blackout — >= ``reduction_threshold`` pruned AND no STRUCTURAL
        entry point was found (every seed is an incidental ``input_pattern``
        match). This is the case that slips past the zero-seed net: a handful of
        incidental seeds yield a 96%+ reduction that looks like success while the
        real public API surface was never analysed (e.g. a C/JS parser library).
    """
    if original_count <= 0 or library_mode:
        return None
    if reachable_count == 0:
        return (f"Reachability kept 0 of {original_count} units — total blackout "
                f"(no entry point could seed the frontier). If this is a library, "
                f"re-run with --library-mode to seed the exported public API surface.")
    reduction = 1.0 - (reachable_count / original_count)
    structural = sum(
        1 for d in (entry_point_details or {}).values()
        if not d.get("synthetic_harness")
        and not d.get("non_runtime_main")
        and any(r.split(":", 1)[0] in _STRUCTURAL_REASON_CATEGORIES
                for r in d.get("reasons", []))
    )
    if reduction >= reduction_threshold and structural == 0:
        return (f"Reachability kept {reachable_count} of {original_count} units "
                f"({reduction * 100:.0f}% pruned) but found NO structural entry point "
                f"(route/main/CLI/handler) — only incidental code-pattern seeds. This is "
                f"the library-blackout pattern: the public API was not seeded, so the core "
                f"was dropped. Re-run with --library-mode to seed the exported public API.")
    return None
