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
    'http_handler',       # Go net/http handlers (go_parser/types.go UnitTypeHTTPHandler)
    'middleware',         # Go HTTP middleware (go_parser/types.go UnitTypeMiddleware)
}

# Decorator patterns indicating entry points (case-insensitive matching)
ENTRY_POINT_DECORATORS = [
    # Python web frameworks
    r'@app\.route',
    r'@router\.(get|post|put|delete|patch|options|head)',
    r'@blueprint\.',
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
]


class EntryPointDetector:
    """
    Detects entry points in a codebase where user input enters the application.

    Entry points are the starting points for taint analysis - if vulnerable code
    is not reachable from any entry point, it cannot be exploited by external users.

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

        # Check 2: Decorators indicate entry point
        decorators = func_data.get('decorators', [])
        decorators_str = ' '.join(decorators)
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


# Reason categories that indicate a STRUCTURAL entry point — a real route, program
# main, CLI command, framework handler, or decorator-marked endpoint — as opposed
# to an INCIDENTAL match (code merely contains an input-reading pattern). A result
# seeded ONLY by incidental matches is the library-blackout signature: the public
# API was never a seed, so the BFS dropped the core.
_STRUCTURAL_REASON_CATEGORIES = {"unit_type", "decorator", "name"}


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
        if any(r.split(":", 1)[0] in _STRUCTURAL_REASON_CATEGORIES
               for r in d.get("reasons", []))
    )
    if reduction >= reduction_threshold and structural == 0:
        return (f"Reachability kept {reachable_count} of {original_count} units "
                f"({reduction * 100:.0f}% pruned) but found NO structural entry point "
                f"(route/main/CLI/handler) — only incidental code-pattern seeds. This is "
                f"the library-blackout pattern: the public API was not seeded, so the core "
                f"was dropped. Re-run with --library-mode to seed the exported public API.")
    return None
