"""#806 end-to-end regression: declaration-only ``.d.ts`` files create NO
analysis units — the FILE-LEVEL half of the C parser's declaration split
(whose own split is node-level: its extractor drops `declaration` nodes
inside ANY file; the boundary is named in the commit body), landed at
the TypeScript analyzer's unit-creation layer.

At the base (``parsers/javascript/typescript_analyzer.js``) the scanner
collected ``.d.ts`` files (the ``.ts`` extension list matches them) and
the analyzer built FUNCTION UNITS from declaration-only content —
``export declare function ...;`` signatures with no bodies. The ONE
existing ``.d.ts`` guard lived in a different layer
(``context_assembler.js:88``, excluded from CONTEXT assembly only) and
never reached unit creation. The measured base (the campaign's fixture,
re-executed at this cycle): **10 of 11 units were declaration-only** —
including a bogus whole-``declare module`` span unit — and only the one
real implementation survived. The issue's corpus read (the openbao
campaign): 24 ``.d.ts`` files / 50 extracted functions / 0 reached the
dataset — every one pure extraction and processing cost, with the
reachability filter as the only thing standing between the declarations
and an LLM call (the reach-to-analyze leg is fixture-only, named as such
by the issue itself).

The fix (the FILE-LEVEL half of the C parser's design contrast): the
type-aware check at the UNIT-CREATION layer — ts-morph's ``sourceFile.isDeclarationFile()`` in
``analyzeFiles``'s Step 2 (extraction) and Step 3 (call graph), so a
declaration file produces ZERO function units and ZERO edges while the
scanner still COLLECTS it and the file still counts as processed (the
C header analog: the prototypes are recorded, never analyzed). The
skip is OBSERVABLE: the new ``declaration_files_skipped`` stat rides
the analyzer's output on its own key — never inside the
processed/errors partition (the #713 family's bucket invariant holds).

The seeding surface follows: the unit_generator derives units from the
analyzer's ``functions`` map, so no ``.d.ts`` functions means no
``.d.ts`` analysis units and no seeding candidates — the falsifier's
"ordinary TypeScript implementations retain their existing extraction
and seeding behavior" is witnessed end-to-end (real.ts keeps its
isExported unit).

Hermetic: the CLI drive exactly as the production pipeline does (the
#713 convention: ``node typescript_analyzer.js <repo> --files-from
<listing> --output <out>``) over the campaign's fixture shapes.

Shapes:

  S1 -- the WITNESS (red at base): the campaign's dts fixture — ZERO
        ``.d.ts`` keys in the analyzer's functions map (10 at the base)
        and zero in the call graph.
  S2 -- the WITNESS (red at base): the surfaced split —
        ``statistics.declaration_files_skipped == 2`` (the key absent
        at the base), while the processed/errors partition holds
        (3 processed, 0 errors at BOTH trees — the files still load).
  S3 -- the CONTROL (green at base AND head): the ordinary
        implementation retains its extraction — real.ts:realHandler
        stands with ``isExported`` true, identical at both trees.
  S4 -- the WITNESS (red at base): the end-to-end seeding surface — the
        unit_generator, driven over the analyzer's output, emits ZERO
        ``.d.ts`` analysis units (the 10 at the base); the real
        implementation's unit stands.
"""

import json
import subprocess
from pathlib import Path

import pytest

PARSERS_JS_DIR = Path(__file__).resolve().parents[3] / "parsers" / "javascript"
ANALYZER = PARSERS_JS_DIR / "typescript_analyzer.js"
UNIT_GENERATOR = PARSERS_JS_DIR / "unit_generator.js"


@pytest.fixture(scope="module", autouse=True)
def _node_modules_settled():
    """The analyzer and generator drive needs ts-morph resolvable from
    the parser package. In a settled checkout (CI, the cycle worktree)
    node_modules exists and this is a no-op; in a bare detached
    worktree (the gates' scratch trees) it settles once per module —
    the same npm ci the pipeline bootstrap runs."""
    if not (PARSERS_JS_DIR / "node_modules").exists():
        subprocess.run(
            ["npm", "ci", "--silent"], cwd=PARSERS_JS_DIR,
            check=True, timeout=300,
        )

# ---------------------------------------------------------------------------
# The campaign's fixture shapes (byte-identical content,
# e2e/campaign/c-header-wave-20261014/review-fixtures/dts/src/)
# ---------------------------------------------------------------------------

_TYPES_DTS = """export declare function parseConfig(path: string): Record<string, unknown>;
export declare function sendMail(to: string, body: string): Promise<void>;
export declare class Client {
    constructor(url: string);
    fetch(path: string): Promise<string>;
    private token: string;
}
declare module "legacy-lib" {
    export function runShell(cmd: string): string;
}
export declare namespace Utils {
    function escapeHtml(s: string): string;
}
export declare const VERSION: string;
export declare function userSearch(req: Request, res: Response): Promise<void>;
export declare function middleware(req: Request, res: Response, next: NextFunction): void;
"""

_GLOBAL_DTS = """declare function evalTemplate(tpl: string, ctx: any): string;
interface Window { openantHook(cmd: string): void; }
"""

_REAL_TS = """export function realHandler(input: string): string { return evalTemplate(input); }
"""


def _build_repo(tmp_path):
    repo = tmp_path / "dts-repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "types.d.ts").write_text(_TYPES_DTS, encoding="utf-8")
    (src / "global.d.ts").write_text(_GLOBAL_DTS, encoding="utf-8")
    (src / "real.ts").write_text(_REAL_TS, encoding="utf-8")
    listing = tmp_path / "files.txt"
    listing.write_text("".join(str(src / n) + "\n"
                               for n in ("types.d.ts", "global.d.ts", "real.ts")))
    return repo, src, listing


def _run_analyzer(tmp_path, repo, listing):
    out = tmp_path / "analyzer.json"
    proc = subprocess.run(
        ["node", str(ANALYZER), str(repo), "--files-from", str(listing),
         "--output", str(out)],
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, f"the analyzer failed: {proc.stderr[-800:]}"
    return json.loads(out.read_text())


# ---------------------------------------------------------------------------
# S1/S2/S3 — the analyzer-level split
# ---------------------------------------------------------------------------

def test_the_dts_files_yield_zero_units(tmp_path):
    """S1: the declaration-only .d.ts files produce ZERO function units
    (the C parser's declaration-vs-definition split, ported to the layer
    that actually gates unit creation — the context_assembler's guard
    never reached it). At the base the campaign's fixture yields 10
    declaration-only units incl. a bogus whole-`declare module` span;
    the falsifier's first half: the .d.ts files create no executable
    analysis units."""
    repo, src, listing = _build_repo(tmp_path)
    out = _run_analyzer(tmp_path, repo, listing)

    assert _PROD_HUNK == "parsers/javascript/typescript_analyzer.js"
    dts_fns = [fid for fid in out["functions"] if ".d.ts:" in fid]
    assert dts_fns == [], (
        f"declaration-only .d.ts content must create NO analysis units "
        f"(the C parser's declaration-vs-definition split); got {dts_fns}")
    dts_edges = [k for k in out.get("call_graph", {}) if ".d.ts:" in k]
    assert dts_edges == [], (
        f"a skipped file has no edges either; got {dts_edges}")
    # r1-F2: a call from real code into a .d.ts-declared name
    # (evalTemplate, declared in global.d.ts) lands in indirect_calls
    # now — never resolving to a body-less phantom unit (the base
    # resolved it to one). Pinned so the base/head edge migration is
    # asserted, not discovered by a later diff of graphs.
    indirect = out.get("indirect_calls", {}).get("src/real.ts:realHandler", [])
    assert "evalTemplate" in indirect, indirect
    # the campaign's exact base shape for the record: 10 .d.ts units
    # incl. the bogus 'declare module' span — all gone at the head


def test_the_split_is_observable_and_the_partition_holds(tmp_path):
    """S2: the skip is VISIBLE — the new declaration_files_skipped stat
    rides the analyzer's output (absent at the base, the silent split);
    the #713 family's bucket invariant holds at BOTH trees: the .d.ts
    files still LOAD (they count in files_processed, never in
    files_with_errors — the C header analog: the file is collected, its
    content recorded, just never analyzed)."""
    repo, src, listing = _build_repo(tmp_path)
    out = _run_analyzer(tmp_path, repo, listing)
    assert _PROD_HUNK == "parsers/javascript/typescript_analyzer.js"
    stats = out["statistics"]
    assert stats.get("declaration_files_skipped") == 2, stats
    assert stats["files_processed"] == 3, stats
    assert stats["files_with_errors"] == 0, stats


def test_the_ordinary_implementation_retains_its_extraction(tmp_path):
    """S3: the CONTROL (the falsifier's second half) — the ordinary
    TypeScript implementation keeps its existing extraction and
    seeding-relevant shape: real.ts:realHandler stands with isExported
    true, identical at the base and the head (the declaration split
    must not eat real units)."""
    repo, src, listing = _build_repo(tmp_path)
    out = _run_analyzer(tmp_path, repo, listing)
    fn = out["functions"].get("src/real.ts:realHandler")
    assert fn is not None, (
        f"the real implementation must retain its extraction: "
        f"{sorted(out['functions'])}")
    assert fn.get("isExported") is True, fn


# ---------------------------------------------------------------------------
# S4 — the end-to-end seeding surface (the unit_generator leg)
# ---------------------------------------------------------------------------

def test_the_generator_emits_no_dts_units(tmp_path):
    """S4: the seeding surface — the unit_generator derives the analysis
    units from the analyzer's functions map (the pipeline's Stage 4; the
    seeding candidates come from these units), so a .d.ts function
    absent there is a .d.ts unit absent here. At the base the generator
    emits the 10 declaration-only units over this fixture; the head
    emits exactly the real implementation's one.
    The fix lives in parsers/javascript/typescript_analyzer.js (the
    unit-creation layer — the file named by _PROD_HUNK; the JS prod
    file cannot be a Python import, so the C4 hunk-revert rows for it
    are the load-bearing proof)."""
    assert _PROD_HUNK == "parsers/javascript/typescript_analyzer.js"
    repo, src, listing = _build_repo(tmp_path)
    _run_analyzer(tmp_path, repo, listing)

    driver = tmp_path / "gen_driver.js"
    driver.write_text(
        "const { UnitGenerator } = require(process.argv[2]);\n"
        "const fs = require('fs');\n"
        "const analyzerOutput = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));\n"
        "const g = new UnitGenerator(process.argv[4]);\n"
        "const result = g.generateUnits(analyzerOutput);\n"
        "console.log(JSON.stringify({\n"
        "  units: g.units.map(u => u.id),\n"
        "}));\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["node", str(driver), str(UNIT_GENERATOR), str(tmp_path / "analyzer.json"),
         str(repo)],
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, f"the generator driver failed: {proc.stderr[-800:]}"
    payload = json.loads(proc.stdout)
    dts_units = [u for u in payload["units"] if ".d.ts:" in u]
    assert dts_units == [], (
        f"the generator must emit NO .d.ts analysis units (the seeding "
        f"surface); got {dts_units}")
    assert payload["units"] == ["src/real.ts:realHandler"], payload["units"]


# The prod file under test (the data-read route: a JS file cannot be a
# Python import; the C4 hunk-revert rows for this file — the S1/S2/S4
# battery failing at the reverted==base state — are the load-bearing proof).
_PROD_HUNK = "parsers/javascript/typescript_analyzer.js"
