"""#355: CLI-args / env-var reads seed as entry points in EVERY shipped language.

`_get_entry_point_reasons` seeds through six checks, and the two idiom lists are
maintained per-language with no single place deciding coverage — each gap arrived by
adding a parser without adding idioms. At HEAD, an environment-variable read is not
seeded in 5 of the 9 shipped languages (process.env in JavaScript, os.Getenv in Go,
getenv in C/PHP, std::env::var in Rust, getEnvVarOwned in Zig); JavaScript and Zig read
NEITHER argv nor env through either route; PHP's CLI forms ($argv, getenv) match
nothing; C's argv helper is seeded only when the file sits under apps/ — a property of
the directory, not of the code.

The unit_type column is load-bearing (the issue's probe models BOTH routes): each row
carries the type that language's REAL parser assigns, because Go/C reach cli_handler
via the parser (Check 1) — invisible if every row is forced to `function`.

The false-negative direction: a missing entry point silently removes a unit and
everything reachable only through it. A false one costs analysis budget — the safe
direction for a scanner is more seeding.
"""
import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

from utilities.agentic_enhancer.entry_point_detector import EntryPointDetector  # noqa: E402


# (key, unit_type the REAL parser assigns, code) — one row per probe case.
CASES = [
    ("python|argv", "function", "def parse_args():\n    return sys.argv[1:]\n"),
    ("python|env", "function", "def cfg():\n    return os.getenv('TOKEN')\n"),
    ("ruby|argv", "function", "def parse_args\n  ARGV.dup\nend\n"),
    ("ruby|env", "function", "def cfg\n  ENV['TOKEN']\nend\n"),
    ("swift|argv", "function",
     "func parseArgs() -> [String] {\n    return CommandLine.arguments\n}\n"),
    ("swift|env", "function",
     'func cfg() -> String? {\n    return ProcessInfo.processInfo.environment["TOKEN"]\n}\n'),
    ("rust|argv", "function",
     "fn parse_args() -> Vec<String> {\n    std::env::args().collect()\n}\n"),
    ("rust|env", "function",
     'fn cfg() -> String {\n    std::env::var("TOKEN").unwrap()\n}\n'),
    ("rust|env_short_os", "function",
     'fn cfg() -> Option<std::ffi::OsString> {\n    use std::env;\n    env::var_os("TOKEN")\n}\n'),
    ("rust|args_short_os", "function",
     'fn cfg() {\n    use std::env;\n    let a: Vec<_> = env::args_os().collect();\n}\n'),
    ("php|argv_server", "function",
     "function parseArgs() {\n    return $_SERVER['argv'][1];\n}\n"),
    ("php|argv", "function", "function parseArgs() {\n    return $argv[1];\n}\n"),
    ("php|env_env", "function", "function cfg() {\n    return $_ENV['TOKEN'];\n}\n"),
    ("php|env_getenv", "function", "function cfg() {\n    return getenv('TOKEN');\n}\n"),
    ("go|argv", "cli_handler", "func parseArgs() []string {\n    return os.Args[1:]\n}\n"),
    ("go|env", "function", 'func cfg() string {\n    return os.Getenv("TOKEN")\n}\n'),
    # wave r1 (fable+sonnet): the row previously contained flag.Parse() —
    # the real Go extractor classifies any function containing it as
    # cli_handler (extractor.go isCLIHandler), so the type carried here was
    # NOT what the parser assigns and the RED count was inflated by a
    # manufactured failure. The honest residual: the flag DECLARATION in a
    # helper with Parse() living in main.
    ("go|flag", "function",
     'func verboseFlag() string {\n    v := flag.String("v", "", "verbose")\n    return *v\n}\n'),
    ("c|argv_apps", "cli_handler",
     "int run(int argc, char **argv) {\n    return atoi(argv[1]);\n}\n"),
    ("c|argv_elsewhere", "function",
     "int run(int argc, char **argv) {\n    return atoi(argv[1]);\n}\n"),
    ("c|env", "function", 'char *cfg(void) {\n    return getenv("TOKEN");\n}\n'),
    ("js|argv", "function",
     "function parseArgs() {\n  return process.argv.slice(2);\n}\n"),
    ("js|env", "function",
     "function cfg() {\n  return process.env.TOKEN;\n}\n"),
    ("js|stdin", "function",
     "function feed() {\n  return process.stdin.read();\n}\n"),
    ("js|yargs", "function",
     "function parseArgs() {\n  return yargs.argv;\n}\n"),
    ("zig|argv", "function",
     "fn parseArgs() !void {\n    const a = try std.process.argsAlloc(alloc);\n}\n"),
    ("zig|env", "function",
     'fn cfg() !void {\n    const t = try std.process.getEnvVarOwned(alloc, "TOKEN");\n}\n'),
]


def _detect():
    funcs = {f"f:{k}": {"name": k.split("|")[0] + "_helper", "code": code,
                       "unitType": ut, "decorators": []}
             for k, ut, code in CASES}
    det = EntryPointDetector(funcs, {})
    det.detect_entry_points()
    return det


def test_every_shipped_language_seeds_cli_and_env_reads():
    """The issue's probe table: every row seeds through the REAL parser's
    unit_type — the directory-independent, route-independent floor."""
    det = _detect()
    unseeded = [k for k, _, _ in CASES if f"f:{k}" not in det.entry_points]
    assert not unseeded, (
        "CLI/env reads not seeded (a missing entry point silently removes a "
        "unit and everything reachable only through it): " + ", ".join(unseeded)
    )


def test_go_and_c_argv_still_seed_via_unit_type():
    """The parser route (Check 1) must keep firing — the fix adds idioms, it
    does not replace the cli_handler classification."""
    det = _detect()
    assert "f:go|argv" in det.entry_points
    assert "f:c|argv_apps" in det.entry_points
    # wave r1 (fable): the unit_type route itself, not the accidental idiom
    # match (the c row's code contains `argv`, so the new idiom seeds it
    # regardless of cli_handler membership).
    reasons = det.entry_point_details["f:c|argv_apps"]["reasons"]
    assert any(r.startswith("unit_type:") for r in reasons), reasons


def test_c_gets_cross_language_match_keeps_firing():
    """The documented accident (the issue's disclosure): the Ruby `\\bgets\\b`
    pattern also matches C's gets(buf) — a genuine stdin read, right by luck.
    Pinned so a future language-scoping change notices it deliberately."""
    det = EntryPointDetector(
        {"f:c|gets": {"name": "r", "code": "void r(char *b) {\n    gets(b);\n}\n",
                      "unitType": "function", "decorators": []}}, {})
    det.detect_entry_points()
    assert "f:c|gets" in det.entry_points
