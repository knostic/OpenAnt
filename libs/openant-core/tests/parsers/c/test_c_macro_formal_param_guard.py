"""S5: a function-like macro must not alias to its OWN formal parameter.

``#define WRAP(g) g()`` substitutes each call site's argument in place; the
body's leading token ``g`` is the macro's formal PARAMETER, never a real
callee. The alias extractor took the body's leading identifier unconditionally,
fabricating an edge ``WRAP -> g`` to any repo function literally named ``g``
(call_graph_builder rewrites ``WRAP(...)`` to ``g``). Guard: skip aliasing when
the target is one of the macro's own formal parameters. Legitimate aliases whose
target is a real function (``OPENSSL_malloc -> CRYPTO_malloc``) are unaffected.
"""

import os
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_c")

from parsers.c.function_extractor import FunctionExtractor  # noqa: E402


def _macro_aliases(src: str) -> dict:
    d = Path(os.path.realpath(tempfile.mkdtemp()))
    (d / "f.c").write_text(src)
    fe = FunctionExtractor(str(d))
    fe.process_file(d / "f.c")
    return dict(fe.macro_aliases)


def test_macro_does_not_alias_to_its_own_formal_param():
    """RED pre-fix: ``WRAP`` aliases to its formal param ``g`` (a phantom edge)."""
    aliases = _macro_aliases(
        "void g(void) { }\n"
        "#define WRAP(g) g()\n"
        "void caller(void) { WRAP(g); }\n"
    )
    assert aliases.get("WRAP") != "g", (
        "WRAP aliased to its own formal parameter `g` -> fabricates a call edge "
        f"to any repo function literally named g; macro_aliases={aliases}"
    )
    assert "WRAP" not in aliases, (
        f"WRAP must not alias at all (body is a bare formal-param call); got {aliases}"
    )


def test_multi_param_formal_shadow_guarded():
    """A later formal param used as the leading callee is also a fabrication."""
    aliases = _macro_aliases(
        "#define CALL(f, x) f(x)\n"
        "void caller(void) { CALL(g, 1); }\n"
    )
    assert "CALL" not in aliases, (
        f"CALL aliased to formal param `f`; got {aliases}"
    )


def test_legitimate_aliases_preserved():
    """NEGATIVE CONTROL: aliases whose target is a real function must survive."""
    aliases = _macro_aliases(
        "int CRYPTO_malloc(int n) { return n; }\n"
        "#define OPENSSL_malloc(size) CRYPTO_malloc(size)\n"
        "#define LOG(m) fprintf(stderr, m)\n"
    )
    assert aliases.get("OPENSSL_malloc") == "CRYPTO_malloc", (
        f"legit alias to a real function was dropped; got {aliases}")
    assert aliases.get("LOG") == "fprintf", (
        f"legit alias to a real function was dropped; got {aliases}")
