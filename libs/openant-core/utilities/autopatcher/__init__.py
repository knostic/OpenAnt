"""Auto Patcher's patch-generation and trust-scoring engine, merged into OpenAnt.

Ported from the standalone auto-patcher-mvp project so end users don't need a
separate checkout, interpreter, or virtualenv. Entry point: :func:`pipeline.run`.
See ``core/patch.py`` for the thin OpenAnt-side wrapper (finding lookup,
eligibility, artifact paths) that calls into this package.
"""
