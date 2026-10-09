"""Shared LLM-call capture mechanics for Auto Patcher tracing/replay tooling.

Both the full-run tracer (``tools/run_traced.py``'s ``LLMCallTracer``) and
single-stage replay (``stage_replay.py``'s use of ``LLMCallCapture``
directly) need the exact same low-level mechanism: monkeypatch the one
``call_llm()`` choke point every stage's ``LLMClient.complete()`` goes
through, record each call's prompt/raw response/timestamps in call order,
restore the original function on exit (even on exception).

This module is that ONE mechanism, extracted once two call sites needed it
identically -- not a generic tracing framework. Everything specific to a
particular tool stays at its own call site:

  - ``tools/run_traced.py``'s ``LLMCallTracer`` writes each call's prompt/
    response to disk immediately (via ``on_call``, see below) so a mid-run
    crash still leaves every already-completed call's trace files behind,
    and owns ``checkpoints.jsonl``/``run_manifest.json``'s exact shape.
  - ``stage_replay.py`` uses ``LLMCallCapture`` directly with no
    ``on_call`` -- at most one call ever happens, and it writes prompt/
    response files (and ``replay_manifest.json``) only after the call
    completes.

Neither policy (file naming, checkpoint schema, replay-manifest schema)
lives here -- only the capture mechanism both share.
"""

from __future__ import annotations

from datetime import datetime, timezone


class LLMCallCapture:
    """Context manager: while active, every
    ``utilities.autopatcher.llm_client.call_llm`` invocation is recorded,
    in call order, into ``self.calls`` -- then the original ``call_llm``
    is restored on exit, unconditionally.

    Each recorded call is a dict: ``seq``, ``stage``, ``prompt``,
    ``response``, ``started_at``, ``finished_at``.

    If ``on_call`` is given, it is invoked synchronously with that same
    dict immediately after each call completes (before the wrapped
    ``call_llm`` returns to its own caller) -- letting a caller persist
    per-call state incrementally instead of only after the whole ``with``
    block exits. The callback may mutate the dict in place (e.g. to add
    its own derived fields) since the same object also ends up in
    ``self.calls``.
    """

    def __init__(self, on_call=None):
        self.calls: "list[dict]" = []
        self._on_call = on_call
        self._module = None
        self._original = None

    def __enter__(self) -> "LLMCallCapture":
        import utilities.autopatcher.llm_client as llm_client_module

        self._module = llm_client_module
        self._original = llm_client_module.call_llm

        def _traced_call_llm(*args, **kwargs):
            prompt = args[0] if args else kwargs.get("prompt", "")
            stage = kwargs.get("stage", args[2] if len(args) > 2 else "unknown")
            seq = len(self.calls) + 1

            started_at = datetime.now(timezone.utc).isoformat()
            raw = self._original(*args, **kwargs)
            finished_at = datetime.now(timezone.utc).isoformat()

            record = {
                "seq": seq,
                "stage": stage,
                "prompt": prompt,
                "response": raw,
                "started_at": started_at,
                "finished_at": finished_at,
            }
            self.calls.append(record)
            if self._on_call is not None:
                self._on_call(record)
            return raw

        llm_client_module.call_llm = _traced_call_llm
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._module is not None and self._original is not None:
            self._module.call_llm = self._original
        return False
