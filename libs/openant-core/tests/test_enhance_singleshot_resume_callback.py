"""#218: single-shot enhance resume must rebase the progress session baseline.

`enhance_dataset` (single-shot mode) resumes from a checkpoint directory — it
loads `processed_ids` and skips finished units — but it did not accept a
`restored_callback`, so on resume the shared ProgressReporter never learned the
restored count. Its counter ended at (remaining)/(total) instead of total/total
and the ETA counted the restored units as phantom remaining work: the same #218
defect the agentic path already fixes via `mark_restored`. This test drives the
real single-shot `enhance_dataset` with every unit already restored (no LLM
call) and asserts the callback fires with the restored count.
"""

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utilities.context_enhancer import ContextEnhancer  # noqa: E402


class _NoLLMEnhancer(ContextEnhancer):
    """Pretends both units were already checkpointed; never calls the LLM."""

    def _load_completed_units(self, checkpoint_dir, context_key="llm_context"):
        return {"u1", "u2"}

    def enhance_unit(self, unit, all_units):  # pragma: no cover - must not run
        raise AssertionError("enhance_unit called — restored units were re-enhanced")


def _unit(uid):
    return {
        "id": uid,
        "unit_type": "function",
        "code": {"primary_origin": {"file_path": "a.py", "function_name": uid}},
        "metadata": {"direct_calls": [], "direct_callers": []},
    }


def test_singleshot_resume_invokes_restored_callback(tmp_path):
    dataset = {"units": [_unit("u1"), _unit("u2")]}
    enh = _NoLLMEnhancer(SimpleNamespace(provider_name="test", model="test"))
    seen = []
    enh.enhance_dataset(
        dataset,
        workers=1,
        checkpoint_path=str(tmp_path / "cp"),
        restored_callback=lambda n: seen.append(n),
    )
    assert seen == [2], (
        f"single-shot resume did not report the restored count to the progress "
        f"reporter (restored_callback calls: {seen!r})"
    )
