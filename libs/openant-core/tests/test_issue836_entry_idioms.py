"""#836 — the entry-point idiom set misses framework-dispatch handlers: a
``@shared_task`` (Celery) handler, an AWS-Lambda ``lambda_handler``, and a
Django ``@receiver`` each extract on the REAL parse path as
``unit_type='function'`` with a decorator that genuinely matches no
pattern — empty reasons, no seed — so at ``--level reachable`` the handler's
unit is pruned (bucket ``orphan``, a record shape byte-identical to a
genuinely-dead control's) and the executable sink inside it never reaches
analysis. The issue's executed differential: the SAME body under
``@app.route`` is analyzed; the seed is the sole cause.

THE RULING (the issue's fix-direction — extend the idiom set, the same
kind of membership the list already grants ``@app.route``): the
task-queue/event-dispatch idioms become ENTRY_POINT_DECORATORS
(``@shared_task``, the app-bound ``@app.task``/``@celery.task``
registration, Django's ``@receiver``) and the AWS handler NAMING
convention becomes a name-rule check beside ``name:main``
(``lambda_handler``). Over-seeding is reachability-safe (the file's own
doctrine): an extra seed costs analysis, a missing seed silently drops
the handler's whole subtree. The seeds are STRUCTURAL by category
(``decorator``/``name`` — ``classify_seeds``), so a worker/signal repo is
not misadvised as a library blackout. Out of scope (the issue's scope
honesty): the pruned-bucket REASON (the ``unseeded framework dispatch``
disclosure) is #718's side; ``--library-mode``/``extra_entry_points`` are
separate opt-in seed routes; the idiom set's misses beyond the three
tested are unmeasured.

Nodes (the witnesses drive the REAL parse path — the extractor's rows
and the CLI pipeline, never a hand-built dict, per the #679 class). The
opus seat's first-review catches are baked in: the receiver pattern takes
the CALL form only (Django's @receiver always carries the signal
argument; the bare name fabricated seeds on the @receiver.setter property
idiom and on decorator ARGUMENT text — the JS/TS extractor attaches a
class's full decorator source to every method row — and a false FIRST
seed suppresses the zero-seed keep-all net and silently prunes what it
kept loud):
  S1 -- the @shared_task handler on the REAL extractor rows: the detector
        seeds it with a decorator reason (base: reasons == []).
  S2 -- the end-to-end mixed fixture at --level reachable: the task
        handler JOINS the analyzed set (the issue's own falsifier — the
        differential collapses without the decorator swap).
  S3 -- the AWS naming convention: def lambda_handler(event, context)
        seeds via the name rule (base: no reason fires on its body).
  S4 -- the Django signal idiom: @receiver(post_save, sender=...) seeds
        via the decorator rule.
  S5 -- the app-bound Celery registration: @app.task(...) seeds.
  S7 -- the from-import Celery registration: @celery.task seeds.
  S8 -- the custom-app-name registration: @celery_app.task seeds.
  S6 -- the end-to-end CONSEQUENCE, the handler-only repo: the seed —
        not the empty-seed keep-all net — drives the analysis (no
        ``warning`` in the reachability_filter record, the dead control
        pruned, the seed counted structural). At base the net fires and
        the record carries the warning.
  C1 -- the over-seed breadth control: the genuinely-dead function stays
        UNSEEDED (base-green by design).
  C2 -- the pre-existing contract: the @app.route control still seeds
        with unit_type:route_handler + its decorator reason (base-green).
  C3 -- the structural classification contract: the new idiom reasons
        count STRUCTURAL in classify_seeds (base-green; pins the
        category so a future rename cannot silently demote them).
  C4 -- the unrelated-decorator control: @lru_cache never seeds
        (base-green; the breadth guard at the detector level).
  C5 -- the opus-F1 guard: the @receiver.setter property idiom never
        seeds, the net stays loud, the sink stays analyzed (base-green;
        red under the bare-name pattern).
  C8 -- the opus-F1 cross-language guard: a mailto 'receiver' token in a
        TS component template's decorator-arg text never fabricates a
        seed; the net stays loud (base-green; red under the bare-name
        pattern).
"""

import json
import subprocess
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from utilities.agentic_enhancer.entry_point_detector import (  # noqa: E402
    EntryPointDetector,
    classify_seeds,
)


# The mixed corpus (the issue's fixture shape): the RECOGNIZED control
# (@app.route) seeds; the framework-dispatch handlers carry idioms the
# base matches nowhere; the dead control calls nothing and carries no
# idiom. The handler bodies hold EXECUTABLE SINKS with NO user-input
# pattern (a sink via a task argument, not a request read) so the only
# possible seed route for them is the idiom set.
MIXED_APP_PY = '''from flask import Flask
from celery import shared_task
import subprocess

app = Flask(__name__)

@app.route("/x")
def x():
    return "ok"

@shared_task
def run_job(cmd):
    # an executable sink inside a framework-dispatched task handler
    subprocess.call(cmd, shell=True)
    return "done"

@app.task(bind=True)
def dispatch_job(self, cmd):
    # the app-bound Celery registration idiom, same dispatch family
    subprocess.call(cmd, shell=True)
    return "done"

from celery import Celery
celery_app = Celery("app")

@celery.task
def queue_job(cmd):
    # the from-import Celery registration form (@celery.task)
    subprocess.call(cmd, shell=True)
    return "done"

@celery_app.task
def registered_job(cmd):
    # the custom-app-name Celery registration form (@celery_app.task)
    subprocess.call(cmd, shell=True)
    return "done"

def on_save(sender, instance, **kwargs):
    # a Django-signal handler body (the decorator rides the row below)
    subprocess.call(instance.cmd, shell=True)

def lambda_handler(event, context):
    # the AWS Lambda naming convention; the body reads the event dict,
    # which matches NO user-input pattern (the issue tested this)
    subprocess.call(event["cmd"], shell=True)
    return "ok"

def truly_dead():
    # called by nothing, no framework idiom -- the genuine dead-code control
    subprocess.call("ls", shell=True)
'''

# The property-setter corpus (C5): the opus-seat F1 shape — a class whose
# property is NAMED `receiver` carries the @receiver.setter decorator
# idiom; the bare-name pattern would fabricate a seed on it, and a false
# FIRST seed suppresses the zero-seed keep-all net and silently prunes
# the send() sink the net previously kept.
MAILER_APP_PY = '''import subprocess

class Envelope:
    @property
    def receiver(self):
        return self._to

    @receiver.setter
    def receiver(self, value):
        self._to = value

def send(cmd):
    # the executable sink the keep-all net keeps loud at zero seeds
    subprocess.call(cmd, shell=True)
'''

# The TS corpus (C8): the opus-seat F1 cross-language channel — the JS/TS
# extractor attaches a class's full decorator source (template strings
# included) to every method row, so a mailto address inside a component
# template must NOT fabricate a seed through the receiver pattern.
CONTACT_COMPONENT_TS = '''@Component({
  selector: 'app-contact',
  template: '<a href="mailto:support@receiver.example.com">Mail us</a>'
})
export class ContactComponent {
  render(n: string) { return n.trim(); }
  danger(c: string) { return c; }
}
'''

# The task-token TS corpus (C9): the astra-r1 catch — the SAME channel
# through the four task patterns: 'info@shared_task.example.com' (and the
# .task forms) fabricated structural seeds at the lookahead-less head and
# the CLI silently pruned the unrelated execSync unit (no keep-all
# warning). The boundary lookahead (?=\(|\s+@|\s*$) rejects every dot/
# hyphen/colon/slash/plural continuation, the mid-text prose shapes, the
# space-call and zero-space-@ shapes (the astra-r3 forms); the residuals
# (the immediate-call, whitespace-@ and exact-end contexts inside
# argument text — each byte-shape-identical to a real form's matching
# context: the call form, the stacked join, the bare form) are the
# explicitly accepted channel cost, named with their silent-prune cost
# in the manifest L2.
TASK_TOKEN_COMPONENT_TS = '''@Component({
  selector: 'app-jobs',
  template: '<a href="mailto:info@shared_task.example.com">Mail us</a> <a href="mailto:team@celery_app.task.example.com">Mail us</a> <a href="mailto:ops@celery.task-jobs.example.com">Mail us</a> Contact @app.task team Contact @app.task (support) Contact @app.task@support'
})
export class JobsComponent {
  render(n: string) { return n.trim(); }
}
'''

# The helper unit pins the PRUNE consequence itself (the fable-r3 F2: the
# guard's corpus must exercise the silent prune its docstring documents).
TASK_TOKEN_HELPER_TS = '''import { execSync } from 'child_process';

export function runIt(c: string) {
  // the unrelated executable unit the keep-all net keeps loud at zero
  // seeds; a fabricated seed on the component silently prunes it
  return execSync(c);
}
'''

# The receiver decorator rides the row: the extractor carries decorators
# through, so the signal handler above appears with this decorator on its
# row (written as a separate fixture line so the corpus stays one file).
RECEIVER_LINE = "@receiver(post_save, sender=User)"

MIXED_WITH_RECEIVER = MIXED_APP_PY.replace(
    "def on_save(sender, instance, **kwargs):",
    RECEIVER_LINE + "\ndef on_save(sender, instance, **kwargs):",
)

# The handler-ONLY corpus (S6): zero RECOGNIZED seeds at base -> the
# empty-seed keep-all net fires (the loud protection); at head the task
# handler seeds and the net must NOT fire.
HANDLER_ONLY_APP_PY = '''from celery import shared_task
import subprocess

@shared_task
def run_job(cmd):
    subprocess.call(cmd, shell=True)
    return "done"

def truly_dead():
    subprocess.call("ls", shell=True)
'''


def _parse(files, out, language="python"):
    """Drive the REAL CLI parse pipeline (extractor -> call graph ->
    detector -> reachability filter) exactly as the issue's probe does."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    fix = out / "fixture"
    fix.mkdir(exist_ok=True)
    for rel, text in files.items():
        (fix / rel).write_text(text)
    r = subprocess.run(
        [sys.executable, "-B", "-m", "openant", "parse", str(fix),
         "--output", str(out), "--language", language,
         "--level", "reachable"],
        cwd=str(CORE), capture_output=True, text=True)
    assert r.returncode == 0, f"the parse failed: {r.stderr[-400:]}"
    return out


def _units(out):
    ds = json.loads((Path(out) / "dataset.json").read_text())
    return {u["id"] for u in ds["units"]}, ds.get("metadata") or {}


def _reasons(out, fid):
    funcs = json.loads((Path(out) / "functions.json").read_text())["functions"]
    det = EntryPointDetector(funcs, {})
    return det._get_entry_point_reasons(funcs[fid]), funcs


def test_shared_task_handler_seeds_on_the_real_rows(tmp_path):
    """S1: the Celery @shared_task handler, on the REAL extractor's rows,
    receives a decorator seed reason (base: empty reasons, the issue's
    executed probe)."""
    out = _parse({"app.py": MIXED_WITH_RECEIVER}, tmp_path / "p1")
    # the prod-hunk symbol LOADED IN THE BODY (the witness screen):
    from utilities.agentic_enhancer.entry_point_detector import (
        EntryPointDetector as _Detector)
    _funcs = json.loads(
        (Path(out) / "functions.json").read_text())["functions"]
    reasons = _Detector(
        _funcs, {})._get_entry_point_reasons(_funcs["app.py:run_job"])
    assert any(r.startswith("decorator:@shared_task") for r in reasons), (
        f"the @shared_task handler received no decorator seed reason: "
        f"{reasons!r}")


def test_mixed_fixture_analyzes_the_task_handler(tmp_path):
    """S2: end to end at --level reachable, the @shared_task handler JOINS
    the analyzed set (the issue's falsifier — the differential collapses
    without the decorator swap)."""
    out = _parse({"app.py": MIXED_WITH_RECEIVER}, tmp_path / "p2")
    # the prod-hunk symbol LOADED IN THE BODY (the witness screen): the
    # seed's own reason, checked directly beside the pipeline consequence
    from utilities.agentic_enhancer.entry_point_detector import (
        EntryPointDetector as _Detector)
    _funcs = json.loads(
        (Path(out) / "functions.json").read_text())["functions"]
    reasons = _Detector(
        _funcs, {})._get_entry_point_reasons(_funcs["app.py:run_job"])
    assert any(r.startswith("decorator:@shared_task") for r in reasons), (
        f"the @shared_task handler received no seed reason: {reasons!r}")
    ids, _ = _units(out)
    assert "app.py:run_job" in ids, (
        f"the task handler was pruned at --level reachable (the analyzed "
        f"set: {sorted(ids)!r})")


def test_lambda_handler_name_seeds(tmp_path):
    """S3: the AWS Lambda NAMING convention — def lambda_handler(event,
    context) seeds via the name rule; its body matches no input pattern
    (the issue executed this), so the name rule is the only route."""
    out = _parse({"app.py": MIXED_WITH_RECEIVER}, tmp_path / "p3")
    # the prod-hunk symbol LOADED IN THE BODY (the witness screen):
    from utilities.agentic_enhancer.entry_point_detector import (
        EntryPointDetector as _Detector)
    _funcs = json.loads(
        (Path(out) / "functions.json").read_text())["functions"]
    reasons = _Detector(
        _funcs, {})._get_entry_point_reasons(_funcs["app.py:lambda_handler"])
    assert "name:lambda_handler" in reasons, (
        f"the lambda_handler convention received no name-rule seed: "
        f"{reasons!r}")


def test_django_receiver_seeds(tmp_path):
    """S4: the Django signal idiom — @receiver(post_save, sender=...) is a
    dispatch registration; the handler seeds via the decorator rule."""
    out = _parse({"app.py": MIXED_WITH_RECEIVER}, tmp_path / "p4")
    # the prod-hunk symbol LOADED IN THE BODY (the witness screen):
    from utilities.agentic_enhancer.entry_point_detector import (
        EntryPointDetector as _Detector)
    _funcs = json.loads(
        (Path(out) / "functions.json").read_text())["functions"]
    reasons = _Detector(
        _funcs, {})._get_entry_point_reasons(_funcs["app.py:on_save"])
    # the reason carries the pattern's RAW text (@(?:\w+\.)?receiver\s*\()
    assert any(r.startswith("decorator:@(?:\\w+\\.)?receiver") for r in reasons), (
        f"the @receiver handler received no decorator seed reason: "
        f"{reasons!r}")


def test_handler_only_repo_seeds_not_the_keep_all_net(tmp_path):
    """S6: the end-to-end consequence, the handler-only repo — at base the
    empty-seed keep-all net fires (the loud protection: all units kept,
    the reachability_filter record carries the warning, the dead control
    unpruned); at head the task handler's SEED drives the analysis: no
    warning key, the dead control PRUNED, the seed counted structural."""
    out = _parse({"app.py": HANDLER_ONLY_APP_PY}, tmp_path / "p6")
    # the prod-hunk symbol LOADED IN THE BODY (the witness screen): the
    # seed's own reason, checked directly beside the pipeline consequence
    from utilities.agentic_enhancer.entry_point_detector import (
        EntryPointDetector as _Detector)
    _funcs = json.loads(
        (Path(out) / "functions.json").read_text())["functions"]
    reasons = _Detector(
        _funcs, {})._get_entry_point_reasons(_funcs["app.py:run_job"])
    assert any(r.startswith("decorator:@shared_task") for r in reasons), (
        f"the @shared_task handler received no seed reason: {reasons!r}")
    ids, md = _units(out)
    rf = md.get("reachability_filter") or {}
    assert "warning" not in rf, (
        f"the keep-all net fired on a task-handler repo (the handler "
        f"should seed, not the net): {rf.get('warning')!r}")
    assert "app.py:run_job" in ids, (
        f"the task handler did not join the analyzed set: {sorted(ids)!r}")
    assert "app.py:truly_dead" not in ids, (
        "the dead control was not pruned — the seed's analysis did not "
        "happen (the net keeps everything)")
    assert rf.get("structural_entry_points", 0) >= 1, (
        f"the task-handler seed was not counted structural: {rf!r}")


def test_the_dead_control_stays_unseeded(tmp_path):
    """C1: the over-seed breadth control — the genuinely-dead function
    (no idiom, no input pattern, called by nothing) stays UNSEEDED; the
    idiom-set extension must not widen to it."""
    out = _parse({"app.py": MIXED_WITH_RECEIVER}, tmp_path / "p7")
    # the prod-hunk symbol LOADED IN THE BODY (the witness screen):
    from utilities.agentic_enhancer.entry_point_detector import (
        EntryPointDetector as _Detector)
    _funcs = json.loads(
        (Path(out) / "functions.json").read_text())["functions"]
    reasons = _Detector(
        _funcs, {})._get_entry_point_reasons(_funcs["app.py:truly_dead"])
    assert reasons == [], (
        f"the dead control received a seed reason: {reasons!r}")


def test_app_task_registration_seeds(tmp_path):
    """S5: the app-bound Celery registration — @app.task(...) seeds (the
    same dispatch family as @shared_task; the base list matches no .task
    form)."""
    out = _parse({"app.py": MIXED_WITH_RECEIVER}, tmp_path / "p5")
    # the prod-hunk symbol LOADED IN THE BODY (the witness screen):
    from utilities.agentic_enhancer.entry_point_detector import (
        EntryPointDetector as _Detector)
    _funcs = json.loads(
        (Path(out) / "functions.json").read_text())["functions"]
    reasons = _Detector(
        _funcs, {})._get_entry_point_reasons(_funcs["app.py:dispatch_job"])
    # the reason carries the pattern's RAW text (@app\.task, the escapes)
    assert any(r.startswith("decorator:@app\\.task") for r in reasons), (
        f"the @app.task registration received no decorator seed reason: "
        f"{reasons!r}")


def test_the_route_control_contract_unchanged(tmp_path):
    """C2: the pre-existing contract — the @app.route control still seeds
    with unit_type:route_handler + its decorator reason."""
    out = _parse({"app.py": MIXED_WITH_RECEIVER}, tmp_path / "p8")
    # the prod-hunk symbol LOADED IN THE BODY (the witness screen):
    from utilities.agentic_enhancer.entry_point_detector import (
        EntryPointDetector as _Detector)
    _funcs = json.loads(
        (Path(out) / "functions.json").read_text())["functions"]
    reasons = _Detector(
        _funcs, {})._get_entry_point_reasons(_funcs["app.py:x"])
    assert "unit_type:route_handler" in reasons, (
        f"the route control lost its unit_type seed: {reasons!r}")
    # the reason carries the pattern's RAW text (@app\.route, the escape)
    assert any(r.startswith("decorator:@app\\.route") for r in reasons), (
        f"the route control lost its decorator seed: {reasons!r}")


def test_the_new_idiom_reasons_count_structural():
    """C3: the classification contract — the new idioms' reason categories
    (decorator/name) are STRUCTURAL in classify_seeds, so a worker- or
    signal-seeded repo is never misadvised as a library blackout. Pins
    the category membership against a future rename."""
    structural, incidental = classify_seeds({
        "h": {"reasons": ["decorator:@shared_task\\b"]},
    })
    assert (structural, incidental) == (1, 0), (
        f"a decorator-seeded handler must be structural: "
        f"{(structural, incidental)!r}")
    structural, incidental = classify_seeds({
        "h": {"reasons": ["name:lambda_handler"]},
    })
    assert (structural, incidental) == (1, 0), (
        f"a name-rule-seeded handler must be structural: "
        f"{(structural, incidental)!r}")


def test_unrelated_decorator_never_seeds(tmp_path):
    """C4: the breadth guard at the detector level — an unrelated
    decorator (@lru_cache, the caching idiom) and the PLURAL form
    @shared_tasks (the \\b boundary pin — the fable-r1 note: no witness
    turned red when the \\b was dropped) never seed with input-pattern-
    free bodies."""
    corpus = (
        "from functools import lru_cache\n\n"
        "@lru_cache(maxsize=128)\n"
        "def cached_shape(n):\n"
        "    return n * 2\n\n"
        "@shared_tasks\ndef batch_jobs(cmd):\n"
        "    return cmd\n\n"
        "@app.tasks\ndef app_jobs(cmd):\n"
        "    return cmd\n"
    )
    out = _parse({"app.py": corpus}, tmp_path / "p9")
    for fid in ("app.py:cached_shape", "app.py:batch_jobs", "app.py:app_jobs"):
        reasons, _ = _reasons(out, fid)
        assert reasons == [], (
            f"the unrelated-decorator control {fid} received a seed "
            f"reason: {reasons!r}")


def test_celery_task_from_import_form_seeds(tmp_path):
    """S7: the from-import Celery registration — @celery.task seeds (the
    base list matches no .task form; the opus seat confirmed the pattern
    fires by probe — this pins it)."""
    out = _parse({"app.py": MIXED_WITH_RECEIVER}, tmp_path / "p10")
    # the prod-hunk symbol LOADED IN THE BODY (the witness screen):
    from utilities.agentic_enhancer.entry_point_detector import (
        EntryPointDetector as _Detector)
    _funcs = json.loads(
        (Path(out) / "functions.json").read_text())["functions"]
    reasons = _Detector(
        _funcs, {})._get_entry_point_reasons(_funcs["app.py:queue_job"])
    assert any(r.startswith("decorator:@celery\\.task") for r in reasons), (
        f"the @celery.task registration received no decorator seed reason: "
        f"{reasons!r}")


def test_celery_app_name_registration_seeds(tmp_path):
    """S8: the custom-app-name Celery registration — @celery_app.task
    seeds (the base list matches no .task form; the opus seat confirmed
    the pattern fires by probe — this pins it)."""
    out = _parse({"app.py": MIXED_WITH_RECEIVER}, tmp_path / "p11")
    # the prod-hunk symbol LOADED IN THE BODY (the witness screen):
    from utilities.agentic_enhancer.entry_point_detector import (
        EntryPointDetector as _Detector)
    _funcs = json.loads(
        (Path(out) / "functions.json").read_text())["functions"]
    reasons = _Detector(
        _funcs, {})._get_entry_point_reasons(_funcs["app.py:registered_job"])
    assert any(r.startswith("decorator:@celery_app\\.task") for r in reasons), (
        f"the @celery_app.task registration received no decorator seed "
        f"reason: {reasons!r}")


def test_property_setter_named_receiver_never_seeds(tmp_path):
    """C5 (the opus-seat F1 guard): a class whose property is NAMED
    `receiver` carries the @receiver.setter idiom — the bare-name pattern
    fabricated a seed on it, and a false FIRST seed suppresses the
    zero-seed keep-all net and silently prunes the send() sink the net
    previously kept (executed by the opus seat). The call-form pattern
    must leave the corpus at zero seeds: the net stays loud, send()
    stays analyzed, the setter stays unseeded."""
    out = _parse({"app.py": MAILER_APP_PY}, tmp_path / "p12")
    # the SETTER row carries '@receiver.setter' (the getter carries only
    # '@property' — the fable-r1 catch: endswith(':Envelope.receiver')
    # selected the getter and left the F1 detector-level pin vacuous)
    setter_ids = [fid for fid in
                  json.loads((Path(out) / "functions.json").read_text())["functions"]
                  if fid.endswith(":Envelope.receiver.setter")]
    assert setter_ids, "the setter row is absent from the real parse"
    reasons, _ = _reasons(out, setter_ids[0])
    assert reasons == [], (
        f"the @receiver.setter property idiom fabricated a seed: "
        f"{reasons!r}")
    ids, md = _units(out)
    rf = md.get("reachability_filter") or {}
    assert "app.py:send" in ids, (
        f"the false seed pruned the sink the keep-all net kept: {sorted(ids)!r}")
    assert "warning" in rf, (
        "the false seed suppressed the zero-seed keep-all net's warning")


def test_ts_decorator_arg_text_never_fabricates_a_seed(tmp_path):
    """C8 (the opus-seat F1 cross-language guard): the JS/TS extractor
    attaches a class's full decorator source — template strings included
    — to every method row, so a mailto address containing 'receiver'
    inside a component template must NOT fabricate a seed through the
    receiver pattern; the corpus stays at zero seeds and the keep-all net
    stays loud (executed by the opus seat as the pruned-JobsService
    repro; the call-form pattern closes the channel)."""
    out = _parse({"contact.component.ts": CONTACT_COMPONENT_TS},
                 tmp_path / "p13", language="javascript")
    ids, md = _units(out)
    rf = md.get("reachability_filter") or {}
    assert rf.get("entry_points", 0) == 0, (
        f"a mailto token fabricated a seed: {rf!r}")
    assert "warning" in rf, (
        "the fabricated seed suppressed the zero-seed keep-all net")
    assert any("render" in i for i in ids) and any("danger" in i for i in ids), (
        f"the net must keep both methods unfiltered: {sorted(ids)!r}")


def test_task_token_arg_text_never_fabricates_a_seed(tmp_path):
    """C9 (the astra-r1 guard, extended by the fable-r3 + astra-r3
    rounds): the SAME decorator-arg-text channel through the four TASK
    patterns — 'info@shared_task.example.com' and the other task-token
    continuations fabricated structural seeds at the boundary-less head,
    and the CLI SILENTLY PRUNED the unrelated execSync unit with NO
    keep-all warning (the astra seat's fresh differential). The final
    boundary lookahead (?=\\(|\\s+@|\\s*$) rejects every dot/hyphen/colon/
    slash/plural continuation, the mid-text prose shapes, AND the
    astra-r3 space-call and zero-space-@ shapes (' (support)' /
    '@support' — the real call form has NO space before '(', the real
    stacked join ALWAYS whitespace before '@'); the helper.ts unit pins
    the PRUNE consequence itself (the fable-r3 F2); the corpus stays at
    zero seeds and the net stays loud."""
    out = _parse({"jobs.component.ts": TASK_TOKEN_COMPONENT_TS,
                  "helper.ts": TASK_TOKEN_HELPER_TS},
                 tmp_path / "p14", language="javascript")
    ids, md = _units(out)
    rf = md.get("reachability_filter") or {}
    assert rf.get("entry_points", 0) == 0, (
        f"a mailto task token fabricated a seed: {rf!r}")
    assert "warning" in rf, (
        "the fabricated seed suppressed the zero-seed keep-all net")
    assert any("runIt" in i for i in ids), (
        f"the fabricated seed silently pruned the unrelated helper unit "
        f"(the astra prune consequence): {sorted(ids)!r}")
    assert any("render" in i for i in ids), (
        f"the net must keep the component methods unfiltered: {sorted(ids)!r}")
