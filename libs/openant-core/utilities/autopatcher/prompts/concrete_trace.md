# Concrete Trace

You will be shown one security concern (its role and a one-sentence
description) and the repository evidence and proposed patch already
available for it. This is a narrow, single task, independent of any prior
analysis of this concern: trace ONE concrete execution.

The concern's description names a suspicious behavior, branch, or
mechanism -- it tells you WHAT part of the code your concrete scenario
should exercise. It does NOT tell you where your trace is allowed to
stop. Actually exercising that behavior/mechanism is an INTERMEDIATE
event in your trace, never the answer by itself. The question you are
actually answering is whether your concrete scenario, followed all the
way through, produces the final, externally-relevant problematic outcome
the concern is ultimately about -- not merely whether it passes through
the behavior the concern happens to name along the way.

Do this, in order:

1. Construct ONE minimal, concrete scenario/input that should exercise
   the behavior the concern describes -- a specific caller, specific
   arguments or values, a specific triggering condition. Not a category
   of inputs, not "any request like this" -- one example.
2. Starting from the relevant entry point for that concrete scenario,
   follow its execution from one consequential point to the next -- an
   operation that matters to whether the final outcome occurs. You do
   not need to cite every statement, call, assignment, or branch that
   executes in between.
3. Before advancing from your current established point to a proposed
   later consequential operation, challenge that transition: on THIS
   scenario's route from here to there, what, if anything, could prevent
   that operation from being reached? That means any condition, guard,
   branch, loop check, early return, raise, exception path, retry/
   redirect/re-dispatch, or equivalent decision on the way. Account for
   each such decision as its own step, before the operation it could
   prevent, evaluated with THIS scenario's own concrete values:
   - if it prevents the operation, stop there with `BLOCKED`;
   - if it lets execution continue, you may advance;
   - if the evidence cannot establish whether execution gets past it,
     stop there with `UNRESOLVED`.

   A decision that cannot prevent that particular operation from being
   reached on this route needs no step, even if it sits in source text
   between two citations. You may cite a supporting statement when its
   value is needed to evaluate whether a later decision permits the
   proposed operation to be reached. Source order is not execution order: never
   conclude an operation executes merely because it appears later in the
   source, because a caller invokes the function containing it, or
   because an earlier mechanism has already activated.
4. A call or recursive call starts a new invocation with its own route.
   Before claiming any operation inside that invocation is reached,
   apply the same challenge from that invocation's own entry, with its
   own concrete values -- a decision you evaluated in an earlier
   invocation does not carry over. Following a call to source text
   elsewhere in the evidence, or back to text you have already cited, is
   correct; revisiting the same text is not a step backward.
5. Do NOT stop merely because you have exercised the behavior/mechanism
   the concern names. Continue following the SAME concrete scenario
   forward from there, challenging each later transition the same way.
   Something later in the same execution -- inside or outside the
   specific fragment the concern names -- may still determine whether
   the final outcome actually occurs.
6. Stop only when one of these is actually established by your own
   steps:
   - your trace establishes that this concrete scenario reaches the
     final, problematic outcome itself, not merely the behavior/
     mechanism the concern names (`REACHED`);
   - a control-flow decision or other evidenced condition -- encountered
     anywhere on this scenario's own execution path, before or after the
     behavior/mechanism the concern names, whether or not it is part of
     the specific fragment the concern points at -- prevents this
     concrete scenario from reaching that final outcome (`BLOCKED`);
   - the evidence shown to you does not let you establish whether this
     scenario's execution gets past a decision or reaches the next
     consequential operation, whether that is before or after the point
     where the concern's own mechanism is exercised (`UNRESOLVED`).
     Reaching the mechanism and then being unable to establish the next
     consequential operation is `UNRESOLVED`, never
     `REACHED` -- never advance to a later operation you have not
     actually traced the scenario into.

## What you are NOT being asked

You are not being asked whether the concern is correct in general, whether
the patch is sufficient, whether the vulnerability is fixed, whether this
should block deployment, or whether any prior reasoning about this concern
was correct. Answer none of those. You are tracing one concrete execution,
nothing else -- a different kind of question than "is this guard's
condition true by default," not a repeat of it.

## REACHED / BLOCKED / UNRESOLVED

- `REACHED`: your own citation-backed steps establish that THIS concrete
  scenario reaches the FINAL problematic outcome itself. Exercising the
  behavior/mechanism the concern names is not sufficient by itself --
  that is one step on the path, not the destination. `REACHED` means you
  followed this same scenario all the way to the outcome and it actually
  occurs.
- `BLOCKED`: your own citation-backed steps establish ONE specific step
  -- anywhere on this scenario's execution path, before or after the
  concern's own named behavior/mechanism is exercised -- that, given
  this scenario's own concrete values, prevents it from reaching the
  final outcome. This does NOT mean the concern is false, refuted, or
  that every possible scenario is blocked -- it means only that the ONE
  scenario you constructed is blocked.
- `UNRESOLVED`: the evidence shown to you cannot establish a complete
  enough step-by-step path all the way to the final outcome. In
  particular, successfully exercising the concern's own named behavior/
  mechanism and then having no further evidence to follow is
  `UNRESOLVED`, not `REACHED` -- you reached an intermediate point, not
  the outcome. This is the answer whenever you are not certain, not a
  last resort -- never guess.

Never write `BLOCKED` because you personally doubt the concern, and never
write `REACHED` because you personally believe it, or because your trace
merely passed through the behavior the concern names. Both verdicts must
follow only from citation-backed steps that actually reach as far as the
final outcome itself.

## Citation rules

Identical to every other citation you are asked for elsewhere: copy the
exact contiguous evidence/patch text for each step, character for
character, with nothing added around it -- no quotes, no backticks, no
escape characters not literally present in the evidence. A step whose
citation cannot be reproduced exactly is not a valid step.

## Response format

Respond with EXACTLY this shape, in EXACTLY this order:

```
Example scenario: <one or two sentences naming the concrete input/call>

Trace:
1. Citation: <your own exact contiguous evidence or patch text>
   Note: <one clause: what this establishes for THIS scenario>
2. Citation: <your own exact contiguous evidence or patch text>
   Note: <one clause: what this establishes for THIS scenario>

Outcome: REACHED | BLOCKED | UNRESOLVED
Blocking step: <the step number above that blocks this scenario, or `none`>
```

- `Example scenario` is your own hypothetical description, not a
  citation -- write it directly, no quote marks.
- Report at least one `Trace` step whenever `Outcome` is `REACHED` or
  `BLOCKED`. Every step must carry its own `Citation:` and `Note:`, in
  that order, exactly one step per number, in the order you followed them.
- `Blocking step` is meaningful ONLY when `Outcome: BLOCKED` -- write the
  exact number of the one step above that blocks this scenario. Write
  `none` for `Outcome: REACHED` or `Outcome: UNRESOLVED`.
- Do not add a confidence score, a trust label, an alternative scenario,
  or any field not shown above.

## Rules

- One example only. Do not describe multiple scenarios or hedge between
  them.
- Reason only from the evidence and patch shown to you in this
  conversation -- never from memory of the real-world issue, never from a
  named vulnerability category, guard pattern, or mechanism label.
- If you cannot construct a genuinely concrete scenario from what you are
  shown, or cannot follow it with real citations, answer `UNRESOLVED`
  rather than inventing steps.
