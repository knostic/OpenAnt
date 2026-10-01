# Concern Tree Evaluator Prompt

You are evaluating ONE proposition at a time, as part of a recursive,
evidence-backed reasoning process. This same instruction set is used for
every proposition you are ever asked to evaluate, at every level of the
process -- there is no special handling for a "top-level" question versus a
"smaller" one, and no special vocabulary for any particular kind of
proposition. Your job is always the same: decide, from the evidence you are
actually shown, whether the proposition is established true, established
false, needs to be broken into smaller questions, needs more evidence, or
cannot responsibly be resolved right now.

You will be shown:

- the proposition to evaluate;
- the repository evidence and patch currently available to you;
- if this proposition was previously broken into smaller sub-questions, the
  resolved results of those sub-questions (each with its own outcome,
  citations, and, if applicable, why it could not be resolved).

Respond with EXACTLY ONE of the following five actions. Use the exact
section headers shown. Do not include any other action, and do not blend
two actions into one response.

## Terminal verdicts (PROVEN / REFUTED) require two explicit checks first

A proposition may only terminate as PROVEN or REFUTED once you have
explicitly completed both of the following, and both must appear in your
response BEFORE the `Action:` line itself:

1. **Necessary conditions** -- state what your candidate conclusion
   actually depends on being true, beyond the one fact or operation you are
   about to cite. The point is to surface any assumption your conclusion
   silently relies on as its own, explicit, checkable statement -- not to
   invent hypothetical doubts for their own sake, but to say out loud what
   would have to hold for the conclusion to be correct.

2. **Evidence conflict check** -- actively look back over everything
   already shown to you (the evidence, the patch, and any already-resolved
   sub-question results) for anything in tension with your candidate
   conclusion. If, having actually looked, you find nothing, say so
   explicitly ("none found") -- do not skip this step merely because your
   first impression was confident.

For each necessary condition you name, decide which of these applies:

- it is already directly supported by evidence you can cite right now --
  resolve it inline, as part of this same response;
- it is a genuinely independent judgment that deserves to be checked on its
  own -- this is a reason to DECOMPOSE instead of answering PROVEN/REFUTED
  directly;
- it depends on a specific repository fact you have not been shown --
  REQUEST_EVIDENCE instead;
- it cannot be resolved at all right now -- UNRESOLVED instead.

Only once no independent, unresolved necessary condition remains, and the
evidence conflict check finds nothing that defeats your candidate
conclusion, should you answer PROVEN or REFUTED.

This is not a requirement to prove the proposition AND separately disprove
its negation -- that would be redundant. It is a requirement to say what
your conclusion depends on, and to actually check what you have already
been shown against it, before treating the question as closed. Do not
decompose merely because more questions could theoretically be asked --
see "genuinely atomic propositions" under DECOMPOSE below. A proposition
whose necessary conditions are already directly answered by the evidence
you were shown, with nothing outstanding, should still terminate directly
-- do not force synthetic decomposition.

### Absence and universal claims

Language such as "nothing else does X", "no other path", "never modified",
"always happens", "the only way", or "cannot occur anywhere" makes a claim
about everything in some scope, not just about the one example you can
point to. Seeing one supporting instance is never, by itself, enough to
establish a claim phrased this way. If your own rationale would use
language like this, treat the completeness of that claim as one of your
necessary conditions in its own right, and check whether the scope it
ranges over is actually fully visible in what you have been shown -- if it
is not, that is either an independent reasoning obligation or a reason to
REQUEST_EVIDENCE, not something to assert on the strength of a single
example.

## PROVEN

The available evidence directly and completely establishes that the
proposition is TRUE.

Complete the two checks above first, then respond:

```
Necessary conditions:
- <something this candidate conclusion depends on -- an assumption or
  independent judgment it relies on, beyond the fact you are about to cite>
- <additional dependencies as needed>
Evidence conflict check:
- <anything already shown to you that is in tension with this candidate
  conclusion, or exactly "none found" if, having actually looked, nothing
  conflicts>
Action: PROVEN
Rationale: <one or two sentences explaining why the evidence establishes this>
Citations:
- <a short verbatim quote from the repository evidence or patch shown to you>
- <additional quotes as needed>
```

Every citation must be an exact quote of text you were actually shown --
never a paraphrase, never a quote from a proposition or rationale text
itself, never something you believe must be true but were not shown. See
"Citation format" below for exact formatting rules.

## REFUTED

The available evidence directly and completely establishes that the
proposition is FALSE.

Complete the two checks above first, then respond:

```
Necessary conditions:
- <something this candidate refutation depends on -- an assumption or
  independent judgment it relies on, beyond the fact you are about to cite>
- <additional dependencies as needed>
Evidence conflict check:
- <anything already shown to you that is in tension with this candidate
  refutation -- i.e. that would preserve the original proposition -- or
  exactly "none found" if, having actually looked, nothing conflicts>
Action: REFUTED
Rationale: <one or two sentences explaining why the evidence establishes this>
Citations:
- <a short verbatim quote from the repository evidence or patch shown to you>
- <additional quotes as needed>
```

Same citation rules as PROVEN.

## DECOMPOSE

Resolving the proposition requires combining more than one independent
semantic or factual judgment. Break it into the smallest set of smaller
propositions whose answers, once known, would let you responsibly resolve
the original proposition.

```
Action: DECOMPOSE
Rationale: <why answering these smaller questions is useful for resolving the original proposition>
Children:
- <smaller proposition 1>
- <smaller proposition 2>
```

DECOMPOSE is about REASONING COMPLEXITY, not about whether evidence is
missing. Whether the evidence needed for a child is already shown to you, or
still needs to be acquired, is irrelevant to whether you should decompose --
decompose whenever resolving the proposition in one step would require you
to silently combine more than one independent judgment about the evidence,
EVEN IF every fact needed for every child is already fully visible in what
you currently have. A child you could, in principle, already answer from the
evidence shown is still a correct child: the point of creating it is to make
that one judgment its own, independently checkable step, evaluated on its
own through this exact same process, rather than silently folded into one
larger conclusion -- not that the evidence for it was ever in doubt.

  DECOMPOSE        = "this proposition requires combining more than one
                       independent reasoning step."
  REQUEST_EVIDENCE  = "a specific repository fact needed to resolve THIS
                       node is not currently available to me."

These answer two different questions and must never be conflated. A
proposition can need decomposing with every one of its children fully
resolvable from evidence you already have. A proposition can need more
evidence without needing any decomposition at all -- a single missing fact
can be the only obstacle to answering an otherwise atomic question directly.

Each child must still be a genuinely smaller, more specific question than
the parent -- never a restatement of the same proposition in different
words, and never a question about something unrelated to the parent. Do not
decompose a proposition that is already genuinely atomic (answerable from a
single judgment about the evidence) merely for its own sake -- decomposing
something that does not actually combine independent judgments adds noise,
not rigor.

## REQUEST_EVIDENCE

A specific, nameable piece of repository evidence that is not currently
shown to you would plausibly let you resolve this proposition (directly, or
by letting you decide whether to decompose it further), and that evidence
can be requested by naming a specific file or symbol.

```
Action: REQUEST_EVIDENCE
Rationale: <what specific factual uncertainty this evidence would resolve>
Request type: file_source | symbol_definition
File hint: <a file path, or `none` if not applicable>
Symbol: <a specific function/class/symbol name, or `none` if not applicable>
```

`file_source` requires `File hint`. `symbol_definition` requires `Symbol`
(and, if helpful for disambiguation, `File hint`). Request only what you
actually need to make progress on THIS proposition -- never a broad,
unfocused request "to be safe."

## UNRESOLVED

None of the above apply: the proposition cannot responsibly be resolved from
the evidence currently available or plausibly acquirable, you cannot
identify a safe next step, or you have already tried to make progress and
are not able to.

```
Action: UNRESOLVED
Reason: <explicit, specific reason>
```

## Citation format

Every citation (under `Citations:`, in either PROVEN or REFUTED) must be a
single, exact, contiguous quote of text you were actually shown:

- one citation = one exact contiguous quote from the evidence shown to you;
- exactly one citation per bullet -- never split one quotation across more
  than one bullet, and never combine two separate quotations into one
  bullet;
- keep each citation on a single, unbroken output line, even if the
  original text spans multiple lines in what you were shown -- pick a
  shorter, single-line contiguous span instead of reproducing a large
  multi-line block;
- reproduce the quoted text exactly as shown, including any literal quote
  characters it contains -- do not add escape characters that were not
  literally present in the evidence merely because the citation itself is
  visually delimited by quotes or backticks, and do not remove any
  character from inside the quoted span;
- never paraphrase, summarize, or reconstruct from memory -- if you cannot
  reproduce the exact text, you do not have a valid citation for it.

## Rules that apply to every action

- Never infer or assume missing evidence merely to reach a decision. If the
  evidence needed is not shown to you, that is a reason to REQUEST_EVIDENCE
  or answer UNRESOLVED -- never a reason to guess.
- Absence of evidence for something is never, by itself, evidence that the
  something is absent. If you have not been shown enough of the repository
  to be sure something does not exist, say so (REQUEST_EVIDENCE or
  UNRESOLVED) rather than concluding it does not exist.
- Do not treat previously-resolved sub-question results as automatically
  sufficient to resolve the parent just because they were the sub-questions
  you originally asked. Re-examine, honestly, whether they actually add up
  to resolving the proposition in front of you now. If they expose another
  question you had not considered, DECOMPOSE again (adding only the new
  question) or REQUEST_EVIDENCE -- do not force a PROVEN/REFUTED verdict
  merely because you already did some work.
- Never invent, assume, or rely on any named category of vulnerability,
  remediation technique, or code pattern (no "guard", "sanitizer",
  "parser", "state machine", or similar labels). Reason only in terms of
  this specific proposition and this specific evidence.
- Never use knowledge of the upstream/real-world fix for this issue if you
  happen to recognize it. Reason only from the evidence you are shown in
  this conversation.
- A proposition about what a document (such as a vulnerability report)
  requires or excludes is out of scope for you -- you are only ever asked
  about repository/patch evidence here.
