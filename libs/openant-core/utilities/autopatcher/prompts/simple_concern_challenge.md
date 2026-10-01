# Simple Concern Resolver -- Pass 2 (Challenge + Finalize)

The ORIGINAL PROPOSITION is the thing you are actually deciding. Whatever
supporting facts you first identify for it are only a candidate
argument, not the question itself -- that argument may be right for the
wrong reason, or wrong even though every fact it relies on is
individually true.

Your job is NOT merely to decide whether the facts you cite are correct,
or whether your reasoning from them is internally consistent. Facts can
be completely correct, and reasoning built on them can be completely
consistent, while still not being enough to establish the original
proposition. Your job is to decide whether the ORIGINAL PROPOSITION
itself actually follows from the available evidence -- treating any
candidate argument you form as one attempt at it, never as the
definition of what you are checking.

Before finalizing:

1. Re-read the original proposition on its own terms, independent of
   whatever argument for it first comes to mind.
2. Identify the facts supporting the proposition, and ask: even granting
   that every one of them is true, are they actually SUFFICIENT,
   together, to establish the proposition -- or could the proposition
   still fail to follow even with all of them true?
3. Ask what else would have to be true for the proposition to actually
   follow from those supporting facts -- a required link the supporting
   facts alone do not establish, and that may not have been named at
   all.
4. Search the evidence already shown for something that speaks to that
   required link -- specifically for evidence that could coexist with
   every one of the supporting facts you identified (it does not need to
   contradict any of them) while still preventing, defeating, or
   invalidating the proposition's claimed outcome. This is a search for
   coexisting defeating evidence, not merely for contradicting evidence:
   something that leaves every cited fact true and uncontradicted, yet
   still breaks the link between those facts and the proposition, is
   exactly what you are looking for, and is easy to miss if you only ask
   whether the cited facts themselves hold up. Also consider relevant
   evidence you have not yet looked at, and whether the shown evidence
   supports an alternate interpretation you have not yet taken.
5. Only once you have done this -- not merely checked your own facts and
   reasoning for internal correctness -- finalize. Concluding that the
   proposition follows is only valid after you have genuinely carried
   out this search; it is never the default.

You will be shown:

- the concern to evaluate;
- the repository evidence and patch currently available, including
  anything acquired to help resolve it.

Respond with EXACTLY this shape, in EXACTLY this order -- `Challenge
result` MUST come before `Final verdict`, so your challenge is genuinely
formed before you commit to a verdict, never written afterward to justify
one you had already settled on:

```
Challenge result: <whether the original proposition's supporting facts are jointly sufficient to establish it, what required link (if any) you identified, and whether the evidence shows anything that could coexist with those facts while still defeating the proposition -- or, if the proposition survives this check, what required link you specifically verified holds>
Final verdict: PROVEN | REFUTED | UNRESOLVED
Final reasoning: <one or two sentences explaining your final assessment>
Citations:
- <your OWN exact contiguous evidence text, copied verbatim with no surrounding delimiter>
- <additional citations as needed, same format>
```

Your citations are independently checked -- each one must actually
establish what you claim on its own merits. If you find something that
changes the picture partway through your own analysis, say so in
`Challenge result` and let your own `Final verdict`/`Citations` reflect
what the evidence actually supports.

If you find a material tension in the evidence that you cannot
responsibly resolve, answer `Final verdict: UNRESOLVED` -- never force a
PROVEN or REFUTED you cannot actually support with your own citations.

You cannot request additional evidence at this stage -- resolve this from
what you have been shown, or answer UNRESOLVED.

## Citation format

Everything after the bullet marker (`- `) is the citation itself: copy
the exact contiguous evidence/repository text there, character for
character, with nothing added around it.

- one citation = one exact contiguous span of the evidence shown to you,
  on a single, unbroken output line -- never split one span across more
  than one bullet, and never combine two separate spans into one bullet;
  for a span that would otherwise cross multiple lines, pick a shorter,
  single-line contiguous span instead;
- do NOT surround the citation with quotes, backticks, code fences, or
  any other delimiter -- write the text directly after `- `, nothing
  else;
- do NOT add escape characters that are not literally present in the
  evidence, even when the evidence itself contains quote characters,
  backticks, or backslashes -- copy it exactly as shown;
- do NOT remove or alter any character from inside the span;
- never paraphrase, summarize, or reconstruct from memory -- if you
  cannot reproduce the exact text, you do not have a valid citation for
  it.

Example -- if the evidence shown to you contains this line:

    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])

the correct citation is:

    Citations:
    - DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])

NOT:

    Citations:
    - "DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Cookie\", \"Authorization\"])"

The quote characters around "Cookie" and "Authorization" are genuinely
part of the evidence and are copied exactly as they are -- but nothing is
added around the whole line. Copying the text is the entire task; there
is no wrapping or serialization step.

## Rules

- Do not assign a confidence score or trust label of any kind -- only one
  of the three verdicts above.
- Never invent, assume, or rely on any named category of vulnerability,
  remediation technique, or code pattern (no "guard", "sanitizer",
  "parser", "state machine", or similar labels). Reason only in terms of
  this specific concern and this specific evidence.
- Never use knowledge of the upstream/real-world fix for this issue if
  you happen to recognize it. Reason only from the evidence you are shown
  in this conversation.
- A proposition about what a document (such as a vulnerability report)
  requires or excludes is out of scope for you -- you are only ever asked
  about repository/patch evidence here.
