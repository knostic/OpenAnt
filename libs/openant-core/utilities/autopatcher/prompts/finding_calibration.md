# Finding Calibration Prompt

You are calibrating the certainty and scope of a security reviewer's adversarial
findings before they are shown to a human reviewer. You are given the
vulnerability advisory, the proposed patch, any repository evidence that was
shown to earlier reviewers, and a numbered list of findings from an
adversarial challenger.

For each finding, do two things:

1. **Classify** it into exactly one of three groups:
   - `Observed` — the evidence shown above directly demonstrates the specific
     state or behavior the finding claims (not merely a related file,
     function, or constant). This includes any intermediate transformation,
     assignment, or normalization step the conclusion depends on: if reaching
     the claimed conclusion requires such a step, that step itself must be
     visible in the evidence above.
   - `Hypothesis` — a plausible behavior inferred from code analysis where any
     part of the reasoning chain (e.g. an intermediate transformation,
     assignment, or normalization step the conclusion depends on, or the
     file/function/library itself) is NOT directly shown in the evidence
     above, and would need validation to confirm.
   - `Hardening` — a security idea unrelated to the specific vulnerability
     described in the advisory (defense-in-depth, other headers, other
     mechanisms not implicated by this advisory).

2. **Reword** it so the certainty of the sentence matches its group:
   - `Observed` findings may state what the evidence shows directly.
   - `Hypothesis` findings must use conditional/hedged language ("may",
     "could", "if X does not do Y, then Z may happen") rather than asserting
     an outcome as if it were observed. Do not state a hypothesis as a fact.
   - `Hardening` findings must make explicit that they are unrelated to the
     current advisory's scope, and must not be worded as if they weaken
     confidence in the proposed patch (no "however", "but", "still fails to"
     framing — these are suggestions, not shortcomings).

Do not invent new findings. Do not drop any finding. Every input finding must
appear exactly once in your output, in the same order given.

Return your answer as a numbered list, one block per input finding, in this
exact format (repeat for every finding, in order):

1. Group: <Observed|Hypothesis|Hardening>
   Reworded: <the reworded finding, one paragraph, no line breaks>

2. Group: <Observed|Hypothesis|Hardening>
   Reworded: <the reworded finding, one paragraph, no line breaks>

Do not include any other content, headers, or commentary outside this list.

Example input findings:

1. Users relying on Cookie persistence across redirects will experience breakage.
2. Redirects within the same origin still strip Cookie.
3. The Proxy-Authorization header is not included in the default strip list.

Example output:

1. Group: Hypothesis
   Reworded: Applications relying on Cookie persistence across redirects may require validation.

2. Group: Hypothesis
   Reworded: If redirect stripping does not distinguish same-origin from cross-origin redirects, same-origin redirects may also strip Cookie.

3. Group: Hardening
   Reworded: The Proxy-Authorization header is not covered by this advisory; adding it to the default strip list would be a separate, unrelated hardening improvement.
