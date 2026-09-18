---
name: mehscan-report-quality
description: Judge the quality and actionability of a final Mehscan Markdown report. Use after AI triage to catch scope leaks, vague verdicts, unreadable finding titles, missing evidence, and non-actionable follow-ups; do not use to replace source-level security triage.
---

# Mehscan Report Quality

Review the final `mehscan-report.md` as a security handoff. Read its canonical
`mehscan-findings.json` sibling when available to reconcile counts and metadata.
This is a quality review of completed triage, not a second scan and not license
to invent source facts.

## Judge the handoff

Return one overall verdict: `pass`, `pass_with_warnings`, or `fail`. Explain
only concrete deficiencies and rank fixes by their effect on user decisions.

Check these invariants:

- Default production results do not silently include unit tests, fixtures,
  examples, generated files, or vendored dependencies. If intentionally
  included, label their scope so they cannot be mistaken for deployed code.
  Portable reports carry that label and their selected-source limitation in
  the report itself; a scan root of `.` or a separate sidecar is insufficient.
- A finding title names the behavior in plain language. CWE identifiers belong
  in metadata, never as the title or the words a reader must decode.
- Every confirmed issue identifies the affected behavior and component, the
  plausible impact, the evidence location, and a remediation direction. Do not
  demand exploit theatrics when the bounded weakness is already actionable.
- `needs_review` names one concrete missing artifact or fact that a person can
  obtain. Generic prompts such as "check whether input is attacker controlled"
  or "verify the effective runtime value" are report-quality failures unless
  they identify exactly where and how to verify it.
- Confidence measures confidence in the verdict, not severity. Medium
  confidence can still be decisive. Do not prefer `needs_review` merely because
  the reviewer cannot prove the whole program safe.
- Dismissals state the supplied reason for inapplicability or safety. They do
  not make broad claims beyond the reviewed operation.
- Verdict explanations stay within the evidence supplied for their exact
  review ID. A neighboring review cannot establish a missing input origin,
  producer or control. Conditional quoting or encoding does not protect a
  separate raw branch. When comparing reviewers, agreement alone is not a
  quality result: both can repeat the same unsupported claim. Record remaining
  disagreements and shared evidence errors separately; an isolated retry is
  a targeted audit, not a complete corpus report.
- Injection explanations identify a compatible producer and consumer operation.
  Unknown helper effects do not establish either sanitization or survival of the
  old value; declarations with another callable or owner do not answer that
  question. Server metadata and session fields need a supplied producer and
  relevant attacker influence, rather than an assumption based on their names.
  A dismissal must not require unsafe input on every execution path or require
  an attacker-controlled condition/selector when a shown branch or selected
  request-derived value already establishes the weakness.
- Evidence and candidate counts are not presented as vulnerability totals.
  Markdown counts reconcile with canonical JSON when it is present.
- Source availability describes conditional compilation/build inclusion, not
  runtime execution frequency. `availability.state: always` can coexist with
  a runtime `if` branch; it does not say that the operation executes on every
  invocation. Supplied typed caller context can support a bounded source
  explanation without a native cross-callable flow. Do not confuse either
  with verified runtime dispatch or deployed endpoint exposure.
- Repeated items are consolidated when they express the same root cause and
  remediation, while materially different call sites remain distinguishable.
  A grouped heading can represent several confirmed finding instances: verify
  the summary against canonical JSON instance counts, not the number of
  Markdown headings, and require every grouped instance to retain its location
  and decision metadata.
  When canonical aggregation merges several source relationships at one sink,
  retain every affected operand in the narrative, not only the first summary.

## Report the quality result

Lead with the overall verdict and whether the report is ready to hand to an
engineer. Then list only actionable quality findings with the affected report
section or finding title, why it impairs a decision, and the smallest useful
fix. Separate scanner/admission defects from AI-reasoning defects and Markdown
presentation defects so the correct layer is repaired.

Do not silently rewrite triage decisions. If asked to improve the report,
preserve the canonical verdicts unless the supplied evidence itself justifies a
change, and regenerate projections from canonical data rather than hand-editing
JSON or SARIF.
