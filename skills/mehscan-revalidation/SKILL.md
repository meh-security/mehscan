---
name: mehscan-revalidation
description: Reassess a completed Mehscan security review when new repository facts or user policy may change its verdict or severity. Use for follow-up, not initial scanning.
---

# Mehscan revalidation

Read the validated review, its original Mehscan bundle, and the new fact or policy. Work on one review ID at a time. Use the bundle's `review_basis.security_question`, anchor, capability, and captured sink operand to identify the exact failure being revalidated. If the original bundle is unavailable, locate it by review ID before changing severity; a response summary alone can blur adjacent operations. Confirm the new fact applies to the same operation, location, and security question; put a different issue in a separate review.

1. Identify the prior verdict, decisive evidence, and any unresolved check.
2. Record the new fact and its source. If code can settle a disputed edge, use the smallest relevant Mehscan query and cite the returned location. Follow through to a template, framework option, helper, or repository test when that determines what the code actually does. Label user-supplied policy or runtime knowledge as such.
   When a behavior test could result from an earlier transformation, establish which operation caused it before attributing the effect to this review's sink; use Mehscan `references` on the route or feature identifier to find an integration or browser test of the exact effect.
3. Reconsider the exact previously missing edge. Choose `issue`, `not_issue`, or `needs_review`. A demonstrated vulnerable branch with a known enablement condition is a conditional source issue; state the condition and seek deployment facts only to decide whether it applies to the assessed instance or changes severity. Keep `needs_review` only with a specific missing fact and a way to check it. If the new fact changes nothing, say why and keep the verdict.
4. For a confirmed issue, reconsider severity from the impact of **this card's exact failure** and applicable user policy. A neighboring server-side execution, payment, or read weakness is a separate lead; it cannot raise this card's severity. Keep confidence about the verdict separate from severity. Do not infer impact from confidence or an unverified effect.

Return a short note:

```text
Review ID / operation:
Previous decision:
New fact and source:
Updated decision and severity (if issue):
Reason:
Remaining check (if any):
```

Preserve the original review and response. This note records the follow-up; it does not silently rewrite a Mehscan report.
