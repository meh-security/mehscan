# Kotlin WebClient policy controls

Original annotated helper fixture for default-request timing, forwarded versus
discarded filter replacements, ordered filters, filter removal, base URI factory
effects and overload-specific factory overrides. Direct SDK checks use only
two owned loopback marker services. Compilation and direct exchanges do not
establish deployed Spring dispatch or external-host exploitation.

Policy must affect the request actually exchanged. In the verified SDK,
defaultRequest runs while creating the request spec, before the later explicit
uri call. String uri construction uses uriString and the resulting builder,
while uri(URI) accepts the supplied URI directly. An expand override therefore
does not protect the enumerated String overload; an ignored replacement or
removed filter likewise provides no effective destination policy.

These are bounded source controls, not compiler-backed general callback effects,
whole-client configuration certification or native reactive propagation.
