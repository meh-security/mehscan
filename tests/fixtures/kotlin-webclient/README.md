# Kotlin WebClient destination controls

Original annotated helper fixture covering String, absolute URI, URI-builder
and template-map request destinations, canonical client construction, lazy
publishers and same-spec URI replacement. Direct runtime checks exercise actual
Spring request construction and subscription using an instrumented ExchangeFunction
that returns only the effective destination, plus four actual HTTP exchanges from
canonical create/builder clients to an owned loopback marker service. Twenty-one
assertions check destination expansion, subscription and replacement; no external
network access or deployed Spring route is claimed. Separate path expansion does not itself establish
host control; a URI on an unused publisher does not establish outbound execution.

Client filters, default-request effects, additional factories and callback/helper
effects remain wider obligations; bounded containing-function context does not
claim compiler overload binding or native reactive flow.
