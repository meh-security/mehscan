# Ktor request and response controls

Original controls cover typed ApplicationCall query/path/body inputs and the
canonical Application routing/get DSL, including an Elvis default. Their values
reach commands, redirects, explicit HTML or typed HttpClient requests. Named
arguments are tested for URL, HTML content/type and client URL selection.

Fixed redirects, fixed HTML and fixed client destinations are negative controls.
Plain-text responses and custom ApplicationCall lookalikes are excluded from the
HTML/request inventory. Unknown receiver lambdas and local `call` shadows stop
implicit routing ownership. The native integration test checks nine request
sources and seven bounded source-to-sink owners.

The fixture compiles with Kotlin 2.4.10/JDK 17 and Ktor 3.6.0. Nine isolated Ktor
test-application HTTP pipeline checks exercise `whoami`, raw/fixed redirect
Locations, reflected HTML, plain-text content type, fixed HTML, decoded HTML
bytes and the distinct fixed invalid-Base64 error response. Redirects
are not followed; no external URLs are contacted. Query/path/body helper
functions and the client request pair are also checked statically but are not
claimed as deployed routes or reproduced SSRF attacks.
