# Kotlin WebFlux request controls

Original functional-handler fixture for canonical ServerRequest Optional query
input, String path variables and Mono String bodies. Source inventory preserves
those representations and does not assert native reactive/lambda effects.
Source review must establish the unwrap, operator binding and actual consumer.
Private Spring WebTestClient routes subscribe these helpers against an owned
JDK loopback server. All returned text is a dummy marker; no deployed routing or
sensitive-service access is claimed. WebClient, reactive DTO binding and broader
response/authorization policies remain separate coverage obligations.

The rawPath parameter is a String interpolated into URL authority syntax, not
a validated numeric port. An owned-loopback control containing user-info syntax
changes the parsed host from 127.0.0.1 to localhost and reads the same dummy
service. A literal loopback prefix therefore does not establish host containment;
external-host exploit reproduction is outside these controls.
