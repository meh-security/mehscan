# JVM boundary controls

Original Kotlin controls exercise canonical ProcessBuilder, File, object/Jackson
decoding, XML parsing/configuration, hostname verification, servlet redirects,
URLConnection consumers and Java/OkHttp request boundaries. Custom lookalikes
must not enter the inventory. Unknown stream, parser, verifier, request and
location origins are ordinary observations, not automatically vulnerabilities.

The mapped raw executable and File path cases demonstrate unsafe selection.
Fixed executable/read targets and a fixed write target are negative controls;
request-controlled write content alone is not path traversal. All fourteen
inventory cases are covered by the native integration tests.

The file compiles with Kotlin 2.4.10/JDK 17, Spring Web 7.0.9, Jackson 3.1.5,
Tomcat servlet API 11.0.24 and OkHttp 4.12.0. Three isolated direct checks launch
only `whoami` through raw/fixed process methods and read an owned temporary file
through the raw File method. The temporary file/directory is then removed.
These checks do not reproduce deserialization, XXE, TLS bypass, redirects or
HTTP client attacks and do not establish deployed Spring endpoints.
