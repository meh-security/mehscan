# Kotlin hostname-verifier policy controls

Original JDK teaching fixture. `rawTls` permits a hostname mismatch before a
connection read. `safeTls` uses the default verifier. `wrongConnection` hardens
a distinct unused connection, then reads the connection with a bypass callback.
Judge each setter separately; ordinary connection reads do not establish SSRF
without a supplied attacker-selected destination.

Compile both files with Kotlin 2.4.10 and JDK 17. Generate a temporary PKCS12
keystore with `keytool -genkeypair -alias fixture -keyalg RSA -storetype PKCS12
-storepass fixture-only -keypass fixture-only -dname CN=localhost
-ext SAN=dns:localhost -validity 1 -keystore <temporary-path>`. Run
`quality.tls.ProbeKt <temporary-path>` and remove the keystore afterward.

The probe binds HTTPS to loopback, trusts only its own generated certificate,
and checks hostname mismatch acceptance/rejection plus a matching hostname.
Four direct checks do not establish deployed reachability. There is no global
trust override, external network target or application-controlled URL source.
