# Kotlin client and process factories

Original Spring/JDK/OkHttp teaching controls. Canonical JDK client factories
and builder chains, and OkHttp constructors/builders, must produce owned
request leads. ProcessBuilder command replacement must be considered at start;
a fixed constructor command does not approve a later request-selected command.
The fixed-command control executes only server-owned `whoami`. Lookalikes must
not borrow JDK client identity.

Compile both files with Kotlin 2.4.10, JDK 17, Spring Web 7.0.9, OkHttp 4.12.0
and its Okio dependencies; run `quality.factories.ProbeKt`. Eight checks use
only the probe's loopback HTTP server and harmless `whoami`. The endpoints are
called directly; deployed Spring registration and access to sensitive resources
are not established. The fixed JDK destination control is compiled and reviewed
but not executed; no listener at that fixed port is required. The lazy OkHttp
control is created but not executed. Factory identity is not destination or
command approval.
