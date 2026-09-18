# Kotlin object-filter policy controls

Original Spring/JDK teaching fixture. `rawObject` materializes request-selected
Java serialized classes without a filter. `safeObject` restricts classes to
String data and limits stream structure. `wrongStream` filters a distinct,
unused stream while the exposed stream remains unrestricted. A cast after
`readObject` does not prevent materialization or callbacks before that cast.

Compile both Kotlin files with Kotlin 2.4.10, JDK 17 and Spring Web 7.0.9;
run `quality.objects.ProbeKt`. Seven direct assertions demonstrate callback
invocation, rejection before callbacks, and acceptance of String data. The
callback only increments its fixture counter. There are no external targets,
filesystem effects, deployed endpoint claims or remote-code-execution claims.
