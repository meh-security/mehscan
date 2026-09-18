# Kotlin XML policy controls

Original Spring/JDK teaching fixture. `rawXml` and `wrongFactory` permit an
external entity to read a file; `safeXml` rejects DOCTYPE before parsing.
The guard on `guarded` does not protect the distinct `exposed` factory.

`Probe.kt` calls the methods directly, creates and removes its own temporary
marker file, and checks external-entity behavior plus ordinary XML for all
three methods. It makes no network requests and does not establish deployed
Spring routing. Compile both Kotlin files with Kotlin 2.4.10, JDK 17, and
Spring Web 7.0.9 on the classpath; run `quality.xml.ProbeKt`.

The scanner should inventory all four feature setters and all three parses.
The setter on `guarded` is a protective operation; the unsafe parse in the
same method must not turn that setter into an unsafe configuration finding.
