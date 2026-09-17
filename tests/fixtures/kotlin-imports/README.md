# Runtime import controls

Original source controls for JVM default imports and an explicit package wildcard.
The custom Runtime ignores the command and returns fixed text. Fully qualified,
explicitly imported and aliased JVM Runtime calls pass request text to execution.
These handlers are source controls, not a deployed application.

All four source files were compiled with the cached Kotlin 2.4.10 compiler and
JDK 17. The custom control returned its fixed result; the three real process
handlers were not executed. A foreign wildcard is rejected conservatively when
the scanner cannot establish that a short default JVM name is canonical.
