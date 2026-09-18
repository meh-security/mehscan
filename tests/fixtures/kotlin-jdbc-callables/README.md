# Kotlin JDBC callable overload controls

Original scalar-input fixture for three/four-argument prepareCall, followed by
same-statement execution, parameter binding or immediate closure. Preparation
does not sanitize already interpolated SQL, and an unused preparation does not
establish executed SQL-injection impact. Private controls compile on JDK17 and
use owned in-memory H2 dummy records; they instrument preparation, execution and
closure for the unused case. No deployed Spring dispatch is claimed.
