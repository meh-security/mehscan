# Kotlin quality application

Original, intentionally unsafe loopback-only Spring/JPA app for scanner quality
evaluation. Requires JDK 17 and Gradle compatible with the pinned plugins.
Run `gradle bootRun`; the server binds `127.0.0.1:8099`. Do not deploy it.
For the runtime regression on Windows with PowerShell 7, run `gradle bootJar`,
then `./smoke.ps1 -Java "$env:JAVA_HOME/bin/java.exe"`. It starts the fixture,
checks unsafe and safe endpoints, saves results under `build`, and stops its
own process. Port 8099 must be free.
Plugin versions match the pinned upstream Petclinic reference used by the
evaluation; no third-party application source is copied here.

Independent source oracle:

| Method | Expected decision | Reason |
| --- | --- | --- |
| rawQuery | issue | Request text becomes quoted HQL syntax. |
| rawJdbcQuery | issue | Request text becomes quoted JdbcTemplate SQL syntax. |
| boundJdbcQuery | not_issue | Fixed SQL uses a separately bound positional value. |
| rawFileRead | issue | Request name selects a file without root containment. |
| rawFileWrite | issue | Request name selects a write target without root containment. |
| safeFileRead | not_issue | Allowed selector maps to a fixed filename; other names fail. |
| boundQuery | not_issue | Fixed query and separately bound name value. |
| numericQuery | not_issue | A Long cannot introduce HQL delimiters. |
| rawCommand | issue | Request text selects the executable and arguments. |
| fixedCommand | not_issue | Fixed local executable; no request-controlled command. |

Runtime/build verification is a separate gate from static scanner and model
checks. The app contains no production credentials. Its smoke script uses
benign query predicates and `whoami` against its own loopback process.

The evaluation built `bootJar` with Temurin 17.0.20.1 and Gradle 9.7.0 and passed
twenty loopback checks: raw/bound JPA and JdbcTemplate queries with ordinary,
injected predicate and quote-containing
names, valid/invalid numeric binding, and benign `whoami` execution through the
raw and fixed command routes. Quote-containing raw query input returns 500;
the bound query returns 200, and a nonnumeric ID returns 400. The external
Petclinic and Ktor corpora were not built or executed.

Seeded Alice and Bob records also permit a predicate-change regression: request
name=' OR '1'='1 at the raw query returns both records; the same name at the
bound query returns none. This is a loopback fixture check only.

Filesystem checks create a unique disposable directory with a `public` child
and one sibling fixture file. The JVM property `mehscan.fixture.root` points
to `public`. The raw read retrieves the sibling via traversal and the raw write
replaces it; the allowlisted read accepts `readme` and rejects traversal. The
script stops its server and removes only that generated directory after checking
the cleanup path. No real private files are used. Direct `bootRun` uses the
server-owned `./fixture-data/public` default until the property is configured.
