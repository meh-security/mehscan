# JVM URL controls

Original vulnerable/safe Spring test handlers for canonical URL/URI factories,
immutable aliases, lazy connection construction and a coroutine fetcher.
The local target at port 8100 is disposable fixture infrastructure, not a
deployment. The fixed/selector routes use an exact server-owned destination;
raw routes accept the complete URL. The lookalike returns constant text.

Scanning these files never runs the application or sends requests.

The files compile with Kotlin 2.4.10/JDK 17. Ten direct method checks against a
disposable loopback HTTP server exercise raw URI and URL reads, connection I/O,
fixed and allowlisted selection, a rejected selector, lazy construction with
no request, coroutine I/O, the constant lookalike and a valid raw destination.
The target listens only on 127.0.0.1 and stops after the checks; no external
targets or deployed application are exercised.
