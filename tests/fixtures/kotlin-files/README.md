# Kotlin filesystem static controls

Original source controls, not a running server or deployed assessment.
Their independent labels concern request selection of the file path (CWE-22),
not file-content validation or a separate authorization policy.

| Method | Label | Reason |
| --- | --- | --- |
| rawRead | issue | Request String selects an unrestricted read path. |
| rawWrite | issue | Request String selects an unrestricted write path. |
| normalizedRead | issue | Resolving and normalizing does not confine the path to the fixed root. |
| fixedRead | not_issue | File path is fixed; the request parameter is unused. |
| allowlistedRead | not_issue | Accepted selector maps to one fixed server-owned path; other names fail. |
| fixedWriteContent | not_issue | Request influences content, not the fixed target path. |

Path factories and transformations preserve influence. Normalization alone is
not root containment or a symlink policy. No filesystem operations are executed
while scanning this fixture.
