# Cryptography and configuration

Identify the security purpose and exact operation first. A hash used as a
checksum has a different requirement from password storage, token signing or
credential derivation. Inspect the effective algorithm, parameters, key
source or random generator at that operation.

For cookies, CORS and similar settings, determine which configuration owns
the reviewed response or route. A possible proxy rewrite does not erase a
shown application setting; a supplied effective deployment rewrite can
change the decision. Treat a runtime-only or deployment-only control as an
explicit missing fact when the repository cannot establish it.

For CORS, establish a browser-readable sensitive response with applicable
credentials before treating permissive origin headers as an issue. Default
`cors()` permits origins but omits credential allowance; preflight registration
alone is not an independent data exposure.
