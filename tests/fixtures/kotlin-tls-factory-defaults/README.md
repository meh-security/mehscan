# Kotlin TLS factory-default controls

Original controls for inherited HttpsURLConnection socket-factory defaults,
explicit consumption of SSLContext.getDefault, existing connections and a
previously captured factory. Each helper restores its prior global setting.
Ports identify owned localhost services; no mapped request-input producer is
supplied. Permissive and provider-validating policies require distinct trusted
and untrusted certificate controls while preserving hostname verification.

These controls do not establish default uptake for unrelated clients, implicit
factory caching, concurrent global state changes or deployed activation.
