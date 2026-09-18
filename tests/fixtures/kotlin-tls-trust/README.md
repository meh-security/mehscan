# Kotlin TLS certificate trust controls

Original SSLContext initialization fixture with permissive server-certificate
checks, provider defaults and validation, wrong contexts, reinitialization,
trust-manager ordering and swallowed validation errors. Direct TLS checks use
only two owned loopback services and disposable certificates for localhost.
Hostname checks remain enabled, so certificate-chain trust is tested separately.

The private runtime harness configures its isolated JVM's default trust store
to the first owned certificate. Protected controls accept that certificate and
reject the second; permissive controls accept both. Those assertions do not
establish deployed TLS activation or safe arbitrary trust-store configuration.
Native callback/lifecycle inference, global defaults and wider client bindings
remain separate release obligations.
