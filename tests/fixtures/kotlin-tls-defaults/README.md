# Kotlin global TLS default controls

Original hostname-default controls distinguish a new consumed connection,
restoration before construction, a preexisting connection and an instance
override. Each helper restores the prior global default on exit. The private
isolated JVM uses one owned HTTPS service with a trusted localhost certificate:
matching localhost and mismatched numeric-loopback connections distinguish
hostname behavior without bypassing certificate-chain validation. Integer ports
refer to that owned service and there is no mapped request-input producer.

These controls do not establish global concurrency effects, deployed activation,
or arbitrary client uptake of SSLContext and socket-factory defaults. Those APIs
have separately recognized canonical setter boundaries and require their own
consumer evidence.
