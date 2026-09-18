package quality.jwtlifetime

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import java.time.Instant

// Access credentials issued here must stop authenticating within five minutes.
// The first six consumers have no separate maximum-age or revocation check.

fun withoutExpiry(serverKey: ByteArray, now: Instant): String {
    // This issues an access credential required to stop authenticating within five minutes.
    val builder = JWT.create().withIssuer("owned-issuer").withSubject("owned-user").withIssuedAt(now)
    val credential = builder.sign(Algorithm.HMAC256(serverKey))
    val accepted = JWT.require(Algorithm.HMAC256(serverKey)).withIssuer("owned-issuer").build().verify(credential)
    require(accepted.subject == "owned-user")
    return credential
}

fun boundedExpiry(serverKey: ByteArray, now: Instant): String {
    // This issues an access credential required to stop authenticating within five minutes.
    val builder = JWT.create().withIssuer("owned-issuer").withSubject("owned-user").withIssuedAt(now).withExpiresAt(now.plusSeconds(300))
    val credential = builder.sign(Algorithm.HMAC256(serverKey))
    val accepted = JWT.require(Algorithm.HMAC256(serverKey)).withIssuer("owned-issuer").build().verify(credential)
    require(accepted.subject == "owned-user")
    return credential
}

fun clearedExpiry(serverKey: ByteArray, now: Instant): String {
    // This issues an access credential required to stop authenticating within five minutes.
    val builder = JWT.create().withIssuer("owned-issuer").withSubject("owned-user").withIssuedAt(now).withExpiresAt(now.plusSeconds(300))
    builder.withExpiresAt(null as Instant?)
    val credential = builder.sign(Algorithm.HMAC256(serverKey))
    val accepted = JWT.require(Algorithm.HMAC256(serverKey)).withIssuer("owned-issuer").build().verify(credential)
    require(accepted.subject == "owned-user")
    return credential
}

fun wrongBuilder(serverKey: ByteArray, now: Instant): String {
    val other = JWT.create().withExpiresAt(now.plusSeconds(300))
    // This issues an access credential required to stop authenticating within five minutes.
    val builder = JWT.create().withIssuer("owned-issuer").withSubject("owned-user").withIssuedAt(now)
    val credential = builder.sign(Algorithm.HMAC256(serverKey))
    val accepted = JWT.require(Algorithm.HMAC256(serverKey)).withIssuer("owned-issuer").build().verify(credential)
    require(accepted.subject == "owned-user")
    return credential
}

fun payloadOverride(serverKey: ByteArray, now: Instant): String {
    // This issues an access credential required to stop authenticating within five minutes.
    val builder = JWT.create().withIssuer("owned-issuer").withSubject("owned-user").withIssuedAt(now).withExpiresAt(now.plusSeconds(300))
    builder.withPayload(mapOf("exp" to null))
    val credential = builder.sign(Algorithm.HMAC256(serverKey))
    val accepted = JWT.require(Algorithm.HMAC256(serverKey)).withIssuer("owned-issuer").build().verify(credential)
    require(accepted.subject == "owned-user")
    return credential
}

fun restoredExpiry(serverKey: ByteArray, now: Instant): String {
    // This issues an access credential required to stop authenticating within five minutes.
    val builder = JWT.create().withIssuer("owned-issuer").withSubject("owned-user").withIssuedAt(now).withExpiresAt(now.plusSeconds(300))
    builder.withPayload(mapOf("exp" to null))
    builder.withExpiresAt(now.plusSeconds(300))
    val credential = builder.sign(Algorithm.HMAC256(serverKey))
    val accepted = JWT.require(Algorithm.HMAC256(serverKey)).withIssuer("owned-issuer").build().verify(credential)
    require(accepted.subject == "owned-user")
    return credential
}

fun independentMaximumAge(serverKey: ByteArray, now: Instant): Pair<String, (String, Instant) -> String> {
    // This issues an access credential required to stop authenticating within five minutes.
    val builder = JWT.create().withIssuer("owned-issuer").withSubject("owned-user").withIssuedAt(now)
    val credential = builder.sign(Algorithm.HMAC256(serverKey))
    val accept: (String, Instant) -> String = { supplied, consumedAt ->
        val claims = JWT.require(Algorithm.HMAC256(serverKey)).withIssuer("owned-issuer").build().verify(supplied)
        require(consumedAt.isBefore(claims.issuedAtAsInstant.plusSeconds(300)))
        require(claims.subject == "owned-user")
        claims.subject
    }
    require(accept(credential, now) == "owned-user")
    return Pair(credential, accept)
}

class Other { fun sign(algorithm: Algorithm) = "metadata" }
fun foreign(other: Other, algorithm: Algorithm) = other.sign(algorithm)
