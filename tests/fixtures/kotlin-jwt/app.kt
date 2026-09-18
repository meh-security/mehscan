package quality.jwt

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException

fun rawAdmin(token: String): String {
    // Caller supplies token as an untrusted bearer credential to this admin-acceptance boundary.
    val claims = JWT.decode(token)
    require(claims.getClaim("admin").asBoolean() == true)
    return "protected-admin-data"
}

fun displayMetadata(token: String): String = JWT.decode(token).subject.orEmpty()

fun verifiedAdmin(token: String, serverKey: ByteArray): String {
    // Caller supplies token as an untrusted bearer credential to this admin-acceptance boundary.
    // serverKey is an operational server secret dependency, independent of the caller credential.
    val verifier = JWT.require(Algorithm.HMAC256(serverKey)).withIssuer("owned-issuer").withAudience("owned-api").build()
    val claims = verifier.verify(token)
    require(claims.getClaim("admin").asBoolean() == true)
    return "protected-admin-data"
}

fun unsignedAdmin(token: String): String {
    // Caller supplies token as an untrusted bearer credential to this admin-acceptance boundary.
    val claims = JWT.require(Algorithm.none()).withIssuer("owned-issuer").build().verify(token)
    require(claims.getClaim("admin").asBoolean() == true)
    return "protected-admin-data"
}

fun ignoredFailure(token: String, serverKey: ByteArray): String {
    // Caller supplies token as an untrusted bearer credential to this admin-acceptance boundary.
    // serverKey is an operational server secret dependency, independent of the caller credential.
    val verifier = JWT.require(Algorithm.HMAC256(serverKey)).withIssuer("owned-issuer").build()
    try { verifier.verify(token) } catch (ignored: JWTVerificationException) {}
    val claims = JWT.decode(token)
    require(claims.getClaim("admin").asBoolean() == true)
    return "protected-admin-data"
}

fun verifiedBeforeDecode(token: String, serverKey: ByteArray): String {
    // Caller supplies token as an untrusted bearer credential to this admin-acceptance boundary.
    // serverKey is an operational server secret dependency, independent of the caller credential.
    JWT.require(Algorithm.HMAC256(serverKey)).withIssuer("owned-issuer").withAudience("owned-api").build().verify(token)
    val claims = JWT().decodeJwt(token)
    require(claims.getClaim("admin").asBoolean() == true)
    return "protected-admin-data"
}

class Other { fun decode(token: String) = token; fun verify(token: String) = token }
fun foreign(other: Other, token: String) = other.decode(token) + other.verify(token)
