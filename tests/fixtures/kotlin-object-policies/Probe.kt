package quality.objects

import java.io.ByteArrayOutputStream
import java.io.InvalidClassException
import java.io.ObjectOutputStream
import java.util.Base64

private fun serialized(value: Any): String {
    val bytes = ByteArrayOutputStream()
    ObjectOutputStream(bytes).use { it.writeObject(value) }
    return Base64.getEncoder().encodeToString(bytes.toByteArray())
}

fun main() {
    val routes = ObjectRoutes()
    val callback = serialized(CallbackValue("fixture-only"))
    CallbackValue.callbacks = 0
    check(routes.rawObject(callback) == "fixture-only")
    check(CallbackValue.callbacks == 1)
    check(routes.wrongStream(callback) == "fixture-only")
    check(CallbackValue.callbacks == 2)
    try {
        routes.safeObject(callback)
        error("Non-data class must be rejected before its callback")
    } catch (_: InvalidClassException) { }
    check(CallbackValue.callbacks == 2)
    check(routes.safeObject(serialized("fixed data")) == "fixed data")
    println("Object policy runtime: 7 checks passed")
}
