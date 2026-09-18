package quality.objects

import java.io.ByteArrayInputStream
import java.io.ObjectInputFilter
import java.io.ObjectInputStream
import java.io.Serializable
import java.util.Base64
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

/** Harmless witness that materialization invokes a classpath callback. */
class CallbackValue(val value: String) : Serializable {
    companion object { var callbacks = 0 }
    private fun readObject(input: ObjectInputStream) {
        input.defaultReadObject()
        callbacks++
    }
}

@RestController
class ObjectRoutes {
    @GetMapping("/objects/raw")
    fun rawObject(@RequestParam payload: String): String {
        val input = ObjectInputStream(ByteArrayInputStream(Base64.getDecoder().decode(payload)))
        return (input.readObject() as CallbackValue).value
    }

    @GetMapping("/objects/safe")
    fun safeObject(@RequestParam payload: String): String {
        require(payload.length <= 8192) { "Encoded payload is too large" }
        val input = ObjectInputStream(ByteArrayInputStream(Base64.getDecoder().decode(payload)))
        input.setObjectInputFilter { info ->
            val type = info.serialClass()
            if (info.depth() > 5 || info.references() > 16 || info.streamBytes() > 4096 ||
                (type != null && type != String::class.java)) ObjectInputFilter.Status.REJECTED
            else ObjectInputFilter.Status.UNDECIDED
        }
        return input.readObject() as String
    }

    @GetMapping("/objects/wrong-stream")
    fun wrongStream(@RequestParam payload: String): String {
        val bytes = Base64.getDecoder().decode(payload)
        val guarded = ObjectInputStream(ByteArrayInputStream(bytes))
        guarded.setObjectInputFilter { ObjectInputFilter.Status.REJECTED }
        val exposed = ObjectInputStream(ByteArrayInputStream(bytes))
        return (exposed.readObject() as CallbackValue).value
    }
}
