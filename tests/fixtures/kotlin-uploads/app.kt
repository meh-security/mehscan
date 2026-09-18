import jakarta.servlet.http.HttpServletRequest as Request
import jakarta.servlet.http.Part
import java.io.File
import javax.script.ScriptEngine
import javax.script.ScriptEngineManager

fun unsafeUpload(request: Request, root: File) {
    // request is the caller's multipart HTTP request; root is a server-owned writable upload directory.
    val part = request.getPart("file")
    val name = part.submittedFileName
    File(root, name).writeBytes(part.inputStream.readBytes())
}
fun safeUpload(request: Request, root: File) {
    // Caller multipart bytes are stored under a fixed server-owned name outside public/executable serving.
    val part = request.getPart("file")
    File(root, "pending.bin").writeBytes(part.getInputStream().readBytes())
}
fun unusedPart(part: Part) {
    // Metadata is read and discarded; no persistence or other consumer.
    val name = part.getSubmittedFileName()
}
fun unsafeScript(engine: ScriptEngine, request: Request) {
    // engine is an operational server-injected script provider; request is an untrusted caller request.
    engine.eval(request.getParameter("code"))
}
fun fixedScript(engine: ScriptEngine) {
    // Operational server-injected provider; this script is a fixed trusted application literal.
    engine.eval("1 + 1")
}
fun allowlistedScript(engine: ScriptEngine, request: Request) {
    // Operational provider and untrusted caller; only this exact trusted script may execute.
    val code = request.getParameter("code")
    require(code == "1 + 1")
    engine.eval(code)
}
fun factoryScript() {
    // Source-only provider factory example; availability is not established. No caller input, only a fixed trusted literal.
    val engine = ScriptEngineManager().getEngineByName("javascript")
    engine.eval("1 + 1")
}
class Foreign {
    fun eval(code: String) = code
    fun getPart(field: String) = field
}
fun unrelated(fake: Foreign) { fake.eval("x"); fake.getPart("file") }
