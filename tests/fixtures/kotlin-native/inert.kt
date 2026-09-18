// java.lang.Runtime.getRuntime().exec(command)
val documentation = "java.nio.file.Files.readString(path)"
class Runtime {
    companion object { fun getRuntime() = Runtime() }
    fun exec(command: String) = command
}
fun lookalikes(command: String) {
    Runtime.getRuntime().exec(command)
    Files.readString(command)
}
