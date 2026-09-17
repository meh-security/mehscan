// java.lang.Runtime.getRuntime().exec(command)
val documentation = "java.nio.file.Files.readString(path)"
fun lookalikes(command: String) {
    Runtime.getRuntime().exec(command)
    Files.readString(command)
}
