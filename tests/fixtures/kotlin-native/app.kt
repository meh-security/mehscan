package demo

class Boundaries {
fun boundaries(command: String, path: java.nio.file.Path, content: ByteArray, algorithm: String, url: String) {
    java.lang.Runtime.getRuntime().exec(command)
    java.nio.file.Files.readAllBytes(path)
    java.nio.file.Files.readString(path)
    java.nio.file.Files.write(path, content)
    java.nio.file.Files.writeString(path, "text")
    java.security.MessageDigest.getInstance(algorithm)
    java.net.URI.create(url)
}
}
