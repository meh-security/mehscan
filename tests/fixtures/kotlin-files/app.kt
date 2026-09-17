package quality.files

import java.nio.file.Files
import java.nio.file.Path as FilePath
import java.nio.file.Paths
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class FileRoutes {
    @GetMapping("/file/raw")
    fun rawRead(@RequestParam name: String): String =
        Files.readString(FilePath.of(name))

    @GetMapping("/file/write")
    fun rawWrite(@RequestParam name: String) {
        Files.writeString(FilePath.of(name), "fixture text")
    }

    @GetMapping("/file/normalized")
    fun normalizedRead(@RequestParam name: String): String {
        val root = FilePath.of("/fixture/public")
        val target = root.resolve(name).normalize()
        return Files.readString(target)
    }

    @GetMapping("/file/fixed")
    fun fixedRead(@RequestParam name: String): String =
        Files.readString(Paths.get("/fixture/public/readme.txt"))

    @GetMapping("/file/allowlisted")
    fun allowlistedRead(@RequestParam name: String): String {
        val target = when (name) {
            "readme" -> FilePath.of("/fixture/public/readme.txt")
            else -> throw IllegalArgumentException("Unknown file")
        }
        return Files.readString(target)
    }

    @GetMapping("/file/content")
    fun fixedWriteContent(@RequestParam content: String) {
        Files.writeString(FilePath.of("/fixture/public/output.txt"), content)
    }
}
