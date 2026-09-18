package quality.fileoverloads

import java.io.File
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class FileRoutes(private val root: File) {
    @GetMapping("/file/read")
    fun rawRead(@RequestParam name: String): String =
        File(root, name).readText(charset = Charsets.UTF_8)

    @GetMapping("/file/write")
    fun rawWrite(@RequestParam name: String, @RequestParam content: String) {
        File(root, name).writeText(charset = Charsets.UTF_8, text = content)
    }

    @GetMapping("/file/append")
    fun rawAppend(@RequestParam name: String, @RequestParam content: String) {
        File(root, name).appendText(content, Charsets.UTF_8)
    }

    @GetMapping("/file/bytes")
    fun rawBytes(@RequestParam name: String, @RequestParam content: String) {
        File(root, name).appendBytes(content.toByteArray(Charsets.UTF_8))
    }

    @GetMapping("/file/fixed")
    fun fixedWrite(@RequestParam content: String) {
        File(root, "fixed.txt").writeText(content, Charsets.UTF_8)
    }

    @GetMapping("/file/approved")
    fun approvedRead(@RequestParam name: String): String {
        require(name == "readme.txt")
        return File(root, "readme.txt").readText(Charsets.UTF_8)
    }
}

class Other { fun appendBytes(content: ByteArray) { require(content.isNotEmpty()) } }
fun lookalike(other: Other) { other.appendBytes(byteArrayOf(1)) }
