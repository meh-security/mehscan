package receivers

import jakarta.persistence.EntityManager
import java.nio.file.Files
import java.nio.file.Path
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

class FixedQuery(val resultList: List<String> = listOf("fixed"))
class OtherManager {
    fun createQuery(ignored: String): FixedQuery = FixedQuery()
}
class OtherPath {
    fun resolve(ignored: String): Path = Path.of("/fixture/public/readme.txt")
}

@RestController
class RealMembers(private val em: EntityManager, private val root: Path) {
    @GetMapping("/receivers/raw-query")
    fun memberQuery(@RequestParam name: String): Any {
        val em = OtherManager()
        return this.em.createQuery("SELECT o FROM Owner o WHERE o.name = '$name'").resultList
    }

    @GetMapping("/receivers/raw-read")
    fun memberRead(@RequestParam name: String): String {
        val root = OtherPath()
        return Files.readString(this.root.resolve(name))
    }
}

@RestController
class FixedMembers(private val realManager: EntityManager) {
    private val em: OtherManager = OtherManager()
    private val root: OtherPath = OtherPath()

    @GetMapping("/receivers/fixed-query")
    fun lookalikeQuery(@RequestParam name: String): Any {
        val em: EntityManager = realManager
        return this.em.createQuery(name).resultList
    }

    @GetMapping("/receivers/fixed-read")
    fun lookalikeRead(@RequestParam name: String): String {
        val root: Path = Path.of("/fixture/public")
        return Files.readString(this.root.resolve(name))
    }
}
