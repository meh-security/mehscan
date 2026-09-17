package quality

import jakarta.persistence.Entity
import jakarta.persistence.EntityManager
import jakarta.persistence.GeneratedValue
import jakarta.persistence.Id
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.transaction.annotation.Transactional
import org.springframework.jdbc.core.JdbcTemplate
import java.nio.file.Files
import java.nio.file.Path
import org.springframework.web.server.ResponseStatusException
import org.springframework.http.HttpStatus

@SpringBootApplication
class Application
fun main(args: Array<String>) { runApplication<Application>(*args) }

@Entity
class Owner(@Id @GeneratedValue var id: Long? = null, var name: String = "")

@RestController
@Transactional
class Routes(private val manager: EntityManager, private val jdbc: JdbcTemplate) {
    @GetMapping("/jdbc/raw")
    fun rawJdbcQuery(@RequestParam name: String): List<*> =
        jdbc.queryForList("SELECT * FROM owner WHERE name = '$name'")

    @GetMapping("/jdbc/bound")
    fun boundJdbcQuery(@RequestParam name: String): List<*> =
        jdbc.queryForList("SELECT * FROM owner WHERE name = ?", name)

    @GetMapping("/query/raw")
    fun rawQuery(@RequestParam name: String): List<*> =
        manager.createQuery("SELECT o FROM Owner o WHERE o.name = '$name'").resultList

    @GetMapping("/query/bound")
    fun boundQuery(@RequestParam name: String): List<*> =
        manager.createQuery("SELECT o FROM Owner o WHERE o.name = :name")
            .setParameter("name", name).resultList

    @GetMapping("/query/numeric")
    fun numericQuery(@RequestParam id: Long): List<*> =
        manager.createQuery("SELECT o FROM Owner o WHERE o.id = $id").resultList

    @GetMapping("/command/raw")
    fun rawCommand(@RequestParam command: String): String =
        Runtime.getRuntime().exec(command).inputStream.bufferedReader().readText()

    @GetMapping("/command/fixed")
    fun fixedCommand(): String =
        Runtime.getRuntime().exec("whoami").inputStream.bufferedReader().readText()
}

@RestController
class FileRoutes {
    private val root: Path = Path.of(System.getProperty("mehscan.fixture.root", "./fixture-data/public"))

    @GetMapping("/file/raw")
    fun rawFileRead(@RequestParam name: String): String =
        Files.readString(root.resolve(name).normalize())

    @GetMapping("/file/write")
    fun rawFileWrite(@RequestParam name: String) {
        Files.writeString(root.resolve(name).normalize(), "fixture text")
    }

    @GetMapping("/file/safe")
    fun safeFileRead(@RequestParam name: String): String {
        val target = when (name) {
            "readme" -> root.resolve("readme.txt")
            else -> throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown file")
        }
        return Files.readString(target)
    }
}
