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
