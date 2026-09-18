package quality.exposed

import org.jetbrains.exposed.v1.core.VarCharColumnType
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.JdbcTransaction
import org.jetbrains.exposed.v1.jdbc.transactions.TransactionManager
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.jetbrains.exposed.v1.jdbc.transactions.transaction as within
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class ExposedRoutes(private val database: Database) {
    @GetMapping("/exposed/raw")
    fun rawTransaction(@RequestParam name: String): Int = transaction(database) {
        exec("SELECT name FROM fixture_people WHERE name = '$name'") { rows ->
            var count = 0
            while (rows.next()) count++
            count
        } ?: 0
    }

    @GetMapping("/exposed/bound")
    fun boundTransaction(@RequestParam name: String): Int = transaction(database) {
        exec("SELECT name FROM fixture_people WHERE name = ?", args = listOf(VarCharColumnType(64) to name)) { rows ->
            var count = 0
            while (rows.next()) count++
            count
        } ?: 0
    }

    @GetMapping("/exposed/current")
    fun rawCurrent(@RequestParam name: String): Int = transaction(database) {
        val active = TransactionManager.current()
        val alias = active
        alias.exec("SELECT name FROM fixture_people WHERE name = '$name'") { rows ->
            var count = 0
            while (rows.next()) count++
            count
        } ?: 0
    }

    @GetMapping("/exposed/alias")
    fun rawAlias(@RequestParam name: String): Int = within(database) {
        exec("SELECT name FROM fixture_people WHERE name = '$name'") { rows ->
            var count = 0
            while (rows.next()) count++
            count
        } ?: 0
    }

    @GetMapping("/exposed/fixed")
    fun fixedSql(@RequestParam name: String): Int = transaction(database) {
        exec("SELECT name FROM fixture_people WHERE name = 'alice'") { rows ->
            var count = 0
            while (rows.next()) count++
            count
        } ?: 0
    }

    @GetMapping("/exposed/typed")
    fun typedExec(@RequestParam name: String, active: JdbcTransaction): Int =
        active.exec("SELECT name FROM fixture_people WHERE name = '$name'") { rows ->
            var count = 0
            while (rows.next()) count++
            count
        } ?: 0
}

class Other { fun exec(query: String): String = query }
fun lookalike(other: Other, name: String): String = other.exec(name)
