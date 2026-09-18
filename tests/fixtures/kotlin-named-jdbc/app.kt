package quality.namedjdbc

import javax.sql.DataSource
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class NamedRoutes(private val source: DataSource, private val named: NamedParameterJdbcOperations) {
    @GetMapping("/named/raw")
    fun rawNamed(@RequestParam name: String): Int {
        val template = NamedParameterJdbcTemplate(source)
        return template.queryForList("SELECT name FROM fixture_people WHERE name = '$name'", emptyMap<String, Any>()).size
    }

    @GetMapping("/named/jdbc")
    fun rawJdbc(@RequestParam name: String): Int {
        val template = NamedParameterJdbcTemplate(JdbcTemplate(source))
        return template.queryForList("SELECT name FROM fixture_people WHERE name = '$name'", emptyMap<String, Any>()).size
    }

    @GetMapping("/named/declared")
    fun rawDeclared(@RequestParam name: String): Int =
        named.queryForList("SELECT name FROM fixture_people WHERE name = '$name'", emptyMap<String, Any>()).size

    @GetMapping("/named/bound-map")
    fun boundMap(@RequestParam name: String): Int {
        val template = NamedParameterJdbcTemplate(source)
        return template.queryForList("SELECT name FROM fixture_people WHERE name = :name", mapOf("name" to name)).size
    }

    @GetMapping("/named/bound-source")
    fun boundSource(@RequestParam name: String): Int {
        val template = NamedParameterJdbcTemplate(source)
        return template.queryForObject("SELECT COUNT(*) FROM fixture_people WHERE name = :name", MapSqlParameterSource("name", name), Int::class.java) ?: 0
    }

    @GetMapping("/named/callback")
    fun rawCallback(@RequestParam name: String): Int {
        val template = NamedParameterJdbcTemplate(source)
        return template.execute("SELECT name FROM fixture_people WHERE name = '$name'", emptyMap<String, Any>()) { prepared ->
            prepared.executeQuery().use { rows ->
                var count = 0
                while (rows.next()) count++
                count
            }
        }
    }
}

class Other { fun queryForList(query: String, params: Map<String, Any>): List<String> = listOf(query) }
fun lookalike(other: Other, name: String): List<String> = other.queryForList(name, emptyMap())
