package quality.jdbcfactories

import java.sql.Connection
import java.sql.ResultSet
import javax.sql.DataSource
import javax.sql.ConnectionPoolDataSource
import javax.sql.XADataSource
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class FactoryRoutes(
    private val source: DataSource,
    private val pool: ConnectionPoolDataSource,
    private val xa: XADataSource,
) {
    @GetMapping("/jdbc/template")
    fun rawTemplate(@RequestParam name: String): Int {
        val template = JdbcTemplate(source)
        return template.queryForList("SELECT name FROM fixture_people WHERE name = '$name'").size
    }

    @GetMapping("/jdbc/template-bound")
    fun boundTemplate(@RequestParam name: String): Int {
        val template = JdbcTemplate(source, false)
        return template.queryForList("SELECT name FROM fixture_people WHERE name = ?", name).size
    }

    @GetMapping("/jdbc/pool")
    fun rawPooled(@RequestParam name: String): Int {
        val handle = pool.getPooledConnection()
        val connection = handle.getConnection()
        val statement = connection.createStatement()
        try {
            val rows = statement.executeQuery("SELECT name FROM fixture_people WHERE name = '$name'")
            var count = 0
            while (rows.next()) count++
            rows.close()
            return count
        } finally { statement.close(); connection.close(); handle.close() }
    }

    @GetMapping("/jdbc/xa")
    fun rawXa(@RequestParam name: String): Int {
        val handle = xa.getXAConnection()
        val connection = handle.getConnection()
        val statement = connection.createStatement()
        try {
            val rows = statement.executeQuery("SELECT name FROM fixture_people WHERE name = '$name'")
            var count = 0
            while (rows.next()) count++
            rows.close()
            return count
        } finally { statement.close(); connection.close(); handle.close() }
    }

    @GetMapping("/jdbc/prepare-three")
    fun rawPrepared3(@RequestParam name: String, connection: Connection): Int {
        val prepared = connection.prepareStatement("SELECT name FROM fixture_people WHERE name = '$name'", ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)
        try {
            val rows = prepared.executeQuery()
            var count = 0
            while (rows.next()) count++
            rows.close()
            return count
        } finally { prepared.close() }
    }

    @GetMapping("/jdbc/prepare-four")
    fun rawPrepared4(@RequestParam name: String, connection: Connection): Int {
        val prepared = connection.prepareStatement("SELECT name FROM fixture_people WHERE name = '$name'", ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY, ResultSet.HOLD_CURSORS_OVER_COMMIT)
        try {
            val rows = prepared.executeQuery()
            var count = 0
            while (rows.next()) count++
            rows.close()
            return count
        } finally { prepared.close() }
    }

    @GetMapping("/jdbc/prepare-bound")
    fun boundPrepared(@RequestParam name: String, connection: Connection): Int {
        val prepared = connection.prepareStatement("SELECT name FROM fixture_people WHERE name = ?", ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)
        try {
            prepared.setString(1, name)
            val rows = prepared.executeQuery()
            var count = 0
            while (rows.next()) count++
            rows.close()
            return count
        } finally { prepared.close() }
    }

    @GetMapping("/jdbc/prepare-unused")
    fun lazyPrepared(@RequestParam name: String, connection: Connection) {
        val prepared = connection.prepareStatement("SELECT name FROM fixture_people WHERE name = '$name'", ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY, ResultSet.HOLD_CURSORS_OVER_COMMIT)
        prepared.close()
    }
}

class Other { fun getPooledConnection(): Other = this; fun getConnection(): Other = this; fun createStatement(): Other = this; fun executeQuery(query: String): String = query }
fun lookalike(other: Other) { other.getPooledConnection().getConnection().createStatement().executeQuery("fixed") }
