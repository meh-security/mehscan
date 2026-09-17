package quality.jdbc

import java.sql.Connection as DatabaseConnection
import java.sql.Statement as SqlStatement
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

// Original static controls. No server or database is started by the scanner.
@RestController
class JdbcRoutes(private val statement: SqlStatement, private val connection: DatabaseConnection) {
    companion object {
        private const val FIXED_SQL = "SELECT * FROM owner WHERE name = 'Alice'"
    }
    @GetMapping("/statement/raw")
    fun rawStatement(@RequestParam name: String) {
        statement.executeQuery("SELECT * FROM owner WHERE name = '$name'")
    }

    @GetMapping("/statement/fixed")
    fun fixedStatement(@RequestParam name: String) {
        statement.executeQuery(FIXED_SQL)
    }

    @GetMapping("/prepared/raw")
    fun rawPrepared(@RequestParam name: String) {
        val prepared = connection.prepareStatement("SELECT * FROM owner WHERE name = '$name'")
        prepared.executeQuery()
    }

    @GetMapping("/prepared/bound")
    fun boundPrepared(@RequestParam name: String) {
        val prepared = connection.prepareStatement("SELECT * FROM owner WHERE name = ?")
        prepared.setString(1, name)
        prepared.executeQuery()
    }
}
