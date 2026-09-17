package quality.factories

import java.sql.Connection
import java.sql.DriverManager as Driver
import javax.sql.DataSource
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class FactoryRoutes(private val connection: Connection, private val source: DataSource) {
    @GetMapping("/factory/raw")
    fun factoryRaw(@RequestParam name: String): Int {
        val database = connection
        val statement = database.createStatement()
        val copy = statement
        val rows = copy.executeQuery("SELECT * FROM owner WHERE name = '$name'")
        var count = 0
        while (rows.next()) count++
        return count
    }

    @GetMapping("/factory/fixed")
    fun factoryFixed(@RequestParam name: String): Int {
        val database = source.getConnection()
        val statement = database.createStatement()
        val rows = statement.executeQuery("SELECT * FROM owner WHERE name = 'Alice'")
        var count = 0
        while (rows.next()) count++
        return count
    }

    @GetMapping("/factory/prepared/raw")
    fun factoryPreparedRaw(@RequestParam name: String): Int {
        val database = Driver.getConnection("jdbc:h2:mem:factory;DB_CLOSE_DELAY=-1")
        val statement = database.prepareStatement("SELECT * FROM owner WHERE name = '$name'")
        val rows = statement.executeQuery()
        var count = 0
        while (rows.next()) count++
        return count
    }

    @GetMapping("/factory/prepared/bound")
    fun factoryPreparedBound(@RequestParam name: String): Int {
        val database = source.getConnection()
        val statement = database.prepareStatement("SELECT * FROM owner WHERE name = ?")
        statement.setString(1, name)
        val rows = statement.executeQuery()
        var count = 0
        while (rows.next()) count++
        return count
    }
}

class OtherConnection {
    fun createStatement(): OtherStatement = OtherStatement()
}
class OtherStatement {
    fun executeQuery(query: String): Int = 7
}
@RestController
class LookalikeRoutes(private val connection: OtherConnection) {
    @GetMapping("/factory/lookalike")
    fun factoryLookalike(@RequestParam name: String): Int {
        val statement = connection.createStatement()
        return statement.executeQuery(name)
    }
}
