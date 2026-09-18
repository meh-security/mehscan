package quality.prepared

import java.sql.Connection
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

class OtherStatement {
    fun setString(index: Int, value: String) { }
}

@RestController
class PreparedRoutes(private val connection: Connection) {
    @GetMapping("/prepared/owned/raw")
    fun ownedRaw(@RequestParam name: String): Int {
        val prepared = connection.prepareStatement("SELECT * FROM owner WHERE name = '$name'")
        val unrelated = OtherStatement()
        unrelated.setString(1, name)
        val alias = prepared
        val rows = alias.executeQuery()
        var count = 0
        while (rows.next()) count++
        return count
    }

    @GetMapping("/prepared/owned/bound")
    fun ownedBound(@RequestParam name: String): Int {
        val prepared = connection.prepareStatement("SELECT * FROM owner WHERE name = ?")
        val alias = prepared
        alias.setString(1, "initial value")
        alias.clearParameters()
        alias.setString(1, name)
        val rows = alias.executeQuery()
        var count = 0
        while (rows.next()) count++
        return count
    }

    @GetMapping("/prepared/only")
    fun preparationOnly(@RequestParam name: String) {
        val prepared = connection.prepareStatement("SELECT * FROM owner WHERE name = 'Alice'")
        prepared.close()
    }

    @GetMapping("/prepared/conditional")
    fun conditionalRaw(@RequestParam name: String, @RequestParam enabled: Boolean): Int {
        val prepared = connection.prepareStatement("SELECT * FROM owner WHERE name = '$name'")
        if (enabled) {
            val rows = prepared.executeQuery()
            var count = 0
            while (rows.next()) count++
            return count
        }
        prepared.close()
        return 0
    }
}
