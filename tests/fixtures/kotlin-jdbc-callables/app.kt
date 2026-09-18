package quality.callables

import java.sql.Connection
import java.sql.ResultSet
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class CallableRoutes(private val connection: Connection) {
    @GetMapping("/callable/raw-three")
    fun rawCall3(@RequestParam name: String): Int {
        val prepared = connection.prepareCall("SELECT name FROM fixture_people WHERE name = '$name'", ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)
        try {
            val rows = prepared.executeQuery()
            var count = 0
            while (rows.next()) count++
            rows.close()
            return count
        } finally { prepared.close() }
    }

    @GetMapping("/callable/raw-four")
    fun rawCall4(@RequestParam name: String): Int {
        val prepared = connection.prepareCall("SELECT name FROM fixture_people WHERE name = '$name'", ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY, ResultSet.HOLD_CURSORS_OVER_COMMIT)
        try {
            val rows = prepared.executeQuery()
            var count = 0
            while (rows.next()) count++
            rows.close()
            return count
        } finally { prepared.close() }
    }

    @GetMapping("/callable/bound-three")
    fun boundCall3(@RequestParam name: String): Int {
        val prepared = connection.prepareCall("SELECT name FROM fixture_people WHERE name = ?", ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)
        try {
            prepared.setString(1, name)
            val rows = prepared.executeQuery()
            var count = 0
            while (rows.next()) count++
            rows.close()
            return count
        } finally { prepared.close() }
    }

    @GetMapping("/callable/unused-four")
    fun lazyCall4(@RequestParam name: String) {
        val prepared = connection.prepareCall("SELECT name FROM fixture_people WHERE name = '$name'", ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY, ResultSet.HOLD_CURSORS_OVER_COMMIT)
        prepared.close()
    }
}
