package quality.authorization

import org.springframework.security.access.prepost.PreAuthorize as Requires
import org.springframework.security.access.annotation.Secured
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam

open class ProtectedService {
    @Requires("hasAuthority('REPORT_READ')")
    open fun report() = "owned report"

    @Secured("ROLE_ADMIN", "ROLE_REPORT")
    open fun roles() = "owned roles"

    @org.springframework.security.access.prepost.PreAuthorize("denyAll()")
    open fun denied() = "owned denied report"
}

annotation class PreAuthorize(val policy: String)
class ForeignService {
    @PreAuthorize("permitAll()")
    fun unrelated() = "public metadata"
}

@RestController
open class QueryRoutes(private val jdbc: JdbcTemplate) {
    @Requires("isAuthenticated()")
    @GetMapping("/query")
    open fun query(@RequestParam sql: String) = jdbc.queryForList(sql)
}
