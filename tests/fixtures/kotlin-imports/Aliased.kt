package precision

import precision.custom.*
import java.lang.Runtime as JVM

@org.springframework.web.bind.annotation.RestController
class AliasedRoutes {
    @org.springframework.web.bind.annotation.GetMapping("/imports/aliased")
    fun aliasedCall(@org.springframework.web.bind.annotation.RequestParam command: kotlin.String): kotlin.Any =
        JVM.getRuntime().exec(command)
}
