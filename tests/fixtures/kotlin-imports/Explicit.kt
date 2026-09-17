package precision

import precision.custom.*
import java.lang.Runtime

@org.springframework.web.bind.annotation.RestController
class ExplicitRoutes {
    @org.springframework.web.bind.annotation.GetMapping("/imports/explicit")
    fun explicitCall(@org.springframework.web.bind.annotation.RequestParam command: kotlin.String): kotlin.Any =
        Runtime.getRuntime().exec(command)
}
