package precision

import precision.custom.*

@org.springframework.web.bind.annotation.RestController
class WildcardRoutes {
    @org.springframework.web.bind.annotation.GetMapping("/imports/custom")
    fun customCall(@org.springframework.web.bind.annotation.RequestParam command: kotlin.String) =
        Runtime.getRuntime().exec(command)

    @org.springframework.web.bind.annotation.GetMapping("/imports/qualified")
    fun qualifiedCall(@org.springframework.web.bind.annotation.RequestParam command: kotlin.String): kotlin.Any =
        java.lang.Runtime.getRuntime().exec(command)
}
