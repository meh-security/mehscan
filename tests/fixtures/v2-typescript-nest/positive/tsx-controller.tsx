import { Controller, Get, Param } from "@nestjs/common"

@Controller("widgets")
export class WidgetController {
  @Get(":id")
  show(@Param("id") id: string) {
    return <p>{id}</p>
  }
}
