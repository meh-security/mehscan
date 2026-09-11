import { Body, Controller, Get, Res, UseGuards, UsePipes, ValidationPipe } from "./decorators"

@Controller("fake")
export class FakeController {
  @Get("entry")
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  entry(@Body() value: string, @Res() response: any) {
    return response.send(value)
  }
}
