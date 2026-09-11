import {
  Body as RequestBody,
  Controller as ApiController,
  Get,
  Post,
  Query,
  Res as NestResponse,
  UseGuards,
  UsePipes,
  ValidationPipe as VP,
} from "@nestjs/common"

@ApiController("reports")
@UseGuards(JwtAuthGuard)
@UsePipes(new VP({ whitelist: true }))
export class ReportsController {
  @Post("preview")
  @UseGuards(RolesGuard)
  @UsePipes(new VP({ whitelist: true, forbidNonWhitelisted: true, transform: true }))
  preview(@RequestBody("html") payload: string, @NestResponse() response: any) {
    const html = payload
    return response.send(html)
  }

  @Get("leave")
  leave(@Query("next") next: string, @NestResponse() reply: any) {
    return reply.redirect(next)
  }
}
