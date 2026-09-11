import { Body, Controller, Post, UseGuards, UsePipes } from "@nestjs/common"

@Controller("jobs")
export class JobsController {
  @Post()
  @UseGuards(FeatureFlagGuard)
  @UsePipes(new CustomPipe())
  run(@Body() job: unknown) {
    return job
  }
}
