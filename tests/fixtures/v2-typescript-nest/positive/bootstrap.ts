import { ValidationPipe as RequestValidation } from "@nestjs/common"
import { NestFactory } from "@nestjs/core"

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  app.useGlobalPipes(new RequestValidation({ whitelist: true }))
  await app.listen(3000)
}

void bootstrap()
