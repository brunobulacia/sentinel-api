import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const PORT = process.env.PORT || 4000;
  const globalPrefix = 'api';
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix(globalPrefix);
  await app.listen(PORT, () => {
    console.log(`listening on: http://localhost:${PORT}/${globalPrefix}`);
  });
}
bootstrap();
