import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const PORT = process.env.PORT ?? 4000;

  app.setGlobalPrefix('api');
  app.enableCors({
    origin: ['https://sentinel-app-swart.vercel.app', 'http://localhost:3000'],
  });
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));

  const config = new DocumentBuilder()
    .setTitle('Sentinel API')
    .setDescription('Web Vulnerability Scanner API')
    .setVersion('1.0')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  await app.listen(PORT, () => {
    console.log(`Sentinel API running on http://localhost:${PORT}/api`);
    console.log(`Swagger docs at http://localhost:${PORT}/api/docs`);
  });
}
bootstrap();
