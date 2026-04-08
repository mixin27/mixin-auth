import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { envSchema, parseAllowedOrigins } from './config/env';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const env = envSchema.parse(process.env);

  const allowedOrigins = parseAllowedOrigins(env.CORS_ALLOWED_ORIGINS);
  app.enableCors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.length === 0) return callback(null, true);
      return callback(null, allowedOrigins.includes(origin));
    },
    credentials: true,
  });

  app.use(cookieParser());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  await app.listen(env.PORT);
}
bootstrap();
