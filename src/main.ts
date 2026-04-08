import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { apiReference } from '@scalar/express-api-reference';
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

  const swaggerConfig = new DocumentBuilder()
    .setTitle('mixin-auth')
    .setDescription('Standalone auth service (users, sessions, orgs, RBAC)')
    .setVersion('0.1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'Authorization',
        description: 'Use `Authorization: Bearer <accessToken>`',
      },
      'access-token',
    )
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('docs', app, document);

  // Nest's `app.get()` is overloaded for DI; use Express adapter to register routes.
  const expressApp = app.getHttpAdapter().getInstance();
  expressApp.get('/openapi.json', (_req: any, res: any) => res.json(document));
  app.use('/scalar', apiReference({ url: '/openapi.json' }));

  await app.listen(env.PORT);
}
bootstrap();
