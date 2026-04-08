import { z } from 'zod';

const boolFromString = z
  .string()
  .transform((v) => v.toLowerCase())
  .pipe(z.enum(['true', 'false']))
  .transform((v) => v === 'true');

export const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().default(3000),

    DATABASE_URL: z
      .string()
      .min(1)
      .default('postgresql://mixin:mixin@localhost:5432/mixin_auth?schema=public'),

    AUTH_ISSUER: z.string().min(1).default('mixin-auth'),
    AUTH_AUDIENCE: z.string().min(1).default('api'),

    AUTH_JWT_KID: z.string().min(1).default('dev-kid'),
    AUTH_JWT_PRIVATE_KEY_PEM: z.string().optional(),
    AUTH_JWT_PUBLIC_KEY_PEM: z.string().optional(),
    AUTH_JWT_HS_SECRET: z.string().optional(),

    REFRESH_TOKEN_PEPPER: z.string().min(8).default('dev-refresh-pepper'),

    CORS_ALLOWED_ORIGINS: z.string().optional(),

    COOKIE_DOMAIN: z.string().optional(),
    COOKIE_SECURE: boolFromString.default(false),
    COOKIE_SAMESITE: z.enum(['lax', 'strict', 'none']).default('lax'),

    GOOGLE_CLIENT_ID: z.string().optional(),
    GOOGLE_CLIENT_SECRET: z.string().optional(),
    GOOGLE_REDIRECT_URI: z.string().optional(),
  })
  .superRefine((val, ctx) => {
    if (val.NODE_ENV === 'production') {
      const hasAsymmetric =
        !!val.AUTH_JWT_PRIVATE_KEY_PEM && !!val.AUTH_JWT_PUBLIC_KEY_PEM;
      if (!hasAsymmetric) {
        ctx.addIssue({
          code: "custom",
          message:
            'In production you must set AUTH_JWT_PRIVATE_KEY_PEM and AUTH_JWT_PUBLIC_KEY_PEM (asymmetric JWT signing).',
          path: ['AUTH_JWT_PRIVATE_KEY_PEM'],
        });
      }
    }
  });

export type Env = z.infer<typeof envSchema>;

export function parseAllowedOrigins(input?: string): string[] {
  if (!input) return [];
  return input
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}
