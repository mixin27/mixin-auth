FROM node:22-slim AS build

WORKDIR /app

RUN corepack enable

COPY package.json pnpm-lock.yaml nest-cli.json tsconfig.json tsconfig.build.json ./
COPY prisma ./prisma
COPY prisma.config.ts ./
COPY src ./src
COPY test ./test

RUN pnpm install --frozen-lockfile
RUN pnpm exec prisma generate
RUN pnpm run build

ENV NODE_ENV=production

CMD ["sh", "-c", "pnpm exec prisma migrate deploy && node dist/main"]

