import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, randomBytes } from 'crypto';

@Injectable()
export class RefreshTokenService {
  constructor(private readonly config: ConfigService) {}

  generateRawToken(): string {
    // 32 bytes => 43 chars base64url-ish if we strip padding and replace chars
    const raw = randomBytes(32).toString('base64url');
    return raw;
  }

  hash(rawToken: string): string {
    const pepper = this.config.get<string>('REFRESH_TOKEN_PEPPER', 'dev-refresh-pepper');
    return createHash('sha256').update(`${pepper}:${rawToken}`).digest('hex');
  }

  getExpiryDate(): Date {
    const days = 30;
    return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  }
}

