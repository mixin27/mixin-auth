import { Injectable, UnauthorizedException } from '@nestjs/common';
import { randomBytes } from 'crypto';
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from './auth.csrf';

@Injectable()
export class CsrfService {
  issueToken(): string {
    return randomBytes(24).toString('base64url');
  }

  assertValid(req: any) {
    const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];
    const headerToken =
      req.headers?.[CSRF_HEADER_NAME] ??
      req.headers?.[CSRF_HEADER_NAME.toLowerCase()];

    if (!cookieToken || typeof cookieToken !== 'string') {
      throw new UnauthorizedException('Missing CSRF cookie');
    }
    if (!headerToken || typeof headerToken !== 'string') {
      throw new UnauthorizedException('Missing CSRF header');
    }
    if (cookieToken !== headerToken) {
      throw new UnauthorizedException('Invalid CSRF token');
    }
  }
}

