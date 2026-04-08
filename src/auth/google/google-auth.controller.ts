import { Controller, Get, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';
import { GoogleAuthService } from './google-auth.service';
import { REFRESH_COOKIE_NAME } from '../auth.constants';
import {
  GOOGLE_LOGIN_COOKIE_NONCE,
  GOOGLE_LOGIN_COOKIE_STATE,
  GOOGLE_LOGIN_COOKIE_VERIFIER,
} from './google-auth.constants';

function base64UrlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

@Controller()
export class GoogleAuthController {
  constructor(
    private readonly google: GoogleAuthService,
    private readonly config: ConfigService,
  ) {}

  @Get('/v1/auth/google/login')
  async login(@Res() res: Response) {
    const state = base64UrlEncode(randomBytes(16));
    const nonce = base64UrlEncode(randomBytes(16));
    const { codeVerifier } = this.google.createPkceArtifacts();

    const secure = this.config.get<boolean>('COOKIE_SECURE', false);
    const sameSite = this.config.get<'lax' | 'strict' | 'none'>(
      'COOKIE_SAMESITE',
      'lax',
    );
    const domain = this.config.get<string | undefined>('COOKIE_DOMAIN');

    // PKCE verifier + state/nonce are validated at callback time.
    res.cookie(GOOGLE_LOGIN_COOKIE_STATE, state, {
      httpOnly: true,
      secure,
      sameSite,
      domain,
      path: '/v1/auth/google',
      maxAge: 10 * 60 * 1000,
    });
    res.cookie(GOOGLE_LOGIN_COOKIE_VERIFIER, codeVerifier, {
      httpOnly: true,
      secure,
      sameSite,
      domain,
      path: '/v1/auth/google',
      maxAge: 10 * 60 * 1000,
    });
    res.cookie(GOOGLE_LOGIN_COOKIE_NONCE, nonce, {
      httpOnly: true,
      secure,
      sameSite,
      domain,
      path: '/v1/auth/google',
      maxAge: 10 * 60 * 1000,
    });

    const url = this.google.createAuthorizationUrl({
      state,
      nonce,
      codeVerifier,
    });
    return res.redirect(url);
  }

  @Get('/v1/auth/google/callback')
  async callback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string | undefined,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (error) {
      throw new Error(`Google OAuth error: ${error}`);
    }
    if (!code || !state) throw new Error('Missing code/state from Google callback');

    const expectedState = req.cookies?.[GOOGLE_LOGIN_COOKIE_STATE];
    const codeVerifier = req.cookies?.[GOOGLE_LOGIN_COOKIE_VERIFIER];
    const expectedNonce = req.cookies?.[GOOGLE_LOGIN_COOKIE_NONCE];

    if (!expectedState || typeof expectedState !== 'string') {
      throw new Error('Missing expected OAuth state');
    }
    if (!codeVerifier || typeof codeVerifier !== 'string') {
      throw new Error('Missing expected OAuth code verifier');
    }

    const secure = this.config.get<boolean>('COOKIE_SECURE', false);
    const sameSite = this.config.get<'lax' | 'strict' | 'none'>(
      'COOKIE_SAMESITE',
      'lax',
    );
    const domain = this.config.get<string | undefined>('COOKIE_DOMAIN');

    const result = await this.google.handleCallback({
      code,
      state,
      expectedState,
      codeVerifier,
      expectedNonce: typeof expectedNonce === 'string' ? expectedNonce : undefined,
    });

    res.cookie(REFRESH_COOKIE_NAME, result.refreshToken, {
      httpOnly: true,
      secure,
      sameSite,
      domain,
      path: '/v1/auth',
      expires: result.refreshExpiresAt,
    });

    // Clear OAuth cookies after successful flow.
    res.clearCookie(GOOGLE_LOGIN_COOKIE_STATE, { path: '/v1/auth/google', domain });
    res.clearCookie(GOOGLE_LOGIN_COOKIE_VERIFIER, { path: '/v1/auth/google', domain });
    res.clearCookie(GOOGLE_LOGIN_COOKIE_NONCE, { path: '/v1/auth/google', domain });

    return {
      accessToken: result.accessToken,
      user: result.user,
      activeOrgId: result.activeOrgId,
      roles: result.roles,
      perms: result.perms,
    };
  }
}

