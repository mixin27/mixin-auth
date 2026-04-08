import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { createHash, randomBytes } from 'crypto';
import { AuthService } from '../auth.service';
import { GOOGLE_AUTHORIZATION_ENDPOINT, GOOGLE_ISSUER, GOOGLE_JWKS_URI, GOOGLE_TOKEN_ENDPOINT } from './google-auth.constants';

function base64UrlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function verifyGoogleIdToken(params: {
  idToken: string;
  audience: string;
  nonce?: string;
}) {
  const { idToken, audience, nonce } = params;
  const jwks = createRemoteJWKSet(new URL(GOOGLE_JWKS_URI));
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: GOOGLE_ISSUER,
    audience,
  });

  if (nonce && payload && typeof payload === 'object') {
    const tokenNonce = (payload as any).nonce;
    if (tokenNonce && tokenNonce !== nonce) {
      throw new UnauthorizedException('OAuth nonce mismatch');
    }
  }

  return payload as any;
}

@Injectable()
export class GoogleAuthService {
  constructor(
    private readonly config: ConfigService,
    private readonly auth: AuthService,
  ) {}

  getGoogleClientId(): string {
    const v = this.config.get<string>('GOOGLE_CLIENT_ID');
    if (!v) throw new Error('GOOGLE_CLIENT_ID is required');
    return v;
  }

  getGoogleClientSecret(): string {
    const v = this.config.get<string>('GOOGLE_CLIENT_SECRET');
    if (!v) throw new Error('GOOGLE_CLIENT_SECRET is required');
    return v;
  }

  getGoogleRedirectUri(): string {
    const v = this.config.get<string>('GOOGLE_REDIRECT_URI');
    if (!v) throw new Error('GOOGLE_REDIRECT_URI is required');
    return v;
  }

  createAuthorizationUrl(params: {
    state: string;
    nonce: string;
    codeVerifier: string;
  }): string {
    const clientId = this.getGoogleClientId();
    const redirectUri = this.getGoogleRedirectUri();

    const codeChallenge = base64UrlEncode(
      createHash('sha256').update(params.codeVerifier).digest(),
    );

    const url = new URL(GOOGLE_AUTHORIZATION_ENDPOINT);
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', params.state);
    url.searchParams.set('nonce', params.nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('access_type', 'online');
    return url.toString();
  }

  createPkceArtifacts() {
    const codeVerifier = base64UrlEncode(randomBytes(32));
    return { codeVerifier };
  }

  async exchangeCodeForTokens(params: { code: string; codeVerifier: string }) {
    const tokenEndpoint = GOOGLE_TOKEN_ENDPOINT;
    const clientId = this.getGoogleClientId();
    const clientSecret = this.getGoogleClientSecret();
    const redirectUri = this.getGoogleRedirectUri();

    const body = new URLSearchParams({
      code: params.code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
      code_verifier: params.codeVerifier,
    });

    const res = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });

    if (!res.ok) {
      throw new UnauthorizedException('Failed to exchange OAuth code');
    }

    const json = await res.json();
    if (!json.id_token) throw new UnauthorizedException('Missing id_token from provider');
    return json as { id_token: string; access_token?: string };
  }

  async handleCallback(params: {
    code: string;
    state: string;
    expectedState: string;
    codeVerifier: string;
    expectedNonce?: string;
  }) {
    if (params.state !== params.expectedState) {
      throw new UnauthorizedException('OAuth state mismatch');
    }

    const tokenRes = await this.exchangeCodeForTokens({
      code: params.code,
      codeVerifier: params.codeVerifier,
    });

    const idTokenPayload = await verifyGoogleIdToken({
      idToken: tokenRes.id_token,
      audience: this.getGoogleClientId(),
      nonce: params.expectedNonce,
    });

    const providerAccountId = String(idTokenPayload.sub);
    const email = String(idTokenPayload.email).toLowerCase();
    const name = idTokenPayload.name ? String(idTokenPayload.name) : undefined;

    // Reuse AuthService's session/token minting.
    return await this.auth.oauthLogin({
      provider: 'GOOGLE',
      providerAccountId,
      email,
      name,
    });
  }
}

