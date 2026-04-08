import { Injectable } from '@nestjs/common';
import { exportJWK, jwtVerify, SignJWT } from 'jose';
import { JwtKeysService } from './jwt-keys.service';
import { AccessTokenPayload } from './auth.types';

@Injectable()
export class AuthJwtService {
  constructor(private readonly keys: JwtKeysService) {}

  async signAccessToken(payload: Omit<AccessTokenPayload, 'iss' | 'aud'>) {
    const alg = await this.keys.getAlg();
    const kid = this.keys.getKid();
    const iss = this.keys.getIssuer();
    const aud = this.keys.getAudience();

    const now = Math.floor(Date.now() / 1000);

    const jwt = await new SignJWT({
      ...payload,
      iss,
      aud,
    })
      .setProtectedHeader({ alg, kid, typ: 'JWT' })
      .setIssuedAt(now)
      .setExpirationTime(now + 60 * 15)
      .sign(
        (alg === 'RS256'
          ? await this.keys.getPrivateKey()
          : await this.keys.getPublicKey()) as any,
      );

    return jwt;
  }

  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    const { payload } = await jwtVerify(token, (await this.keys.getPublicKey()) as any, {
      issuer: this.keys.getIssuer(),
      audience: this.keys.getAudience(),
    });
    return payload as unknown as AccessTokenPayload;
  }

  async getJwks() {
    const alg = await this.keys.getAlg();
    if (alg !== 'RS256') {
      return { keys: [] };
    }

    const jwk = await exportJWK((await this.keys.getPublicKey()) as any);
    return {
      keys: [
        {
          ...jwk,
          use: 'sig',
          alg: 'RS256',
          kid: this.keys.getKid(),
        },
      ],
    };
  }
}

