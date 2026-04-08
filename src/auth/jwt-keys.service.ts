import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createSecretKey, KeyObject } from 'crypto';
import { importPKCS8, importSPKI } from 'jose';

type JwtAlg = 'RS256' | 'HS256';

@Injectable()
export class JwtKeysService {
  private alg?: JwtAlg;
  private privateKey?: unknown;
  private publicKey?: unknown;
  private hsKey?: KeyObject;

  constructor(private readonly config: ConfigService) {}

  getKid(): string {
    return this.config.get<string>('AUTH_JWT_KID', 'dev-kid');
  }

  getIssuer(): string {
    return this.config.get<string>('AUTH_ISSUER', 'mixin-auth');
  }

  getAudience(): string {
    return this.config.get<string>('AUTH_AUDIENCE', 'api');
  }

  async getAlg(): Promise<JwtAlg> {
    if (this.alg) return this.alg;
    const hasAsymmetric =
      !!this.config.get<string>('AUTH_JWT_PRIVATE_KEY_PEM') &&
      !!this.config.get<string>('AUTH_JWT_PUBLIC_KEY_PEM');
    this.alg = hasAsymmetric ? 'RS256' : 'HS256';
    return this.alg;
  }

  async getPrivateKey(): Promise<unknown> {
    const alg = await this.getAlg();
    if (alg !== 'RS256') {
      throw new Error('Private key requested but AUTH is using HS256.');
    }
    if (this.privateKey) return this.privateKey;

    const pem = this.mustGetPem('AUTH_JWT_PRIVATE_KEY_PEM');
    this.privateKey = await importPKCS8(pem, 'RS256');
    return this.privateKey;
  }

  async getPublicKey(): Promise<unknown> {
    const alg = await this.getAlg();
    if (alg === 'HS256') {
      // HS256 uses shared secret; use that for verification
      return this.getHsKey();
    }
    if (this.publicKey) return this.publicKey;
    const pem = this.mustGetPem('AUTH_JWT_PUBLIC_KEY_PEM');
    this.publicKey = await importSPKI(pem, 'RS256');
    return this.publicKey;
  }

  private getHsKey(): KeyObject {
    if (this.hsKey) return this.hsKey;
    const secret =
      this.config.get<string>('AUTH_JWT_HS_SECRET') ?? 'dev-jwt-secret';
    this.hsKey = createSecretKey(Buffer.from(secret, 'utf8'));
    return this.hsKey;
  }

  private mustGetPem(key: string): string {
    const raw = this.config.get<string>(key);
    if (!raw) throw new Error(`Missing required env var ${key}`);
    // support keys passed with literal \n
    return raw.includes('\\n') ? raw.replace(/\\n/g, '\n') : raw;
  }
}

