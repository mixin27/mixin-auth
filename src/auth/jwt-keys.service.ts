import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, generateKeyPairSync } from 'crypto';
import { importPKCS8, importSPKI } from 'jose';

@Injectable()
export class JwtKeysService {
  private alg?: 'RS256';
  private privateKey?: unknown;
  private publicKey?: unknown;
  private ephemeralPrivatePem?: string;
  private ephemeralPublicPem?: string;
  private ephemeralKid?: string;

  constructor(private readonly config: ConfigService) {}

  getIssuer(): string {
    return this.config.get<string>('AUTH_ISSUER', 'mixin-auth');
  }

  getAudience(): string {
    return this.config.get<string>('AUTH_AUDIENCE', 'api');
  }

  async getAlg(): Promise<'RS256'> {
    if (this.alg) return this.alg;
    const hasAsymmetric =
      !!this.config.get<string>('AUTH_JWT_PRIVATE_KEY_PEM') &&
      !!this.config.get<string>('AUTH_JWT_PUBLIC_KEY_PEM');
    // Prefer RS256 for JWKS interoperability.
    // In dev, generate ephemeral keys if RSA keys are not provided.
    this.alg = 'RS256';
    return this.alg;
  }

  async getPrivateKey(): Promise<unknown> {
    const alg = await this.getAlg();
    if (alg !== 'RS256') {
      throw new Error('Private key requested but AUTH is using HS256.');
    }
    if (this.privateKey) return this.privateKey;

    const pem = this.config.get<string>('AUTH_JWT_PRIVATE_KEY_PEM');
    if (pem) {
      this.privateKey = await importPKCS8(this.mustGetPem('AUTH_JWT_PRIVATE_KEY_PEM'), 'RS256');
      return this.privateKey;
    }

    this.ensureEphemeralKeys();
    this.privateKey = await importPKCS8(this.ephemeralPrivatePem as string, 'RS256');
    return this.privateKey;
  }

  async getPublicKey(): Promise<unknown> {
    const alg = await this.getAlg();
    if (this.publicKey) return this.publicKey;

    const pem = this.config.get<string>('AUTH_JWT_PUBLIC_KEY_PEM');
    if (pem) {
      this.publicKey = await importSPKI(this.mustGetPem('AUTH_JWT_PUBLIC_KEY_PEM'), 'RS256');
      return this.publicKey;
    }

    this.ensureEphemeralKeys();
    this.publicKey = await importSPKI(this.ephemeralPublicPem as string, 'RS256');
    return this.publicKey;
  }

  private ensureEphemeralKeys() {
    if (this.ephemeralPrivatePem && this.ephemeralPublicPem) return;

    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    this.ephemeralPrivatePem = privateKey as string;
    this.ephemeralPublicPem = publicKey as string;

    const digest = createHash('sha256').update(this.ephemeralPublicPem).digest('base64url');
    this.ephemeralKid = `dev-${digest.slice(0, 16)}`;
  }

  private mustGetPem(key: string): string {
    const raw = this.config.get<string>(key);
    if (!raw) throw new Error(`Missing required env var ${key}`);
    // support keys passed with literal \n
    return raw.includes('\\n') ? raw.replace(/\\n/g, '\n') : raw;
  }

  getKid(): string {
    // If explicit KID provided, use it (useful when rotating keys in prod).
    const configured = this.config.get<string>('AUTH_JWT_KID');
    if (configured) return configured;
    // Otherwise use ephemeral kid.
    if (!this.ephemeralKid) this.ensureEphemeralKeys();
    return this.ephemeralKid as string;
  }
}

