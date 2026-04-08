import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { RefreshTokenService } from './refresh-token.service';
import { AuthJwtService } from './jwt.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly refreshTokens: RefreshTokenService,
    private readonly jwt: AuthJwtService,
    private readonly config: ConfigService,
  ) {}

  async register(input: { email: string; password: string; name?: string }) {
    const existing = await this.prisma.user.findUnique({
      where: { email: input.email.toLowerCase() },
    });
    if (existing) throw new BadRequestException('Email already registered');

    const passwordHash = await argon2.hash(input.password);
    const user = await this.prisma.user.create({
      data: {
        email: input.email.toLowerCase(),
        passwordHash,
        name: input.name,
      },
      select: { id: true, email: true, name: true, createdAt: true },
    });
    return { user };
  }

  async login(input: { email: string; password: string; orgId?: string }, meta: { ip?: string; userAgent?: string }) {
    const user = await this.prisma.user.findUnique({
      where: { email: input.email.toLowerCase() },
    });
    if (!user || !user.passwordHash) throw new UnauthorizedException('Invalid credentials');
    if (user.disabledAt) throw new ForbiddenException('User is disabled');

    const ok = await argon2.verify(user.passwordHash, input.password);
    if (!ok) throw new UnauthorizedException('Invalid credentials');

    const activeOrgId =
      input.orgId ?? (await this.findDefaultOrgIdForUser(user.id));
    if (activeOrgId) {
      await this.assertOrgMembership(user.id, activeOrgId);
    }

    const refreshRaw = this.refreshTokens.generateRawToken();
    const refreshHash = this.refreshTokens.hash(refreshRaw);
    const expiresAt = this.refreshTokens.getExpiryDate();

    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        refreshTokenHash: refreshHash,
        expiresAt,
        ip: meta.ip,
        userAgent: meta.userAgent,
        activeOrgId: activeOrgId ?? null,
      },
      select: { id: true, activeOrgId: true, expiresAt: true },
    });

    const { roles, perms } = await this.getRolesAndPerms(user.id, activeOrgId);
    const accessToken = await this.jwt.signAccessToken({
      sub: user.id,
      sid: session.id,
      org_id: activeOrgId ?? undefined,
      roles,
      perms,
    });

    return {
      accessToken,
      refreshToken: refreshRaw,
      refreshExpiresAt: session.expiresAt,
      user: { id: user.id, email: user.email, name: user.name },
      activeOrgId: activeOrgId ?? null,
      roles,
      perms,
    };
  }

  async refresh(rawRefreshToken: string) {
    const refreshHash = this.refreshTokens.hash(rawRefreshToken);
    const session = await this.prisma.session.findFirst({
      where: {
        refreshTokenHash: refreshHash,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      select: { id: true, userId: true, activeOrgId: true, expiresAt: true },
    });
    if (!session) throw new UnauthorizedException('Invalid refresh token');

    const newRaw = this.refreshTokens.generateRawToken();
    const newHash = this.refreshTokens.hash(newRaw);
    const newExpiresAt = this.refreshTokens.getExpiryDate();

    const updated = await this.prisma.session.update({
      where: { id: session.id },
      data: { refreshTokenHash: newHash, expiresAt: newExpiresAt },
      select: { id: true, userId: true, activeOrgId: true, expiresAt: true },
    });

    const { roles, perms } = await this.getRolesAndPerms(updated.userId, updated.activeOrgId ?? undefined);
    const accessToken = await this.jwt.signAccessToken({
      sub: updated.userId,
      sid: updated.id,
      org_id: updated.activeOrgId ?? undefined,
      roles,
      perms,
    });

    return {
      accessToken,
      refreshToken: newRaw,
      refreshExpiresAt: updated.expiresAt,
      activeOrgId: updated.activeOrgId,
      roles,
      perms,
    };
  }

  async logout(rawRefreshToken: string) {
    const refreshHash = this.refreshTokens.hash(rawRefreshToken);
    await this.prisma.session.updateMany({
      where: { refreshTokenHash: refreshHash, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    return { ok: true };
  }

  async switchActiveOrg(input: { userId: string; sessionId: string; orgId: string }) {
    await this.assertOrgMembership(input.userId, input.orgId);

    const session = await this.prisma.session.update({
      where: { id: input.sessionId },
      data: { activeOrgId: input.orgId },
      select: { id: true, userId: true, activeOrgId: true },
    });

    const { roles, perms } = await this.getRolesAndPerms(session.userId, session.activeOrgId ?? undefined);
    const accessToken = await this.jwt.signAccessToken({
      sub: session.userId,
      sid: session.id,
      org_id: session.activeOrgId ?? undefined,
      roles,
      perms,
    });

    return { accessToken, activeOrgId: session.activeOrgId, roles, perms };
  }

  private async findDefaultOrgIdForUser(userId: string): Promise<string | undefined> {
    const membership = await this.prisma.orgMembership.findFirst({
      where: { userId, status: 'ACTIVE' },
      select: { orgId: true },
      orderBy: { createdAt: 'asc' },
    });
    return membership?.orgId;
  }

  private async assertOrgMembership(userId: string, orgId: string) {
    const membership = await this.prisma.orgMembership.findUnique({
      where: { orgId_userId: { orgId, userId } },
      select: { status: true },
    });
    if (!membership || membership.status !== 'ACTIVE') {
      throw new ForbiddenException('Not a member of this org');
    }
  }

  private async getRolesAndPerms(userId: string, orgId?: string | null): Promise<{ roles: string[]; perms: string[] }> {
    if (!orgId) return { roles: [], perms: [] };

    const membership = await this.prisma.orgMembership.findUnique({
      where: { orgId_userId: { orgId, userId } },
      include: {
        roles: {
          include: {
            role: {
              include: {
                permissions: { include: { permission: true } },
              },
            },
          },
        },
      },
    });
    if (!membership) return { roles: [], perms: [] };

    const roles = membership.roles.map((mr) => mr.role.key);
    const perms = membership.roles.flatMap((mr) =>
      mr.role.permissions.map((rp) => rp.permission.key),
    );

    return {
      roles: Array.from(new Set(roles)),
      perms: Array.from(new Set(perms)),
    };
  }
}

