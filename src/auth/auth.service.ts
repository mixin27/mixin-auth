import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../prisma/prisma.service';
import { RefreshTokenService } from './refresh-token.service';
import { AuthJwtService } from './jwt.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly refreshTokens: RefreshTokenService,
    private readonly jwt: AuthJwtService,
    private readonly audit: AuditService,
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

    await this.prisma.account.create({
      data: {
        userId: user.id,
        provider: 'EMAIL',
        providerAccountId: user.email,
      },
    });

    await this.audit.log({
      eventType: 'AUTH_REGISTER',
      outcome: 'SUCCESS',
      actorUserId: user.id,
      targetType: 'USER',
      targetId: user.id,
      metadata: { email: user.email },
    });

    return { user };
  }

  async oauthLogin(input: {
    provider: 'GOOGLE';
    providerAccountId: string;
    email: string;
    name?: string;
  }) {
    const email = input.email.toLowerCase();

    const account =
      await this.prisma.account.findUnique({
        where: {
          provider_providerAccountId: {
            provider: input.provider,
            providerAccountId: input.providerAccountId,
          },
        },
        select: { userId: true },
      });

    let userId: string;
    let user: { id: string; email: string; name: string | null };

    if (account) {
      userId = account.userId;
      user = await this.prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, email: true, name: true },
      }).then((u) => u as any);
    } else {
      const existingUser = await this.prisma.user.findUnique({
        where: { email },
        select: { id: true, email: true, name: true },
      });

      if (existingUser) {
        userId = existingUser.id;
        user = existingUser;
      } else {
        const created = await this.prisma.user.create({
          data: {
            email,
            name: input.name,
          },
          select: { id: true, email: true, name: true },
        });
        userId = created.id;
        user = created;
      }

      await this.prisma.account.create({
        data: {
          userId,
          provider: input.provider,
          providerAccountId: input.providerAccountId,
        },
      });
    }

    if (!user) {
      throw new UnauthorizedException('OAuth user not found');
    }

    const acceptedOrgIds = await this.acceptPendingInvitationsForEmail(userId, email);
    const activeOrgId =
      (await this.findDefaultOrgIdForUser(userId)) ?? acceptedOrgIds[0];

    const refreshRaw = this.refreshTokens.generateRawToken();
    const refreshHash = this.refreshTokens.hash(refreshRaw);
    const expiresAt = this.refreshTokens.getExpiryDate();

    const session = await this.prisma.session.create({
      data: {
        userId,
        refreshTokenHash: refreshHash,
        expiresAt,
        activeOrgId: activeOrgId ?? null,
      },
      select: { id: true, activeOrgId: true, expiresAt: true },
    });

    const { roles, perms } = await this.getRolesAndPerms(userId, activeOrgId ?? undefined);
    const accessToken = await this.jwt.signAccessToken({
      sub: userId,
      sid: session.id,
      org_id: activeOrgId ?? undefined,
      roles,
      perms,
    });

    await this.audit.log({
      eventType: 'AUTH_OAUTH_LOGIN',
      outcome: 'SUCCESS',
      actorUserId: userId,
      orgId: activeOrgId ?? undefined,
      sessionId: session.id,
      targetType: 'SESSION',
      targetId: session.id,
      metadata: { provider: input.provider, acceptedInvitations: acceptedOrgIds.length },
    });

    return {
      accessToken,
      refreshToken: refreshRaw,
      refreshExpiresAt: session.expiresAt,
      user,
      activeOrgId: activeOrgId ?? null,
      roles,
      perms,
    };
  }

  async linkGoogleAccount(input: {
    userId: string;
    providerAccountId: string;
    email: string;
    name?: string;
  }) {
    const email = input.email.toLowerCase();

    const user = await this.prisma.user.findUnique({
      where: { id: input.userId },
      select: { id: true, email: true, name: true, emailVerifiedAt: true },
    });
    if (!user) throw new UnauthorizedException('User not found');

    // Safety: only allow linking if Google email matches the logged-in user's email.
    if (user.email.toLowerCase() !== email) {
      throw new ForbiddenException('Google email does not match current user email');
    }

    const existing = await this.prisma.account.findUnique({
      where: {
        provider_providerAccountId: {
          provider: 'GOOGLE',
          providerAccountId: input.providerAccountId,
        },
      },
      select: { userId: true },
    });

    if (existing && existing.userId !== user.id) {
      await this.audit.log({
        eventType: 'AUTH_OAUTH_GOOGLE_LINK',
        outcome: 'FAILURE',
        actorUserId: user.id,
        targetType: 'ACCOUNT',
        targetId: input.providerAccountId,
        metadata: { reason: 'already_linked_to_other_user' },
      });
      throw new ForbiddenException('Google account is already linked to another user');
    }

    if (!existing) {
      await this.prisma.account.create({
        data: {
          userId: user.id,
          provider: 'GOOGLE',
          providerAccountId: input.providerAccountId,
        },
      });
    }

    // Mark email verified if not already.
    if (!user.emailVerifiedAt) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: { emailVerifiedAt: new Date(), name: user.name ?? input.name },
      });
    } else if (!user.name && input.name) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: { name: input.name },
      });
    }

    const acceptedOrgIds = await this.acceptPendingInvitationsForEmail(user.id, email);
    await this.audit.log({
      eventType: 'AUTH_OAUTH_GOOGLE_LINK',
      outcome: 'SUCCESS',
      actorUserId: user.id,
      targetType: 'ACCOUNT',
      targetId: input.providerAccountId,
      metadata: { acceptedOrgIdsCount: acceptedOrgIds.length },
    });
    return { ok: true, acceptedOrgIds };
  }

  private async acceptPendingInvitationsForEmail(userId: string, email: string): Promise<string[]> {
    const now = new Date();
    const invites = await this.prisma.orgInvitation.findMany({
      where: {
        invitedEmail: email,
        revokedAt: null,
        acceptedAt: null,
        expiresAt: { gt: now },
      },
      select: {
        id: true,
        orgId: true,
        roles: { select: { roleId: true } },
      },
      orderBy: { createdAt: 'asc' },
    });

    if (invites.length === 0) return [];

    const acceptedOrgIds: string[] = [];

    await this.prisma.$transaction(async (tx) => {
      for (const inv of invites) {
        // Upsert membership and activate.
        const membership = await tx.orgMembership.upsert({
          where: { orgId_userId: { orgId: inv.orgId, userId } },
          update: { status: 'ACTIVE' },
          create: { orgId: inv.orgId, userId, status: 'ACTIVE' },
          select: { id: true },
        });

        if (inv.roles.length > 0) {
          // Replace roles with invited roles (keeps invitation as source of truth).
          await tx.membershipRole.deleteMany({
            where: { membershipId: membership.id },
          });
          await tx.membershipRole.createMany({
            data: inv.roles.map((r) => ({ membershipId: membership.id, roleId: r.roleId })),
            skipDuplicates: true,
          });
        }

        await tx.orgInvitation.update({
          where: { id: inv.id },
          data: { acceptedAt: now },
          select: { id: true },
        });

        acceptedOrgIds.push(inv.orgId);
      }
    });

    return acceptedOrgIds;
  }

  async login(input: { email: string; password: string; orgId?: string }, meta: { ip?: string; userAgent?: string }) {
    const user = await this.prisma.user.findUnique({
      where: { email: input.email.toLowerCase() },
    });
    if (!user || !user.passwordHash) {
      await this.audit.log({
        eventType: 'AUTH_LOGIN_PASSWORD',
        outcome: 'FAILURE',
        targetType: 'USER',
        ip: meta.ip,
        userAgent: meta.userAgent,
        metadata: { email: input.email.toLowerCase(), reason: 'invalid_credentials' },
      });
      throw new UnauthorizedException('Invalid credentials');
    }
    if (user.disabledAt) {
      await this.audit.log({
        eventType: 'AUTH_LOGIN_PASSWORD',
        outcome: 'FAILURE',
        actorUserId: user.id,
        targetType: 'USER',
        targetId: user.id,
        ip: meta.ip,
        userAgent: meta.userAgent,
        metadata: { reason: 'user_disabled' },
      });
      throw new ForbiddenException('User is disabled');
    }

    const ok = await argon2.verify(user.passwordHash, input.password);
    if (!ok) {
      await this.audit.log({
        eventType: 'AUTH_LOGIN_PASSWORD',
        outcome: 'FAILURE',
        actorUserId: user.id,
        targetType: 'USER',
        targetId: user.id,
        ip: meta.ip,
        userAgent: meta.userAgent,
        metadata: { reason: 'invalid_credentials' },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

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

    await this.audit.log({
      eventType: 'AUTH_LOGIN_PASSWORD',
      outcome: 'SUCCESS',
      actorUserId: user.id,
      orgId: activeOrgId ?? undefined,
      sessionId: session.id,
      targetType: 'SESSION',
      targetId: session.id,
      ip: meta.ip,
      userAgent: meta.userAgent,
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

    await this.audit.log({
      eventType: 'AUTH_REFRESH',
      outcome: 'SUCCESS',
      actorUserId: updated.userId,
      orgId: updated.activeOrgId ?? undefined,
      sessionId: updated.id,
      targetType: 'SESSION',
      targetId: updated.id,
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
    const res = await this.prisma.session.updateMany({
      where: { refreshTokenHash: refreshHash, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    await this.audit.log({
      eventType: 'AUTH_LOGOUT',
      outcome: 'SUCCESS',
      metadata: { revokedSessions: res.count },
    });
    return { ok: true };
  }

  async switchActiveOrg(input: { userId: string; sessionId: string; orgId: string }) {
    const orgById = await this.prisma.org.findUnique({
      where: { id: input.orgId },
      select: { id: true },
    });

    const orgBySlug = await this.prisma.org.findUnique({
      where: { slug: input.orgId },
      select: { id: true },
    });

    const resolvedOrgId = orgById?.id ?? orgBySlug?.id;
    if (!resolvedOrgId) throw new ForbiddenException('Org not found');

    await this.assertOrgMembership(input.userId, resolvedOrgId);

    const session = await this.prisma.session.update({
      where: { id: input.sessionId },
      data: { activeOrgId: resolvedOrgId },
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

    await this.audit.log({
      eventType: 'AUTH_SWITCH_ORG',
      outcome: 'SUCCESS',
      actorUserId: session.userId,
      orgId: session.activeOrgId ?? undefined,
      sessionId: session.id,
      targetType: 'ORG',
      targetId: session.activeOrgId ?? undefined,
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

