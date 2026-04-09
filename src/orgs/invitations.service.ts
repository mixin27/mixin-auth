import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../prisma/prisma.service';
import { AuthService } from '../auth/auth.service';
import { RefreshTokenService } from '../auth/refresh-token.service';
import * as argon2 from 'argon2';
import { AcceptInvitationDto } from './dto/accept-invitation.dto';

const INVITATION_TOKEN_MAX_DAYS = 7;

@Injectable()
export class InvitationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly auth: AuthService,
    private readonly refreshTokens: RefreshTokenService,
    private readonly audit: AuditService,
  ) {}

  async createInvitation(input: {
    orgId: string;
    invitedByUserId: string;
    email: string;
    roleKeys: string[];
  }) {
    // Require org management permission for inviting.
    const membership = await this.prisma.orgMembership.findUnique({
      where: { orgId_userId: { orgId: input.orgId, userId: input.invitedByUserId } },
      select: {
        status: true,
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

    if (!membership || membership.status !== 'ACTIVE') {
      await this.audit.log({
        eventType: 'INVITATION_CREATE',
        outcome: 'FAILURE',
        actorUserId: input.invitedByUserId,
        orgId: input.orgId,
        metadata: { reason: 'not_member_or_inactive' },
      });
      throw new ForbiddenException('Not a member of this org');
    }

    const perms = membership.roles.flatMap((mr) =>
      mr.role.permissions.map((rp) => rp.permission.key),
    );
    if (!perms.includes('org:manage')) {
      await this.audit.log({
        eventType: 'INVITATION_CREATE',
        outcome: 'FAILURE',
        actorUserId: input.invitedByUserId,
        orgId: input.orgId,
        metadata: { reason: 'missing_permission', permissionKey: 'org:manage' },
      });
      throw new ForbiddenException('Missing required permission');
    }

    const invitedEmail = input.email.trim().toLowerCase();

    const org = await this.prisma.org.findUnique({
      where: { id: input.orgId },
      select: { id: true },
    });
    if (!org) {
      await this.audit.log({
        eventType: 'INVITATION_CREATE',
        outcome: 'FAILURE',
        actorUserId: input.invitedByUserId,
        orgId: input.orgId,
        metadata: { reason: 'org_not_found' },
      });
      throw new NotFoundException('Org not found');
    }

    // Generate token + store only hash.
    const rawToken = this.refreshTokens.generateRawToken();
    const tokenHash = this.refreshTokens.hash(rawToken);
    const expiresAt = new Date(Date.now() + INVITATION_TOKEN_MAX_DAYS * 24 * 60 * 60 * 1000);

    const invite = await this.prisma.orgInvitation.create({
      data: {
        orgId: input.orgId,
        invitedEmail,
        tokenHash,
        expiresAt,
        invitedByUserId: input.invitedByUserId,
      },
      select: { id: true },
    });

    let roleIdRows: { id: string }[] = [];
    if (input.roleKeys.length > 0) {
      roleIdRows = await this.prisma.role.findMany({
        where: { orgId: input.orgId, key: { in: input.roleKeys } },
        select: { id: true },
      });

      if (roleIdRows.length !== input.roleKeys.length) {
        await this.audit.log({
          eventType: 'INVITATION_CREATE',
          outcome: 'FAILURE',
          actorUserId: input.invitedByUserId,
          orgId: input.orgId,
          metadata: { reason: 'role_not_found', roleKeys: input.roleKeys },
        });
        throw new NotFoundException('One or more roles not found');
      }

      await this.prisma.orgInvitationRole.createMany({
        data: roleIdRows.map((r) => ({
          invitationId: invite.id,
          roleId: r.id,
        })),
        skipDuplicates: true,
      });
    }

    await this.audit.log({
      eventType: 'INVITATION_CREATE',
      outcome: 'SUCCESS',
      actorUserId: input.invitedByUserId,
      orgId: input.orgId,
      targetType: 'INVITATION',
      targetId: invite.id,
      metadata: { invitedEmail, roleKeys: input.roleKeys },
    });

    return { invitationId: invite.id, token: rawToken, expiresAt };
  }

  async acceptInvitation(params: {
    orgId: string;
    token: string;
    dto: AcceptInvitationDto;
    meta: { ip?: string; userAgent?: string };
  }) {
    const tokenHash = this.refreshTokens.hash(params.token);
    const invitation = await this.prisma.orgInvitation.findFirst({
      where: {
        orgId: params.orgId,
        tokenHash,
        revokedAt: null,
        acceptedAt: null,
        expiresAt: { gt: new Date() },
      },
      select: {
        id: true,
        invitedEmail: true,
        roles: { select: { roleId: true } },
      },
    });

    if (!invitation) {
      await this.audit.log({
        eventType: 'INVITATION_ACCEPT',
        outcome: 'FAILURE',
        orgId: params.orgId,
        ip: params.meta.ip,
        userAgent: params.meta.userAgent,
        metadata: { reason: 'invalid_or_expired_token', email: params.dto.email },
      });
      throw new UnauthorizedException('Invalid or expired invitation token');
    }

    const emailFromInvite = invitation.invitedEmail.toLowerCase();
    const emailProvided = params.dto.email?.trim().toLowerCase();
    if (emailProvided && emailProvided !== emailFromInvite) {
      await this.audit.log({
        eventType: 'INVITATION_ACCEPT',
        outcome: 'FAILURE',
        orgId: params.orgId,
        targetType: 'INVITATION',
        targetId: invitation.id,
        ip: params.meta.ip,
        userAgent: params.meta.userAgent,
        metadata: { reason: 'email_mismatch', provided: emailProvided },
      });
      throw new ForbiddenException('Invitation email mismatch');
    }

    const email = emailFromInvite;
    const password = params.dto.password;
    const name = params.dto.name;

    // Ensure user + email/password account exist.
    let user = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true, email: true, passwordHash: true, name: true },
    });

    if (!user) {
      const passwordHash = await argon2.hash(password);
      user = await this.prisma.user.create({
        data: {
          email,
          passwordHash,
          name,
        },
        select: { id: true, email: true, passwordHash: true, name: true },
      });

      await this.prisma.account.create({
        data: {
          userId: user.id,
          provider: 'EMAIL',
          providerAccountId: email,
        },
      });
    } else {
      if (!user.passwordHash) {
        const passwordHash = await argon2.hash(password);
        user = await this.prisma.user.update({
          where: { id: user.id },
          data: { passwordHash, name },
          select: { id: true, email: true, passwordHash: true, name: true },
        });
      } else {
        const ok = await argon2.verify(user.passwordHash, password);
        if (!ok) {
          await this.audit.log({
            eventType: 'INVITATION_ACCEPT',
            outcome: 'FAILURE',
            actorUserId: user.id,
            orgId: params.orgId,
            targetType: 'INVITATION',
            targetId: invitation.id,
            ip: params.meta.ip,
            userAgent: params.meta.userAgent,
            metadata: { reason: 'invalid_password' },
          });
          throw new UnauthorizedException('Invalid password');
        }
      }

      // Ensure account exists.
      const account = await this.prisma.account.findUnique({
        where: {
          provider_providerAccountId: { provider: 'EMAIL', providerAccountId: email },
        },
        select: { userId: true },
      });
      if (!account) {
        await this.prisma.account.create({
          data: { userId: user.id, provider: 'EMAIL', providerAccountId: email },
        });
      }
    }

    // Activate membership and assign roles.
    let membership = await this.prisma.orgMembership.findUnique({
      where: { orgId_userId: { orgId: params.orgId, userId: user.id } },
      select: { id: true, status: true },
    });

    if (!membership) {
      membership = await this.prisma.orgMembership.create({
        data: {
          orgId: params.orgId,
          userId: user.id,
          status: 'ACTIVE',
        },
        select: { id: true, status: true },
      });
    } else if (membership.status !== 'ACTIVE') {
      await this.prisma.orgMembership.update({
        where: { id: membership.id },
        data: { status: 'ACTIVE' },
        select: { id: true, status: true },
      });
    }

    if (invitation.roles.length > 0) {
      await this.prisma.membershipRole.deleteMany({
        where: { membershipId: membership.id },
      });

      await this.prisma.membershipRole.createMany({
        data: invitation.roles.map((r) => ({ membershipId: membership.id, roleId: r.roleId })),
        skipDuplicates: true,
      });
    }

    await this.prisma.orgInvitation.update({
      where: { id: invitation.id },
      data: { acceptedAt: new Date() },
      select: { id: true },
    });

    // Mint tokens using the already-implemented login flow, forcing active org.
    const login = await this.auth.login(
      { email, password, orgId: params.orgId },
      { ip: params.meta.ip, userAgent: params.meta.userAgent },
    );

    await this.audit.log({
      eventType: 'INVITATION_ACCEPT',
      outcome: 'SUCCESS',
      actorUserId: user.id,
      orgId: params.orgId,
      targetType: 'INVITATION',
      targetId: invitation.id,
      ip: params.meta.ip,
      userAgent: params.meta.userAgent,
    });

    return login;
  }
}

