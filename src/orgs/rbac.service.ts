import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class RbacService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async assertOrgPermission(userId: string, orgId: string, permissionKey: string) {
    const membership = await this.prisma.orgMembership.findUnique({
      where: { orgId_userId: { orgId, userId } },
      select: {
        status: true,
        roles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: { permission: true },
                },
              },
            },
          },
        },
      },
    });

    if (!membership || membership.status !== 'ACTIVE') {
      await this.audit.log({
        eventType: 'RBAC_PERMISSION_CHECK',
        outcome: 'FAILURE',
        actorUserId: userId,
        orgId,
        targetType: 'ORG',
        targetId: orgId,
        metadata: { permissionKey, reason: 'not_member_or_inactive' },
      });
      throw new ForbiddenException('Not a member of this org');
    }

    const perms = membership.roles.flatMap((mr) =>
      mr.role.permissions.map((rp) => rp.permission.key),
    );

    if (!perms.includes(permissionKey)) {
      await this.audit.log({
        eventType: 'RBAC_PERMISSION_CHECK',
        outcome: 'FAILURE',
        actorUserId: userId,
        orgId,
        targetType: 'ORG',
        targetId: orgId,
        metadata: { permissionKey, reason: 'missing_permission' },
      });
      throw new ForbiddenException('Missing required permission');
    }
  }

  async createRoleWithPermissions(input: {
    actorUserId?: string;
    orgId: string;
    key: string;
    name: string;
    permissionKeys: string[];
  }) {
    const role = await this.prisma.role.create({
      data: {
        orgId: input.orgId,
        key: input.key,
        name: input.name,
      },
      select: { id: true, key: true, name: true },
    });

    await this.prisma.permission.createMany({
      data: input.permissionKeys.map((k) => ({ key: k, name: k })),
      skipDuplicates: true,
    });

    const permissionRows = await this.prisma.permission.findMany({
      where: { key: { in: input.permissionKeys } },
      select: { id: true, key: true },
    });

    await this.prisma.rolePermission.createMany({
      data: permissionRows.map((p) => ({ roleId: role.id, permissionId: p.id })),
      skipDuplicates: true,
    });

    await this.audit.log({
      eventType: 'RBAC_ROLE_CREATE',
      outcome: 'SUCCESS',
      actorUserId: input.actorUserId,
      orgId: input.orgId,
      targetType: 'ROLE',
      targetId: role.id,
      metadata: { key: input.key, permissions: input.permissionKeys },
    });

    return role;
  }

  async assignRolesToMember(input: {
    actorUserId?: string;
    orgId: string;
    memberUserId: string;
    roleKeys: string[];
    mode: 'add' | 'replace';
  }) {
    const membership = await this.prisma.orgMembership.findUnique({
      where: { orgId_userId: { orgId: input.orgId, userId: input.memberUserId } },
      select: { id: true, status: true },
    });
    if (!membership || membership.status !== 'ACTIVE') {
      throw new NotFoundException('Member is not active in this org');
    }

    if (input.mode === 'replace') {
      await this.prisma.membershipRole.deleteMany({
        where: { membershipId: membership.id },
      });
    }

    const roleRows = await this.prisma.role.findMany({
      where: { orgId: input.orgId, key: { in: input.roleKeys } },
      select: { id: true, key: true },
    });

    if (roleRows.length !== input.roleKeys.length) {
      throw new NotFoundException('One or more roles not found');
    }

    await this.prisma.membershipRole.createMany({
      data: roleRows.map((r) => ({ membershipId: membership.id, roleId: r.id })),
      skipDuplicates: true,
    });

    await this.audit.log({
      eventType: 'RBAC_ROLE_ASSIGN',
      outcome: 'SUCCESS',
      actorUserId: input.actorUserId,
      orgId: input.orgId,
      targetType: 'MEMBERSHIP',
      targetId: membership.id,
      metadata: { memberUserId: input.memberUserId, roleKeys: input.roleKeys, mode: input.mode },
    });

    return { ok: true };
  }
}

