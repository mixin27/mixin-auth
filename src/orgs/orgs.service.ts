import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { AuthService } from '../auth/auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { DEFAULT_OWNER_PERMISSIONS, OWNER_ROLE_KEY } from './orgs.constants';

type CreateOrgInput = {
  slug: string;
  name: string;
  activate: boolean;
  userId: string;
  sessionId: string;
};

@Injectable()
export class OrgsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly auth: AuthService,
  ) {}

  async createOrg(input: CreateOrgInput) {
    const slug = input.slug.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9-_]{2,30}$/i.test(slug)) {
      throw new BadRequestException('Invalid org slug');
    }

    const org = await this.prisma.org.create({
      data: {
        slug,
        name: input.name,
      },
      select: { id: true, slug: true, name: true },
    }).catch((e: any) => {
      if (e?.code === 'P2002') throw new ConflictException('Org slug already exists');
      throw e;
    });

    const membership = await this.prisma.orgMembership.create({
      data: {
        orgId: org.id,
        userId: input.userId,
        status: 'ACTIVE',
      },
      select: { id: true },
    });

    // Seed default RBAC permissions + owner role for this org.
    const permissions = await this.prisma.permission.createMany({
      data: DEFAULT_OWNER_PERMISSIONS.map((key) => ({ key, name: key })),
      skipDuplicates: true,
    });

    const permissionRows = await this.prisma.permission.findMany({
      where: { key: { in: [...DEFAULT_OWNER_PERMISSIONS] } },
      select: { id: true, key: true },
    });

    const ownerRole = await this.prisma.role.create({
      data: {
        orgId: org.id,
        key: OWNER_ROLE_KEY,
        name: 'Owner',
      },
      select: { id: true },
    });

    await this.prisma.rolePermission.createMany({
      data: permissionRows.map((p) => ({
        roleId: ownerRole.id,
        permissionId: p.id,
      })),
      skipDuplicates: true,
    });

    await this.prisma.membershipRole.createMany({
      data: [{ membershipId: membership.id, roleId: ownerRole.id }],
      skipDuplicates: true,
    });

    if (!input.activate) {
      return org;
    }

    const switched = await this.auth.switchActiveOrg({
      userId: input.userId,
      sessionId: input.sessionId,
      orgId: org.id,
    });

    return {
      ...org,
      accessToken: switched.accessToken,
    };
  }

  async listMyOrgs(userId: string) {
    const memberships = await this.prisma.orgMembership.findMany({
      where: { userId, status: 'ACTIVE' },
      include: {
        org: true,
        roles: {
          include: {
            role: true,
          },
        },
      },
    });

    return memberships.map((m) => ({
      id: m.org.id,
      slug: m.org.slug,
      name: m.org.name,
      roles: m.roles.map((mr) => mr.role.key),
      status: m.status,
    }));
  }

  async getOrgMember(orgId: string, userId: string) {
    const membership = await this.prisma.orgMembership.findUnique({
      where: { orgId_userId: { orgId, userId } },
      include: { roles: { include: { role: true } } },
    });
    if (!membership) throw new NotFoundException('Org membership not found');
    return membership;
  }

  async getOrgBySlug(slug: string) {
    const orgSlug = slug.trim().toLowerCase();
    const org = await this.prisma.org.findUnique({
      where: { slug: orgSlug },
      select: { id: true, slug: true, name: true },
    });
    if (!org) throw new NotFoundException('Org not found');
    return org;
  }
}

