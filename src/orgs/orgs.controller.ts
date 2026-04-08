import { Body, Controller, Get, Param, Post, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AccessTokenGuard } from '../auth/guards/access-token.guard';
import { CreateOrgDto } from './dto/create-org.dto';
import { CreateRoleDto } from './dto/create-role.dto';
import { AssignRolesDto } from './dto/assign-roles.dto';
import { OrgsService } from './orgs.service';
import { RbacService } from './rbac.service';
import { AuthService } from '../auth/auth.service';

@ApiTags('orgs')
@ApiBearerAuth('access-token')
@Controller()
export class OrgsController {
  constructor(
    private readonly orgs: OrgsService,
    private readonly rbac: RbacService,
    private readonly auth: AuthService,
  ) {}

  @Post('/v1/orgs')
  @UseGuards(AccessTokenGuard)
  @ApiOperation({ summary: 'Create org (seeds owner role + permissions)' })
  @ApiResponse({ status: 201, description: 'Org created' })
  async createOrg(@Body() dto: CreateOrgDto, @Req() req: Request & any) {
    const userId = req.auth?.sub as string;
    const sessionId = req.auth?.sid as string;
    const activate = dto.activate ?? true;
    return await this.orgs.createOrg({
      slug: dto.slug,
      name: dto.name,
      activate,
      userId,
      sessionId,
    });
  }

  @Get('/v1/orgs')
  @UseGuards(AccessTokenGuard)
  @ApiOperation({ summary: 'List orgs for current user' })
  async listMyOrgs(@Req() req: Request & any) {
    const userId = req.auth?.sub as string;
    return await this.orgs.listMyOrgs(userId);
  }

  @Post('/v1/orgs/:orgId/roles')
  @UseGuards(AccessTokenGuard)
  @ApiOperation({ summary: 'Create role in org (requires rbac:manage)' })
  async createRole(
    @Param('orgId') orgId: string,
    @Body() dto: CreateRoleDto,
    @Req() req: Request & any,
  ) {
    const userId = req.auth?.sub as string;
    const org = await this.orgs.getOrgBySlug(orgId);
    await this.rbac.assertOrgPermission(userId, org.id, 'rbac:manage');
    return await this.rbac.createRoleWithPermissions({
      orgId: org.id,
      key: dto.key,
      name: dto.name,
      permissionKeys: dto.permissionKeys ?? [],
    });
  }

  @Post('/v1/orgs/:orgId/members/:userId/roles')
  @UseGuards(AccessTokenGuard)
  @ApiOperation({ summary: 'Assign roles to member (requires rbac:manage)' })
  async assignRolesToMember(
    @Param('orgId') orgId: string,
    @Param('userId') memberUserId: string,
    @Body() dto: AssignRolesDto,
    @Req() req: Request & any,
  ) {
    const userId = req.auth?.sub as string;
    const org = await this.orgs.getOrgBySlug(orgId);
    await this.rbac.assertOrgPermission(userId, org.id, 'rbac:manage');
    return await this.rbac.assignRolesToMember({
      orgId: org.id,
      memberUserId,
      roleKeys: dto.roleKeys,
      mode: dto.mode ?? 'add',
    });
  }
}

