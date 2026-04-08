import { Body, Controller, Param, Post, Req, Res, UseGuards } from '@nestjs/common';
import type { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AccessTokenGuard } from '../auth/guards/access-token.guard';
import { OrgsService } from './orgs.service';
import { InvitationsService } from './invitations.service';
import { InviteMemberDto } from './dto/invite-member.dto';
import { AcceptInvitationDto } from './dto/accept-invitation.dto';
import { REFRESH_COOKIE_NAME } from '../auth/auth.constants';

@ApiTags('invitations')
@Controller()
export class InvitationsController {
  constructor(
    private readonly orgs: OrgsService,
    private readonly invitations: InvitationsService,
    private readonly config: ConfigService,
  ) {}

  @Post('/v1/orgs/:orgId/invitations')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Invite member by email (requires org:manage)' })
  @ApiResponse({ status: 201, description: 'Invitation created (dev returns token)' })
  async invite(
    @Param('orgId') orgId: string,
    @Body() dto: InviteMemberDto,
    @Req() req: Request & any,
  ) {
    const userId = req.auth?.sub as string;
    const org = await this.orgs.getOrgBySlug(orgId);
    return await this.invitations.createInvitation({
      orgId: org.id,
      invitedByUserId: userId,
      email: dto.email,
      roleKeys: dto.roleKeys ?? [],
    });
  }

  @Post('/v1/orgs/:orgId/invitations/accept')
  @ApiOperation({ summary: 'Accept invitation (creates user if needed)' })
  @ApiResponse({ status: 201, description: 'Returns access token and sets refresh cookie' })
  async accept(
    @Param('orgId') orgId: string,
    @Body() dto: AcceptInvitationDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const ip = req.ip;
    const userAgent = req.headers['user-agent'];
    const org = await this.orgs.getOrgBySlug(orgId);

    const login = await this.invitations.acceptInvitation({
      orgId: org.id,
      token: dto.token,
      dto,
      meta: { ip, userAgent },
    });

    this.setRefreshCookie(res, login.refreshToken, login.refreshExpiresAt);

    return {
      accessToken: login.accessToken,
      user: login.user,
      activeOrgId: login.activeOrgId,
      roles: login.roles,
      perms: login.perms,
    };
  }

  private setRefreshCookie(res: Response, raw: string, expiresAt: Date) {
    const secure = this.config.get<boolean>('COOKIE_SECURE', false);
    const sameSite = this.config.get<'lax' | 'strict' | 'none'>(
      'COOKIE_SAMESITE',
      'lax',
    );
    const domain = this.config.get<string | undefined>('COOKIE_DOMAIN');

    res.cookie(REFRESH_COOKIE_NAME, raw, {
      httpOnly: true,
      secure,
      sameSite,
      domain,
      path: '/v1/auth',
      expires: expiresAt,
    });
  }
}

