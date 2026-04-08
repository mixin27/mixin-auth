import { Body, Controller, Param, Post, Req, Res, UseGuards } from '@nestjs/common';
import type { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { ApiBearerAuth, ApiHeader, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { AccessTokenGuard } from '../auth/guards/access-token.guard';
import { OrgsService } from './orgs.service';
import { InvitationsService } from './invitations.service';
import { InviteMemberDto } from './dto/invite-member.dto';
import { AcceptInvitationDto } from './dto/accept-invitation.dto';
import { REFRESH_COOKIE_NAME } from '../auth/auth.constants';
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from '../auth/auth.csrf';
import { CsrfService } from '../auth/csrf.service';

@ApiTags('invitations')
@Controller()
export class InvitationsController {
  constructor(
    private readonly orgs: OrgsService,
    private readonly invitations: InvitationsService,
    private readonly csrf: CsrfService,
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
  @Throttle({ default: { ttl: 60_000, limit: 15 } })
  @ApiOperation({ summary: 'Accept invitation (creates user if needed)' })
  @ApiHeader({
    name: CSRF_HEADER_NAME,
    required: true,
    description: `Must match ${CSRF_COOKIE_NAME} cookie value.`,
  })
  @ApiResponse({
    status: 201,
    description: `Returns access token, sets refresh cookie, and rotates CSRF cookie (${CSRF_COOKIE_NAME}).`,
  })
  async accept(
    @Param('orgId') orgId: string,
    @Body() dto: AcceptInvitationDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    this.csrf.assertValid(req);
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
    this.setCsrfCookie(res, this.csrf.issueToken());

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

  private setCsrfCookie(res: Response, token: string) {
    const secure = this.config.get<boolean>('COOKIE_SECURE', false);
    const sameSite = this.config.get<'lax' | 'strict' | 'none'>(
      'COOKIE_SAMESITE',
      'lax',
    );
    const domain = this.config.get<string | undefined>('COOKIE_DOMAIN');
    res.cookie(CSRF_COOKIE_NAME, token, {
      httpOnly: false,
      secure,
      sameSite,
      domain,
      path: '/',
      maxAge: 24 * 60 * 60 * 1000,
    });
  }
}

