import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { REFRESH_COOKIE_NAME } from './auth.constants';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { SwitchActiveOrgDto } from './dto/switch-org.dto';
import { AccessTokenGuard } from './guards/access-token.guard';
import { AuthJwtService } from './jwt.service';

@ApiTags('auth')
@Controller()
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly jwt: AuthJwtService,
    private readonly config: ConfigService,
  ) {}

  @Post('/v1/auth/register')
  @ApiOperation({ summary: 'Register with email/password' })
  @ApiResponse({ status: 201, description: 'User created' })
  async register(@Body() dto: RegisterDto) {
    return await this.auth.register(dto);
  }

  @Post('/v1/auth/login')
  @ApiOperation({ summary: 'Login with email/password (sets refresh cookie)' })
  @ApiResponse({ status: 201, description: 'Access token returned and refresh cookie set' })
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const ip = req.ip;
    const userAgent = req.headers['user-agent'];
    const result = await this.auth.login(dto, { ip, userAgent });
    this.setRefreshCookie(res, result.refreshToken, result.refreshExpiresAt);
    return {
      accessToken: result.accessToken,
      user: result.user,
      activeOrgId: result.activeOrgId,
      roles: result.roles,
      perms: result.perms,
    };
  }

  @Post('/v1/auth/refresh')
  @ApiOperation({ summary: 'Refresh access token (rotates refresh cookie)' })
  @ApiResponse({ status: 201, description: 'New access token returned and refresh cookie rotated' })
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const token = req.cookies?.[REFRESH_COOKIE_NAME];
    if (!token || typeof token !== 'string') {
      throw new UnauthorizedException('Missing refresh cookie');
    }
    const result = await this.auth.refresh(token);
    this.setRefreshCookie(res, result.refreshToken, result.refreshExpiresAt);
    return {
      accessToken: result.accessToken,
      activeOrgId: result.activeOrgId,
      roles: result.roles,
      perms: result.perms,
    };
  }

  @Post('/v1/auth/logout')
  @ApiOperation({ summary: 'Logout (revokes refresh token and clears cookie)' })
  @ApiResponse({ status: 201, description: 'Logout successful' })
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const token = req.cookies?.[REFRESH_COOKIE_NAME];
    if (token && typeof token === 'string') {
      await this.auth.logout(token);
    }
    this.clearRefreshCookie(res);
    return { ok: true };
  }

  @Post('/v1/sessions/active-org')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Switch active org for current session' })
  async switchActiveOrg(@Body() dto: SwitchActiveOrgDto, @Req() req: any) {
    const auth = req.auth;
    if (!auth?.sub || !auth?.sid) throw new UnauthorizedException();
    return await this.auth.switchActiveOrg({
      userId: auth.sub,
      sessionId: auth.sid,
      orgId: dto.orgId,
    });
  }

  @Get('/.well-known/jwks.json')
  @ApiTags('jwks')
  @ApiOperation({ summary: 'JWKS for JWT verification' })
  async jwks() {
    return await this.jwt.getJwks();
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

  private clearRefreshCookie(res: Response) {
    const domain = this.config.get<string | undefined>('COOKIE_DOMAIN');
    res.clearCookie(REFRESH_COOKIE_NAME, { path: '/v1/auth', domain });
  }
}

