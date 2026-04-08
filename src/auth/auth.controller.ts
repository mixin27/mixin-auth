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
import { ApiBearerAuth, ApiHeader, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { REFRESH_COOKIE_NAME } from './auth.constants';
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from './auth.csrf';
import { CsrfService } from './csrf.service';
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
    private readonly csrf: CsrfService,
    private readonly config: ConfigService,
  ) {}

  @Post('/v1/auth/register')
  @Throttle({ default: { ttl: 60_000, limit: 15 } })
  @ApiOperation({ summary: 'Register with email/password' })
  @ApiResponse({ status: 201, description: 'User created' })
  async register(@Body() dto: RegisterDto) {
    return await this.auth.register(dto);
  }

  @Post('/v1/auth/login')
  @Throttle({ default: { ttl: 60_000, limit: 12 } })
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
    this.setCsrfCookie(res, this.csrf.issueToken());
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
  @Throttle({ default: { ttl: 60_000, limit: 30 } })
  @ApiOperation({ summary: 'Refresh access token (rotates refresh cookie)' })
  @ApiHeader({
    name: CSRF_HEADER_NAME,
    required: true,
    description: `Must match ${CSRF_COOKIE_NAME} cookie value.`,
  })
  @ApiResponse({
    status: 401,
    description: `Missing/invalid CSRF. Send header ${CSRF_HEADER_NAME} matching CSRF cookie.`,
  })
  @ApiResponse({ status: 201, description: 'New access token returned and refresh cookie rotated' })
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    this.csrf.assertValid(req);
    const token = req.cookies?.[REFRESH_COOKIE_NAME];
    if (!token || typeof token !== 'string') {
      throw new UnauthorizedException('Missing refresh cookie');
    }
    const result = await this.auth.refresh(token);
    this.setCsrfCookie(res, this.csrf.issueToken());
    this.setRefreshCookie(res, result.refreshToken, result.refreshExpiresAt);
    return {
      accessToken: result.accessToken,
      activeOrgId: result.activeOrgId,
      roles: result.roles,
      perms: result.perms,
    };
  }

  @Post('/v1/auth/logout')
  @Throttle({ default: { ttl: 60_000, limit: 30 } })
  @ApiOperation({ summary: 'Logout (revokes refresh token and clears cookie)' })
  @ApiHeader({
    name: CSRF_HEADER_NAME,
    required: true,
    description: `Must match ${CSRF_COOKIE_NAME} cookie value.`,
  })
  @ApiResponse({ status: 201, description: 'Logout successful' })
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    this.csrf.assertValid(req);
    const token = req.cookies?.[REFRESH_COOKIE_NAME];
    if (token && typeof token === 'string') {
      await this.auth.logout(token);
    }
    this.clearRefreshCookie(res);
    this.clearCsrfCookie(res);
    return { ok: true };
  }

  @Get('/v1/auth/csrf')
  @ApiOperation({ summary: 'Issue or rotate CSRF cookie token' })
  @ApiResponse({
    status: 200,
    description: `Returns CSRF token; send it in ${CSRF_HEADER_NAME} for cookie-auth POSTs.`,
  })
  csrfToken(@Res({ passthrough: true }) res: Response) {
    const token = this.csrf.issueToken();
    this.setCsrfCookie(res, token);
    return { csrfToken: token, header: CSRF_HEADER_NAME };
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

  private clearCsrfCookie(res: Response) {
    const domain = this.config.get<string | undefined>('COOKIE_DOMAIN');
    res.clearCookie(CSRF_COOKIE_NAME, { path: '/', domain });
  }
}

