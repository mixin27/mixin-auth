import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { GoogleAuthController } from './google/google-auth.controller';
import { GoogleAuthService } from './google/google-auth.service';
import { AuthService } from './auth.service';
import { CsrfService } from './csrf.service';
import { AccessTokenGuard } from './guards/access-token.guard';
import { JwtKeysService } from './jwt-keys.service';
import { AuthJwtService } from './jwt.service';
import { RefreshTokenService } from './refresh-token.service';

@Module({
  controllers: [AuthController, GoogleAuthController],
  providers: [
    AuthService,
    RefreshTokenService,
    CsrfService,
    JwtKeysService,
    AuthJwtService,
    AccessTokenGuard,
    GoogleAuthService,
  ],
  exports: [AuthService, AuthJwtService, AccessTokenGuard, RefreshTokenService, CsrfService],
})
export class AuthModule {}

