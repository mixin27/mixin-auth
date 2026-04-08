import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AccessTokenGuard } from './guards/access-token.guard';
import { JwtKeysService } from './jwt-keys.service';
import { AuthJwtService } from './jwt.service';
import { RefreshTokenService } from './refresh-token.service';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    RefreshTokenService,
    JwtKeysService,
    AuthJwtService,
    AccessTokenGuard,
  ],
  exports: [AuthService, AuthJwtService, AccessTokenGuard],
})
export class AuthModule {}

