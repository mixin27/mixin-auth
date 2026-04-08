import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthJwtService } from '../jwt.service';

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(private readonly jwt: AuthJwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const authHeader = req.headers['authorization'];
    if (!authHeader || typeof authHeader !== 'string') {
      throw new UnauthorizedException('Missing Authorization header');
    }

    const [kind, token] = authHeader.split(' ');
    if (kind !== 'Bearer' || !token) {
      throw new UnauthorizedException('Invalid Authorization header');
    }

    req.auth = await this.jwt.verifyAccessToken(token);
    return true;
  }
}

