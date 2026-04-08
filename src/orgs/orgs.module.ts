import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { OrgsController } from './orgs.controller';
import { InvitationsController } from './invitations.controller';
import { OrgsService } from './orgs.service';
import { RbacService } from './rbac.service';
import { InvitationsService } from './invitations.service';

@Module({
  imports: [AuthModule],
  controllers: [OrgsController, InvitationsController],
  providers: [OrgsService, RbacService, InvitationsService],
})
export class OrgsModule {}

