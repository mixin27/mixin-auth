import { Injectable, Logger } from '@nestjs/common';
import { Prisma } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';

type AuditInput = {
  eventType: string;
  outcome: 'SUCCESS' | 'FAILURE';
  actorUserId?: string;
  orgId?: string;
  sessionId?: string;
  targetType?: string;
  targetId?: string;
  ip?: string;
  userAgent?: string;
  metadata?: Prisma.InputJsonValue;
};

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly prisma: PrismaService) {}

  async log(input: AuditInput) {
    try {
      await this.prisma.auditEvent.create({
        data: {
          eventType: input.eventType,
          outcome: input.outcome,
          actorUserId: input.actorUserId,
          orgId: input.orgId,
          sessionId: input.sessionId,
          targetType: input.targetType,
          targetId: input.targetId,
          ip: input.ip,
          userAgent: input.userAgent,
          metadata: input.metadata,
        },
      });
    } catch (error) {
      // Never block auth flows on audit log write failures.
      this.logger.warn(`audit write failed for ${input.eventType}`);
    }
  }
}

