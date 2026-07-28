import { Injectable } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import type { Env } from '../config/env.schema';

@Injectable()
export class ReaperService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService<Env, true>,
  ) {}

  @Cron(CronExpression.EVERY_30_SECONDS)
  async handleCron(): Promise<void> {
    await this.reap();
  }

  // Marca ABORTED + veredicto INVALID las sesiones ACTIVE sin actividad > timeout.
  async reap(now: Date = new Date()): Promise<number> {
    const multiplier = this.config.get('SESSION_TIMEOUT_MULTIPLIER', {
      infer: true,
    });
    const stale = await this.prisma.session.findMany({
      where: { status: 'ACTIVE' },
    });
    let count = 0;
    for (const session of stale) {
      const timeoutMs = multiplier * session.expectedIntervalSec * 1000;
      if (now.getTime() - session.lastSeenAt.getTime() > timeoutMs) {
        await this.prisma.session.update({
          where: { id: session.id },
          data: { status: 'ABORTED', verdict: 'INVALID', endedAt: now },
        });
        count += 1;
      }
    }
    return count;
  }
}
