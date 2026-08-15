import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { CreateBlacklistEntryDto } from './dto/blacklist.dto';

@Injectable()
export class BlacklistService {
  constructor(private readonly prisma: PrismaService) {}

  private async bumpVersion(): Promise<number> {
    // Fila singleton id=1; se crea si no existe y se incrementa.
    const state = await this.prisma.blacklistState.upsert({
      where: { id: 1 },
      create: { id: 1, version: 1 },
      update: { version: { increment: 1 } },
    });
    return state.version;
  }

  async currentVersion(): Promise<number> {
    const state = await this.prisma.blacklistState.findUnique({
      where: { id: 1 },
    });
    return state?.version ?? 1;
  }

  async list(): Promise<{
    version: number;
    entries: Array<{ packageName: string; label: string; severity: string }>;
  }> {
    const [version, rows] = await Promise.all([
      this.currentVersion(),
      this.prisma.blacklistEntry.findMany({
        where: { active: true },
        orderBy: { addedAt: 'asc' },
      }),
    ]);
    return {
      version,
      entries: rows.map((r) => ({
        packageName: r.packageName,
        label: r.label,
        severity: r.severity,
      })),
    };
  }

  async activeSet(): Promise<Set<string>> {
    const rows = await this.prisma.blacklistEntry.findMany({
      where: { active: true },
      select: { packageName: true },
    });
    return new Set(rows.map((r) => r.packageName));
  }

  async add(dto: CreateBlacklistEntryDto) {
    const entry = await this.prisma.blacklistEntry.upsert({
      where: { packageName: dto.packageName },
      create: { ...dto, active: true },
      update: { label: dto.label, severity: dto.severity, active: true },
    });
    await this.bumpVersion();
    return entry;
  }

  async remove(id: string): Promise<void> {
    await this.prisma.blacklistEntry.update({
      where: { id },
      data: { active: false },
    });
    await this.bumpVersion();
  }
}
