import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SignatureService } from '../common/crypto/signature.service';
import type { EnrollDeviceDto } from './dto/enroll.dto';

@Injectable()
export class DevicesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly signature: SignatureService,
  ) {}

  async enroll(
    dto: EnrollDeviceDto,
  ): Promise<{ deviceId: string; createdAt: Date }> {
    const fp = this.signature.fingerprint(dto.publicKey);
    // Idempotente: misma clave → mismo device.
    const device = await this.prisma.device.upsert({
      where: { publicKeyFp: fp },
      create: {
        publicKey: dto.publicKey,
        publicKeyFp: fp,
        platform: dto.platform,
        keyAlgo: dto.keyAlgo ?? 'ES256',
        attestationType:
          dto.attestation?.type === 'PLAY_INTEGRITY'
            ? 'PLAY_INTEGRITY'
            : 'NONE',
        attestationData: dto.attestation ? { ...dto.attestation } : undefined,
      },
      update: { lastSeenAt: new Date() },
    });
    return { deviceId: device.id, createdAt: device.createdAt };
  }

  async getByIdOrThrow(id: string) {
    const device = await this.prisma.device.findUnique({ where: { id } });
    if (!device) {
      throw new NotFoundException({
        message: 'Device no encontrado',
        code: 'DEVICE_NOT_FOUND',
      });
    }
    return device;
  }

  async history(id: string) {
    const device = await this.getByIdOrThrow(id);
    const sessions = await this.prisma.session.findMany({
      where: { deviceId: id },
      orderBy: { startedAt: 'desc' },
      include: { flags: true },
    });
    return {
      deviceId: device.id,
      platform: device.platform,
      revoked: device.revoked,
      sessions,
    };
  }
}
