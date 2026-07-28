import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { SignatureService } from '../common/crypto/signature.service';
import { NonceService } from '../common/crypto/nonce.service';
import { DevicesService } from '../devices/devices.service';
import { BlacklistService } from '../blacklist/blacklist.service';
import type { Env } from '../config/env.schema';
import type { StartSessionDto } from './dto/session.dto';

@Injectable()
export class SessionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly signature: SignatureService,
    private readonly nonce: NonceService,
    private readonly devices: DevicesService,
    private readonly blacklist: BlacklistService,
    private readonly config: ConfigService<Env, true>,
  ) {}

  async start(dto: StartSessionDto) {
    const device = await this.devices.getByIdOrThrow(dto.deviceId);
    // El device prueba posesión de su clave firmando (deviceId + clientTimestamp).
    const challenge = Buffer.from(`${dto.deviceId}${dto.clientTimestamp}`);
    if (!this.signature.verify(device.publicKey, challenge, dto.signatureB64)) {
      throw new UnauthorizedException({
        message: 'Firma de device inválida',
        code: 'DEVICE_AUTH_FAILED',
      });
    }
    const nonce = this.nonce.generate();
    const blacklistVersion = await this.blacklist.currentVersion();
    const session = await this.prisma.session.create({
      data: {
        deviceId: device.id,
        currentNonce: nonce,
        blacklistVersion,
        status: 'ACTIVE',
      },
    });
    return {
      sessionId: session.id,
      nonce,
      expectedIntervalSec: session.expectedIntervalSec,
      jitterSec: session.jitterSec,
      blacklistVersion,
    };
  }
}
