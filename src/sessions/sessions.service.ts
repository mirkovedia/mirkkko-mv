import {
  BadRequestException,
  ConflictException,
  GoneException,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { SignatureService } from '../common/crypto/signature.service';
import { NonceService } from '../common/crypto/nonce.service';
import { DevicesService } from '../devices/devices.service';
import { BlacklistService } from '../blacklist/blacklist.service';
import {
  ATTESTATION_VERIFIER,
  type AttestationVerifier,
} from '../attestation/attestation-verifier.interface';
import { evaluateSignals } from '../verdict/signal-evaluator';
import type { IntegrityVerdict, SignalSet } from '../verdict/types';
import type { Env } from '../config/env.schema';
import type { StartSessionDto, SnapshotDto } from './dto/session.dto';

// Forma del payload firmado que envía el cliente (dentro de payloadB64).
interface SnapshotPayload {
  deviceId: string;
  sessionId: string;
  seq: number;
  nonce: string;
  clientTimestamp: string;
  integrityTokenHash?: string;
  signals: SignalSet;
}

@Injectable()
export class SessionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly signature: SignatureService,
    private readonly nonce: NonceService,
    private readonly devices: DevicesService,
    private readonly blacklist: BlacklistService,
    private readonly config: ConfigService<Env, true>,
    @Inject(ATTESTATION_VERIFIER)
    private readonly attestation: AttestationVerifier,
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

  async processSnapshot(sessionId: string, dto: SnapshotDto) {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { device: true },
    });
    if (!session) {
      throw new NotFoundException({
        message: 'Sesión no encontrada',
        code: 'SESSION_NOT_FOUND',
      });
    }
    if (session.status !== 'ACTIVE') {
      throw new GoneException({
        message: 'Sesión no activa',
        code: 'SESSION_NOT_ACTIVE',
      });
    }

    const payloadBytes = Buffer.from(dto.payloadB64, 'base64');

    // 1) Verificar firma sobre los bytes exactos. Si falla, se registra como evidencia y se corta.
    const signatureValid = this.signature.verify(
      session.device.publicKey,
      payloadBytes,
      dto.signatureB64,
    );
    if (!signatureValid) {
      await this.recordRejected(
        session.id,
        `${session.currentNonce}:badsig`,
        'SIGNATURE_INVALID',
        payloadBytes,
      );
      throw new UnauthorizedException({
        message: 'Firma inválida',
        code: 'SIGNATURE_INVALID',
      });
    }

    // 2) Parsear el payload (recién ahora que la firma es válida).
    const payload = this.parsePayload(payloadBytes);

    // 3) Validar binding y nonce.
    if (
      payload.sessionId !== session.id ||
      payload.deviceId !== session.deviceId
    ) {
      throw new UnauthorizedException({
        message: 'Binding inválido',
        code: 'BINDING_MISMATCH',
      });
    }
    if (payload.nonce !== session.currentNonce) {
      await this.recordRejected(
        session.id,
        `${session.currentNonce}:reuse`,
        'NONCE_REUSE',
        payloadBytes,
      );
      throw new ConflictException({
        message: 'Nonce inválido o reusado',
        code: 'NONCE_REUSE',
      });
    }

    // 4) Validar skew temporal.
    const skewSec =
      Math.abs(Date.now() - new Date(payload.clientTimestamp).getTime()) / 1000;
    const maxSkew = this.config.get('CLOCK_SKEW_TOLERANCE_SEC', {
      infer: true,
    });
    if (skewSec > maxSkew) {
      throw new UnauthorizedException({
        message: 'Timestamp fuera de ventana',
        code: 'CLOCK_SKEW',
      });
    }

    // 5) Validar que el hash del integrityToken coincida con el firmado.
    const token = dto.integrityToken ?? null;
    if (token !== null) {
      const tokenHash = createHash('sha256').update(token).digest('hex');
      if (tokenHash !== payload.integrityTokenHash) {
        throw new UnauthorizedException({
          message: 'integrityTokenHash no coincide',
          code: 'TOKEN_HASH_MISMATCH',
        });
      }
    }

    // 6) Atestación — un fallo de infra se trata como DEGRADED (nunca se descarta).
    let integrityVerdict: IntegrityVerdict = 'DEGRADED';
    try {
      const result = await this.attestation.verify({
        token,
        nonce: session.currentNonce,
        platform: session.device.platform,
      });
      integrityVerdict = result.verdict;
    } catch {
      integrityVerdict = 'DEGRADED';
    }

    // 7) Evaluar señales → flags.
    const blacklist = await this.blacklist.activeSet();
    const flags = evaluateSignals(payload.signals, integrityVerdict, blacklist);

    // 8) Persistir snapshot + flags + próximo nonce (los @@unique atrapan replays por carrera).
    const nextNonce = this.nonce.generate();
    const seq = payload.seq;
    await this.prisma.$transaction([
      this.prisma.snapshot.create({
        data: {
          sessionId: session.id,
          seq,
          clientTimestamp: new Date(payload.clientTimestamp),
          signals: { ...payload.signals },
          signedPayload: payloadBytes,
          signatureValid: true,
          nonceUsed: session.currentNonce,
          integrityVerdict,
          flags: {
            create: flags.map((f) => ({
              sessionId: session.id,
              type: f.type,
              severity: f.severity,
              details: f.details ? { ...f.details } : undefined,
            })),
          },
        },
      }),
      this.prisma.session.update({
        where: { id: session.id },
        data: { currentNonce: nextNonce, lastSeenAt: new Date() },
      }),
    ]);

    return { accepted: true as const, nextNonce, seq };
  }

  // Registra un intento rechazado como evidencia inmutable + flag, sin avanzar el nonce.
  private async recordRejected(
    sessionId: string,
    nonceUsed: string,
    type: 'SIGNATURE_INVALID' | 'NONCE_REUSE',
    bytes: Buffer,
  ): Promise<void> {
    try {
      await this.prisma.snapshot.create({
        data: {
          sessionId,
          seq: -1,
          clientTimestamp: new Date(),
          signals: {},
          signedPayload: bytes,
          signatureValid: false,
          nonceUsed,
          integrityVerdict: 'UNKNOWN',
          flags: { create: [{ sessionId, type, severity: 'HIGH' }] },
        },
      });
    } catch {
      // Si choca con un @@unique (replay), el rechazo ya quedó registrado; no relanzar.
    }
  }

  private parsePayload(bytes: Buffer): SnapshotPayload {
    try {
      return JSON.parse(bytes.toString('utf8')) as SnapshotPayload;
    } catch {
      throw new BadRequestException({
        message: 'Payload no es JSON válido',
        code: 'BAD_PAYLOAD',
      });
    }
  }
}
