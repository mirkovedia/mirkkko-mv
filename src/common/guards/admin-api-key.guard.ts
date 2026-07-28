import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import type { Env } from '../../config/env.schema';

@Injectable()
export class AdminApiKeyGuard implements CanActivate {
  constructor(private readonly config: ConfigService<Env, true>) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const provided = req.header('x-api-key');
    const expected = this.config.get('ADMIN_API_KEY', { infer: true });
    if (!provided || provided !== expected) {
      throw new UnauthorizedException({
        message: 'API key inválida',
        code: 'UNAUTHORIZED',
      });
    }
    return true;
  }
}
