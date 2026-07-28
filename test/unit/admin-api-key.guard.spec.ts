import { UnauthorizedException, ExecutionContext } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AdminApiKeyGuard } from '../../src/common/guards/admin-api-key.guard';

const ctx = (apiKey?: string) =>
  ({
    switchToHttp: () => ({
      getRequest: () => ({ header: (_: string) => apiKey }),
    }),
  }) as unknown as ExecutionContext;
const cfg = { get: () => 'k'.repeat(32) } as unknown as ConfigService;

describe('AdminApiKeyGuard', () => {
  const guard = new AdminApiKeyGuard(cfg);
  it('permite con la key correcta', () => {
    expect(guard.canActivate(ctx('k'.repeat(32)))).toBe(true);
  });
  it('rechaza sin key', () => {
    expect(() => guard.canActivate(ctx(undefined))).toThrow(
      UnauthorizedException,
    );
  });
  it('rechaza con key equivocada', () => {
    expect(() => guard.canActivate(ctx('mala'))).toThrow(UnauthorizedException);
  });
});
