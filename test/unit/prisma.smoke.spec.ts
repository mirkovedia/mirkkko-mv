import { PrismaService } from '../../src/prisma/prisma.service';

describe('Prisma smoke', () => {
  const prisma = new PrismaService();
  beforeAll(async () => prisma.$connect());
  afterAll(async () => prisma.$disconnect());

  it('crea y lee un Device', async () => {
    const device = await prisma.device.create({
      data: {
        publicKey: 'k',
        publicKeyFp: `fp-${Date.now()}`,
        platform: 'ANDROID',
      },
    });
    const found = await prisma.device.findUnique({ where: { id: device.id } });
    expect(found?.platform).toBe('ANDROID');
    await prisma.device.delete({ where: { id: device.id } });
  });
});
