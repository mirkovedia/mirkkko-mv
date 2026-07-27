import { Test } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../../src/app.module';

describe('Health (e2e)', () => {
  let app: INestApplication;
  beforeAll(async () => {
    process.env.DATABASE_URL = 'postgresql://u:p@localhost:5432/test';
    process.env.ADMIN_API_KEY = 'x'.repeat(32);
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    await app.init();
  });
  afterAll(async () => app.close());

  it('GET /health → 200 { status: OK }', async () => {
    const res = await request(app.getHttpServer()).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('OK');
  });
});
