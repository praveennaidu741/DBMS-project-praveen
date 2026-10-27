// ==============================================================================
// AssetVault: AI Security Testing Agent Test Suite
// Course: BCSE307L Database Systems (Fall 2026-27)
// ==============================================================================

import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../app';
import { systemPrisma } from '../config/prisma';

describe('AI Security Testing Agent API Suite', () => {
  let adminToken: string;
  let memberToken: string;

  beforeAll(async () => {
    const adminLogin = await request(app)
      .post('/api/auth/login')
      .send({ email: 'techcorp.admin@techcorp.io', password: 'Password123!' });
    expect(adminLogin.status).toBe(200);
    adminToken = adminLogin.body.data.accessToken;

    const memberLogin = await request(app)
      .post('/api/auth/login')
      .send({ email: 'techcorp.dev1@techcorp.io', password: 'Password123!' });
    expect(memberLogin.status).toBe(200);
    memberToken = memberLogin.body.data.accessToken;
  });

  it('blocks non-admin members from accessing AI Security Testing routes -> 403 Forbidden', async () => {
    const res = await request(app)
      .post('/api/admin/security-tests')
      .set('Authorization', `Bearer ${memberToken}`)
      .send({ categories: ['TENANT_ISOLATION'] });

    expect(res.status).toBe(403);
  });

  it('allows tenant admins to trigger and retrieve security test runs', async () => {
    const triggerRes = await request(app)
      .post('/api/admin/security-tests')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ categories: ['TENANT_ISOLATION', 'AUTH_RBAC'] });

    expect(triggerRes.status).toBe(201);
    expect(triggerRes.body.success).toBe(true);
    const runId = triggerRes.body.data.id;
    expect(runId).toBeDefined();

    // Retrieve run details
    const getRes = await request(app)
      .get(`/api/admin/security-tests/${runId}`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(getRes.status).toBe(200);
    expect(getRes.body.data.id).toBe(runId);
  });
});
