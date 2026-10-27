// ==============================================================================
// AssetVault: AI Security Testing Center API Controller
// Course: BCSE307L Database Systems (Fall 2026-27)
// ==============================================================================

import { Request, Response } from 'express';
import { AiSecurityTestingService } from '../services/aiSecurityAgent.service';
import { asyncHandler } from '../utils/asyncHandler';
import { AppError } from '../errors/AppError';

const testingService = new AiSecurityTestingService();

export const startSecurityTestRun = asyncHandler(async (req: Request, res: Response) => {
  const user = (req as any).user;
  if (!user || (user.role !== 'SUPER_ADMIN' && user.role !== 'TENANT_ADMIN')) {
    throw new AppError('Forbidden: Administrator access required to execute security tests.', 403);
  }

  const { categories = [] } = req.body;
  const runRecord = await testingService.runSecurityTestSuite(user.id, categories);

  return res.status(201).json({
    success: true,
    message: 'AI Security Testing Suite execution initiated successfully.',
    data: runRecord,
  });
});

export const getSecurityTestRun = asyncHandler(async (req: Request, res: Response) => {
  const user = (req as any).user;
  if (!user || (user.role !== 'SUPER_ADMIN' && user.role !== 'TENANT_ADMIN')) {
    throw new AppError('Forbidden: Administrator access required.', 403);
  }

  const { id } = req.params;
  const run = testingService.getTestRun(id);
  if (!run) {
    throw new AppError(`Security test run ${id} not found`, 404);
  }

  return res.status(200).json({
    success: true,
    data: run,
  });
});

export const getSecurityTestFindings = asyncHandler(async (req: Request, res: Response) => {
  const user = (req as any).user;
  if (!user || (user.role !== 'SUPER_ADMIN' && user.role !== 'TENANT_ADMIN')) {
    throw new AppError('Forbidden: Administrator access required.', 403);
  }

  const { id } = req.params;
  const run = testingService.getTestRun(id);
  if (!run) {
    throw new AppError(`Security test run ${id} not found`, 404);
  }

  return res.status(200).json({
    success: true,
    data: run.findings,
  });
});

export const listSecurityTestHistory = asyncHandler(async (_req: Request, res: Response) => {
  const history = testingService.listTestHistory();
  return res.status(200).json({
    success: true,
    data: history,
  });
});
