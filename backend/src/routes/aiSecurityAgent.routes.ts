// ==============================================================================
// AssetVault: AI Security Testing Center API Routes
// Course: BCSE307L Database Systems (Fall 2026-27)
// ==============================================================================

import { Router } from 'express';
import {
  startSecurityTestRun,
  getSecurityTestRun,
  getSecurityTestFindings,
  listSecurityTestHistory,
} from '../controllers/aiSecurityAgent.controller';
import { authenticate } from '../middleware/auth.middleware';
import { authorize } from '../middleware/authorize.middleware';

const router = Router();

// All security test routes require authentication and admin privileges
router.use(authenticate);
router.use(authorize(['SUPER_ADMIN', 'TENANT_ADMIN']));

router.post('/', startSecurityTestRun);
router.get('/history', listSecurityTestHistory);
router.get('/:id', getSecurityTestRun);
router.get('/:id/findings', getSecurityTestFindings);

export default router;
