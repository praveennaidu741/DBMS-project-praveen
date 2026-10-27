// ==============================================================================
// AssetVault: AI Tenant-Isolation Hardened Snapshot Service
// Course: BCSE307L Database Systems (Fall 2026-27)
// Fixes Phase 2 requirements: strictly enforces tenantId scoping without cross-tenant
// mock fallbacks, failing closed if tenant identity cannot be verified.
// ==============================================================================

import { TenantSnapshot } from './ai.service';
import { mockStore } from '../config/mockStore';

export async function getStrictTenantSnapshot(
  prismaClient: any,
  tenantId?: string | null,
  isSuperAdmin?: boolean
): Promise<TenantSnapshot> {
  if (!tenantId && !isSuperAdmin) {
    throw new Error('Security Error: Tenant ID is required for AI data snapshots.');
  }

  let assets: any[] = [];
  let licenses: any[] = [];
  let allocations: any[] = [];
  let vendors: any[] = [];
  let users: any[] = [];

  try {
    const whereClause = isSuperAdmin && !tenantId ? {} : { tenantId: tenantId! };

    [assets, licenses, allocations, vendors, users] = await Promise.all([
      prismaClient.asset.findMany({ where: whereClause, take: 50 }),
      prismaClient.license.findMany({ where: whereClause, take: 50 }),
      prismaClient.allocation
        ? prismaClient.allocation.findMany({ where: whereClause, take: 100 })
        : prismaClient.licenseAllocation
        ? prismaClient.licenseAllocation.findMany({ where: whereClause, take: 100 })
        : Promise.resolve([]),
      prismaClient.vendor.findMany({ where: whereClause, take: 50 }),
      prismaClient.user
        ? prismaClient.user.findMany({ where: whereClause, take: 100 })
        : Promise.resolve([]),
    ]);
  } catch (err) {
    // If DB fails, fallback ONLY to exact tenant-scoped mock rows if tenantId is provided
    if (tenantId) {
      assets = mockStore.state.assets.filter((a) => a.tenantId === tenantId);
      licenses = mockStore.state.licenses.filter((l) => l.tenantId === tenantId);
      allocations = mockStore.state.allocations.filter((al) => al.tenantId === tenantId);
      vendors = mockStore.state.vendors.filter((v) => v.tenantId === tenantId);
      users = mockStore.state.users.filter((u) => u.tenantId === tenantId);
    } else if (isSuperAdmin) {
      assets = mockStore.state.assets;
      licenses = mockStore.state.licenses;
      allocations = mockStore.state.allocations;
      vendors = mockStore.state.vendors;
      users = mockStore.state.users;
    } else {
      throw new Error('Security Error: Unable to retrieve tenant snapshot securely.');
    }
  }

  const totalSeats = licenses.reduce((acc, l) => acc + Number(l.totalSeats || 0), 0);
  const allocatedSeats = licenses.reduce((acc, l) => {
    const activeForLicense = allocations.filter(
      (al) => al.licenseId === l.id && !al.revokedAt && !al.releasedAt
    ).length;
    const recorded = Number(l.allocatedSeats ?? l.usedSeats ?? 0);
    return acc + Math.max(recorded, activeForLicense);
  }, 0);
  const unallocatedSeats = Math.max(0, totalSeats - allocatedSeats);
  const utilizationPct = totalSeats > 0 ? Math.round((allocatedSeats / totalSeats) * 100) : 0;
  const totalAnnualSpend = licenses.reduce((acc, l) => acc + Number(l.cost || 0), 0);

  return {
    tenantId: tenantId || 'super-admin-global',
    assetsCount: assets.length,
    licensesCount: licenses.length,
    usersCount: users.length,
    totalSeats,
    allocatedSeats,
    unallocatedSeats,
    utilizationPct,
    totalAnnualSpend,
    assets,
    licenses,
    allocations,
    vendors,
    users,
  };
}
