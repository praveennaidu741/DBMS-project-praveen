// ==============================================================================
// AssetVault: AI Security Testing Center Dashboard Page
// Course: BCSE307L Database Systems (Fall 2026-27)
// Allows administrators to execute automated security regression test suites,
// inspect findings, and review AI security audits.
// ==============================================================================

import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Play,
  RotateCcw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronRight,
  ShieldAlert,
  Lock,
  Cpu,
  FileText,
  Sparkles,
} from 'lucide-react';
import { api } from '../../services/api';
import { useToast } from '../../context/ToastContext';

export interface SecurityFinding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: 'TENANT_ISOLATION' | 'AUTH_RBAC' | 'DATABASE_SECURITY' | 'AI_SECURITY' | 'REGRESSION';
  affectedComponent: string;
  evidence: string;
  expectedVsActual: string;
  reproductionSteps: string;
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';
  remediation: string;
  status: 'OPEN' | 'VERIFIED_SECURE' | 'MITIGATED';
}

export interface SecurityTestRun {
  id: string;
  triggeredBy: string;
  triggeredAt: string;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED';
  summary: {
    total: number;
    passed: number;
    failed: number;
    skipped: number;
    errored: number;
  };
  findings: SecurityFinding[];
}

export const AiSecurityTestingPage: React.FC = () => {
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const [currentRun, setCurrentRun] = useState<SecurityTestRun | null>(null);
  const [history, setHistory] = useState<SecurityTestRun[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);

  const fetchHistory = async () => {
    try {
      const res = await api.get('/admin/security-tests/history');
      if (res.data && res.data.success) {
        setHistory(res.data.data);
        if (res.data.data.length > 0 && !currentRun) {
          setCurrentRun(res.data.data[0]);
        }
      }
    } catch (err: any) {
      console.error('Failed to load security test history:', err);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleStartRun = async () => {
    setLoading(true);
    try {
      const res = await api.post('/admin/security-tests', {
        categories: ['TENANT_ISOLATION', 'AUTH_RBAC', 'DATABASE_SECURITY', 'AI_SECURITY', 'REGRESSION'],
      });
      if (res.data && res.data.success) {
        setCurrentRun(res.data.data);
        toast.success('AI Security Test Suite initiated successfully.');
        // Poll for completion
        setTimeout(fetchHistory, 2500);
      }
    } catch (err: any) {
      toast.error(err.response?.data?.message || 'Failed to start security test run.');
    } finally {
      setLoading(false);
    }
  };

  const filteredFindings = currentRun?.findings.filter((f) => {
    if (selectedCategory === 'ALL') return true;
    return f.category === selectedCategory;
  }) || [];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 rounded-2xl p-6 text-white shadow-xl border border-indigo-500/20 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-2 text-indigo-400 font-medium text-sm mb-1">
            <ShieldCheck className="w-4 h-4" /> AssetVault Autonomous Security Agent
          </div>
          <h1 className="text-2xl font-bold">AI Security Testing Center</h1>
          <p className="text-slate-300 text-sm mt-1 max-w-2xl">
            Execute automated security regression test suites, inspect multi-tenant RLS isolation, validate RBAC privileges, and review Gemini-powered vulnerability assessments.
          </p>
        </div>
        <button
          onClick={handleStartRun}
          disabled={loading || currentRun?.status === 'RUNNING'}
          className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white px-5 py-2.5 rounded-xl font-medium shadow-lg shadow-indigo-600/30 transition-all disabled:opacity-50 cursor-pointer"
        >
          {loading || currentRun?.status === 'RUNNING' ? (
            <>
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              Running Test Suite...
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-white" />
              Run Security Test Suite
            </>
          )}
        </button>
      </div>

      {/* Summary Cards */}
      {currentRun && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
            <div className="text-slate-500 text-xs font-medium uppercase tracking-wider">Total Tests</div>
            <div className="text-2xl font-bold mt-1 text-slate-800 dark:text-slate-100">{currentRun.summary.total}</div>
          </div>
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-emerald-500/30 shadow-sm">
            <div className="text-emerald-600 dark:text-emerald-400 text-xs font-medium uppercase tracking-wider flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Passed
            </div>
            <div className="text-2xl font-bold mt-1 text-emerald-600 dark:text-emerald-400">{currentRun.summary.passed}</div>
          </div>
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-rose-500/30 shadow-sm">
            <div className="text-rose-600 dark:text-rose-400 text-xs font-medium uppercase tracking-wider flex items-center gap-1">
              <XCircle className="w-3.5 h-3.5" /> Failed / Findings
            </div>
            <div className="text-2xl font-bold mt-1 text-rose-600 dark:text-rose-400">{currentRun.summary.failed}</div>
          </div>
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
            <div className="text-slate-500 text-xs font-medium uppercase tracking-wider flex items-center gap-1">
              <Clock className="w-3.5 h-3.5" /> Execution Status
            </div>
            <div className="text-lg font-semibold mt-1 text-indigo-600 dark:text-indigo-400">{currentRun.status}</div>
          </div>
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-center">
            <div className="text-slate-500 text-xs font-medium uppercase tracking-wider">Run ID</div>
            <div className="text-xs font-mono mt-1 text-slate-600 dark:text-slate-400 truncate">{currentRun.id}</div>
          </div>
        </div>
      )}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Findings Table */}
        <div className="lg:col-span-2 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden flex flex-col">
          <div className="p-5 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
            <h2 className="text-lg font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-indigo-500" /> Security Findings & Vulnerabilities
            </h2>
            <div className="flex items-center gap-2 text-sm">
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                className="bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-1.5 text-slate-700 dark:text-slate-300 text-xs"
              >
                <option value="ALL">All Categories</option>
                <option value="TENANT_ISOLATION">Tenant Isolation</option>
                <option value="AUTH_RBAC">Auth & RBAC</option>
                <option value="DATABASE_SECURITY">Database Security</option>
                <option value="AI_SECURITY">AI Security</option>
              </select>
            </div>
          </div>

          <div className="divide-y divide-slate-200 dark:divide-slate-800 overflow-y-auto max-h-[500px]">
            {filteredFindings.length === 0 ? (
              <div className="p-12 text-center text-slate-500 dark:text-slate-400">
                <ShieldCheck className="w-12 h-12 mx-auto text-emerald-500 mb-3 opacity-80" />
                <p className="font-medium text-slate-700 dark:text-slate-300">No security findings recorded for this run.</p>
                <p className="text-xs mt-1">All multi-tenant isolation, RBAC, and database integrity checks passed successfully.</p>
              </div>
            ) : (
              filteredFindings.map((finding) => (
                <div
                  key={finding.id}
                  onClick={() => setSelectedFinding(finding)}
                  className="p-4 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer flex items-center justify-between gap-4"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide ${
                          finding.severity === 'CRITICAL'
                            ? 'bg-rose-100 text-rose-700 dark:bg-rose-950/50 dark:text-rose-400'
                            : finding.severity === 'HIGH'
                            ? 'bg-amber-100 text-amber-700 dark:bg-amber-950/50 dark:text-amber-400'
                            : 'bg-indigo-100 text-indigo-700 dark:bg-indigo-950/50 dark:text-indigo-400'
                        }`}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-xs font-mono text-slate-400">{finding.category}</span>
                    </div>
                    <h3 className="font-semibold text-slate-800 dark:text-slate-200 text-sm">{finding.title}</h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400 truncate max-w-md">{finding.affectedComponent}</p>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-400 flex-shrink-0" />
                </div>
              ))
            )}
          </div>
        </div>

        {/* Finding Detail / Remediation Drawer */}
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm p-5 flex flex-col justify-between">
          {selectedFinding ? (
            <div className="space-y-4">
              <div className="flex justify-between items-start">
                <span className="text-xs font-mono text-indigo-500 font-semibold">{selectedFinding.id}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide bg-rose-100 text-rose-700 dark:bg-rose-950 dark:text-rose-400">
                  {selectedFinding.severity}
                </span>
              </div>
              <h3 className="font-bold text-slate-900 dark:text-slate-100 text-base">{selectedFinding.title}</h3>

              <div className="space-y-3 text-xs text-slate-600 dark:text-slate-300">
                <div>
                  <span className="font-semibold text-slate-700 dark:text-slate-200">Affected Component:</span>
                  <p className="mt-0.5 font-mono bg-slate-100 dark:bg-slate-800 p-1.5 rounded">{selectedFinding.affectedComponent}</p>
                </div>
                <div>
                  <span className="font-semibold text-slate-700 dark:text-slate-200">Evidence:</span>
                  <p className="mt-0.5 bg-slate-100 dark:bg-slate-800 p-1.5 rounded font-mono text-[11px] text-rose-600 dark:text-rose-400">{selectedFinding.evidence}</p>
                </div>
                <div>
                  <span className="font-semibold text-slate-700 dark:text-slate-200">Remediation Recommendation:</span>
                  <p className="mt-0.5 bg-indigo-50 dark:bg-indigo-950/30 border border-indigo-500/20 p-2 rounded text-indigo-900 dark:text-indigo-200">{selectedFinding.remediation}</p>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center py-20 text-slate-400">
              <FileText className="w-10 h-10 mx-auto mb-2 opacity-50" />
              <p className="text-sm">Select a finding to view remediation guidance and evidence.</p>
            </div>
          )}

          <div className="border-t border-slate-200 dark:border-slate-800 pt-4 mt-6">
            <div className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-2">Previous Runs History</div>
            <div className="space-y-2 max-h-36 overflow-y-auto">
              {history.map((run) => (
                <div
                  key={run.id}
                  onClick={() => setCurrentRun(run)}
                  className={`p-2 rounded-lg text-xs flex justify-between items-center cursor-pointer transition-colors ${
                    currentRun?.id === run.id
                      ? 'bg-indigo-50 dark:bg-indigo-950/50 border border-indigo-500/30 text-indigo-900 dark:text-indigo-200'
                      : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-400'
                  }`}
                >
                  <span className="font-mono">{run.id}</span>
                  <span className="flex items-center gap-1">
                    {run.summary.failed === 0 ? <CheckCircle2 className="w-3 h-3 text-emerald-500" /> : <AlertTriangle className="w-3 h-3 text-amber-500" />}
                    {run.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
export default AiSecurityTestingPage;
