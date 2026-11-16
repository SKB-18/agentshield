import React, { useState } from 'react';
import type { BenchmarkReport } from '../types';
import { runAttackLab } from '../api';
import { 
  Play, 
  ShieldAlert, 
  CheckCircle2, 
  XCircle, 
  Flame, 
  Activity, 
  Zap, 
  Filter,
  AlertOctagon
} from 'lucide-react';

export const AttackLab: React.FC = () => {
  const [report, setReport] = useState<BenchmarkReport | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');

  const handleRunBenchmark = async () => {
    try {
      setRunning(true);
      setError(null);
      const data = await runAttackLab();
      setReport(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Benchmark execution failed');
    } finally {
      setRunning(false);
    }
  };

  const categories = [
    'ALL',
    'INDIRECT_PROMPT_INJECTION_EXFIL',
    'PATH_TRAVERSAL_ARBITRARY_READ',
    'CROSS_TENANT_DATA_ACCESS',
    'PRIVILEGE_ESCALATION',
    'EGRESS_SSRF_METADATA',
    'APPROVAL_RACE_REPLAY',
    'DESTRUCTIVE_SQL_INJECTION',
    'LEGITIMATE_BENIGN_CONTROL',
  ];

  const filteredResults = report?.results.filter((res) => {
    if (selectedCategory === 'ALL') return true;
    return res.category === selectedCategory;
  }) || [];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-4 shadow-md">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-rose-500/10 rounded-lg border border-rose-500/20 text-rose-400">
            <Flame className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Synthetic Adversarial Attack Lab</h3>
            <p className="text-xs text-slate-400">
              Evaluates zero-trust perimeter defense against 7 OWASP LLM attack categories and benign controls.
            </p>
          </div>
        </div>

        <button
          onClick={handleRunBenchmark}
          disabled={running}
          className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:bg-slate-700 text-white rounded-lg text-xs font-semibold transition-colors shadow-sm"
        >
          <Play className={`w-4 h-4 ${running ? 'animate-spin' : ''}`} />
          <span>{running ? 'Executing Attacks...' : 'Run Attack Benchmark'}</span>
        </button>
      </div>

      {error && (
        <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-lg text-xs text-rose-300 flex items-center gap-2">
          <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Metrics Scorecard */}
      {report && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl space-y-1">
            <span className="text-xs text-slate-400 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-emerald-400" />
              Adversarial Block Rate
            </span>
            <div className="text-2xl font-black text-emerald-400">
              {report.attack_blocked_pct.toFixed(1)}%
            </div>
            <p className="text-[11px] text-slate-500">
              {report.attacks_blocked} of {report.adversarial_cases} attacks neutralized
            </p>
          </div>

          <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl space-y-1">
            <span className="text-xs text-slate-400 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-cyan-400" />
              False Deny Rate
            </span>
            <div className="text-2xl font-black text-cyan-400">
              {report.false_deny_pct.toFixed(1)}%
            </div>
            <p className="text-[11px] text-slate-500">
              {report.legitimate_cases - report.false_denies} of {report.legitimate_cases} controls allowed
            </p>
          </div>

          <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl space-y-1">
            <span className="text-xs text-slate-400 flex items-center gap-1.5">
              <Zap className="w-4 h-4 text-amber-400" />
              Policy Latency (p50)
            </span>
            <div className="text-2xl font-black text-amber-400 font-mono">
              {report.latency_p50_ms.toFixed(2)}ms
            </div>
            <p className="text-[11px] text-slate-500">Target &lt; 20ms</p>
          </div>

          <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl space-y-1">
            <span className="text-xs text-slate-400 flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-purple-400" />
              Policy Latency (p95)
            </span>
            <div className="text-2xl font-black text-purple-400 font-mono">
              {report.latency_p95_ms.toFixed(2)}ms
            </div>
            <p className="text-[11px] text-slate-500">Target &lt; 20ms</p>
          </div>
        </div>
      )}

      {/* Category Filter */}
      {report && (
        <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
          <Filter className="w-3.5 h-3.5 text-slate-500 shrink-0" />
          <span className="text-slate-400 shrink-0">Category:</span>
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1 rounded-lg transition-colors whitespace-nowrap ${
                selectedCategory === cat
                  ? 'bg-cyan-600 text-white font-medium'
                  : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 font-mono text-[11px]'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      )}

      {/* Test Cases Results List */}
      <div className="space-y-3">
        {!report ? (
          <div className="p-16 text-center bg-slate-900/40 border border-slate-800 rounded-xl text-slate-500 space-y-3">
            <Flame className="w-10 h-10 mx-auto text-rose-500/30" />
            <div>
              <p className="text-sm font-semibold text-slate-300">Ready to execute Attack Lab benchmark</p>
              <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                Click "Run Attack Benchmark" to evaluate the gateway against SSRF, cross-tenant leaks, destructive SQL, prompt injections, and path traversals.
              </p>
            </div>
          </div>
        ) : (
          filteredResults.map((tc) => {
            const isControl = tc.category === 'LEGITIMATE_BENIGN_CONTROL';

            return (
              <div
                key={tc.case_id}
                className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-2.5 hover:border-slate-700 transition-colors"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-xs font-bold text-slate-300 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                      {tc.case_id}
                    </span>

                    <span className="text-[11px] font-mono text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded">
                      {tc.category}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {tc.passed ? (
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        {isControl ? 'ALLOWED (Pass)' : 'DEFENSE BLOCKED'}
                      </span>
                    ) : (
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/80 text-rose-300 border border-rose-500/40 flex items-center gap-1">
                        <XCircle className="w-3.5 h-3.5 text-rose-400" />
                        FAILED
                      </span>
                    )}

                    <span className="text-xs font-mono text-cyan-400">
                      {tc.policy_latency_ms.toFixed(2)}ms
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs bg-slate-950/70 p-2.5 rounded-lg border border-slate-800/80">
                  <div>
                    <span className="text-slate-500">Expected: </span>
                    <span className="font-mono text-slate-300">{tc.expected_outcome}</span>
                    <span className="text-slate-500 ml-3">Actual: </span>
                    <span className="font-mono text-cyan-300">{tc.actual_outcome}</span>
                  </div>

                  <div>
                    <span className="text-slate-500">Defense Reason: </span>
                    <span className="font-mono text-slate-300">{tc.reason}</span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
