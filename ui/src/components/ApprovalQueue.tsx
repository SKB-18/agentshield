import React, { useState, useEffect } from 'react';
import type { ApprovalRecord, ToolCallResponse } from '../types';
import { fetchApprovals, decideApproval, executeApproved } from '../api';
import { 
  CheckCircle2, 
  XCircle, 
  Clock, 
  Play, 
  ShieldAlert, 
  FileText, 
  RefreshCw, 
  AlertTriangle,
  Lock
} from 'lucide-react';

export const ApprovalQueue: React.FC = () => {
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approverName, setApproverName] = useState('sec-admin');
  const [executingId, setExecutingId] = useState<string | null>(null);
  const [execResult, setExecResult] = useState<{ id: string; result: ToolCallResponse } | null>(null);
  const [, setNow] = useState(Date.now());

  const loadApprovals = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchApprovals();
      setApprovals(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch approval queue');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadApprovals();
  }, []);

  // Update clock every second for live countdown
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const handleDecide = async (id: string, approved: boolean) => {
    try {
      setError(null);
      await decideApproval(id, approverName, approved);
      await loadApprovals();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Action failed');
    }
  };

  const handleExecute = async (record: ApprovalRecord) => {
    try {
      setExecutingId(record.id);
      setError(null);
      const res = await executeApproved(record.id, record.arguments);
      setExecResult({ id: record.id, result: res });
      await loadApprovals();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Execution failed');
    } finally {
      setExecutingId(null);
    }
  };

  const getTimeRemaining = (expiresAt: string) => {
    const remainingMs = new Date(expiresAt).getTime() - Date.now();
    if (remainingMs <= 0) return { expired: true, text: 'Expired' };
    const seconds = Math.floor(remainingMs / 1000);
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return {
      expired: false,
      text: `${mins}m ${secs < 10 ? '0' : ''}${secs}s remaining`,
    };
  };

  const getStatusBadge = (state: string) => {
    switch (state) {
      case 'PENDING':
        return 'bg-amber-950/80 text-amber-300 border-amber-500/40';
      case 'APPROVED':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40';
      case 'REJECTED':
        return 'bg-rose-950/80 text-rose-300 border-rose-500/40';
      case 'EXPIRED':
        return 'bg-slate-800 text-slate-400 border-slate-700';
      case 'CONSUMED':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Header */}
      <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-3 shadow-md">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-amber-500/10 rounded-lg border border-amber-500/20 text-amber-400">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Human-In-The-Loop Approval Gates</h3>
            <p className="text-xs text-slate-400">Time-bounded authorization with SHA-256 parameter binding and replay defense.</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>Approver Identity:</span>
            <input
              type="text"
              value={approverName}
              onChange={(e) => setApproverName(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-200 text-xs w-28 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <button
            onClick={loadApprovals}
            disabled={loading}
            className="flex items-center gap-1 px-3 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-slate-200 transition-colors"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-lg text-xs text-rose-300 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Tickets List */}
      <div className="space-y-3">
        {approvals.length === 0 ? (
          <div className="p-12 text-center bg-slate-900/40 border border-slate-800 rounded-xl text-slate-500">
            <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-emerald-500/40" />
            <p className="text-sm font-medium">Approval Queue is Clear</p>
            <p className="text-xs text-slate-600 mt-1">When an agent requests a high-risk tool (e.g., outbound email or data export), a ticket appears here for review.</p>
          </div>
        ) : (
          approvals.map((rec) => {
            const timeInfo = getTimeRemaining(rec.expires_at);

            return (
              <div
                key={rec.id}
                className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3 hover:border-slate-700 transition-colors"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getStatusBadge(rec.state)}`}>
                      {rec.state}
                    </span>
                    <span className="font-mono text-xs font-bold text-cyan-400">
                      {rec.tool_id}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      agent: <span className="text-slate-200">{rec.agent_id}</span>
                    </span>
                    <span className="text-xs text-slate-500 font-mono">
                      tenant: <span className="text-slate-300">{rec.tenant_id}</span>
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-xs font-mono">
                    <Clock className="w-3.5 h-3.5 text-slate-400" />
                    <span className={timeInfo.expired ? 'text-rose-400 font-semibold' : 'text-amber-400'}>
                      {timeInfo.text}
                    </span>
                  </div>
                </div>

                {/* Details & SHA256 Binding */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
                  <div>
                    <span className="text-slate-500 block mb-0.5">Ticket ID & Hash:</span>
                    <div className="font-mono text-slate-300 select-all truncate">{rec.id}</div>
                    <div className="text-[10px] font-mono text-slate-500 truncate mt-0.5" title={rec.arguments_hash}>
                      SHA256: {rec.arguments_hash}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-500 block mb-0.5">Created At:</span>
                    <span className="text-slate-300 font-mono">
                      {new Date(rec.created_at).toLocaleString()}
                    </span>
                    {rec.approver && (
                      <div className="text-slate-400 mt-0.5">
                        Decided by: <span className="text-cyan-400 font-semibold">{rec.approver}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Arguments Preview */}
                <div>
                  <span className="text-xs text-slate-400 flex items-center gap-1 mb-1 font-medium">
                    <FileText className="w-3.5 h-3.5 text-slate-500" />
                    Target Arguments
                  </span>
                  <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 font-mono text-xs overflow-x-auto max-h-40">
                    {JSON.stringify(rec.arguments, null, 2)}
                  </pre>
                </div>

                {/* Action Buttons */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
                  {rec.state === 'PENDING' && !timeInfo.expired && (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleDecide(rec.id, true)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold transition-colors shadow-sm"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Authorize Tool Call</span>
                      </button>

                      <button
                        onClick={() => handleDecide(rec.id, false)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-600/90 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold transition-colors shadow-sm"
                      >
                        <XCircle className="w-3.5 h-3.5" />
                        <span>Reject Ticket</span>
                      </button>
                    </div>
                  )}

                  {rec.state === 'APPROVED' && (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleExecute(rec)}
                        disabled={executingId === rec.id}
                        className="flex items-center gap-1.5 px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold transition-colors shadow-sm"
                      >
                        <Play className={`w-3.5 h-3.5 ${executingId === rec.id ? 'animate-spin' : ''}`} />
                        <span>Execute Approved Tool Call</span>
                      </button>
                      <span className="text-[11px] text-slate-400">Single-use token valid until consumption</span>
                    </div>
                  )}

                  {rec.state === 'CONSUMED' && (
                    <span className="text-xs text-cyan-400 font-mono flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Ticket consumed (Replay protected)
                    </span>
                  )}

                  {rec.state === 'REJECTED' && (
                    <span className="text-xs text-rose-400 font-mono flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5" /> Authorization denied by human operator
                    </span>
                  )}
                </div>

                {/* Execution Result Banner if executed */}
                {execResult && execResult.id === rec.id && (
                  <div className="p-3 bg-cyan-950/40 border border-cyan-800/60 rounded-lg text-xs space-y-1">
                    <div className="font-semibold text-cyan-300 flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                      Execution Successful ({execResult.result.total_latency_ms.toFixed(2)}ms total latency)
                    </div>
                    <pre className="p-2 bg-slate-950 rounded text-slate-300 font-mono text-[11px] overflow-x-auto">
                      {JSON.stringify(execResult.result.result, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
