import React, { useState, useEffect } from 'react';
import type { PolicyDecision, PolicyEvalRequest } from '../types';
import { fetchPolicyCode, testPolicy } from '../api';
import { 
  Code2, 
  Play, 
  ShieldCheck, 
  ShieldAlert, 
  Clock, 
  CheckCircle, 
  AlertCircle,
  FileCode,
  Sliders
} from 'lucide-react';

export const PolicyInspector: React.FC = () => {
  const [regoCode, setRegoCode] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Simulator Inputs
  const [simRole, setSimRole] = useState<'reader' | 'analyst' | 'admin'>('reader');
  const [simTenant, setSimTenant] = useState('tenant-alpha');
  const [simTool, setSimTool] = useState('search_docs');
  const [simDestination, setSimDestination] = useState('');
  const [simArgsJson, setSimArgsJson] = useState('{\n  "query": "security architecture",\n  "dataset_id": "kb-public"\n}');
  const [simDecision, setSimDecision] = useState<PolicyDecision | null>(null);

  useEffect(() => {
    const loadCode = async () => {
      try {
        setLoading(true);
        const data = await fetchPolicyCode();
        setRegoCode(data.rego);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Failed to load policy code');
      } finally {
        setLoading(false);
      }
    };
    loadCode();
  }, []);

  const handleSimulate = async () => {
    try {
      setEvaluating(true);
      setError(null);
      let parsedArgs: Record<string, unknown> = {};
      try {
        parsedArgs = JSON.parse(simArgsJson);
      } catch {
        throw new Error('Arguments must be valid JSON');
      }

      const input: PolicyEvalRequest = {
        agent_id: 'sim-agent-01',
        tenant_id: simTenant,
        role: simRole,
        scopes: ['tools:read', 'tools:execute'],
        tool_id: simTool,
        tool_risk: simTool === 'search_docs' ? 'low' : simTool === 'read_file' ? 'medium' : simTool === 'query_db' ? 'medium' : 'high',
        destination: simDestination || undefined,
        arguments: parsedArgs,
      };

      const decision = await testPolicy(input);
      setSimDecision(decision);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Evaluation error');
    } finally {
      setEvaluating(false);
    }
  };

  const getPreset = (name: string) => {
    switch (name) {
      case 'reader_search':
        setSimRole('reader');
        setSimTenant('tenant-alpha');
        setSimTool('search_docs');
        setSimDestination('');
        setSimArgsJson('{\n  "query": "architecture doc",\n  "dataset_id": "kb-public"\n}');
        break;
      case 'cross_tenant_attack':
        setSimRole('reader');
        setSimTenant('tenant-alpha');
        setSimTool('search_docs');
        setSimDestination('');
        setSimArgsJson('{\n  "query": "customer financial data",\n  "dataset_id": "kb-tenant-beta"\n}');
        break;
      case 'analyst_high_risk':
        setSimRole('analyst');
        setSimTenant('tenant-alpha');
        setSimTool('send_email');
        setSimDestination('company.internal');
        setSimArgsJson('{\n  "to": "officer@company.internal",\n  "subject": "Compliance Report"\n}');
        break;
      case 'unauthorized_egress':
        setSimRole('analyst');
        setSimTenant('tenant-alpha');
        setSimTool('send_email');
        setSimDestination('evil-exfiltrator.com');
        setSimArgsJson('{\n  "to": "exfil@evil-exfiltrator.com",\n  "subject": "Stolen credentials"\n}');
        break;
      default:
        break;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 flex items-center justify-between gap-3 shadow-md">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/10 rounded-lg border border-cyan-500/20 text-cyan-400">
            <FileCode className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Open Policy Agent (OPA) In-Process Rego Engine</h3>
            <p className="text-xs text-slate-400">Decoupled authorization policies evaluated sub-millisecond with zero external network hops.</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-1 rounded border border-emerald-500/30">
            Engine: Embedded OPA v1.0.0
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Interactive Policy Simulator */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                Live Dry-Run Policy Simulator
              </span>
              <div className="flex items-center gap-1.5 text-xs text-slate-400">
                <span>Presets:</span>
                <button onClick={() => getPreset('reader_search')} className="text-cyan-400 hover:underline">Allowed</button>
                <span>|</span>
                <button onClick={() => getPreset('cross_tenant_attack')} className="text-rose-400 hover:underline">Tenant Attack</button>
                <span>|</span>
                <button onClick={() => getPreset('analyst_high_risk')} className="text-amber-400 hover:underline">Approval Req</button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Agent Role:</label>
                <select
                  value={simRole}
                  onChange={(e) => setSimRole(e.target.value as 'reader' | 'analyst' | 'admin')}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="reader">reader (Read-only low-risk)</option>
                  <option value="analyst">analyst (Can execute approved high-risk)</option>
                  <option value="admin">admin (Full privileged access)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Tenant ID:</label>
                <input
                  type="text"
                  value={simTenant}
                  onChange={(e) => setSimTenant(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Tool Target:</label>
                <select
                  value={simTool}
                  onChange={(e) => setSimTool(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="search_docs">search_docs (low)</option>
                  <option value="read_file">read_file (medium)</option>
                  <option value="query_db">query_db (medium)</option>
                  <option value="send_email">send_email (high)</option>
                  <option value="export_data">export_data (high)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Destination Host / Target:</label>
                <input
                  type="text"
                  placeholder="e.g. company.internal"
                  value={simDestination}
                  onChange={(e) => setSimDestination(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-slate-400 text-xs mb-1">Input Arguments (JSON):</label>
              <textarea
                rows={6}
                value={simArgsJson}
                onChange={(e) => setSimArgsJson(e.target.value)}
                className="w-full p-3 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div className="space-y-3 pt-3">
            <button
              onClick={handleSimulate}
              disabled={evaluating}
              className="w-full flex items-center justify-center gap-2 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 text-white rounded-lg text-xs font-semibold transition-colors shadow-sm"
            >
              <Play className={`w-3.5 h-3.5 ${evaluating ? 'animate-spin' : ''}`} />
              <span>Evaluate Policy with OPA</span>
            </button>

            {error && (
              <div className="p-2.5 bg-rose-950/40 border border-rose-800/60 rounded text-rose-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Decision Display */}
            {simDecision && (
              <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-medium">Evaluation Decision:</span>
                  {simDecision.allow ? (
                    <span className="px-2.5 py-0.5 rounded-full font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
                      <ShieldCheck className="w-3.5 h-3.5" /> ALLOW
                    </span>
                  ) : simDecision.require_approval ? (
                    <span className="px-2.5 py-0.5 rounded-full font-bold bg-amber-950 text-amber-300 border border-amber-500/40 flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5" /> APPROVE (Human-in-the-loop)
                    </span>
                  ) : (
                    <span className="px-2.5 py-0.5 rounded-full font-bold bg-rose-950 text-rose-300 border border-rose-500/40 flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5" /> DENY
                    </span>
                  )}
                </div>

                <div>
                  <span className="text-slate-500 block">Decision Reasons:</span>
                  <ul className="list-disc list-inside text-slate-300 space-y-0.5 mt-0.5">
                    {simDecision.reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>

                <div>
                  <span className="text-slate-500 block">Matched Rule IDs:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {simDecision.matched_rule_ids && simDecision.matched_rule_ids.length > 0 ? (
                      simDecision.matched_rule_ids.map((rule, idx) => (
                        <span key={idx} className="px-2 py-0.5 bg-slate-800 border border-slate-700 text-cyan-300 rounded font-mono text-[10px]">
                          {rule}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-600 font-mono">none (default deny triggered)</span>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right: Rego Policy Code Viewer */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3 shadow-sm flex flex-col">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              Active Policy Source (policies/default.rego)
            </span>
            <span className="text-xs text-slate-400 font-mono">rego v1</span>
          </div>

          <div className="flex-1 overflow-hidden relative">
            {loading ? (
              <div className="p-8 text-center text-slate-500">Loading policy source...</div>
            ) : (
              <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 font-mono text-[11px] leading-relaxed overflow-auto max-h-[500px]">
                {regoCode}
              </pre>
            )}
          </div>

          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 text-xs text-slate-400 space-y-1">
            <span className="font-semibold text-slate-300 flex items-center gap-1.5">
              <CheckCircle className="w-3.5 h-3.5 text-cyan-400" />
              Guaranteed Security Invariants:
            </span>
            <p>1. Default Deny: All requests are rejected unless explicitly allowed by role & scope capabilities.</p>
            <p>2. Complete Tenant Isolation: Arguments containing tenant markers must strictly equal token claims.</p>
            <p>3. Destination Whitelist: Egress domains must match tool descriptor destinations.</p>
            <p>4. Human Escalation: Sensitive operations (risk=high) require time-bounded approval.</p>
          </div>
        </div>
      </div>
    </div>
  );
};
