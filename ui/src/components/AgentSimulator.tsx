import React, { useState } from 'react';
import type { ToolCallResponse } from '../types';
import { issueAgentToken, callTool } from '../api';
import { 
  Key, 
  Send, 
  ShieldCheck, 
  ShieldAlert, 
  Clock, 
  Terminal, 
  AlertCircle,
  Sparkles
} from 'lucide-react';

export const AgentSimulator: React.FC = () => {
  // Token generation state
  const [agentId, setAgentId] = useState('agent-analyst-07');
  const [tenantId, setTenantId] = useState('tenant-alpha');
  const [role, setRole] = useState<'reader' | 'analyst' | 'admin'>('analyst');
  const [token, setToken] = useState<string>('');
  const [issuingToken, setIssuingToken] = useState(false);

  // Tool execution state
  const [toolId, setToolId] = useState('search_docs');
  const [argumentsJson, setArgumentsJson] = useState('{\n  "query": "zero trust gateway security",\n  "dataset_id": "kb-public"\n}');
  const [calling, setCalling] = useState(false);
  const [response, setResponse] = useState<ToolCallResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleIssueToken = async () => {
    try {
      setIssuingToken(true);
      setError(null);
      const res = await issueAgentToken(agentId, tenantId, role, ['tools:read', 'tools:execute']);
      setToken(res.token);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Token issuance failed');
    } finally {
      setIssuingToken(false);
    }
  };

  const handleCallTool = async () => {
    try {
      setCalling(true);
      setError(null);
      setResponse(null);

      // Issue token automatically if not present
      let activeToken = token;
      if (!activeToken) {
        const tokenRes = await issueAgentToken(agentId, tenantId, role, ['tools:read', 'tools:execute']);
        activeToken = tokenRes.token;
        setToken(activeToken);
      }

      let parsedArgs: Record<string, unknown> = {};
      try {
        parsedArgs = JSON.parse(argumentsJson);
      } catch {
        throw new Error('Arguments must be valid JSON');
      }

      const res = await callTool(activeToken, toolId, parsedArgs);
      setResponse(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Tool call failed');
    } finally {
      setCalling(false);
    }
  };

  const handleSelectPreset = (tool: string) => {
    setToolId(tool);
    switch (tool) {
      case 'search_docs':
        setArgumentsJson('{\n  "query": "zero trust security",\n  "dataset_id": "kb-public"\n}');
        break;
      case 'read_file':
        setArgumentsJson('{\n  "path": "config.json"\n}');
        break;
      case 'query_db':
        setArgumentsJson('{\n  "sql": "SELECT name, email FROM users LIMIT 10",\n  "database": "analytics"\n}');
        break;
      case 'send_email':
        setArgumentsJson('{\n  "to": "security-officer@company.internal",\n  "subject": "System Audit Complete",\n  "body": "All adversarial tests passed with 100% defense rate."\n}');
        break;
      case 'export_data':
        setArgumentsJson('{\n  "destination_url": "https://export.partner.com/v1/sync",\n  "format": "csv",\n  "role": "analyst"\n}');
        break;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 flex items-center justify-between gap-3 shadow-md">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-500/10 rounded-lg border border-purple-500/20 text-purple-400">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Interactive Agent Playground & Simulator</h3>
            <p className="text-xs text-slate-400">
              Issue signed cryptographic JWT identity tokens and simulate live agent tool calls against the gateway.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Identity Token & Request Config */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Key className="w-4 h-4 text-purple-400" />
              Agent Cryptographic Identity (JWT Claims)
            </span>
            <button
              onClick={handleIssueToken}
              disabled={issuingToken}
              className="text-xs text-purple-400 hover:text-purple-300 font-medium transition-colors"
            >
              {issuingToken ? 'Signing...' : 'Re-issue Token'}
            </button>
          </div>

          <div className="grid grid-cols-3 gap-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Agent ID:</label>
              <input
                type="text"
                value={agentId}
                onChange={(e) => setAgentId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Tenant ID:</label>
              <input
                type="text"
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Role:</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value as 'reader' | 'analyst' | 'admin')}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
              >
                <option value="reader">reader</option>
                <option value="analyst">analyst</option>
                <option value="admin">admin</option>
              </select>
            </div>
          </div>

          {token && (
            <div className="text-xs bg-slate-950/80 p-2.5 rounded-lg border border-slate-800/80 space-y-1">
              <span className="text-slate-500 text-[10px] block">Active Signed Token:</span>
              <div className="font-mono text-[10px] text-purple-300 truncate select-all">{token}</div>
            </div>
          )}

          {/* Tool Call Setup */}
          <div className="border-t border-slate-800 pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">Tool Target:</span>
              <div className="flex items-center gap-1 text-[11px] text-slate-400">
                <span>Presets:</span>
                {['search_docs', 'read_file', 'query_db', 'send_email', 'export_data'].map((t) => (
                  <button
                    key={t}
                    onClick={() => handleSelectPreset(t)}
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                      toolId === t ? 'bg-cyan-600 text-white' : 'text-cyan-400 hover:underline'
                    }`}
                  >
                    {t.split('_')[0]}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-slate-400 text-xs mb-1">Arguments Payload (JSON):</label>
              <textarea
                rows={5}
                value={argumentsJson}
                onChange={(e) => setArgumentsJson(e.target.value)}
                className="w-full p-3 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              onClick={handleCallTool}
              disabled={calling}
              className="w-full flex items-center justify-center gap-2 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 text-white rounded-lg text-xs font-semibold transition-colors shadow-sm"
            >
              <Send className={`w-3.5 h-3.5 ${calling ? 'animate-spin' : ''}`} />
              <span>{calling ? 'Evaluating & Executing...' : 'Dispatch Tool Call via Gateway'}</span>
            </button>
          </div>
        </div>

        {/* Right: Live Response & Inspection */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                Gateway Decision & Sandboxed Execution Result
              </span>
            </div>

            {error && (
              <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-lg text-xs text-rose-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {!response && !error && (
              <div className="p-16 text-center text-slate-500 space-y-2">
                <Terminal className="w-8 h-8 mx-auto opacity-40" />
                <p className="text-xs">Dispatch a tool call to view the zero-trust decision and execution output.</p>
              </div>
            )}

            {response && (
              <div className="space-y-3 text-xs">
                {/* Decision Header */}
                <div className="flex items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 font-medium">Gateway Outcome:</span>
                    {response.outcome === 'ALLOW' && (
                      <span className="px-2.5 py-0.5 rounded-full font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
                        <ShieldCheck className="w-3.5 h-3.5" /> ALLOW
                      </span>
                    )}
                    {response.outcome === 'DENY' && (
                      <span className="px-2.5 py-0.5 rounded-full font-bold bg-rose-950 text-rose-300 border border-rose-500/40 flex items-center gap-1">
                        <ShieldAlert className="w-3.5 h-3.5" /> DENY
                      </span>
                    )}
                    {response.outcome === 'APPROVE' && (
                      <span className="px-2.5 py-0.5 rounded-full font-bold bg-amber-950 text-amber-300 border border-amber-500/40 flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5" /> APPROVAL REQUIRED
                      </span>
                    )}
                  </div>

                  <div className="font-mono text-slate-400">
                    Policy: <span className="text-cyan-400">{response.policy_latency_ms.toFixed(2)}ms</span>
                  </div>
                </div>

                {/* Reason */}
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                  <span className="text-slate-500 block mb-0.5">Policy Rationale:</span>
                  <span className={response.outcome === 'DENY' ? 'text-rose-300 font-mono' : 'text-slate-200'}>
                    {response.reason}
                  </span>
                </div>

                {/* Approval Ticket Info if APPROVE */}
                {response.approval_id && (
                  <div className="p-3 bg-amber-950/40 border border-amber-800/60 rounded-lg space-y-1 text-amber-300">
                    <span className="font-semibold block">Approval Ticket Generated:</span>
                    <div className="font-mono text-[11px] select-all">{response.approval_id}</div>
                    <p className="text-[10px] text-amber-400/80">
                      Navigate to the "Human Approvals" tab to review and authorize this action.
                    </p>
                  </div>
                )}

                {/* Execution Payload if ALLOW */}
                {response.result !== undefined && (
                  <div>
                    <span className="text-slate-400 block mb-1 font-medium">Sandboxed Execution Output:</span>
                    <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-200 font-mono text-[11px] overflow-x-auto max-h-56">
                      {JSON.stringify(response.result, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="text-[11px] text-slate-500 border-t border-slate-800 pt-3">
            Every call is automatically logged with redacted arguments into the Immutable Audit Store.
          </div>
        </div>
      </div>
    </div>
  );
};
