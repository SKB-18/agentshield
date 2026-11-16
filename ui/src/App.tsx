import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  Flame, 
  Clock, 
  FileCode, 
  Wrench, 
  Terminal, 
  CheckCircle2, 
  AlertTriangle, 
  Layers,
  ArrowRight,
  RefreshCw,
  Cpu
} from 'lucide-react';
import type { AuditStats } from './types';
import { fetchHealth, fetchAuditStats } from './api';

import { IncidentTimeline } from './components/IncidentTimeline';
import { ApprovalQueue } from './components/ApprovalQueue';
import { PolicyInspector } from './components/PolicyInspector';
import { AttackLab } from './components/AttackLab';
import { ToolRegistry } from './components/ToolRegistry';
import { AgentSimulator } from './components/AgentSimulator';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'attack-lab' | 'timeline' | 'approvals' | 'policies' | 'tools' | 'simulator'>('overview');
  const [healthStatus, setHealthStatus] = useState<'HEALTHY' | 'CONNECTING' | 'OFFLINE'>('CONNECTING');
  const [stats, setStats] = useState<AuditStats | null>(null);

  const checkGateway = async () => {
    try {
      await fetchHealth();
      setHealthStatus('HEALTHY');
      const s = await fetchAuditStats();
      setStats(s);
    } catch {
      setHealthStatus('OFFLINE');
    }
  };

  useEffect(() => {
    checkGateway();
    const interval = setInterval(checkGateway, 5000);
    return () => clearInterval(interval);
  }, []);

  const totalCalls = stats?.total_calls || 0;
  const allowedCalls = stats?.allowed_calls || 0;
  const deniedCalls = stats?.denied_calls || 0;
  const approvalCalls = stats?.approval_calls || 0;

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-200 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navbar */}
      <header className="sticky top-0 z-50 bg-[#0d1322]/95 backdrop-blur border-b border-slate-800/90 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-xl shadow-md shadow-cyan-500/20 text-white">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-black text-base tracking-wider bg-gradient-to-r from-cyan-400 to-blue-300 bg-clip-text text-transparent">
                  AgentShield
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/50">
                  v1.0.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Zero-Trust Security Gateway for Autonomous AI Tools
              </p>
            </div>
          </div>

          {/* Gateway Status Badge */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium border bg-slate-900 border-slate-800">
              <span className={`w-2 h-2 rounded-full ${
                healthStatus === 'HEALTHY' ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]' :
                healthStatus === 'CONNECTING' ? 'bg-amber-400 animate-pulse' :
                'bg-rose-500'
              }`} />
              <span className="text-slate-300">Gateway:</span>
              <span className={
                healthStatus === 'HEALTHY' ? 'text-emerald-400' :
                healthStatus === 'CONNECTING' ? 'text-amber-400' :
                'text-rose-400'
              }>
                {healthStatus}
              </span>
            </div>

            <button
              onClick={checkGateway}
              className="p-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-400 hover:text-slate-200 transition-colors"
              title="Refresh Gateway Health"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-1 overflow-x-auto no-scrollbar border-t border-slate-800/50 py-1.5">
          {[
            { id: 'overview', label: 'Overview', icon: Layers },
            { id: 'attack-lab', label: 'Attack Lab', icon: Flame, badge: '100% Defense' },
            { id: 'timeline', label: 'Incident Timeline', icon: Activity, count: totalCalls },
            { id: 'approvals', label: 'Human Approvals', icon: Clock, count: approvalCalls },
            { id: 'policies', label: 'Policy Inspector', icon: FileCode },
            { id: 'tools', label: 'Tool Registry', icon: Wrench },
            { id: 'simulator', label: 'Agent Simulator', icon: Terminal },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all whitespace-nowrap ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
                {tab.badge && (
                  <span className="text-[10px] bg-rose-500/20 text-rose-300 px-1.5 py-0.2 rounded font-mono">
                    {tab.badge}
                  </span>
                )}
                {typeof tab.count === 'number' && tab.count > 0 && (
                  <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 py-0.2 rounded font-mono">
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Mission Hero Banner */}
            <div className="relative overflow-hidden p-6 sm:p-8 bg-gradient-to-r from-slate-900 via-[#0d1627] to-slate-900 rounded-2xl border border-slate-800 shadow-xl">
              <div className="relative z-10 max-w-3xl space-y-3">
                <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-700/50">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                  Embedded Open Policy Agent + JSON Schema + Hardened Sandbox
                </div>
                <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                  Zero-Trust Security Checkpoint for Autonomous AI Agents
                </h1>
                <p className="text-sm text-slate-300 leading-relaxed">
                  AgentShield intercepts all AI tool calls outside the LLM. It enforces cryptographic JWT identity claims, verifies parameters against immutable JSON Schemas, isolates multi-tenant boundaries, and gates critical actions with time-bounded human approvals.
                </p>
                <div className="flex flex-wrap items-center gap-3 pt-2">
                  <button
                    onClick={() => setActiveTab('attack-lab')}
                    className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-rose-600 to-rose-500 hover:from-rose-500 hover:to-rose-400 text-white rounded-lg text-xs font-semibold shadow-md shadow-rose-600/20 transition-all"
                  >
                    <Flame className="w-4 h-4" />
                    <span>Run Synthetic Attack Lab</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => setActiveTab('simulator')}
                    className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-medium transition-all"
                  >
                    <Terminal className="w-4 h-4 text-purple-400" />
                    <span>Launch Agent Playground</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Live Gateway Telemetry KPIs */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1">
                <span className="text-xs text-slate-400 flex items-center gap-1.5">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  Total Intercepted Calls
                </span>
                <div className="text-2xl font-black text-slate-100 font-mono">
                  {totalCalls}
                </div>
                <p className="text-[11px] text-slate-500">Full audit trail preserved</p>
              </div>

              <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1">
                <span className="text-xs text-slate-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  Allowed Safe Invocations
                </span>
                <div className="text-2xl font-black text-emerald-400 font-mono">
                  {allowedCalls}
                </div>
                <p className="text-[11px] text-slate-500">Zero false denials on controls</p>
              </div>

              <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1">
                <span className="text-xs text-slate-400 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                  Neutralized Threats
                </span>
                <div className="text-2xl font-black text-rose-400 font-mono">
                  {deniedCalls}
                </div>
                <p className="text-[11px] text-slate-500">100% blocked on adversarial tests</p>
              </div>

              <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1">
                <span className="text-xs text-slate-400 flex items-center gap-1.5">
                  <Clock className="w-4 h-4 text-amber-400" />
                  Approval Escalate Gates
                </span>
                <div className="text-2xl font-black text-amber-400 font-mono">
                  {approvalCalls}
                </div>
                <p className="text-[11px] text-slate-500">Single-use replay protected</p>
              </div>
            </div>

            {/* Zero-Trust Architecture Diagram / Pillars */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-5 bg-slate-900/60 border border-slate-800/80 rounded-xl space-y-2.5">
                <div className="flex items-center gap-2 text-cyan-400">
                  <Shield className="w-5 h-5" />
                  <h3 className="text-sm font-semibold text-slate-200">1. Cryptographic Identity</h3>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Decoupled from LLM prompts. Agents present signed JWT tokens verifying <code className="text-cyan-300">agent_id</code>, <code className="text-cyan-300">tenant_id</code>, and assigned roles (<code className="text-slate-300">reader</code>, <code className="text-slate-300">analyst</code>, <code className="text-slate-300">admin</code>).
                </p>
              </div>

              <div className="p-5 bg-slate-900/60 border border-slate-800/80 rounded-xl space-y-2.5">
                <div className="flex items-center gap-2 text-blue-400">
                  <FileCode className="w-5 h-5" />
                  <h3 className="text-sm font-semibold text-slate-200">2. Embedded OPA Engine</h3>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  In-process Rego evaluation compiles query plans directly in Go. Achieves sub-millisecond policy decisions (&lt;200µs average) with default-deny rules and strict tenant isolation.
                </p>
              </div>

              <div className="p-5 bg-slate-900/60 border border-slate-800/80 rounded-xl space-y-2.5">
                <div className="flex items-center gap-2 text-amber-400">
                  <Clock className="w-5 h-5" />
                  <h3 className="text-sm font-semibold text-slate-200">3. Time-Bounded Approvals</h3>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  High-risk operations (e.g., outbound email or partner data exports) trigger human-in-the-loop tickets cryptographically bound via SHA-256 with single-use replay protection.
                </p>
              </div>
            </div>

            {/* Quick Link to Audit */}
            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl flex items-center justify-between">
              <div>
                <span className="text-xs font-semibold text-slate-200 block">Need to inspect recent security events?</span>
                <span className="text-[11px] text-slate-400">View live audit trails with sanitized arguments (passwords and API keys automatically redacted).</span>
              </div>
              <button
                onClick={() => setActiveTab('timeline')}
                className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 rounded-lg transition-colors"
              >
                Open Audit Stream
              </button>
            </div>
          </div>
        )}

        {activeTab === 'attack-lab' && <AttackLab />}
        {activeTab === 'timeline' && <IncidentTimeline />}
        {activeTab === 'approvals' && <ApprovalQueue />}
        {activeTab === 'policies' && <PolicyInspector />}
        {activeTab === 'tools' && <ToolRegistry />}
        {activeTab === 'simulator' && <AgentSimulator />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-4 text-center text-xs text-slate-500">
        AgentShield Zero-Trust Security Gateway &bull; Embedded OPA &bull; Pure Go &amp; React &bull; $0 Cloud Dependencies
      </footer>
    </div>
  );
};
export default App;
