import React, { useState, useEffect } from 'react';
import type { AuditEvent } from '../types';
import { fetchAuditEvents } from '../api';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Clock, 
  RefreshCw, 
  Filter, 
  Search, 
  ChevronDown, 
  ChevronUp, 
  Key,
  Layers,
  Terminal
} from 'lucide-react';

export const IncidentTimeline: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcomeFilter, setOutcomeFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const loadEvents = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchAuditEvents(
        outcomeFilter !== 'ALL' ? { outcome: outcomeFilter } : undefined
      );
      setEvents(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch audit events');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [outcomeFilter]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadEvents();
    }, 4000);
    return () => clearInterval(interval);
  }, [autoRefresh, outcomeFilter]);

  const filteredEvents = events.filter((ev) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      ev.tool_id.toLowerCase().includes(q) ||
      ev.agent_id.toLowerCase().includes(q) ||
      ev.tenant_id.toLowerCase().includes(q) ||
      ev.correlation_id.toLowerCase().includes(q) ||
      ev.reason.toLowerCase().includes(q)
    );
  });

  const getBadgeStyle = (outcome: string) => {
    switch (outcome) {
      case 'ALLOW':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40';
      case 'DENY':
        return 'bg-rose-950/80 text-rose-300 border-rose-500/40';
      case 'APPROVE':
        return 'bg-amber-950/80 text-amber-300 border-amber-500/40';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getBadgeIcon = (outcome: string) => {
    switch (outcome) {
      case 'ALLOW':
        return <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />;
      case 'DENY':
        return <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />;
      case 'APPROVE':
        return <Clock className="w-3.5 h-3.5 text-amber-400" />;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-4">
      {/* Controls & Search */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-slate-900/90 rounded-xl border border-slate-800 shadow-md">
        <div className="flex items-center gap-2 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search by agent, tenant, tool, or correlation ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-sm bg-slate-950 border border-slate-700/80 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <span>Outcome:</span>
            <select
              value={outcomeFilter}
              onChange={(e) => setOutcomeFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Outcomes</option>
              <option value="ALLOW">ALLOW Only</option>
              <option value="DENY">DENY Only</option>
              <option value="APPROVE">APPROVE Only</option>
            </select>
          </div>

          <label className="flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0"
            />
            <span>Live Stream</span>
          </label>

          <button
            onClick={loadEvents}
            disabled={loading}
            className="flex items-center gap-1 px-3 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-slate-200 transition-colors"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-lg text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Events List */}
      <div className="space-y-2.5">
        {filteredEvents.length === 0 ? (
          <div className="p-12 text-center bg-slate-900/40 border border-slate-800 rounded-xl text-slate-500">
            <Layers className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm font-medium">No audit events match your filter criteria.</p>
            <p className="text-xs text-slate-600 mt-1">Execute tool calls or run the Attack Lab benchmark to generate security telemetry.</p>
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const isExpanded = expandedId === ev.id;
            const policyMs = ev.policy_latency_ms.toFixed(3);
            const execMs = ev.execution_latency_ms.toFixed(3);
            const dateStr = new Date(ev.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

            return (
              <div
                key={ev.id}
                className="bg-slate-900/80 border border-slate-800/90 rounded-xl overflow-hidden hover:border-slate-700 transition-all shadow-sm"
              >
                {/* Header Row */}
                <div
                  onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                  className="p-3.5 flex flex-wrap items-center justify-between gap-3 cursor-pointer select-none"
                >
                  <div className="flex items-center gap-3">
                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getBadgeStyle(ev.outcome)}`}>
                      {getBadgeIcon(ev.outcome)}
                      {ev.outcome}
                    </span>

                    <span className="font-mono text-xs font-bold text-cyan-400">
                      {ev.tool_id}
                    </span>

                    <span className="text-xs text-slate-400 font-mono hidden sm:inline">
                      agent: <span className="text-slate-200">{ev.agent_id}</span>
                    </span>

                    <span className="text-xs text-slate-500 font-mono hidden md:inline">
                      tenant: <span className="text-slate-300">{ev.tenant_id}</span>
                    </span>
                  </div>

                  <div className="flex items-center gap-4 text-xs font-mono">
                    <span className="text-slate-400" title={`Policy: ${policyMs}ms | Exec: ${execMs}ms`}>
                      <span className="text-cyan-400">{policyMs}ms</span> (policy)
                    </span>
                    <span className="text-slate-500">{dateStr}</span>
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Reason Preview banner */}
                {ev.reason && (
                  <div className="px-3.5 pb-2.5 text-xs text-slate-400 flex items-center gap-2">
                    <span className="text-slate-500">Rationale:</span>
                    <span className={ev.outcome === 'DENY' ? 'text-rose-300 font-mono' : 'text-slate-300 font-mono'}>
                      {ev.reason}
                    </span>
                  </div>
                )}

                {/* Expanded Details Drawer */}
                {isExpanded && (
                  <div className="px-4 py-3 bg-slate-950/70 border-t border-slate-800/80 space-y-3 text-xs">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div>
                        <span className="text-slate-500 block">Correlation ID:</span>
                        <span className="font-mono text-slate-300 select-all">{ev.correlation_id}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Client IP:</span>
                        <span className="font-mono text-slate-300">{ev.client_ip || '127.0.0.1'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Enforced Policy Rules:</span>
                        <span className="font-mono text-cyan-300">
                          {ev.rule_ids && ev.rule_ids.length > 0 ? ev.rule_ids.join(', ') : 'default_fallback'}
                        </span>
                      </div>
                    </div>

                    {/* Redacted Arguments Inspector */}
                    <div>
                      <div className="flex items-center justify-between text-slate-400 mb-1">
                        <span className="flex items-center gap-1">
                          <Terminal className="w-3.5 h-3.5 text-slate-500" />
                          <span>Sanitized Input Arguments (Secrets & PII Redacted)</span>
                        </span>
                        <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                          <Key className="w-3 h-3" /> Redaction active
                        </span>
                      </div>
                      <pre className="p-3 bg-slate-900/90 rounded-lg border border-slate-800 text-slate-300 font-mono text-xs overflow-x-auto max-h-48">
                        {JSON.stringify(ev.arguments, null, 2)}
                      </pre>
                    </div>

                    {ev.error && (
                      <div className="p-2.5 bg-rose-950/40 border border-rose-900/40 rounded text-rose-300">
                        <span className="font-semibold">Execution Error: </span>
                        <span>{ev.error}</span>
                      </div>
                    )}
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
