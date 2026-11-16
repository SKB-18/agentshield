import React, { useState, useEffect } from 'react';
import type { ToolDescriptor } from '../types';
import { fetchTools } from '../api';
import { 
  Wrench, 
  ShieldAlert, 
  Globe, 
  Clock, 
  FileCode, 
  CheckCircle, 
  RefreshCw,
  ChevronDown,
  ChevronUp
} from 'lucide-react';

export const ToolRegistry: React.FC = () => {
  const [tools, setTools] = useState<ToolDescriptor[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const loadTools = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchTools();
      setTools(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch registered tools');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTools();
  }, []);

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case 'low':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40';
      case 'medium':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40';
      case 'high':
        return 'bg-amber-950/80 text-amber-300 border-amber-500/40';
      case 'critical':
        return 'bg-rose-950/80 text-rose-300 border-rose-500/40';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 flex items-center justify-between gap-3 shadow-md">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/10 rounded-lg border border-cyan-500/20 text-cyan-400">
            <Wrench className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Enforceable Tool Registry & Schema Catalog</h3>
            <p className="text-xs text-slate-400">
              Only explicitly registered tools with immutable JSON Schemas can be invoked by external agents.
            </p>
          </div>
        </div>

        <button
          onClick={loadTools}
          disabled={loading}
          className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-slate-200 transition-colors"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-lg text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Tools Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {tools.map((tool) => {
          const isExpanded = expandedId === tool.id;

          return (
            <div
              key={tool.id}
              className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3 hover:border-slate-700 transition-all flex flex-col justify-between"
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-slate-200">
                      {tool.name}
                    </span>
                    <span className="font-mono text-xs text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/50">
                      {tool.id}
                    </span>
                  </div>

                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getRiskBadge(tool.risk)}`}>
                    risk: {tool.risk}
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">
                  {tool.description}
                </p>

                {/* Configuration Constraints */}
                <div className="grid grid-cols-2 gap-2 text-xs bg-slate-950/70 p-2.5 rounded-lg border border-slate-800/80">
                  <div className="flex items-center gap-1.5 text-slate-300">
                    <Clock className="w-3.5 h-3.5 text-slate-500" />
                    <span>Timeout: {tool.timeout_ms}ms</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-300">
                    <CheckCircle className="w-3.5 h-3.5 text-slate-500" />
                    <span>Cap: {(tool.max_response_bytes / 1024).toFixed(0)}KB</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-300 col-span-2">
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
                    <span>Approval Required: {tool.requires_approval ? 'Yes (Mandatory)' : 'No'}</span>
                  </div>
                </div>

                {/* Allowed Destinations */}
                {tool.allowed_destinations && tool.allowed_destinations.length > 0 && (
                  <div className="text-xs space-y-1">
                    <span className="text-slate-500 flex items-center gap-1">
                      <Globe className="w-3.5 h-3.5 text-cyan-400" />
                      Allowed Egress Destinations:
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {tool.allowed_destinations.map((dest, i) => (
                        <span key={i} className="px-2 py-0.5 bg-slate-950 border border-slate-800 text-slate-300 rounded font-mono text-[11px]">
                          {dest}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Expandable JSON Schema */}
              <div className="pt-2 border-t border-slate-800/80">
                <button
                  onClick={() => setExpandedId(isExpanded ? null : tool.id)}
                  className="w-full flex items-center justify-between text-xs text-slate-400 hover:text-cyan-400 transition-colors"
                >
                  <span className="flex items-center gap-1">
                    <FileCode className="w-3.5 h-3.5" />
                    <span>JSON Schema Contract</span>
                  </span>
                  {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>

                {isExpanded && (
                  <div className="mt-2 text-xs space-y-1">
                    <div className="text-[10px] text-slate-500 font-mono">
                      Schema Hash: {tool.schema_hash.slice(0, 16)}...
                    </div>
                    <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 font-mono text-[11px] overflow-x-auto max-h-48">
                      {JSON.stringify(tool.json_schema, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
