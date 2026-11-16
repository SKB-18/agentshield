import type {
  ToolDescriptor,
  AuditEvent,
  AuditStats,
  ApprovalRecord,
  BenchmarkReport,
  PolicyEvalRequest,
  PolicyDecision,
  ToolCallResponse,
} from './types';

const API_BASE = import.meta.env.VITE_API_URL || '';

export async function fetchHealth(): Promise<{ status: string; service: string }> {
  const res = await fetch(`${API_BASE}/healthz`);
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
  return res.json();
}

export async function fetchTools(): Promise<ToolDescriptor[]> {
  const res = await fetch(`${API_BASE}/v1/tools`);
  if (!res.ok) throw new Error(`Failed to fetch tools: ${res.statusText}`);
  return res.json();
}

export async function fetchAuditEvents(filters?: {
  correlation_id?: string;
  agent_id?: string;
  tenant_id?: string;
  tool_id?: string;
  outcome?: string;
}): Promise<AuditEvent[]> {
  const params = new URLSearchParams();
  if (filters?.correlation_id) params.set('correlation_id', filters.correlation_id);
  if (filters?.agent_id) params.set('agent_id', filters.agent_id);
  if (filters?.tenant_id) params.set('tenant_id', filters.tenant_id);
  if (filters?.tool_id) params.set('tool_id', filters.tool_id);
  if (filters?.outcome) params.set('outcome', filters.outcome);

  const res = await fetch(`${API_BASE}/v1/audit?${params.toString()}`);
  if (!res.ok) throw new Error(`Failed to fetch audit events: ${res.statusText}`);
  return res.json();
}

export async function fetchAuditStats(): Promise<AuditStats> {
  const res = await fetch(`${API_BASE}/v1/audit/stats`);
  if (!res.ok) throw new Error(`Failed to fetch audit stats: ${res.statusText}`);
  return res.json();
}

export async function fetchApprovals(): Promise<ApprovalRecord[]> {
  const res = await fetch(`${API_BASE}/v1/approvals`);
  if (!res.ok) throw new Error(`Failed to fetch approvals: ${res.statusText}`);
  return res.json();
}

export async function decideApproval(
  id: string,
  approver: string,
  approved: boolean,
  rationale?: string
): Promise<ApprovalRecord> {
  const res = await fetch(`${API_BASE}/v1/approvals/${encodeURIComponent(id)}/decision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approver, approved, rationale }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Approval decision failed: ${err}`);
  }
  return res.json();
}

export async function executeApproved(
  id: string,
  argumentsPayload: Record<string, unknown>
): Promise<ToolCallResponse> {
  const res = await fetch(`${API_BASE}/v1/approvals/${encodeURIComponent(id)}/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ arguments: argumentsPayload }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Approved tool execution failed: ${err}`);
  }
  return res.json();
}

export async function runAttackLab(): Promise<BenchmarkReport> {
  const res = await fetch(`${API_BASE}/v1/attack-lab/run`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Attack Lab benchmark failed: ${err}`);
  }
  return res.json();
}

export async function testPolicy(input: PolicyEvalRequest): Promise<PolicyDecision> {
  const res = await fetch(`${API_BASE}/v1/policies/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Policy test evaluation failed: ${err}`);
  }
  return res.json();
}

export async function fetchPolicyCode(): Promise<{ version: string; rego: string }> {
  const res = await fetch(`${API_BASE}/v1/policies`);
  if (!res.ok) throw new Error(`Failed to fetch policy code: ${res.statusText}`);
  return res.json();
}

export async function issueAgentToken(
  agent_id: string,
  tenant_id: string,
  role: string,
  scopes: string[] = ['tools:read', 'tools:execute']
): Promise<{ token: string; expires_in: number }> {
  const res = await fetch(`${API_BASE}/v1/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_id, tenant_id, role, scopes }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Token issuance failed: ${err}`);
  }
  return res.json();
}

export async function callTool(
  token: string,
  tool_id: string,
  args: Record<string, unknown>
): Promise<ToolCallResponse> {
  const res = await fetch(`${API_BASE}/v1/tool-calls`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      agent_token: token,
      tool_id,
      arguments: args,
    }),
  });
  // Note: 403 Forbidden on DENY and 202 Accepted on APPROVE still return json
  return res.json();
}
