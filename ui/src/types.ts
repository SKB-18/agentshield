export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface ToolDescriptor {
  id: string;
  name: string;
  description: string;
  version: string;
  risk: RiskLevel;
  allowed_destinations?: string[];
  json_schema: Record<string, unknown>;
  schema_hash: string;
  timeout_ms: number;
  max_response_bytes: number;
  requires_approval: boolean;
  enabled: boolean;
}

export type Outcome = 'ALLOW' | 'DENY' | 'APPROVE';

export interface AuditEvent {
  id: string;
  correlation_id: string;
  timestamp: string;
  agent_id: string;
  tenant_id: string;
  tool_id: string;
  resource_id?: string;
  outcome: Outcome;
  rule_ids?: string[];
  reason: string;
  arguments: Record<string, unknown>;
  policy_latency_ms: number;
  execution_latency_ms: number;
  client_ip?: string;
  error?: string;
}

export interface AuditStats {
  total_calls: number;
  allowed_calls: number;
  denied_calls: number;
  approval_calls: number;
  avg_policy_latency_ms: number;
}

export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CONSUMED';

export interface ApprovalRecord {
  id: string;
  correlation_id: string;
  agent_id: string;
  tenant_id: string;
  role: string;
  tool_id: string;
  arguments: Record<string, unknown>;
  argument_hash: string;
  status: ApprovalStatus;
  requested_at: string;
  expires_at: string;
  decided_at?: string;
  decided_by?: string;
  decision_rationale?: string;
  consumed: boolean;
  consumed_at?: string;
}

export interface CaseResult {
  case_id: string;
  category: string;
  passed: boolean;
  actual_outcome: Outcome;
  expected_outcome: Outcome;
  reason: string;
  policy_latency_ms: number;
}

export interface CategoryMetric {
  total: number;
  blocked: number;
  ratio_pct: number;
}

export interface BenchmarkReport {
  timestamp: string;
  total_cases: number;
  adversarial_cases: number;
  legitimate_cases: number;
  attacks_blocked: number;
  attack_blocked_pct: number;
  false_denies: number;
  false_deny_pct: number;
  latency_p50_ms: number;
  latency_p95_ms: number;
  category_breakdown: Record<string, CategoryMetric>;
  results: CaseResult[];
}

export interface PolicyEvalRequest {
  agent_id: string;
  tenant_id: string;
  role: string;
  scopes: string[];
  tool_id: string;
  tool_risk: string;
  destination?: string;
  arguments: Record<string, unknown>;
}

export interface PolicyDecision {
  allow: boolean;
  require_approval: boolean;
  reasons: string[];
  matched_rule_ids: string[];
}

export interface ToolCallResponse {
  correlation_id: string;
  outcome: Outcome;
  reason: string;
  approval_id?: string;
  expires_at?: string;
  result?: unknown;
  policy_latency_ms: number;
  total_latency_ms: number;
}
