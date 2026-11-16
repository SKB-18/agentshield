package proxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SKB-18/agentshield/internal/approval"
	"github.com/SKB-18/agentshield/internal/audit"
	"github.com/SKB-18/agentshield/internal/identity"
	"github.com/SKB-18/agentshield/internal/policy"
	"github.com/SKB-18/agentshield/internal/registry"
	"github.com/SKB-18/agentshield/internal/tools"
)

func setupTestProxy(t *testing.T) (*GatewayProxy, *identity.TokenManager) {
	tokens := identity.NewTokenManager("test-proxy-secret-1234", "test-issuer", "agentshield-gateway")
	reg := registry.NewRegistry()

	// Register tools
	reg.Register(registry.ToolDescriptor{
		ID:          "search_docs",
		Name:        "Search Docs",
		Risk:        registry.RiskLow,
		Enabled:     true,
		TimeoutMs:   3000,
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"query", "dataset_id"},
			"properties": map[string]interface{}{
				"query":      map[string]interface{}{"type": "string"},
				"dataset_id": map[string]interface{}{"type": "string"},
			},
		},
	})

	reg.Register(registry.ToolDescriptor{
		ID:          "send_email",
		Name:        "Send Email",
		Risk:        registry.RiskHigh,
		Enabled:     true,
		TimeoutMs:   3000,
		AllowedDestinations: []string{"company.internal"},
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"to", "subject", "body"},
			"properties": map[string]interface{}{
				"to":      map[string]interface{}{"type": "string"},
				"subject": map[string]interface{}{"type": "string"},
				"body":    map[string]interface{}{"type": "string"},
			},
		},
	})

	regoPath := filepath.Join("..", "..", "policies", "default.rego")
	code, err := os.ReadFile(regoPath)
	if err != nil {
		t.Fatalf("failed to read test rego: %v", err)
	}

	pol, err := policy.NewEngine("v1.0.0", string(code))
	if err != nil {
		t.Fatalf("failed to init policy engine: %v", err)
	}

	appr := approval.NewService()
	aud := audit.NewStore()
	exec := tools.NewToolExecutor("/workspace/data")

	proxy := NewGatewayProxy(tokens, reg, pol, appr, aud, exec)
	return proxy, tokens
}

func TestProxy_HandleToolCall_Allow(t *testing.T) {
	p, tm := setupTestProxy(t)
	ctx := context.Background()

	token, _ := tm.IssueToken("agent-reader", "tenant-alpha", "reader", []string{"tools:read"}, 1*time.Hour)

	req := Request{
		AgentToken: token,
		ToolID:     "search_docs",
		Arguments: map[string]interface{}{
			"query":      "zero trust",
			"dataset_id": "kb-public",
		},
	}

	resp, err := p.HandleToolCall(ctx, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Outcome != "ALLOW" {
		t.Fatalf("expected ALLOW outcome, got %s (reason: %s)", resp.Outcome, resp.Reason)
	}
	if !resp.Allowed {
		t.Errorf("expected Allowed = true")
	}
	if resp.Result == nil {
		t.Errorf("expected non-nil execution result")
	}
}

func TestProxy_HandleToolCall_RequireApproval_And_Execute(t *testing.T) {
	p, tm := setupTestProxy(t)
	ctx := context.Background()

	token, _ := tm.IssueToken("agent-analyst", "tenant-alpha", "analyst", []string{"tools:execute"}, 1*time.Hour)

	args := map[string]interface{}{
		"to":      "audit-team@company.internal",
		"subject": "Quarterly Findings",
		"body":    "Here are the findings...",
	}

	req := Request{
		AgentToken: token,
		ToolID:     "send_email",
		Arguments:  args,
	}

	resp, err := p.HandleToolCall(ctx, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Outcome != "APPROVE" {
		t.Fatalf("expected APPROVE outcome, got %s (reason: %s)", resp.Outcome, resp.Reason)
	}
	if resp.ApprovalID == "" {
		t.Fatal("expected approval ticket ID")
	}

	// Human decides approval
	_, err = p.approvals.DecideApproval(resp.ApprovalID, "admin-bob", true)
	if err != nil {
		t.Fatalf("error deciding approval: %v", err)
	}

	// Execute approved ticket
	execResp, err := p.ExecuteApproved(ctx, resp.ApprovalID, args)
	if err != nil {
		t.Fatalf("error executing approved ticket: %v", err)
	}

	if execResp.Outcome != "ALLOW" {
		t.Fatalf("expected ALLOW execution outcome, got %s", execResp.Outcome)
	}
	if execResp.Result == nil {
		t.Fatal("expected non-nil result from executed approved tool")
	}

	// Replay of consumed approval MUST fail
	_, err = p.ExecuteApproved(ctx, resp.ApprovalID, args)
	if err == nil {
		t.Fatal("expected replay of consumed approval to fail, got nil")
	}
}

func TestProxy_HandleToolCall_UntrustedToken_Denied(t *testing.T) {
	p, _ := setupTestProxy(t)
	ctx := context.Background()

	req := Request{
		AgentToken: "invalid.jwt.token",
		ToolID:     "search_docs",
		Arguments:  map[string]interface{}{"query": "hello"},
	}

	resp, err := p.HandleToolCall(ctx, req, "127.0.0.1")
	if err == nil {
		t.Fatal("expected authentication error, got nil")
	}
	if resp.Outcome != "DENY" {
		t.Errorf("expected DENY outcome, got %s", resp.Outcome)
	}
}
