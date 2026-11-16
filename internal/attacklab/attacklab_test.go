package attacklab

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/SKB-18/agentshield/internal/approval"
	"github.com/SKB-18/agentshield/internal/audit"
	"github.com/SKB-18/agentshield/internal/identity"
	"github.com/SKB-18/agentshield/internal/policy"
	"github.com/SKB-18/agentshield/internal/proxy"
	"github.com/SKB-18/agentshield/internal/registry"
	"github.com/SKB-18/agentshield/internal/tools"
)

func TestAttackLab_FullBenchmarkRun(t *testing.T) {
	tokens := identity.NewTokenManager("attacklab-secret-key-999", "agentshield-auth", "agentshield-gateway")
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
			"required": []string{"dataset_id"},
			"properties": map[string]interface{}{
				"query":      map[string]interface{}{"type": "string"},
				"dataset_id": map[string]interface{}{"type": "string"},
			},
		},
	})

	reg.Register(registry.ToolDescriptor{
		ID:          "read_file",
		Name:        "Read File",
		Risk:        registry.RiskMedium,
		Enabled:     true,
		TimeoutMs:   3000,
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"path"},
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string"},
			},
		},
	})

	reg.Register(registry.ToolDescriptor{
		ID:          "query_db",
		Name:        "Query Database",
		Risk:        registry.RiskMedium,
		Enabled:     true,
		TimeoutMs:   3000,
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"sql", "database"},
			"properties": map[string]interface{}{
				"sql":      map[string]interface{}{"type": "string"},
				"database": map[string]interface{}{"type": "string"},
			},
		},
	})

	reg.Register(registry.ToolDescriptor{
		ID:          "send_email",
		Name:        "Send Email",
		Risk:        registry.RiskHigh,
		Enabled:     true,
		TimeoutMs:   3000,
		AllowedDestinations: []string{"company.internal", "corp.internal"},
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"to", "subject"},
			"properties": map[string]interface{}{
				"to":      map[string]interface{}{"type": "string"},
				"subject": map[string]interface{}{"type": "string"},
				"body":    map[string]interface{}{"type": "string"},
			},
		},
	})

	reg.Register(registry.ToolDescriptor{
		ID:          "export_data",
		Name:        "Export Data",
		Risk:        registry.RiskHigh,
		Enabled:     true,
		TimeoutMs:   3000,
		AllowedDestinations: []string{"https://export.partner.com", "s3.corporate.internal"},
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"destination_url"},
			"properties": map[string]interface{}{
				"destination_url": map[string]interface{}{"type": "string"},
				"format":          map[string]interface{}{"type": "string"},
				"role":            map[string]interface{}{"type": "string"}, // Handled for self-assertion tests
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

	p := proxy.NewGatewayProxy(tokens, reg, pol, appr, aud, exec)
	runner := NewLabRunner(p, tokens, appr)

	ctx := context.Background()
	report, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("attack lab execution failed: %v", err)
	}

	t.Logf("=== Attack Lab Benchmark Summary ===")
	t.Logf("Total Test Cases: %d", report.TotalCases)
	t.Logf("Adversarial Cases: %d | Blocked: %d (%.1f%%)", report.AdversarialCases, report.AttacksBlocked, report.AttackBlockedPct)
	t.Logf("Legitimate Controls: %d | False Denies: %d (%.1f%%)", report.LegitimateCases, report.FalseDenies, report.FalseDenyPct)
	t.Logf("Policy Decision Latency: p50=%.3fms, p95=%.3fms", report.LatencyP50Ms, report.LatencyP95Ms)

	// Invariants from Blueprint Section 11:
	// 1. Attacks Blocked %: 100% of disallowed attempts stopped
	if report.AttackBlockedPct < 100.0 {
		t.Errorf("expected 100%% of attacks blocked, got %.1f%% (%d/%d)", report.AttackBlockedPct, report.AttacksBlocked, report.AdversarialCases)
	}

	// 2. False Deny %: 0% of legitimate calls blocked
	if report.FalseDenyPct > 0.0 {
		t.Errorf("expected 0%% false deny, got %.1f%%", report.FalseDenyPct)
	}

	// 3. Policy Latency: < 20ms p95
	if report.LatencyP95Ms > 20.0 {
		t.Errorf("expected p95 policy latency < 20ms, got %.3fms", report.LatencyP95Ms)
	}
}
