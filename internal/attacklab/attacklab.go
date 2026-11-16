package attacklab

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/SKB-18/agentshield/internal/approval"
	"github.com/SKB-18/agentshield/internal/identity"
	"github.com/SKB-18/agentshield/internal/proxy"
)

// ThreatCategory classifies the security attack class.
type ThreatCategory string

const (
	CatPromptInjectionExfil ThreatCategory = "INDIRECT_PROMPT_INJECTION_EXFIL"
	CatPathTraversal        ThreatCategory = "PATH_TRAVERSAL_ARBITRARY_READ"
	CatCrossTenantAccess    ThreatCategory = "CROSS_TENANT_DATA_ACCESS"
	CatPrivilegeEscalation  ThreatCategory = "PRIVILEGE_ESCALATION"
	CatEgressSSRF           ThreatCategory = "EGRESS_SSRF_METADATA"
	CatApprovalReplay       ThreatCategory = "APPROVAL_RACE_REPLAY"
	CatDestructiveSQL       ThreatCategory = "DESTRUCTIVE_SQL_INJECTION"
	CatLegitimateControl    ThreatCategory = "LEGITIMATE_BENIGN_CONTROL"
)

// TestCase defines a single test fixture in the attack lab.
type TestCase struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Category        ThreatCategory         `json:"category"`
	Description     string                 `json:"description"`
	AgentRole       string                 `json:"agent_role"`
	AgentTenant     string                 `json:"agent_tenant"`
	ToolID          string                 `json:"tool_id"`
	Arguments       map[string]interface{} `json:"arguments"`
	ExpectedOutcome string                 `json:"expected_outcome"` // "ALLOW", "DENY", "APPROVE"
	IsAdversarial   bool                   `json:"is_adversarial"`
}

// CaseResult holds the outcome of executing a single test case.
type CaseResult struct {
	CaseID          string         `json:"case_id"`
	Category        ThreatCategory `json:"category"`
	Passed          bool           `json:"passed"`
	ActualOutcome   string         `json:"actual_outcome"`
	ExpectedOutcome string         `json:"expected_outcome"`
	Reason          string         `json:"reason"`
	PolicyLatencyMs float64        `json:"policy_latency_ms"`
}

// BenchmarkReport summarizes the attack lab run metrics.
type BenchmarkReport struct {
	Timestamp          time.Time                 `json:"timestamp"`
	TotalCases         int                       `json:"total_cases"`
	AdversarialCases   int                       `json:"adversarial_cases"`
	LegitimateCases    int                       `json:"legitimate_cases"`
	AttacksBlocked     int                       `json:"attacks_blocked"`
	AttackBlockedPct   float64                   `json:"attack_blocked_pct"`
	FalseDenies        int                       `json:"false_denies"`
	FalseDenyPct       float64                   `json:"false_deny_pct"`
	LatencyP50Ms       float64                   `json:"latency_p50_ms"`
	LatencyP95Ms       float64                   `json:"latency_p95_ms"`
	CategoryBreakdown  map[string]CategoryMetric `json:"category_breakdown"`
	Results            []CaseResult              `json:"results"`
}

// CategoryMetric tracks per-category security prevention stats.
type CategoryMetric struct {
	Total    int     `json:"total"`
	Blocked  int     `json:"blocked"`
	RatioPct float64 `json:"ratio_pct"`
}

// LabRunner executes the attack benchmark suite against the gateway.
type LabRunner struct {
	proxy     *proxy.GatewayProxy
	tokens    *identity.TokenManager
	approvals *approval.Service
	cases     []TestCase
}

// NewLabRunner initializes the runner with built-in benchmark fixtures.
func NewLabRunner(p *proxy.GatewayProxy, tm *identity.TokenManager, appr *approval.Service) *LabRunner {
	return &LabRunner{
		proxy:     p,
		tokens:    tm,
		approvals: appr,
		cases:     DefaultFixtures(),
	}
}

// Run executes all fixtures and calculates benchmark metrics.
func (r *LabRunner) Run(ctx context.Context) (*BenchmarkReport, error) {
	report := &BenchmarkReport{
		Timestamp:         time.Now().UTC(),
		TotalCases:        len(r.cases),
		CategoryBreakdown: make(map[string]CategoryMetric),
		Results:           make([]CaseResult, 0, len(r.cases)),
	}

	var policyLatencies []float64

	for _, tc := range r.cases {
		// Generate verified token for the case's assigned identity
		token, err := r.tokens.IssueToken(
			fmt.Sprintf("agent-%s", tc.ID),
			tc.AgentTenant,
			tc.AgentRole,
			[]string{"tools:execute"},
			1*time.Hour,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to issue token for case %s: %w", tc.ID, err)
		}

		// Handle Special Case: APPROVAL REPLAY ATTACK
		if tc.Category == CatApprovalReplay {
			// Simulate an already consumed approval
			appr, _ := r.approvals.CreateApproval("agent-01", tc.AgentTenant, tc.ToolID, "", tc.Arguments, "pre-approved", 5*time.Minute)
			r.approvals.DecideApproval(appr.ID, "admin", true)
			r.approvals.ConsumeApproval(appr.ID, tc.ToolID, tc.Arguments)

			// Attacker attempts replay
			_, replayErr := r.proxy.ExecuteApproved(ctx, appr.ID, tc.Arguments)
			passed := replayErr != nil // Replay MUST fail

			actualOutcome := "ALLOW"
			if passed {
				actualOutcome = "DENY"
			}

			report.Results = append(report.Results, CaseResult{
				CaseID:          tc.ID,
				Category:        tc.Category,
				Passed:          passed,
				ActualOutcome:   actualOutcome,
				ExpectedOutcome: tc.ExpectedOutcome,
				Reason:          "Approval replay blocked by single-use token invariant",
			})
			continue
		}

		req := proxy.Request{
			AgentToken: token,
			ToolID:     tc.ToolID,
			Arguments:  tc.Arguments,
			RequestID:  fmt.Sprintf("lab_%s", tc.ID),
		}

		resp, _ := r.proxy.HandleToolCall(ctx, req, "10.0.0.1")
		actualOutcome := resp.Outcome
		policyLatencies = append(policyLatencies, resp.PolicyLatencyMs)

		passed := actualOutcome == tc.ExpectedOutcome

		catKey := string(tc.Category)
		catMetric := report.CategoryBreakdown[catKey]
		catMetric.Total++

		if tc.IsAdversarial {
			report.AdversarialCases++
			if actualOutcome == "DENY" {
				report.AttacksBlocked++
				catMetric.Blocked++
			}
		} else {
			report.LegitimateCases++
			if actualOutcome != "ALLOW" && actualOutcome != "APPROVE" {
				report.FalseDenies++
			} else {
				catMetric.Blocked++ // Counted as handled correctly
			}
		}

		catMetric.RatioPct = (float64(catMetric.Blocked) / float64(catMetric.Total)) * 100.0
		report.CategoryBreakdown[catKey] = catMetric

		report.Results = append(report.Results, CaseResult{
			CaseID:          tc.ID,
			Category:        tc.Category,
			Passed:          passed,
			ActualOutcome:   actualOutcome,
			ExpectedOutcome: tc.ExpectedOutcome,
			Reason:          resp.Reason,
			PolicyLatencyMs: resp.PolicyLatencyMs,
		})
	}

	// Compute High-Level Percentages
	if report.AdversarialCases > 0 {
		report.AttackBlockedPct = (float64(report.AttacksBlocked) / float64(report.AdversarialCases)) * 100.0
	}
	if report.LegitimateCases > 0 {
		report.FalseDenyPct = (float64(report.FalseDenies) / float64(report.LegitimateCases)) * 100.0
	}

	// Compute p50 & p95 Policy Latency
	if len(policyLatencies) > 0 {
		sort.Float64s(policyLatencies)
		p50Idx := int(float64(len(policyLatencies)) * 0.50)
		p95Idx := int(float64(len(policyLatencies)) * 0.95)
		if p95Idx >= len(policyLatencies) {
			p95Idx = len(policyLatencies) - 1
		}
		report.LatencyP50Ms = policyLatencies[p50Idx]
		report.LatencyP95Ms = policyLatencies[p95Idx]
	}

	return report, nil
}
