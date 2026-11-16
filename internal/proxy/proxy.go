package proxy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/SKB-18/agentshield/internal/approval"
	"github.com/SKB-18/agentshield/internal/audit"
	"github.com/SKB-18/agentshield/internal/identity"
	"github.com/SKB-18/agentshield/internal/policy"
	"github.com/SKB-18/agentshield/internal/registry"
	"github.com/SKB-18/agentshield/internal/tools"
)

var (
	ErrUnauthorized   = errors.New("authentication failed: invalid or missing agent token")
	ErrToolRestricted = errors.New("tool authorization rejected by policy")
)

// Request defines the incoming tool call payload.
type Request struct {
	AgentToken string                 `json:"agent_token"`
	ToolID     string                 `json:"tool_id"`
	Arguments  map[string]interface{} `json:"arguments"`
	RequestID  string                 `json:"request_id"`
}

// Response defines the security gateway's decision and optional proxied execution result.
type Response struct {
	CorrelationID      string                 `json:"correlation_id"`
	Outcome            string                 `json:"outcome"` // "ALLOW", "DENY", "APPROVE"
	Allowed            bool                   `json:"allowed"`
	RequiresApproval   bool                   `json:"requires_approval"`
	ApprovalID         string                 `json:"approval_id,omitempty"`
	Reason             string                 `json:"reason"`
	RuleIDs            []string               `json:"rule_ids"`
	Result             map[string]interface{} `json:"result,omitempty"`
	PolicyLatencyMs    float64                `json:"policy_latency_ms"`
	ExecutionLatencyMs float64                `json:"execution_latency_ms"`
}

// GatewayProxy coordinates the zero-trust authorization pipeline.
type GatewayProxy struct {
	tokens    *identity.TokenManager
	registry  *registry.Registry
	policy    *policy.Engine
	approvals *approval.Service
	audit     *audit.Store
	executor  *tools.ToolExecutor
}

// NewGatewayProxy initializes the central gateway proxy.
func NewGatewayProxy(
	tokens *identity.TokenManager,
	reg *registry.Registry,
	pol *policy.Engine,
	appr *approval.Service,
	aud *audit.Store,
	exec *tools.ToolExecutor,
) *GatewayProxy {
	return &GatewayProxy{
		tokens:    tokens,
		registry:  reg,
		policy:    pol,
		approvals: appr,
		audit:     aud,
		executor:  exec,
	}
}

// HandleToolCall executes the complete zero-trust gateway pipeline.
func (p *GatewayProxy) HandleToolCall(ctx context.Context, req Request, clientIP string) (*Response, error) {
	correlationID := req.RequestID
	if correlationID == "" {
		correlationID = fmt.Sprintf("corr_%s", uuid.New().String())
	}

	// 1. Identity & Token Verification:
	// CRITICAL INVARIANT: Role and identity are extracted ONLY from cryptographically verified claims.
	claims, err := p.tokens.VerifyToken(req.AgentToken)
	if err != nil {
		p.audit.Record(audit.AuditEvent{
			CorrelationID: correlationID,
			ToolID:        req.ToolID,
			Outcome:       "DENY",
			Reason:        fmt.Sprintf("Authentication failed: %v", err),
			RuleIDs:       []string{"RULE_AUTH_FAILED"},
			Arguments:     req.Arguments,
			ClientIP:      clientIP,
		})
		return &Response{
			CorrelationID: correlationID,
			Outcome:       "DENY",
			Allowed:       false,
			Reason:        fmt.Sprintf("%v: %v", ErrUnauthorized, err),
			RuleIDs:       []string{"RULE_AUTH_FAILED"},
		}, ErrUnauthorized
	}

	// 2. Tool Lookup & Schema Validation
	toolDesc, err := p.registry.Get(req.ToolID)
	if err != nil {
		p.audit.Record(audit.AuditEvent{
			CorrelationID: correlationID,
			AgentID:       claims.AgentID,
			TenantID:      claims.TenantID,
			ToolID:        req.ToolID,
			Outcome:       "DENY",
			Reason:        fmt.Sprintf("Registry error: %v", err),
			RuleIDs:       []string{"RULE_UNKNOWN_TOOL"},
			Arguments:     req.Arguments,
			ClientIP:      clientIP,
		})
		return &Response{
			CorrelationID: correlationID,
			Outcome:       "DENY",
			Allowed:       false,
			Reason:        err.Error(),
			RuleIDs:       []string{"RULE_UNKNOWN_TOOL"},
		}, err
	}

	// Validate Arguments against registered JSON Schema
	if err := p.registry.ValidateArguments(req.ToolID, req.Arguments); err != nil {
		p.audit.Record(audit.AuditEvent{
			CorrelationID: correlationID,
			AgentID:       claims.AgentID,
			TenantID:      claims.TenantID,
			ToolID:        req.ToolID,
			Outcome:       "DENY",
			Reason:        fmt.Sprintf("Schema validation failed: %v", err),
			RuleIDs:       []string{"RULE_SCHEMA_VALIDATION_FAILED"},
			Arguments:     req.Arguments,
			ClientIP:      clientIP,
		})
		return &Response{
			CorrelationID: correlationID,
			Outcome:       "DENY",
			Allowed:       false,
			Reason:        err.Error(),
			RuleIDs:       []string{"RULE_SCHEMA_VALIDATION_FAILED"},
		}, err
	}

	// 3. Extract ResourceID and Destination constraints
	resourceID := ""
	if r, ok := req.Arguments["dataset_id"].(string); ok {
		resourceID = r
	} else if r, ok := req.Arguments["database"].(string); ok {
		resourceID = r
	} else if r, ok := req.Arguments["path"].(string); ok {
		resourceID = r
	}

	destination := ""
	if d, ok := req.Arguments["destination_url"].(string); ok {
		destination = d
	} else if d, ok := req.Arguments["to"].(string); ok {
		destination = d
	}

	// 4. Construct OPA Input & Evaluate Policy
	policyInput := policy.PolicyInput{}
	policyInput.Identity.AgentID = claims.AgentID
	policyInput.Identity.SessionID = claims.SessionID
	policyInput.Identity.TenantID = claims.TenantID
	policyInput.Identity.Role = claims.Role
	policyInput.Identity.AllowedScopes = claims.AllowedScopes

	policyInput.Tool.ID = toolDesc.ID
	policyInput.Tool.Risk = string(toolDesc.Risk)
	policyInput.Tool.SchemaHash = toolDesc.SchemaHash

	policyInput.Action.Arguments = req.Arguments
	policyInput.Action.Destination = destination
	policyInput.Action.ResourceID = resourceID
	policyInput.Context.Timestamp = time.Now().Unix()
	policyInput.Context.ClientIP = clientIP

	t0Policy := time.Now()
	decision, err := p.policy.Evaluate(ctx, policyInput)
	policyDurationMs := float64(time.Since(t0Policy).Microseconds()) / 1000.0
	if err != nil {
		decision = &policy.PolicyDecision{
			Decision: "DENY",
			Reasons:  []string{fmt.Sprintf("Policy evaluation error: %v", err)},
			RuleIDs:  []string{"RULE_EVAL_ERROR"},
		}
	}

	reasonStr := ""
	if len(decision.Reasons) > 0 {
		reasonStr = decision.Reasons[0]
	}

	// 5. Route Decision Outcomes: DENY, APPROVE, ALLOW
	switch decision.Decision {
	case "DENY":
		p.audit.Record(audit.AuditEvent{
			CorrelationID:   correlationID,
			AgentID:         claims.AgentID,
			TenantID:        claims.TenantID,
			ToolID:          req.ToolID,
			ResourceID:      resourceID,
			Outcome:         "DENY",
			Reason:          reasonStr,
			RuleIDs:         decision.RuleIDs,
			Arguments:       req.Arguments,
			PolicyLatencyMs: policyDurationMs,
			ClientIP:        clientIP,
		})

		return &Response{
			CorrelationID:   correlationID,
			Outcome:         "DENY",
			Allowed:         false,
			Reason:          reasonStr,
			RuleIDs:         decision.RuleIDs,
			PolicyLatencyMs: policyDurationMs,
		}, nil

	case "APPROVE":
		// Create time-bounded human approval envelope
		appr, err := p.approvals.CreateApproval(
			claims.AgentID,
			claims.TenantID,
			req.ToolID,
			resourceID,
			req.Arguments,
			reasonStr,
			5*time.Minute,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to enqueue approval request: %w", err)
		}

		p.audit.Record(audit.AuditEvent{
			CorrelationID:   correlationID,
			AgentID:         claims.AgentID,
			TenantID:        claims.TenantID,
			ToolID:          req.ToolID,
			ResourceID:      resourceID,
			Outcome:         "APPROVE",
			Reason:          reasonStr,
			RuleIDs:         decision.RuleIDs,
			Arguments:       req.Arguments,
			PolicyLatencyMs: policyDurationMs,
			ClientIP:        clientIP,
		})

		return &Response{
			CorrelationID:    correlationID,
			Outcome:          "APPROVE",
			Allowed:          false,
			RequiresApproval: true,
			ApprovalID:       appr.ID,
			Reason:           reasonStr,
			RuleIDs:          decision.RuleIDs,
			PolicyLatencyMs:  policyDurationMs,
		}, nil

	case "ALLOW":
		// Enforce execution deadline based on tool descriptor timeout
		execCtx, cancel := context.WithTimeout(ctx, time.Duration(toolDesc.TimeoutMs)*time.Millisecond)
		defer cancel()

		t0Exec := time.Now()
		execResult, err := p.executor.Execute(execCtx, req.ToolID, req.Arguments, toolDesc.MaxResponseBytes)
		execDurationMs := float64(time.Since(t0Exec).Microseconds()) / 1000.0

		if err != nil {
			p.audit.Record(audit.AuditEvent{
				CorrelationID:      correlationID,
				AgentID:            claims.AgentID,
				TenantID:           claims.TenantID,
				ToolID:             req.ToolID,
				ResourceID:         resourceID,
				Outcome:            "DENY",
				Reason:             fmt.Sprintf("Execution error: %v", err),
				RuleIDs:            []string{"RULE_EXECUTION_FAILURE"},
				Arguments:          req.Arguments,
				PolicyLatencyMs:    policyDurationMs,
				ExecutionLatencyMs: execDurationMs,
				ClientIP:           clientIP,
			})
			return &Response{
				CorrelationID:      correlationID,
				Outcome:            "DENY",
				Allowed:            false,
				Reason:             fmt.Sprintf("Execution failed: %v", err),
				RuleIDs:            []string{"RULE_EXECUTION_FAILURE"},
				PolicyLatencyMs:    policyDurationMs,
				ExecutionLatencyMs: execDurationMs,
			}, err
		}

		p.audit.Record(audit.AuditEvent{
			CorrelationID:      correlationID,
			AgentID:            claims.AgentID,
			TenantID:           claims.TenantID,
			ToolID:             req.ToolID,
			ResourceID:         resourceID,
			Outcome:            "ALLOW",
			Reason:             reasonStr,
			RuleIDs:            decision.RuleIDs,
			Arguments:          req.Arguments,
			PolicyLatencyMs:    policyDurationMs,
			ExecutionLatencyMs: execDurationMs,
			ClientIP:           clientIP,
		})

		return &Response{
			CorrelationID:      correlationID,
			Outcome:            "ALLOW",
			Allowed:            true,
			Reason:             reasonStr,
			RuleIDs:            decision.RuleIDs,
			Result:             execResult,
			PolicyLatencyMs:    policyDurationMs,
			ExecutionLatencyMs: execDurationMs,
		}, nil

	default:
		return &Response{
			CorrelationID: correlationID,
			Outcome:       "DENY",
			Allowed:       false,
			Reason:        "Unknown policy evaluation state: default deny",
			RuleIDs:       []string{"RULE_DEFAULT_DENY"},
		}, nil
	}
}

// ExecuteApproved consumes an approved ticket and executes the tool securely.
func (p *GatewayProxy) ExecuteApproved(ctx context.Context, approvalID string, expectedArgs map[string]interface{}) (*Response, error) {
	appr, err := p.approvals.GetApproval(approvalID)
	if err != nil {
		return nil, err
	}

	// Consume approval ticket (single-use, cryptographic argument hash match)
	_, err = p.approvals.ConsumeApproval(approvalID, appr.ToolID, expectedArgs)
	if err != nil {
		return nil, err
	}

	toolDesc, err := p.registry.Get(appr.ToolID)
	if err != nil {
		return nil, err
	}

	execCtx, cancel := context.WithTimeout(ctx, time.Duration(toolDesc.TimeoutMs)*time.Millisecond)
	defer cancel()

	t0 := time.Now()
	res, err := p.executor.Execute(execCtx, appr.ToolID, expectedArgs, toolDesc.MaxResponseBytes)
	execLatency := float64(time.Since(t0).Microseconds()) / 1000.0

	correlationID := fmt.Sprintf("corr_appr_%s", uuid.New().String())
	p.audit.Record(audit.AuditEvent{
		CorrelationID:      correlationID,
		AgentID:            appr.AgentID,
		TenantID:           appr.TenantID,
		ToolID:             appr.ToolID,
		ResourceID:         appr.ResourceID,
		Outcome:            "ALLOW",
		Reason:             fmt.Sprintf("Executed under human approval decision by '%s'", appr.Approver),
		RuleIDs:            []string{"RULE_APPROVED_EXECUTION"},
		Arguments:          expectedArgs,
		ExecutionLatencyMs: execLatency,
	})

	return &Response{
		CorrelationID:      correlationID,
		Outcome:            "ALLOW",
		Allowed:            true,
		Reason:             fmt.Sprintf("Executed under human approval decision by '%s'", appr.Approver),
		RuleIDs:            []string{"RULE_APPROVED_EXECUTION"},
		Result:             res,
		ExecutionLatencyMs: execLatency,
	}, nil
}
