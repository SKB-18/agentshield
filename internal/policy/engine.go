package policy

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
)

//go:embed default.rego
var DefaultRegoCode string

var (
	ErrCompilationFailed = errors.New("rego compilation failed")
	ErrEvaluationFailed  = errors.New("policy evaluation failed")
)

// PolicyInput encapsulates all identity, tool, and action context sent to the policy engine.
type PolicyInput struct {
	Identity struct {
		AgentID       string   `json:"agent_id"`
		SessionID     string   `json:"session_id"`
		TenantID      string   `json:"tenant_id"`
		Role          string   `json:"role"`
		AllowedScopes []string `json:"allowed_scopes"`
	} `json:"identity"`
	Tool struct {
		ID         string `json:"id"`
		Risk       string `json:"risk"`
		SchemaHash string `json:"schema_hash"`
	} `json:"tool"`
	Action struct {
		Arguments  map[string]interface{} `json:"arguments"`
		Destination string                `json:"destination"`
		ResourceID string                 `json:"resource_id"`
	} `json:"action"`
	Context struct {
		Timestamp int64  `json:"timestamp"`
		ClientIP  string `json:"client_ip"`
	} `json:"context"`
}

// PolicyDecision represents the evaluated authorization outcome.
type PolicyDecision struct {
	Decision           string        `json:"decision"` // "ALLOW", "DENY", "APPROVE"
	Allowed            bool          `json:"allowed"`
	RequiresApproval   bool          `json:"requires_approval"`
	RuleIDs            []string      `json:"rule_ids"`
	Reasons            []string      `json:"reasons"`
	PolicyVersion      string        `json:"policy_version"`
	Checksum           string        `json:"checksum"`
	EvaluationDuration time.Duration `json:"evaluation_duration"`
}

// Engine wraps an in-memory OPA Rego evaluator with prepared queries for sub-millisecond latency.
type Engine struct {
	mu            sync.RWMutex
	version       string
	regoCode      string
	checksum      string
	preparedQuery rego.PreparedEvalQuery
}

// NewEngine initializes the OPA policy engine with given Rego code.
func NewEngine(version, regoCode string) (*Engine, error) {
	if version == "" {
		version = "v1.0.0"
	}
	e := &Engine{
		version: version,
	}
	if err := e.compile(regoCode); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) compile(code string) error {
	ctx := context.Background()

	h := sha256.Sum256([]byte(code))
	checksum := hex.EncodeToString(h[:])

	// Create and prepare evaluation query for high performance
	r := rego.New(
		rego.Query("data.agentshield.authz"),
		rego.Module("default.rego", code),
	)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCompilationFailed, err)
	}

	e.regoCode = code
	e.checksum = checksum
	e.preparedQuery = pq
	return nil
}

// Evaluate runs the prepared query against the provided PolicyInput.
func (e *Engine) Evaluate(ctx context.Context, input PolicyInput) (*PolicyDecision, error) {
	e.mu.RLock()
	pq := e.preparedQuery
	version := e.version
	checksum := e.checksum
	e.mu.RUnlock()

	t0 := time.Now()
	rs, err := pq.Eval(ctx, rego.EvalInput(input))
	latency := time.Since(t0)

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvaluationFailed, err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return &PolicyDecision{
			Decision:           "DENY",
			Allowed:            false,
			RequiresApproval:   false,
			RuleIDs:            []string{"RULE_DEFAULT_DENY"},
			Reasons:            []string{"Empty policy evaluation output - defaulting to DENY"},
			PolicyVersion:      version,
			Checksum:           checksum,
			EvaluationDuration: latency,
		}, nil
	}

	evalMap, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected policy expression output format")
	}

	decision, _ := evalMap["decision"].(string)
	if decision == "" {
		decision = "DENY"
	}

	allowed, _ := evalMap["allowed"].(bool)
	requiresApproval, _ := evalMap["requires_approval"].(bool)

	// Extract rule_ids
	var ruleIDs []string
	if rawRules, ok := evalMap["rule_ids"].([]interface{}); ok {
		for _, r := range rawRules {
			if s, ok := r.(string); ok {
				ruleIDs = append(ruleIDs, s)
			}
		}
	}

	// Extract reasons
	var reasons []string
	if rawReasons, ok := evalMap["reasons"].([]interface{}); ok {
		for _, r := range rawReasons {
			if s, ok := r.(string); ok {
				reasons = append(reasons, s)
			}
		}
	}

	if len(reasons) == 0 {
		reasons = append(reasons, fmt.Sprintf("Decision outcome: %s", decision))
	}

	return &PolicyDecision{
		Decision:           decision,
		Allowed:            allowed,
		RequiresApproval:   requiresApproval,
		RuleIDs:            ruleIDs,
		Reasons:            reasons,
		PolicyVersion:      version,
		Checksum:           checksum,
		EvaluationDuration: latency,
	}, nil
}

// GetInfo returns metadata about the current policy engine state.
func (e *Engine) GetInfo() (version, checksum, code string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.version, e.checksum, e.regoCode
}

// Reload updates the engine with fresh Rego policy code at runtime.
func (e *Engine) Reload(newCode string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.compile(newCode)
}
