package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrEventNotFound = errors.New("audit event not found")
)

// AuditEvent represents an immutable decision & execution log record.
type AuditEvent struct {
	ID                 string                 `json:"id"`
	CorrelationID      string                 `json:"correlation_id"`
	Timestamp          time.Time              `json:"timestamp"`
	AgentID            string                 `json:"agent_id"`
	TenantID           string                 `json:"tenant_id"`
	ToolID             string                 `json:"tool_id"`
	ResourceID         string                 `json:"resource_id,omitempty"`
	Outcome            string                 `json:"outcome"` // "ALLOW", "DENY", "APPROVE"
	RuleIDs            []string               `json:"rule_ids"`
	Reason             string                 `json:"reason"`
	Arguments          map[string]interface{} `json:"arguments"`
	PolicyLatencyMs    float64                `json:"policy_latency_ms"`
	ExecutionLatencyMs float64                `json:"execution_latency_ms"`
	ClientIP           string                 `json:"client_ip,omitempty"`
}

// AuditFilter defines search parameters for querying audit logs.
type AuditFilter struct {
	CorrelationID string
	AgentID       string
	TenantID      string
	ToolID        string
	Outcome       string
	Limit         int
}

// AuditStats summarizes high-level telemetry for dashboards.
type AuditStats struct {
	TotalCalls       int     `json:"total_calls"`
	AllowedCalls     int     `json:"allowed_calls"`
	DeniedCalls      int     `json:"denied_calls"`
	ApprovalCalls    int     `json:"approval_calls"`
	AvgPolicyLatency float64 `json:"avg_policy_latency_ms"`
}

// Store provides an in-memory thread-safe audit log repository.
type Store struct {
	mu     sync.RWMutex
	events []*AuditEvent
}

// NewStore initializes a new audit store.
func NewStore() *Store {
	return &Store{
		events: make([]*AuditEvent, 0, 1000),
	}
}

// Record persists an audit event after applying privacy redactions.
func (s *Store) Record(event AuditEvent) *AuditEvent {
	if event.ID == "" {
		event.ID = fmt.Sprintf("aud_%s", uuid.New().String())
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Apply sensitive data redactions
	event.Arguments = RedactMap(event.Arguments)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, &event)

	return &event
}

// Query retrieves audit events matching the provided filter, newest first.
func (s *Store) Query(f AuditFilter) []*AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matched []*AuditEvent
	for i := len(s.events) - 1; i >= 0; i-- {
		ev := s.events[i]

		if f.CorrelationID != "" && ev.CorrelationID != f.CorrelationID {
			continue
		}
		if f.AgentID != "" && ev.AgentID != f.AgentID {
			continue
		}
		if f.TenantID != "" && ev.TenantID != f.TenantID {
			continue
		}
		if f.ToolID != "" && ev.ToolID != f.ToolID {
			continue
		}
		if f.Outcome != "" && ev.Outcome != f.Outcome {
			continue
		}

		matched = append(matched, ev)
		if f.Limit > 0 && len(matched) >= f.Limit {
			break
		}
	}
	return matched
}

// GetByCorrelationID retrieves an audit event by correlation ID.
func (s *Store) GetByCorrelationID(corrID string) (*AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, ev := range s.events {
		if ev.CorrelationID == corrID {
			return ev, nil
		}
	}
	return nil, ErrEventNotFound
}

// Stats computes summary metrics across the audit history.
func (s *Store) Stats() AuditStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := AuditStats{TotalCalls: len(s.events)}
	var sumPolicyLatency float64

	for _, ev := range s.events {
		switch ev.Outcome {
		case "ALLOW":
			stats.AllowedCalls++
		case "DENY":
			stats.DeniedCalls++
		case "APPROVE":
			stats.ApprovalCalls++
		}
		sumPolicyLatency += ev.PolicyLatencyMs
	}

	if stats.TotalCalls > 0 {
		stats.AvgPolicyLatency = sumPolicyLatency / float64(stats.TotalCalls)
	}

	return stats
}

// RedactMap recursively walks a map and masks sensitive keys or string patterns.
func RedactMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	sensitiveKeys := []string{"password", "secret", "token", "api_key", "apikey", "credential", "auth", "private_key", "bearer"}

	for k, v := range m {
		lowerKey := strings.ToLower(k)
		isSensitive := false
		for _, sk := range sensitiveKeys {
			if strings.Contains(lowerKey, sk) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			out[k] = "[REDACTED]"
			continue
		}

		switch val := v.(type) {
		case string:
			if strings.HasPrefix(strings.ToLower(val), "bearer ") || strings.HasPrefix(val, "sk-") {
				out[k] = "[REDACTED]"
			} else {
				out[k] = val
			}
		case map[string]interface{}:
			out[k] = RedactMap(val)
		default:
			out[k] = v
		}
	}
	return out
}

// ToJSON returns pretty JSON representation of the audit envelope.
func (ev *AuditEvent) ToJSON() string {
	b, _ := json.MarshalIndent(ev, "", "  ")
	return string(b)
}
