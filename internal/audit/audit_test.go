package audit

import (
	"testing"
)

func TestAudit_Redaction(t *testing.T) {
	rawArgs := map[string]interface{}{
		"query":         "financial statements",
		"api_key":       "sk-1234567890abcdef",
		"password":      "SuperSecretP@ssword",
		"nested": map[string]interface{}{
			"client_secret": "my-client-secret-999",
			"public_info":   "welcome",
		},
		"auth_header": "Bearer eyJhbGciOiJIUzI1NiIsIn...",
	}

	redacted := RedactMap(rawArgs)

	if redacted["query"] != "financial statements" {
		t.Errorf("unrelated field should not be redacted, got: %v", redacted["query"])
	}
	if redacted["api_key"] != "[REDACTED]" {
		t.Errorf("expected api_key to be redacted, got: %v", redacted["api_key"])
	}
	if redacted["password"] != "[REDACTED]" {
		t.Errorf("expected password to be redacted, got: %v", redacted["password"])
	}

	nested, ok := redacted["nested"].(map[string]interface{})
	if !ok || nested["client_secret"] != "[REDACTED]" {
		t.Errorf("expected nested client_secret to be redacted, got: %v", nested)
	}
	if nested["public_info"] != "welcome" {
		t.Errorf("expected public_info preserved, got: %v", nested["public_info"])
	}
}

func TestAudit_StoreRecordAndQuery(t *testing.T) {
	store := NewStore()

	store.Record(AuditEvent{
		CorrelationID:   "corr-101",
		AgentID:         "agent-01",
		TenantID:        "tenant-alpha",
		ToolID:          "search_docs",
		Outcome:         "ALLOW",
		PolicyLatencyMs: 0.15,
		Arguments:       map[string]interface{}{"query": "sales", "token": "secret-token"},
	})

	store.Record(AuditEvent{
		CorrelationID:   "corr-102",
		AgentID:         "agent-02",
		TenantID:        "tenant-beta",
		ToolID:          "export_data",
		Outcome:         "DENY",
		PolicyLatencyMs: 0.22,
		Arguments:       map[string]interface{}{"dest": "http://evil.com"},
	})

	// Query by correlation ID
	ev, err := store.GetByCorrelationID("corr-101")
	if err != nil {
		t.Fatalf("expected to find corr-101: %v", err)
	}
	if ev.Arguments["token"] != "[REDACTED]" {
		t.Errorf("stored arguments should be redacted, got: %v", ev.Arguments["token"])
	}

	// Query by outcome
	denied := store.Query(AuditFilter{Outcome: "DENY"})
	if len(denied) != 1 || denied[0].CorrelationID != "corr-102" {
		t.Fatalf("expected 1 denied event, got %d", len(denied))
	}

	// Stats
	stats := store.Stats()
	if stats.TotalCalls != 2 || stats.AllowedCalls != 1 || stats.DeniedCalls != 1 {
		t.Errorf("unexpected stats: %+v", stats)
	}
}
