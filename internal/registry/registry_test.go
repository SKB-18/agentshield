package registry

import (
	"testing"
)

func sampleRegistry() *Registry {
	r := NewRegistry()

	r.Register(ToolDescriptor{
		ID:          "search_docs",
		Name:        "Document Search",
		Description: "Search internal knowledge base",
		Version:     "1.0.0",
		Risk:        RiskLow,
		AllowedDestinations: []string{
			"kb.internal.company.com",
		},
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"query", "dataset_id"},
			"properties": map[string]interface{}{
				"query":      map[string]interface{}{"type": "string", "minLength": 1},
				"dataset_id": map[string]interface{}{"type": "string"},
				"limit":      map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 50},
			},
		},
		TimeoutMs:        3000,
		MaxResponseBytes: 32 * 1024,
		Enabled:          true,
	})

	r.Register(ToolDescriptor{
		ID:          "export_data",
		Name:        "Data Exporter",
		Description: "Export data to certified partner endpoints",
		Version:     "1.0.0",
		Risk:        RiskHigh,
		AllowedDestinations: []string{
			"https://export.partner.com",
			"s3.corporate.internal",
		},
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"destination_url", "format"},
			"properties": map[string]interface{}{
				"destination_url": map[string]interface{}{"type": "string", "format": "uri"},
				"format":          map[string]interface{}{"type": "string", "enum": []string{"json", "csv"}},
			},
		},
		RequiresApproval: true,
		Enabled:          true,
	})

	return r
}

func TestRegistry_Validation(t *testing.T) {
	r := sampleRegistry()

	// Valid search_docs arguments
	err := r.ValidateArguments("search_docs", map[string]interface{}{
		"query":      "quarterly revenue",
		"dataset_id": "kb-public",
		"limit":      10,
	})
	if err != nil {
		t.Fatalf("expected valid arguments, got error: %v", err)
	}

	// Invalid: missing required dataset_id
	err = r.ValidateArguments("search_docs", map[string]interface{}{
		"query": "quarterly revenue",
	})
	if err == nil {
		t.Fatal("expected schema validation error for missing dataset_id, got nil")
	}

	// Invalid: limit exceeds maximum
	err = r.ValidateArguments("search_docs", map[string]interface{}{
		"query":      "quarterly revenue",
		"dataset_id": "kb-public",
		"limit":      1000,
	})
	if err == nil {
		t.Fatal("expected schema validation error for limit > 50, got nil")
	}
}

func TestRegistry_DestinationChecking(t *testing.T) {
	r := sampleRegistry()

	// Allowed destination
	allowed, reason := r.CheckDestination("export_data", "https://export.partner.com/api/v1/dump")
	if !allowed {
		t.Fatalf("expected destination to be allowed, got: %s", reason)
	}

	// Blocked destination (arbitrary attacker endpoint)
	allowed, _ = r.CheckDestination("export_data", "https://attacker.evil.com/exfiltrate")
	if allowed {
		t.Fatal("expected attacker destination to be blocked")
	}

	// Blocked SSRF: AWS metadata endpoint
	allowed, reason = r.CheckDestination("export_data", "http://169.254.169.254/latest/meta-data")
	if allowed {
		t.Fatal("expected 169.254.169.254 to be blocked by SSRF protection")
	}
	if reason == "" {
		t.Fatal("expected explanation reason for SSRF block")
	}
}
