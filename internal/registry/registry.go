package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/xeipuuv/gojsonschema"
)

var (
	ErrToolNotFound       = errors.New("tool not found in registry")
	ErrToolDisabled       = errors.New("tool is currently disabled by administrator")
	ErrSchemaValidation   = errors.New("argument schema validation failed")
	ErrDestinationBlocked = errors.New("destination egress is disallowed for this tool")
)

// RiskLevel categorizes tool sensitivity.
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// ToolDescriptor defines trusted metadata, boundaries, and validation schemas for a registered tool.
type ToolDescriptor struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	Version             string                 `json:"version"`
	Risk                RiskLevel              `json:"risk"`
	AllowedDestinations []string               `json:"allowed_destinations"` // URL prefixes or hostnames allowed
	JSONSchema          map[string]interface{} `json:"json_schema"`
	SchemaHash          string                 `json:"schema_hash"`
	TimeoutMs           int                    `json:"timeout_ms"`
	MaxResponseBytes    int                    `json:"max_response_bytes"`
	RequiresApproval    bool                   `json:"requires_approval"`
	Enabled             bool                   `json:"enabled"`

	// internal compiled schema
	schemaLoader gojsonschema.JSONLoader `json:"-"`
}

// Registry manages thread-safe tool registration and verification.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]*ToolDescriptor
}

// NewRegistry initializes an empty thread-safe Registry.
func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]*ToolDescriptor),
	}
}

// RegisterDefaultTools populates the registry with standard enterprise simulated tools.
func RegisterDefaultTools(reg *Registry) {
	reg.Register(ToolDescriptor{
		ID:          "search_docs",
		Name:        "Document Search",
		Description: "Search internal knowledge base with tenant isolation",
		Version:     "1.0.0",
		Risk:        RiskLow,
		AllowedDestinations: []string{"kb.internal.company.com"},
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"dataset_id"},
			"properties": map[string]interface{}{
				"query":      map[string]interface{}{"type": "string"},
				"dataset_id": map[string]interface{}{"type": "string"},
				"limit":      map[string]interface{}{"type": "integer", "maximum": 50},
			},
		},
		TimeoutMs:        3000,
		MaxResponseBytes: 32 * 1024,
		Enabled:          true,
	})

	reg.Register(ToolDescriptor{
		ID:          "read_file",
		Name:        "Workspace File Reader",
		Description: "Read sandboxed configuration files",
		Version:     "1.0.0",
		Risk:        RiskMedium,
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"path"},
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string"},
			},
		},
		TimeoutMs:        3000,
		MaxResponseBytes: 64 * 1024,
		Enabled:          true,
	})

	reg.Register(ToolDescriptor{
		ID:          "query_db",
		Name:        "Database Analytics Query",
		Description: "Execute read-only SQL queries on analytical data",
		Version:     "1.0.0",
		Risk:        RiskMedium,
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"sql", "database"},
			"properties": map[string]interface{}{
				"sql":      map[string]interface{}{"type": "string"},
				"database": map[string]interface{}{"type": "string"},
			},
		},
		TimeoutMs:        5000,
		MaxResponseBytes: 128 * 1024,
		Enabled:          true,
	})

	reg.Register(ToolDescriptor{
		ID:          "send_email",
		Name:        "Outbound Notification Email",
		Description: "Send operational emails (high-risk tool requiring approval)",
		Version:     "1.0.0",
		Risk:        RiskHigh,
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
		RequiresApproval: true,
		TimeoutMs:        4000,
		MaxResponseBytes: 16 * 1024,
		Enabled:          true,
	})

	reg.Register(ToolDescriptor{
		ID:          "export_data",
		Name:        "Data Exporter",
		Description: "Export data to partner endpoints (high-risk tool requiring approval)",
		Version:     "1.0.0",
		Risk:        RiskHigh,
		AllowedDestinations: []string{"https://export.partner.com", "s3.corporate.internal"},
		JSONSchema: map[string]interface{}{
			"type": "object",
			"required": []string{"destination_url"},
			"properties": map[string]interface{}{
				"destination_url": map[string]interface{}{"type": "string"},
				"format":          map[string]interface{}{"type": "string"},
				"role":            map[string]interface{}{"type": "string"},
			},
		},
		RequiresApproval: true,
		TimeoutMs:        5000,
		MaxResponseBytes: 64 * 1024,
		Enabled:          true,
	})
}


// Register registers or updates a tool descriptor.
func (r *Registry) Register(tool ToolDescriptor) error {
	if tool.ID == "" {
		return errors.New("tool ID cannot be empty")
	}
	if tool.TimeoutMs <= 0 {
		tool.TimeoutMs = 5000 // Default 5 seconds
	}
	if tool.MaxResponseBytes <= 0 {
		tool.MaxResponseBytes = 64 * 1024 // Default 64KB
	}

	// Compute SchemaHash
	schemaBytes, err := json.Marshal(tool.JSONSchema)
	if err != nil {
		return fmt.Errorf("invalid json schema: %w", err)
	}
	h := sha256.Sum256(schemaBytes)
	tool.SchemaHash = hex.EncodeToString(h[:])

	// Compile JSON schema loader
	tool.schemaLoader = gojsonschema.NewGoLoader(tool.JSONSchema)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[tool.ID] = &tool
	return nil
}

// Get retrieves a tool by ID.
func (r *Registry) Get(id string) (*ToolDescriptor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tool, exists := r.tools[id]
	if !exists {
		return nil, ErrToolNotFound
	}
	if !tool.Enabled {
		return nil, ErrToolDisabled
	}
	return tool, nil
}

// List returns all registered tools.
func (r *Registry) List() []ToolDescriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]ToolDescriptor, 0, len(r.tools))
	for _, t := range r.tools {
		result = append(result, *t)
	}
	return result
}

// ValidateArguments validates input arguments against the tool's JSON Schema.
func (r *Registry) ValidateArguments(toolID string, arguments map[string]interface{}) error {
	tool, err := r.Get(toolID)
	if err != nil {
		return err
	}

	if tool.schemaLoader == nil {
		return nil
	}

	documentLoader := gojsonschema.NewGoLoader(arguments)
	result, err := gojsonschema.Validate(tool.schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("schema evaluation error: %w", err)
	}

	if !result.Valid() {
		var errMsgs []string
		for _, desc := range result.Errors() {
			errMsgs = append(errMsgs, desc.String())
		}
		return fmt.Errorf("%w: %s", ErrSchemaValidation, strings.Join(errMsgs, "; "))
	}

	return nil
}

// CheckDestination verifies whether a destination URL/host is within allowed destinations.
func (r *Registry) CheckDestination(toolID string, target string) (bool, string) {
	tool, err := r.Get(toolID)
	if err != nil {
		return false, err.Error()
	}

	// If no restrictions are specified, default to internal only
	if len(tool.AllowedDestinations) == 0 {
		return false, "no allowed destinations configured for tool"
	}

	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" {
		// Treat as plain hostname or address
		for _, allowed := range tool.AllowedDestinations {
			if strings.EqualFold(allowed, target) || strings.HasSuffix(strings.ToLower(target), strings.ToLower(allowed)) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("target host '%s' not in allowed destinations", target)
	}

	host := strings.ToLower(parsed.Hostname())

	// SSRF Protection: Block cloud metadata and loopback IP addresses explicitly
	if host == "169.254.169.254" || host == "127.0.0.1" || host == "localhost" || strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") {
		for _, allowed := range tool.AllowedDestinations {
			if allowed == host {
				return true, ""
			}
		}
		return false, fmt.Sprintf("SSRF protection: prohibited destination '%s'", host)
	}

	for _, allowed := range tool.AllowedDestinations {
		allowedLower := strings.ToLower(allowed)
		if allowedLower == "*" || host == allowedLower || strings.HasSuffix(host, "."+allowedLower) || strings.HasPrefix(target, allowed) {
			return true, ""
		}
	}

	return false, fmt.Sprintf("destination host '%s' is not in allowed destinations: %v", host, tool.AllowedDestinations)
}
