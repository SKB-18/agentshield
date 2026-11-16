package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrUnknownTool      = errors.New("unknown tool implementation")
	ErrPathTraversal    = errors.New("security violation: path traversal detected")
	ErrExecutionTimeout = errors.New("tool execution exceeded deadline")
	ErrResponseSizeCap  = errors.New("tool response exceeded max response size cap")
)

// ToolExecutor executes mock tools in a safe, sandboxed environment.
type ToolExecutor struct {
	baseDir string // Sandboxed directory root for file operations
}

// NewToolExecutor initializes the executor.
func NewToolExecutor(baseDir string) *ToolExecutor {
	if baseDir == "" {
		baseDir = "/workspace/data"
	}
	return &ToolExecutor{
		baseDir: filepath.Clean(baseDir),
	}
}

// Execute runs the requested tool with timeout, sandbox constraints, and output cap.
func (e *ToolExecutor) Execute(ctx context.Context, toolID string, args map[string]interface{}, maxBytes int) (map[string]interface{}, error) {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}

	resultChan := make(chan struct {
		data map[string]interface{}
		err  error
	}, 1)

	go func() {
		var res map[string]interface{}
		var err error

		switch toolID {
		case "search_docs":
			res, err = e.execSearchDocs(args)
		case "read_file":
			res, err = e.execReadFile(args)
		case "send_email":
			res, err = e.execSendEmail(args)
		case "query_db":
			res, err = e.execQueryDB(args)
		case "export_data":
			res, err = e.execExportData(args)
		default:
			err = fmt.Errorf("%w: %s", ErrUnknownTool, toolID)
		}

		resultChan <- struct {
			data map[string]interface{}
			err  error
		}{data: res, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ErrExecutionTimeout
	case out := <-resultChan:
		if out.err != nil {
			return nil, out.err
		}

		// Enforce Response Size Cap
		raw, err := json.Marshal(out.data)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize tool output: %w", err)
		}
		if len(raw) > maxBytes {
			return nil, fmt.Errorf("%w: returned %d bytes (limit: %d bytes)", ErrResponseSizeCap, len(raw), maxBytes)
		}

		return out.data, nil
	}
}

// 1. search_docs
func (e *ToolExecutor) execSearchDocs(args map[string]interface{}) (map[string]interface{}, error) {
	query, _ := args["query"].(string)
	datasetID, _ := args["dataset_id"].(string)

	limit := 5
	if l, ok := args["limit"].(float64); ok && l > 0 {
		limit = int(l)
	}

	// Synthetic document corpus
	docs := []map[string]interface{}{
		{
			"id":        "doc_001",
			"dataset":   datasetID,
			"title":     "Q3 Architecture & Security Guidelines",
			"snippet":   fmt.Sprintf("Matched query '%s': Zero-trust access controls mandate that tool calls pass an independent policy evaluator.", query),
			"score":     0.94,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
		{
			"id":        "doc_002",
			"dataset":   datasetID,
			"title":     "Service Authorization Model",
			"snippet":   "All tools must declare allowed destinations and JSON schemas before being invoked by autonomous agents.",
			"score":     0.88,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	}

	if limit < len(docs) {
		docs = docs[:limit]
	}

	return map[string]interface{}{
		"query":        query,
		"dataset_id":   datasetID,
		"total_hits":   len(docs),
		"documents":    docs,
		"execution_ms": 12,
	}, nil
}

// 2. read_file
func (e *ToolExecutor) execReadFile(args map[string]interface{}) (map[string]interface{}, error) {
	path, _ := args["path"].(string)
	if path == "" {
		return nil, errors.New("missing 'path' argument")
	}

	cleanPath := filepath.Clean(filepath.ToSlash(path))

	// Detect Path Traversal or Absolute Escapes
	if strings.Contains(cleanPath, "..") || strings.HasPrefix(cleanPath, "/etc") || strings.HasPrefix(cleanPath, "C:") || strings.HasPrefix(cleanPath, "\\") {
		return nil, fmt.Errorf("%w: attempted access to prohibited path '%s'", ErrPathTraversal, path)
	}

	// Synthetic file system
	content := fmt.Sprintf("# Secure Workspace Config\n# Path: %s\nservice_mode: zero_trust\npolicy_version: 1.0.0", cleanPath)

	return map[string]interface{}{
		"path":         cleanPath,
		"bytes":        len(content),
		"content":      content,
		"sandboxed":    true,
		"execution_ms": 5,
	}, nil
}

// 3. send_email
func (e *ToolExecutor) execSendEmail(args map[string]interface{}) (map[string]interface{}, error) {
	to, _ := args["to"].(string)
	subject, _ := args["subject"].(string)
	body, _ := args["body"].(string)

	messageID := fmt.Sprintf("msg_%d", time.Now().UnixNano())

	return map[string]interface{}{
		"status":       "delivered",
		"message_id":   messageID,
		"to":           to,
		"subject":      subject,
		"body_bytes":   len(body),
		"delivered_at": time.Now().UTC().Format(time.RFC3339),
		"execution_ms": 45,
	}, nil
}

// 4. query_db
func (e *ToolExecutor) execQueryDB(args map[string]interface{}) (map[string]interface{}, error) {
	sql, _ := args["sql"].(string)
	database, _ := args["database"].(string)

	upperSQL := strings.ToUpper(strings.TrimSpace(sql))

	// Enforce Read-Only SQL Invariant
	if !strings.HasPrefix(upperSQL, "SELECT") && !strings.HasPrefix(upperSQL, "WITH") && !strings.HasPrefix(upperSQL, "EXPLAIN") {
		return nil, errors.New("destructive query rejected: only read-only statements (SELECT) permitted")
	}

	rows := []map[string]interface{}{
		{"metric": "total_active_agents", "value": 42},
		{"metric": "p95_tool_latency_ms", "value": 18.5},
		{"metric": "blocked_injection_attempts", "value": 128},
	}

	return map[string]interface{}{
		"database":     database,
		"sql":          sql,
		"row_count":    len(rows),
		"rows":         rows,
		"execution_ms": 19,
	}, nil
}

// 5. export_data
func (e *ToolExecutor) execExportData(args map[string]interface{}) (map[string]interface{}, error) {
	destURL, _ := args["destination_url"].(string)
	format, _ := args["format"].(string)

	return map[string]interface{}{
		"status":          "exported",
		"destination_url": destURL,
		"format":          format,
		"bytes_exported":  1024,
		"completed_at":    time.Now().UTC().Format(time.RFC3339),
		"execution_ms":    32,
	}, nil
}
