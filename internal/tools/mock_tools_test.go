package tools

import (
	"context"
	"testing"
	"time"
)

func TestToolExecutor_SearchDocs(t *testing.T) {
	exec := NewToolExecutor("/workspace/data")
	ctx := context.Background()

	res, err := exec.Execute(ctx, "search_docs", map[string]interface{}{
		"query":      "zero trust",
		"dataset_id": "kb-public",
		"limit":      float64(2),
	}, 1024*1024)

	if err != nil {
		t.Fatalf("expected successful execution, got error: %v", err)
	}

	hits, ok := res["total_hits"].(int)
	if !ok || hits <= 0 {
		t.Errorf("expected positive total_hits, got %v", res["total_hits"])
	}
}

func TestToolExecutor_PathTraversalBlocked(t *testing.T) {
	exec := NewToolExecutor("/workspace/data")
	ctx := context.Background()

	traversalPaths := []string{
		"../../../../etc/passwd",
		"../secrets/keys.env",
		"/etc/shadow",
		"C:\\Windows\\System32\\config\\SAM",
	}

	for _, p := range traversalPaths {
		_, err := exec.Execute(ctx, "read_file", map[string]interface{}{
			"path": p,
		}, 1024*1024)

		if err == nil {
			t.Errorf("expected path traversal detection for '%s', got nil", p)
		}
	}
}

func TestToolExecutor_DestructiveSQLBlocked(t *testing.T) {
	exec := NewToolExecutor("/workspace/data")
	ctx := context.Background()

	queries := []string{
		"DROP TABLE users;",
		"DELETE FROM audit_log WHERE 1=1;",
		"UPDATE accounts SET balance = 0;",
		"INSERT INTO admins VALUES ('hacker');",
	}

	for _, q := range queries {
		_, err := exec.Execute(ctx, "query_db", map[string]interface{}{
			"sql":      q,
			"database": "production_analytics",
		}, 1024*1024)

		if err == nil {
			t.Errorf("expected destructive SQL rejection for '%s', got nil", q)
		}
	}
}

func TestToolExecutor_Timeout(t *testing.T) {
	exec := NewToolExecutor("/workspace/data")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	time.Sleep(2 * time.Millisecond) // Ensure context is expired

	_, err := exec.Execute(ctx, "search_docs", map[string]interface{}{
		"query":      "test",
		"dataset_id": "kb-public",
	}, 1024)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestToolExecutor_ResponseSizeCap(t *testing.T) {
	exec := NewToolExecutor("/workspace/data")
	ctx := context.Background()

	// MaxBytes set to 10 bytes (too small for standard response)
	_, err := exec.Execute(ctx, "search_docs", map[string]interface{}{
		"query":      "test",
		"dataset_id": "kb-public",
	}, 10)

	if err == nil {
		t.Fatal("expected response size cap violation error, got nil")
	}
}
