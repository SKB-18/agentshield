package approval

import (
	"testing"
	"time"
)

func TestApproval_HappyPath(t *testing.T) {
	svc := NewService()

	args := map[string]interface{}{
		"to":      "finance@company.internal",
		"subject": "Monthly Ledger",
	}

	appr, err := svc.CreateApproval("agent-01", "tenant-alpha", "send_email", "", args, "High risk tool", 5*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error creating approval: %v", err)
	}

	if appr.State != StatePending {
		t.Fatalf("expected StatePending, got %s", appr.State)
	}

	// Human approves
	appr, err = svc.DecideApproval(appr.ID, "security-admin-jane", true)
	if err != nil {
		t.Fatalf("unexpected error deciding approval: %v", err)
	}

	if appr.State != StateApproved {
		t.Fatalf("expected StateApproved, got %s", appr.State)
	}
	if appr.Approver != "security-admin-jane" {
		t.Errorf("expected Approver security-admin-jane, got %s", appr.Approver)
	}

	// Consume approval
	consumed, err := svc.ConsumeApproval(appr.ID, "send_email", args)
	if err != nil {
		t.Fatalf("unexpected error consuming approval: %v", err)
	}

	if consumed.State != StateConsumed {
		t.Fatalf("expected StateConsumed, got %s", consumed.State)
	}
}

func TestApproval_ReplayProtection(t *testing.T) {
	svc := NewService()

	args := map[string]interface{}{"data": "confidential"}
	appr, _ := svc.CreateApproval("agent-01", "tenant-alpha", "export_data", "", args, "Export", 5*time.Minute)
	svc.DecideApproval(appr.ID, "admin", true)

	// First execution succeeds
	_, err := svc.ConsumeApproval(appr.ID, "export_data", args)
	if err != nil {
		t.Fatalf("first consume should succeed: %v", err)
	}

	// Second execution (replay) MUST fail
	_, err = svc.ConsumeApproval(appr.ID, "export_data", args)
	if err != ErrApprovalAlreadyConsumed {
		t.Fatalf("expected ErrApprovalAlreadyConsumed on replay, got: %v", err)
	}
}

func TestApproval_ArgumentTamperingDetection(t *testing.T) {
	svc := NewService()

	originalArgs := map[string]interface{}{
		"destination": "https://approved.internal/api",
	}
	tamperedArgs := map[string]interface{}{
		"destination": "https://attacker.evil.com/dump", // Tampered parameter!
	}

	appr, _ := svc.CreateApproval("agent-01", "tenant-alpha", "export_data", "", originalArgs, "Export", 5*time.Minute)
	svc.DecideApproval(appr.ID, "admin", true)

	// Attempting to execute with tampered arguments MUST fail
	_, err := svc.ConsumeApproval(appr.ID, "export_data", tamperedArgs)
	if err == nil {
		t.Fatal("expected argument tampering error, got nil")
	}
}

func TestApproval_Expiration(t *testing.T) {
	svc := NewService()

	args := map[string]interface{}{"foo": "bar"}
	// Create with very short TTL
	appr, _ := svc.CreateApproval("agent-01", "tenant-alpha", "send_email", "", args, "Test", 5*time.Millisecond)

	time.Sleep(10 * time.Millisecond) // Let it expire

	// Decision on expired ticket fails
	_, err := svc.DecideApproval(appr.ID, "admin", true)
	if err != ErrApprovalExpired {
		t.Fatalf("expected ErrApprovalExpired, got: %v", err)
	}
}
