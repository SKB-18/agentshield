package identity

import (
	"testing"
	"time"
)

func TestTokenManager_IssueAndVerify(t *testing.T) {
	tm := NewTokenManager("test-secret-key-12345", "test-issuer", "test-aud")

	token, err := tm.IssueToken("agent-007", "tenant-alpha", "analyst", []string{"tools:read", "tools:execute"}, 10*time.Minute)
	if err != nil {
		t.Fatalf("expected no error issuing token, got: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	claims, err := tm.VerifyToken(token)
	if err != nil {
		t.Fatalf("expected valid token, got: %v", err)
	}

	if claims.AgentID != "agent-007" {
		t.Errorf("expected AgentID agent-007, got %s", claims.AgentID)
	}
	if claims.TenantID != "tenant-alpha" {
		t.Errorf("expected TenantID tenant-alpha, got %s", claims.TenantID)
	}
	if claims.Role != "analyst" {
		t.Errorf("expected Role analyst, got %s", claims.Role)
	}
	if len(claims.AllowedScopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(claims.AllowedScopes))
	}
}

func TestTokenManager_ExpiredToken(t *testing.T) {
	tm := NewTokenManager("test-secret-key-12345", "test-issuer", "test-aud")

	// Issue token with -1s duration (already expired)
	token, err := tm.IssueToken("agent-expired", "tenant-alpha", "reader", nil, -1*time.Second)
	if err != nil {
		t.Fatalf("unexpected error issuing token: %v", err)
	}

	_, err = tm.VerifyToken(token)
	if err == nil {
		t.Fatal("expected error verifying expired token, got nil")
	}
}

func TestTokenManager_Revocation(t *testing.T) {
	tm := NewTokenManager("test-secret-key-12345", "test-issuer", "test-aud")

	token, err := tm.IssueToken("agent-revoked", "tenant-alpha", "reader", nil, 10*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := tm.VerifyToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Revoke token ID
	tm.RevokeToken(claims.ID)

	_, err = tm.VerifyToken(token)
	if err != ErrRevokedToken {
		t.Fatalf("expected ErrRevokedToken, got: %v", err)
	}
}

func TestTokenManager_TamperedSignature(t *testing.T) {
	tm1 := NewTokenManager("secret-key-1", "test-issuer", "test-aud")
	tm2 := NewTokenManager("secret-key-2", "test-issuer", "test-aud")

	token, err := tm1.IssueToken("agent-hacker", "tenant-alpha", "admin", nil, 10*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify with different key should fail
	_, err = tm2.VerifyToken(token)
	if err == nil {
		t.Fatal("expected verification failure with mismatched secret key, got nil")
	}
}
