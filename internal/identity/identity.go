package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken   = errors.New("invalid or malformed token")
	ErrExpiredToken   = errors.New("token has expired")
	ErrRevokedToken   = errors.New("token has been revoked")
	ErrUntrustedIssuer= errors.New("untrusted token issuer")
)

// AgentClaims represents trusted claims extracted from cryptographically signed tokens.
type AgentClaims struct {
	AgentID       string   `json:"agent_id"`
	SessionID     string   `json:"session_id"`
	TenantID      string   `json:"tenant_id"`
	Role          string   `json:"role"` // "reader", "analyst", "admin"
	AllowedScopes []string `json:"allowed_scopes"`
	jwt.RegisteredClaims
}

// TokenManager handles issuing, validating, and revoking agent tokens.
type TokenManager struct {
	secretKey     []byte
	issuer        string
	audience      string
	revokedTokens sync.Map // tokenID (jti) -> revocationTime
}

// NewTokenManager initializes a JWT token manager with a secret key.
func NewTokenManager(secretKey string, issuer, audience string) *TokenManager {
	if secretKey == "" {
		secretKey = "agentshield-default-secret-key-change-in-prod"
	}
	if issuer == "" {
		issuer = "agentshield-identity-service"
	}
	if audience == "" {
		audience = "agentshield-gateway"
	}
	return &TokenManager{
		secretKey: []byte(secretKey),
		issuer:    issuer,
		audience:  audience,
	}
}

// IssueToken generates a signed JWT token with trusted claims.
func (tm *TokenManager) IssueToken(agentID, tenantID, role string, scopes []string, ttl time.Duration) (string, error) {
	if ttl == 0 {
		ttl = 1 * time.Hour
	}
	jti := uuid.New().String()
	sessionID := uuid.New().String()
	now := time.Now().UTC()

	claims := AgentClaims{
		AgentID:       agentID,
		SessionID:     sessionID,
		TenantID:      tenantID,
		Role:          role,
		AllowedScopes: scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tm.issuer,
			Subject:   agentID,
			Audience:  jwt.ClaimStrings{tm.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(tm.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// VerifyToken validates the JWT signature, expiry, and revocation state.
// Crucially, it maps the agent identity ONLY from trusted claims, preventing self-asserted roles.
func (tm *TokenManager) VerifyToken(tokenString string) (*AgentClaims, error) {
	if tokenString == "" {
		return nil, ErrInvalidToken
	}

	token, err := jwt.ParseWithClaims(tokenString, &AgentClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return tm.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*AgentClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.Issuer != tm.issuer {
		return nil, ErrUntrustedIssuer
	}

	// Check revocation denylist
	if claims.ID != "" {
		if _, revoked := tm.revokedTokens.Load(claims.ID); revoked {
			return nil, ErrRevokedToken
		}
	}

	return claims, nil
}

// RevokeToken adds the token JTI to the revocation denylist.
func (tm *TokenManager) RevokeToken(tokenID string) {
	if tokenID != "" {
		tm.revokedTokens.Store(tokenID, time.Now().UTC())
	}
}

// HashToken generates a deterministic SHA256 hex string for logging without exposing the token.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:8]) // First 8 bytes (16 hex chars)
}
