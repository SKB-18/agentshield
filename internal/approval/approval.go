package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrApprovalNotFound     = errors.New("approval request not found")
	ErrApprovalExpired      = errors.New("approval request has expired")
	ErrApprovalAlreadyDecided = errors.New("approval request has already been decided")
	ErrApprovalNotApproved  = errors.New("approval request has not been approved")
	ErrApprovalAlreadyConsumed = errors.New("approval replay detected: approval token has already been executed")
	ErrArgumentHashMismatch = errors.New("argument tampering detected: arguments do not match approved envelope")
)

type ApprovalState string

const (
	StatePending  ApprovalState = "PENDING"
	StateApproved ApprovalState = "APPROVED"
	StateRejected ApprovalState = "REJECTED"
	StateExpired  ApprovalState = "EXPIRED"
	StateConsumed ApprovalState = "CONSUMED"
)

// ApprovalRecord durable entity tracking human authorization lifecycle.
type ApprovalRecord struct {
	ID            string                 `json:"id"`
	DecisionID    string                 `json:"decision_id"`
	AgentID       string                 `json:"agent_id"`
	TenantID      string                 `json:"tenant_id"`
	ToolID        string                 `json:"tool_id"`
	ResourceID    string                 `json:"resource_id"`
	Arguments     map[string]interface{} `json:"arguments"`
	ArgumentsHash string                 `json:"arguments_hash"`
	Reason        string                 `json:"reason"`
	State         ApprovalState          `json:"state"`
	Approver      string                 `json:"approver,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
	DecisionTime  *time.Time             `json:"decision_time,omitempty"`
	ConsumedTime  *time.Time             `json:"consumed_time,omitempty"`
}

// Service manages the approval queue, state transitions, and replay-protection.
type Service struct {
	mu        sync.RWMutex
	approvals map[string]*ApprovalRecord
}

// NewService initializes an in-memory thread-safe approval service.
func NewService() *Service {
	return &Service{
		approvals: make(map[string]*ApprovalRecord),
	}
}

// ComputeArgumentsHash generates a deterministic SHA256 hex digest of argument JSON.
func ComputeArgumentsHash(args map[string]interface{}) string {
	b, _ := json.Marshal(args)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// CreateApproval creates a pending approval record bound to exact argument hash.
func (s *Service) CreateApproval(agentID, tenantID, toolID, resourceID string, args map[string]interface{}, reason string, ttl time.Duration) (*ApprovalRecord, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	now := time.Now().UTC()
	id := fmt.Sprintf("appr_%s", uuid.New().String())
	decisionID := fmt.Sprintf("dec_%s", uuid.New().String())
	argHash := ComputeArgumentsHash(args)

	record := &ApprovalRecord{
		ID:            id,
		DecisionID:    decisionID,
		AgentID:       agentID,
		TenantID:      tenantID,
		ToolID:        toolID,
		ResourceID:    resourceID,
		Arguments:     args,
		ArgumentsHash: argHash,
		Reason:        reason,
		State:         StatePending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.approvals[id] = record

	return record, nil
}

// GetApproval retrieves an approval by ID, updating expired state lazily.
func (s *Service) GetApproval(id string) (*ApprovalRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.approvals[id]
	if !exists {
		return nil, ErrApprovalNotFound
	}

	// Lazy expiration check
	if record.State == StatePending && time.Now().UTC().After(record.ExpiresAt) {
		record.State = StateExpired
	}

	return record, nil
}

// DecideApproval approves or rejects a pending ticket.
func (s *Service) DecideApproval(id, approver string, approve bool) (*ApprovalRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.approvals[id]
	if !exists {
		return nil, ErrApprovalNotFound
	}

	now := time.Now().UTC()
	if record.State == StatePending && now.After(record.ExpiresAt) {
		record.State = StateExpired
		return record, ErrApprovalExpired
	}

	if record.State != StatePending {
		return record, fmt.Errorf("%w: current state is %s", ErrApprovalAlreadyDecided, record.State)
	}

	record.Approver = approver
	record.DecisionTime = &now
	if approve {
		record.State = StateApproved
	} else {
		record.State = StateRejected
	}

	return record, nil
}

// ConsumeApproval enforces single-use execution and cryptographic argument binding.
func (s *Service) ConsumeApproval(id, expectedToolID string, args map[string]interface{}) (*ApprovalRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.approvals[id]
	if !exists {
		return nil, ErrApprovalNotFound
	}

	now := time.Now().UTC()
	if now.After(record.ExpiresAt) {
		record.State = StateExpired
		return nil, ErrApprovalExpired
	}

	if record.State == StateConsumed {
		return nil, ErrApprovalAlreadyConsumed
	}

	if record.State != StateApproved {
		return nil, fmt.Errorf("%w: ticket state is %s", ErrApprovalNotApproved, record.State)
	}

	if record.ToolID != expectedToolID {
		return nil, fmt.Errorf("tool mismatch: ticket was approved for '%s', requested '%s'", record.ToolID, expectedToolID)
	}

	// Verify cryptographic argument binding to defeat parameter tampering
	reqHash := ComputeArgumentsHash(args)
	if reqHash != record.ArgumentsHash {
		return nil, fmt.Errorf("%w: approved hash %s != requested hash %s", ErrArgumentHashMismatch, record.ArgumentsHash, reqHash)
	}

	// Mark CONSUMED (single-use replay prevention)
	record.State = StateConsumed
	record.ConsumedTime = &now

	return record, nil
}

// ListPending returns all currently pending unexpired approval records.
func (s *Service) ListPending() []*ApprovalRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var pending []*ApprovalRecord
	for _, rec := range s.approvals {
		if rec.State == StatePending {
			if now.After(rec.ExpiresAt) {
				rec.State = StateExpired
			} else {
				pending = append(pending, rec)
			}
		}
	}
	return pending
}

// ListAll returns all approval records.
func (s *Service) ListAll() []*ApprovalRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ApprovalRecord, 0, len(s.approvals))
	for _, rec := range s.approvals {
		result = append(result, rec)
	}
	return result
}
