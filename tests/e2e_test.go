package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/SKB-18/agentshield/internal/approval"
	"github.com/SKB-18/agentshield/internal/attacklab"
	"github.com/SKB-18/agentshield/internal/audit"
	"github.com/SKB-18/agentshield/internal/identity"
	"github.com/SKB-18/agentshield/internal/policy"
	"github.com/SKB-18/agentshield/internal/proxy"
	"github.com/SKB-18/agentshield/internal/registry"
	"github.com/SKB-18/agentshield/internal/tools"
)

func setupTestServer(t *testing.T) (http.Handler, *identity.TokenManager) {
	tokens := identity.NewTokenManager("e2e-secret-key-12345", "agentshield-auth", "agentshield-gateway")
	reg := registry.NewRegistry()
	registry.RegisterDefaultTools(reg)

	pol, err := policy.NewEngine("v1.0.0", policy.DefaultRegoCode)
	if err != nil {
		t.Fatalf("failed to init policy: %v", err)
	}

	appr := approval.NewService()
	aud := audit.NewStore()
	exec := tools.NewToolExecutor("/workspace/data")
	gwProxy := proxy.NewGatewayProxy(tokens, reg, pol, appr, aud, exec)
	runner := attacklab.NewLabRunner(gwProxy, tokens, appr)

	r := chi.NewRouter()

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	r.Route("/v1", func(v1 chi.Router) {
		v1.Post("/auth/token", func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				AgentID  string   `json:"agent_id"`
				TenantID string   `json:"tenant_id"`
				Role     string   `json:"role"`
				Scopes   []string `json:"scopes"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			token, _ := tokens.IssueToken(body.AgentID, body.TenantID, body.Role, body.Scopes, 1*time.Hour)
			json.NewEncoder(w).Encode(map[string]interface{}{"token": token})
		})

		v1.Post("/tool-calls", func(w http.ResponseWriter, r *http.Request) {
			var req proxy.Request
			json.NewDecoder(r.Body).Decode(&req)
			resp, _ := gwProxy.HandleToolCall(r.Context(), req, "127.0.0.1")
			if resp.Outcome == "DENY" {
				w.WriteHeader(http.StatusForbidden)
			} else if resp.Outcome == "APPROVE" {
				w.WriteHeader(http.StatusAccepted)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			json.NewEncoder(w).Encode(resp)
		})

		v1.Get("/tools", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(reg.List())
		})

		v1.Get("/approvals", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(appr.ListAll())
		})

		v1.Post("/approvals/{id}/decision", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			var body struct {
				Approver string `json:"approver"`
				Approved bool   `json:"approved"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			rec, _ := appr.DecideApproval(id, body.Approver, body.Approved)
			json.NewEncoder(w).Encode(rec)
		})

		v1.Post("/approvals/{id}/execute", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			var body struct {
				Arguments map[string]interface{} `json:"arguments"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			res, err := gwProxy.ExecuteApproved(r.Context(), id, body.Arguments)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(res)
		})

		v1.Get("/audit", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(aud.Query(audit.AuditFilter{}))
		})

		v1.Get("/audit/stats", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(aud.Stats())
		})

		v1.Post("/attack-lab/run", func(w http.ResponseWriter, r *http.Request) {
			report, _ := runner.Run(r.Context())
			json.NewEncoder(w).Encode(report)
		})
	})

	return r, tokens
}

func TestE2E_Health(t *testing.T) {
	handler, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
}

func TestE2E_ToolCallLifecycle(t *testing.T) {
	handler, tm := setupTestServer(t)

	token, _ := tm.IssueToken("agent-reader", "tenant-alpha", "reader", []string{"tools:read"}, 1*time.Hour)

	// 1. Legitimate search_docs -> 200 OK (ALLOW)
	allowBody, _ := json.Marshal(proxy.Request{
		AgentToken: token,
		ToolID:     "search_docs",
		Arguments: map[string]interface{}{
			"query":      "system architecture",
			"dataset_id": "kb-public",
		},
	})

	req := httptest.NewRequest("POST", "/v1/tool-calls", bytes.NewReader(allowBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for allowed call, got %d (body: %s)", w.Code, w.Body.String())
	}

	var allowResp proxy.Response
	json.NewDecoder(w.Body).Decode(&allowResp)
	if allowResp.Outcome != "ALLOW" {
		t.Errorf("expected outcome ALLOW, got %s", allowResp.Outcome)
	}

	// 2. Cross-tenant access attempt -> 403 Forbidden (DENY)
	denyBody, _ := json.Marshal(proxy.Request{
		AgentToken: token,
		ToolID:     "search_docs",
		Arguments: map[string]interface{}{
			"query":      "steal secrets",
			"dataset_id": "kb-tenant-beta", // Prohibited cross-tenant
		},
	})

	req = httptest.NewRequest("POST", "/v1/tool-calls", bytes.NewReader(denyBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant attack, got %d", w.Code)
	}

	// 3. High-risk call with Analyst token -> 202 Accepted (APPROVE)
	analystToken, _ := tm.IssueToken("agent-analyst", "tenant-alpha", "analyst", []string{"tools:execute"}, 1*time.Hour)
	emailArgs := map[string]interface{}{
		"to":      "officer@company.internal",
		"subject": "Monthly Report",
	}

	approveBody, _ := json.Marshal(proxy.Request{
		AgentToken: analystToken,
		ToolID:     "send_email",
		Arguments:  emailArgs,
	})

	req = httptest.NewRequest("POST", "/v1/tool-calls", bytes.NewReader(approveBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for approval ticket, got %d", w.Code)
	}

	var apprResp proxy.Response
	json.NewDecoder(w.Body).Decode(&apprResp)
	if apprResp.ApprovalID == "" {
		t.Fatal("expected approval ID in response")
	}

	// 4. Human Decision: Approve
	decBody, _ := json.Marshal(map[string]interface{}{
		"approver": "sec-admin",
		"approved": true,
	})
	req = httptest.NewRequest("POST", "/v1/approvals/"+apprResp.ApprovalID+"/decision", bytes.NewReader(decBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK deciding approval, got %d", w.Code)
	}

	// 5. Execute Approved Ticket
	execBody, _ := json.Marshal(map[string]interface{}{"arguments": emailArgs})
	req = httptest.NewRequest("POST", "/v1/approvals/"+apprResp.ApprovalID+"/execute", bytes.NewReader(execBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK executing approved ticket, got %d", w.Code)
	}

	// 6. Verify Audit Trail Contains the events
	req = httptest.NewRequest("GET", "/v1/audit", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var auditEvents []audit.AuditEvent
	json.NewDecoder(w.Body).Decode(&auditEvents)
	if len(auditEvents) < 3 {
		t.Fatalf("expected at least 3 recorded audit events, got %d", len(auditEvents))
	}
}

func TestE2E_AttackLabRun(t *testing.T) {
	handler, _ := setupTestServer(t)

	req := httptest.NewRequest("POST", "/v1/attack-lab/run", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from attack lab run, got %d", w.Code)
	}

	var report attacklab.BenchmarkReport
	json.NewDecoder(w.Body).Decode(&report)

	if report.TotalCases == 0 {
		t.Fatal("expected non-zero benchmark test cases")
	}
	if report.AttackBlockedPct < 100.0 {
		t.Errorf("expected 100%% attack blocked rate, got %.1f%%", report.AttackBlockedPct)
	}
	if report.FalseDenyPct > 0.0 {
		t.Errorf("expected 0%% false deny rate, got %.1f%%", report.FalseDenyPct)
	}
}
