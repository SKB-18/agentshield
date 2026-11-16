package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/SKB-18/agentshield/internal/approval"
	"github.com/SKB-18/agentshield/internal/attacklab"
	"github.com/SKB-18/agentshield/internal/audit"
	"github.com/SKB-18/agentshield/internal/identity"
	"github.com/SKB-18/agentshield/internal/policy"
	"github.com/SKB-18/agentshield/internal/proxy"
	"github.com/SKB-18/agentshield/internal/registry"
	"github.com/SKB-18/agentshield/internal/tools"
)

func main() {
	port := os.Getenv("AGENTSHIELD_PORT")
	if port == "" {
		port = "8080"
	}
	jwtSecret := os.Getenv("AGENTSHIELD_JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "agentshield-super-secret-key-32-bytes!!"
	}

	log.Printf("[AgentShield] Initializing Zero-Trust Security Gateway...")

	// 1. Identity Manager
	tokens := identity.NewTokenManager(jwtSecret, "agentshield-auth", "agentshield-gateway")

	// 2. Tool Registry
	reg := registry.NewRegistry()
	registry.RegisterDefaultTools(reg)

	// 3. Policy Engine
	regoCode := policy.DefaultRegoCode
	if customRegoPath := os.Getenv("AGENTSHIELD_REGO_PATH"); customRegoPath != "" {
		if b, err := os.ReadFile(customRegoPath); err == nil {
			regoCode = string(b)
		}
	}

	policyEngine, err := policy.NewEngine("v1.0.0", regoCode)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize OPA policy engine: %v", err)
	}

	// 4. Approval Service
	approvals := approval.NewService()

	// 5. Audit Store
	auditStore := audit.NewStore()

	// 6. Tool Executor
	executor := tools.NewToolExecutor("/workspace/data")

	// 7. Gateway Proxy
	gwProxy := proxy.NewGatewayProxy(tokens, reg, policyEngine, approvals, auditStore, executor)

	// 8. Attack Lab Runner
	labRunner := attacklab.NewLabRunner(gwProxy, tokens, approvals)

	// Router setup
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// CORS configuration for UI
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health probes
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "healthy", "service": "agentshield-gateway"})
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ready": true, "policies_loaded": true})
	})

	// API Routes (v1)
	r.Route("/v1", func(v1 chi.Router) {
		// Auth helper for local test tokens
		v1.Post("/auth/token", func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				AgentID  string   `json:"agent_id"`
				TenantID string   `json:"tenant_id"`
				Role     string   `json:"role"`
				Scopes   []string `json:"scopes"`
				TTLSec   int      `json:"ttl_seconds"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if body.AgentID == "" {
				body.AgentID = "agent-local"
			}
			if body.TenantID == "" {
				body.TenantID = "tenant-alpha"
			}
			if body.Role == "" {
				body.Role = "analyst"
			}
			ttl := 1 * time.Hour
			if body.TTLSec > 0 {
				ttl = time.Duration(body.TTLSec) * time.Second
			}

			token, err := tokens.IssueToken(body.AgentID, body.TenantID, body.Role, body.Scopes, ttl)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"token":      token,
				"agent_id":   body.AgentID,
				"tenant_id":  body.TenantID,
				"role":       body.Role,
				"expires_in": int(ttl.Seconds()),
			})
		})

		// Tool Calls Execution Gateway
		v1.Post("/tool-calls", func(w http.ResponseWriter, r *http.Request) {
			var req proxy.Request
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
				return
			}

			resp, err := gwProxy.HandleToolCall(r.Context(), req, r.RemoteAddr)
			if err != nil {
				if resp != nil && resp.Outcome == "DENY" {
					writeJSON(w, http.StatusForbidden, resp)
					return
				}
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if resp.Outcome == "DENY" {
				writeJSON(w, http.StatusForbidden, resp)
				return
			} else if resp.Outcome == "APPROVE" {
				writeJSON(w, http.StatusAccepted, resp)
				return
			}

			writeJSON(w, http.StatusOK, resp)
		})

		// Policy Test (Dry Run)
		v1.Post("/policies/test", func(w http.ResponseWriter, r *http.Request) {
			var input policy.PolicyInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			dec, err := policyEngine.Evaluate(r.Context(), input)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, dec)
		})

		// View Active Policy
		v1.Get("/policies", func(w http.ResponseWriter, r *http.Request) {
			version, checksum, code := policyEngine.GetInfo()
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"version":   version,
				"checksum":  checksum,
				"rego_code": code,
			})
		})

		// List Tools
		v1.Get("/tools", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, reg.List())
		})

		// Approval Queue Endpoints
		v1.Get("/approvals", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, approvals.ListAll())
		})

		v1.Post("/approvals/{id}/decision", func(w http.ResponseWriter, r *http.Request) {
			approvalID := chi.URLParam(r, "id")
			var body struct {
				Approver string `json:"approver"`
				Approved bool   `json:"approved"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if body.Approver == "" {
				body.Approver = "security-administrator"
			}

			rec, err := approvals.DecideApproval(approvalID, body.Approver, body.Approved)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, rec)
		})

		v1.Post("/approvals/{id}/execute", func(w http.ResponseWriter, r *http.Request) {
			approvalID := chi.URLParam(r, "id")
			var body struct {
				Arguments map[string]interface{} `json:"arguments"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			res, err := gwProxy.ExecuteApproved(r.Context(), approvalID, body.Arguments)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, res)
		})

		// Audit Log Endpoints
		v1.Get("/audit", func(w http.ResponseWriter, r *http.Request) {
			filter := audit.AuditFilter{
				CorrelationID: r.URL.Query().Get("correlation_id"),
				AgentID:       r.URL.Query().Get("agent_id"),
				TenantID:      r.URL.Query().Get("tenant_id"),
				ToolID:        r.URL.Query().Get("tool_id"),
				Outcome:       r.URL.Query().Get("outcome"),
			}
			events := auditStore.Query(filter)
			writeJSON(w, http.StatusOK, events)
		})

		v1.Get("/audit/stats", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, auditStore.Stats())
		})

		// Attack Lab Trigger
		v1.Post("/attack-lab/run", func(w http.ResponseWriter, r *http.Request) {
			report, err := labRunner.Run(r.Context())
			if err != nil {
				http.Error(w, fmt.Sprintf("attack lab failed: %v", err), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, report)
		})
	})

	// Static Frontend Serving (if dist folder exists)
	distPath := filepath.Join("ui", "dist")
	if info, err := os.Stat(distPath); err == nil && info.IsDir() {
		fs := http.FileServer(http.Dir(distPath))
		r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := os.Stat(filepath.Join(distPath, r.URL.Path)); os.IsNotExist(err) {
				http.ServeFile(w, r, filepath.Join(distPath, "index.html"))
				return
			}
			fs.ServeHTTP(w, r)
		}))
		log.Printf("[AgentShield] Serving web UI from %s", distPath)
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("[AgentShield] Gateway listening on http://127.0.0.1:%s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server error: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("[AgentShield] Shutting down gateway gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	log.Println("[AgentShield] Server stopped.")
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

